// Package caddygeoip provides a Caddy HTTP handler module that resolves the
// client IP against an ip2region xdb database and publishes the resulting
// country as placeholders for downstream handlers and matchers, mirrored as
// X-LB-GeoIP-* request headers for downstream coraza SecRules (v2.2.0 GeoIP
// 区域拦截匹配目标；同名客户端头在入口剥离，防伪造）。
package caddygeoip

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/lionsoul2014/ip2region/binding/golang/service"
	"go.uber.org/zap"
	"lazy-balancer-v2/geoipnames"
)

func init() {
	caddy.RegisterModule(GeoIPHandler{})
}

// GeoIPHandler looks up the client IP in the ip2region database and sets the
// geoip.country_name/region/province/city placeholders on the request
// replacer. Blocking decisions belong to downstream matchers; this handler
// always passes the request through.
type GeoIPHandler struct {
	// XdbPath is the path to the ip2region xdb database. When empty it
	// defaults to /app/data/ip2region.xdb.
	XdbPath string `json:"xdb_path,omitempty"`

	// CrawlerExempt 由渲染侧按绑定策略输出（任一策略 GeoIPCrawlerExempt）。
	// false 时只剥离客户端伪造的验证头、不做 PTR/DNS 验证（无豁免
	// 规则消费结论，验证纯属浪费；旧实现无法关闭验证）。未配置按 false。
	CrawlerExempt bool `json:"crawler_exempt,omitempty"`

	// CrawlerIPListFile 厂商爬虫 IP 段快照交换文件路径（root 服务写、插件读）。
	// 根服务经 ConfigureWafDirs 按 data_dir 派生后由渲染侧发射本键（仅在
	// 派生值不同于下方默认时发射）；空值默认 /app/data/crawler-ip-lists.json
	// ——与根服务容器默认逐字节一致（插件侧兜底，非渲染层）。
	CrawlerIPListFile string `json:"crawler_ip_list_file,omitempty"`

	searcher *service.Ip2Region
}

// CaddyModule returns the Caddy module information.
func (GeoIPHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.geoip2region",
		New: func() caddy.Module { return new(GeoIPHandler) },
	}
}

// Provision opens the ip2region database. A missing or unreadable database
// disables lookups (the handler degrades to a pass-through) instead of
// failing the Caddy configuration load.
func (h *GeoIPHandler) Provision(ctx caddy.Context) error {
	if h.XdbPath == "" {
		h.XdbPath = "/app/data/ip2region.xdb"
	}
	if h.CrawlerIPListFile == "" {
		h.CrawlerIPListFile = defaultCrawlerIPListFile
	}
	setCrawlerIPListFilePath(h.CrawlerIPListFile)
	searcher, err := sharedGeoIPSearcher(h.XdbPath)
	if err != nil {
		// 告警已在 sharedGeoIPSearcher 内按（原因|路径）节流上报——一次
		// reload 每条地域规则各调一次本函数，此处再 Warn 会按规则数放大。
		ctx.Logger().Debug("geoip2region: ip2region database unavailable, geoip disabled",
			zap.String("xdb_path", h.XdbPath), zap.Error(err))
		return nil
	}
	h.searcher = searcher
	return nil
}

// geoipSharedSearcher：按 XdbPath 进程级共享的 Ip2Region 单例条目。
// 每条 GeoIP 规则各建一份 NewIp2RegionWithPath（内部 NewV4Config(VIndexCache,
// path, 20)——20 个 searcher 各持 1 个 xdb fd + vIndex 缓冲），50 条规则≈1000 fd
// 逼近 soft limit，重载期新旧实例并存再翻倍；fd 耗尽 → Provision 降级
// pass-through → 全客户端判「海外」→ 含海外 deny 的策略全量误拦。SearcherPool
// 内部 channel 借还本就并发安全，同路径跨 handler 共享一份即可。modTime/size
// 记录建库时的文件形态：xdb 更新流程 rename 换库后 Caddy 随 reloader 重载，
// 纯路径键缓存会让新配置继续持有旧 inode 的 fd、更新静默失效（ip2regionupdate.go
// 依赖「Caddy 侧 geoip 随 reloader 收敛」），文件形态变化即重建。
type geoipSharedSearcher struct {
	searcher *service.Ip2Region
	modTime  time.Time
	size     int64
	// needsRebuild 标记「文件形态曾不可 stat」：下一次 Provision 即使 stat
	// 形态与缓存一致也必须重建（rsync -a 保留 mtime+size 的重铺形态），
	// 防被删 inode 的旧库被无限期当有效数据服务。重建成功后由新条目清除。
	needsRebuild bool
}

var (
	geoipSharedMu        sync.Mutex
	geoipSharedSearchers = map[string]*geoipSharedSearcher{}
)

// geoipWarnLogInterval 是同路径同原因告警的最小间隔：每条地域规则各调一次
// sharedGeoIPSearcher，文件不可 stat/重建失败会按规则数放大重复 WARN（稀释
// 真实告警）。恢复成功后清除记录——再次故障即时上报。
var geoipWarnThrottle = newKeyedWarnThrottle(time.Minute)

// geoipWarnCallsForTest 仅测试观测「实际写日志次数」（节流生效的机器断言）。
var geoipWarnCallsForTest atomic.Int64

// geoipWarnThrottled 按（路径|原因）节流后写 WARN。
func geoipWarnThrottled(reason, path, msg string, fields ...zap.Field) {
	if !geoipWarnThrottle.allow(path + "|" + reason) {
		return
	}
	geoipWarnCallsForTest.Add(1)
	caddy.Log().Named("geoip2region").Warn(msg, fields...)
}

// clearGeoIPWarnLogs 清除路径的节流记录（成功重建/命中后调用：恢复后再次
// 故障必须立即上报）。
func clearGeoIPWarnLogs(path string) {
	geoipWarnThrottle.clearPrefix(path + "|")
}

// geoipOldInstanceCloseDelay 换库重建后旧实例的延迟关闭窗口：重载窗口内旧
// 配置的 handler 仍可能持旧实例在途查询（BorrowSearcher 落空会判「海外」
// 误拦——恰是要修的问题），故不立即关闭；但旧实例也不再「保留至进程
// 退出」（每次 xdb 更新遗留 20 个 fd + vIndex 缓冲），延迟窗口过后 Close
// 收敛。测试可缩短。
var geoipOldInstanceCloseDelay = 60 * time.Second

// sharedGeoIPSearcher 返回按路径共享的单例：文件形态未变时命中缓存，变化时重建；
// 曾因不可 stat 被标记的条目（needsRebuild）即使形态未变也重建。
// 被替换的旧实例经 geoipOldInstanceCloseDelay 延迟关闭——新实例先接管（下方
// 缓存替换完成后 Provision 返回，新配置随之重载），旧实例在窗口内继续服务
// 在途查询，窗口过后由定时器 Close（Ip2Region.Close 等待借出的 searcher
// 归还，在途查询不受截断）。
func sharedGeoIPSearcher(path string) (*service.Ip2Region, error) {
	st, err := os.Stat(path)
	if err != nil {
		// stat 失败（xdb 更新 rename 窗口/文件被删）且缓存持有该路径条目时
		// **本次仍返回该实例**（fail-stale），并把条目标为「必须重建」：
		//   - 返回 error 会让 Provision 降级 pass-through → 该次 reload 之后
		//     全部客户端判「海外」→ allow 模式的 geoip 规则等价全量拦截
		//     （deny 海外同样全量命中），唯一痕迹只有一条 Warn；而 stat 瞬时
		//     失败（挂载抖动、权限瞬变、rm+cp 交错）并不等于数据库已不可用。
		//   - 标记而不删条目：一次 reload 里每个 geoip 规则各调一次本函数，
		//     删掉条目会让第二个及之后的实例拿不到缓存而再次降级（只有首个
		//     规则免于全量拦截，同一份配置内部行为不一致）。
		//   - 标记保证下一次 Provision 必然重读重建（不复用旧 inode）：文件以
		//     「同 modtime+size」形态恢复（rsync -a 保时间戳重铺）时缓存命中
		//     判定不会把被删 inode 的旧库当有效数据继续服务。
		geoipSharedMu.Lock()
		cached, ok := geoipSharedSearchers[path]
		if ok {
			cached.needsRebuild = true
		}
		geoipSharedMu.Unlock()
		if !ok {
			// 无缓存形态（首次缺失/权限错/挂载未就绪）是最常见的失败分支，
			// 必须与 fail-stale 分支同族节流：一次 reload 会为每条地域规则
			// 各调一次本函数，不节流则 WARN 按规则数放大并稀释真实告警。
			geoipWarnThrottled("unavailable", path, "ip2region database unavailable, geoip disabled",
				zap.String("xdb_path", path), zap.Error(err))
			return nil, err
		}
		geoipWarnThrottled("stat", path, "ip2region database is not stat-able, serving the previous database instance and rebuilding on the next reload",
			zap.String("xdb_path", path), zap.Error(err))
		return cached.searcher, nil
	}
	geoipSharedMu.Lock()
	defer geoipSharedMu.Unlock()
	if cached, ok := geoipSharedSearchers[path]; ok && !cached.needsRebuild &&
		cached.modTime.Equal(st.ModTime()) && cached.size == st.Size() {
		clearGeoIPWarnLogs(path)
		return cached.searcher, nil
	}
	searcher, err := service.NewIp2RegionWithPath(path, "")
	if err != nil {
		// 重建失败（带外损坏的 xdb 等）不回退缓存旧实例，则
		// Provision 收到 error → handler 降级 pass-through → 全部客户端判
		// 「海外」→ deny 海外策略全量误拦（与 wafiplist 的 fail-stale 不对称）。
		// 正常更新走 rename（文件形态变化即命中成功重建），失败分支只可能是
		// 带外损坏：保留旧实例继续服务（fail-stale），文件修复后的下一次
		// Provision/reload 再重建。缓存条目保持旧形态，不驱逐。
		if cached, ok := geoipSharedSearchers[path]; ok {
			geoipWarnThrottled("rebuild", path, "ip2region rebuild failed, serving the previous database instance",
				zap.String("xdb_path", path), zap.Error(err))
			return cached.searcher, nil
		}
		// 无缓存的重建失败同样按（原因|路径）节流上报，与有缓存分支同族。
		geoipWarnThrottled("rebuild-unavailable", path, "ip2region database unavailable, geoip disabled",
			zap.String("xdb_path", path), zap.Error(err))
		return nil, err
	}
	if replaced, ok := geoipSharedSearchers[path]; ok {
		old := replaced.searcher
		time.AfterFunc(geoipOldInstanceCloseDelay, func() { old.Close() })
	}
	geoipSharedSearchers[path] = &geoipSharedSearcher{searcher: searcher, modTime: st.ModTime(), size: st.Size()}
	clearGeoIPWarnLogs(path)
	return searcher, nil
}

// geoipCorazaHeaders lists the request headers this module owns. v2.2.0 地域
// 拦截改走 coraza（BuildCorazaDirectives 的 GeoIP SecRule 在 phase:1 读取
// X-LB-GeoIP-Loc），其中 X-LB-GeoIP-Loc 是 geoip.* 变量的镜像；其余同名头
// 只做剥离、不再发射（X-LB-GeoIP-Country-Code 的发射已删除，
// geoip.country_code 变量与测试均按「不发布」钉住）。客户端伪造的同名头在
// ServeHTTP 入口无条件删除（先删后设，防伪造绕过/误伤）——不要按「镜像」
// 语义把已删的发射加回来。
var geoipCorazaHeaders = []string{
	"X-LB-GeoIP-Country", "X-LB-GeoIP-Country-Code", "X-LB-GeoIP-Region",
	"X-LB-GeoIP-Province", "X-LB-GeoIP-City", "X-LB-GeoIP-Loc",
}

// ServeHTTP publishes the client country and always delegates to the next
// handler in the chain.
func (h *GeoIPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 无论 xdb 是否可用都先剥掉客户端伪造的 X-LB-GeoIP-* 头：xdb 缺失时
	// setGeoIPPlaceholders 不执行，伪造头若残留会直接喂给下游 coraza 的
	// 地域规则（伪造 X-LB-GeoIP-Loc=某 allow 名单省份即可绕过 allow 模式拦截）。
	for _, name := range geoipCorazaHeaders {
		r.Header.Del(name)
	}
	// v2.3.8 爬虫豁免：客户端伪造的验证头一并剥除（与 GeoIP 头同防御边界），
	// 随后 UA 命中引擎时做 PTR 双跳验证并注入结论头（coraza 豁免规则消费）。
	r.Header.Del(crawlerVerifiedHeader)
	r.Header.Del(crawlerSpoofHeader)
	if h.searcher != nil {
		h.setGeoIPPlaceholders(r)
	} else {
		// xdb 缺失/损坏（Provision 降级 pass-through）：coraza 的地域规则读
		// REQUEST_HEADERS:X-LB-GeoIP-Loc，缺失变量在 coraza 连取反算子都不产生
		// 匹配（rule.go evaluate 按值循环）——不置哨兵则 deny/allow 两模式的
		// id:8 恒不命中，地域拦截静默 fail-open。必须与查询失败分支同口径发射
		// 全套哨兵（变量 + 头）：只发 Loc 头会让 geoip.* 变量消费方
		// （流量统计桶/未来 CEL 规则）读到未设置变量，形成
		// 「collecting=true 但恒零」的静默口径分裂。
		setGeoIPSentinels(r.Context(), r)
	}
	h.applyCrawlerVerification(r)
	return next.ServeHTTP(w, r)
}

// 爬虫验证结论头（服务端注入；客户端携带的同名头已在上游剥除）。
const (
	crawlerVerifiedHeader = "X-LB-Crawler-Verified"
	crawlerSpoofHeader    = "X-LB-Crawler-Spoof"
)

// applyCrawlerVerification UA 命中引擎 → PTR 双跳验证三态置头：
//   - Verified=引擎 ID（下游豁免规则 @streq 消费）；
//   - Spoof=引擎 ID（伪装事件规则消费——渲染侧按策略已选引擎集合
//     @rx^(?:engine|…)$ 匹配，见 buildIPPrecheckDirectives。旧注释写 Spoof=1
//     与实际发射的引擎 ID 矛盾，按旧注释把规则改回 @eq 1 会让伪装事件族
//     静默永不命中）；
//   - 瞬态（DNS 抖动/超时/并发饱和/官方段快照不可用/客户端地址不可解析）：
//     不置任何头——本次既不豁免也不判伪装。二态实现曾把瞬态一律置 Spoof，
//     真实爬虫在 DNS 抖动下被伪装规则实际阻断并产生伪安全事件。
//
// 非爬虫 UA 不做 DNS/PTR，但 MatchCrawlerEngine 仍需顺序扫描引擎正则表；
// 未命中时承担全表预编译正则成本，命中时每个 UA 只匹配一次。
func (h *GeoIPHandler) applyCrawlerVerification(r *http.Request) {
	// 渲染门控字段 false（无爬虫豁免策略）时零 DNS/PTR 开销；
	// 客户端伪造头已在 ServeHTTP 入口剥离，因此「只剥不验」是安全形态。
	if !h.CrawlerExempt {
		return
	}
	// （并入）：UA 只匹配一次（旧实现对同一 UA 调两次
	// MatchCrawlerEngine，2000/s 正常流量下多付一次全表正则）。
	ua := r.Header.Get("User-Agent")
	engine := geoipnames.MatchCrawlerEngine(ua)
	if engine == "" {
		return
	}
	ip := clientIPForVerify(r)
	verdict := CrawlerVerdictTransient
	if ip != "" {
		verdict = VerifyCrawler(ip, engine)
	}
	switch verdict {
	case CrawlerVerdictVerified:
		r.Header.Set(crawlerVerifiedHeader, engine)
	case CrawlerVerdictSpoof:
		// 值携带引擎 ID（与 Verified 对称）——coraza 伪装规则按
		// 策略已选引擎集合匹配，不再全局 @eq 1。
		//
		// 只有「UA 命中了该引擎的伪装证据门」才发射：宽品牌标记（裸
		// DeepSeek 等）或对话式标记单独命中不构成伪装证据，否则普通浏览器
		// UA 会产出伪伪装事件（判定口径留在引擎注册表单源）。
		if geoipnames.CrawlerSpoofEvidence(engine, ua) {
			r.Header.Set(crawlerSpoofHeader, engine)
		}
	default:
		// 瞬态：不置头（见上方三态说明）。
	}
}

// clientIPForVerify 取验证用客户端 IP：复用 realClientIP 单源——
// 优先 Caddy client_ip 变量（受信代理还原后的真实客户端），而非 socket
// RemoteAddr。旧注释「RemoteAddr 已是真实客户端地址」在 CDN/受信代理部署下
// 不成立：socket 对端是 CDN 回源 IP，PTR 验证必然失败（真爬虫被判伪装）。
// 变量缺席时 realClientIP 回退 RemoteAddr 并做 ParseIP 校验（fail-closed）。
func clientIPForVerify(r *http.Request) string {
	return realClientIP(r)
}

// Cleanup 不关闭也不置空共享 searcher：单例按 XdbPath 进程级共享，换库由
// geoipOldInstanceCloseDelay 延迟回收。保留旧 handler 的指针可让 Caddy 重载
// 窗口内的在途请求继续查库，并消除 Cleanup 与 ServeHTTP 之间的数据竞争。
func (h *GeoIPHandler) Cleanup() error {
	return nil
}

// setGeoIPSentinels 发射 fail-closed 哨兵形态：4 个 geoip.* 变量与 4 个空串
// 头哨兵 + X-LB-GeoIP-Loc=「海外」。已解析行随后覆盖（国内为省/省-市，海外
// 为国名）。xdb 不可用与查询失败两条分支必须共用本实现——只发 Loc 头会让
// geoip.* 变量消费方（流量统计桶、未来 CEL 规则）读到未设置变量，形成与
// 「查询失败」不同的静默口径。
func setGeoIPSentinels(ctx context.Context, r *http.Request) {
	caddyhttp.SetVar(ctx, "geoip.country_name", "")
	caddyhttp.SetVar(ctx, "geoip.region", "")
	caddyhttp.SetVar(ctx, "geoip.province", "")
	caddyhttp.SetVar(ctx, "geoip.city", "")
	r.Header.Set("X-LB-GeoIP-Country", "")
	r.Header.Set("X-LB-GeoIP-Region", "")
	r.Header.Set("X-LB-GeoIP-Province", "")
	r.Header.Set("X-LB-GeoIP-City", "")
	r.Header.Set("X-LB-GeoIP-Loc", "海外")
}

// setGeoIPPlaceholders resolves the client IP against the database and
// publishes the country fields on the request replacer. v2.2.0 起同值镜像为
// X-LB-GeoIP-* 请求头（含 fail-closed 空串哨兵），供下游 coraza 的 GeoIP
// SecRule 匹配；X-LB-GeoIP-Loc 是地域规则匹配键：国名/省/省-市，海外为
// 解析失败与非国家值的兜底（详见下方）。
func (h *GeoIPHandler) setGeoIPPlaceholders(r *http.Request) {
	ctx := r.Context()
	// （裁决：fail-closed 哨兵）：不可解析客户端（全部 IPv6 流量、
	// 查询失败、残缺 region）此前不发任何变量 → geoip CEL 对未设置变量求值出
	// 错 → match=false → deny 模式地域拦截对 IPv6 静默零强制。现恒发全部变量，
	// 空串哨兵下：海外项 country_name != "中国" 对空串成立（IPv6 按海外处理，
	// 与 fail-closed 立场一致）；省/市项对空串恒不匹配（不误伤）。
	// 头镜像同语义：X-LB-GeoIP-Loc 先置「海外」哨兵（承载 fail-closed 海外裁决
	// ——不可解析客户端保此值）；已解析行随后覆盖为国名（海外）或省/省-市（国内，
	// 域 G 历史）。省/市空串对 coraza 锚定正则（^(?:...)$）恒不匹配。
	setGeoIPSentinels(ctx, r)
	province, city := "", ""
	ip := realClientIP(r)
	if ip == "" {
		return
	}
	region, err := h.searcher.Search(ip)
	if err != nil || region == "" {
		return
	}
	emitted, ok := parseGeoIPRegion(region)
	if !ok {
		return
	}
	province, city = emitted.Province, emitted.City
	caddyhttp.SetVar(ctx, "geoip.country_name", emitted.Country)
	caddyhttp.SetVar(ctx, "geoip.region", emitted.Region)
	r.Header.Set("X-LB-GeoIP-Country", emitted.Country)
	r.Header.Set("X-LB-GeoIP-Region", emitted.Region)
	caddyhttp.SetVar(ctx, "geoip.province", province)
	r.Header.Set("X-LB-GeoIP-Province", province)
	caddyhttp.SetVar(ctx, "geoip.city", city)
	r.Header.Set("X-LB-GeoIP-City", city)
	// X-LB-GeoIP-Loc：地域规则匹配键（coraza SecRule 的锚定正则全值目标）。
	r.Header.Set("X-LB-GeoIP-Loc", emitted.Loc)
}

// geoIPRegionFields 是 xdb region 行的发射侧投影：变量、X-LB-GeoIP-* 头与
// 流量统计桶全部消费同一份归一值，避免多路径各自取原始列造成口径漂移。
type geoIPRegionFields struct {
	Country  string // xdb 国家列（TrimSpace + 异体归一，与 Loc/统计桶同口径）
	Region   string // xdb 原始 region 串（region 变量/头沿用）
	Province string // 省列规范化值
	City     string // 城市列规范化值（省列为空时恒为空——树不变式）
	Loc      string // 地域规则匹配键
}

// parseGeoIPRegion 把 xdb region 行解析为发射字段。
// 国家列统一 TrimSpace + NormalizeCountry 异体归一（复用统计桶入口的
// normalizeTrafficCountryKey：「中国」保留、中文异体「美国」折叠为规范名、
// 空/0/Reserved 归空串）——前变量/头发射原始列，而 geoipLocFor 与统计桶走
// 归一值：同一 xdb 行会出现 Loc=United States 但 country_name=美国 的
// 口径分裂，按 Country 头/变量的匹配对中文异体段恒不命中。
func parseGeoIPRegion(region string) (geoIPRegionFields, bool) {
	fields := strings.Split(region, "|")
	if len(fields) < 5 {
		return geoIPRegionFields{}, false
	}
	out := geoIPRegionFields{Country: normalizeTrafficCountryKey(fields[0]), Region: region}
	// 上方 len(fields)>=5 已保证,原两处 len>=3 守卫
	// 恒真,直接执行块内逻辑。
	if raw := fields[1]; raw != "" && raw != "0" {
		// 省列规范化——xdb 存在双形态（上海/上海市）与
		// 台湾城市误入省列；规范表已单源收敛进 geoipnames 包（选项树侧
		// ProvinceForTree / 发射侧 ProvinceForEmit 同表驱动，见 region.go），
		// 发射变量与选项树同规范化后 CEL 等值匹配才成立。
		out.Province = normalizeProvince(raw)
	}
	// 市级粒度——region 第 3 列为城市；无效值（空/0）置空串，
	// 使 CEL {http.vars.geoip.city} == X 对无城市段恒不命中。
	// 城市列经 normalizeCity 规范化——xdb 部分段城市列为拼音/
	// 英文（Guangzhou Shi/Taipei City），策略树侧已映射为中文，发射侧不映射
	// 会导致「广东省/广州市」类城市级规则对这些段恒不命中。
	// 台湾城市误入省列的段：城市名在省列（城市列是该段的乱码罗马化值）——
	// 城市变量改发省列值，与树侧归并语义一致，使「台湾省/台中市」可命中。
	if rawProv := strings.TrimSpace(fields[1]); geoipnames.IsTaiwanCity(rawProv) {
		out.City = rawProv
	} else if c := strings.TrimSpace(fields[2]); c != "" && c != "0" {
		out.City = normalizeCity(c)
	}
	// 代码级不变量（树不变式）：省列归一为空时城市一律置空——不得发射
	// 树侧不可表达的「/城市」Loc 或孤立城市变量。当前三份随包 xdb 全段扫描
	// 该形态为 0 行，但 xdb 可在线更新，守卫把「新库引入脏形态」从静默
	// 脏值变为显性丢弃。
	if out.Province == "" {
		out.City = ""
	}
	// geoipLocFor 承载三态判定。传入已归一的国家列（out.Country）——归一
	// 是单源（normalizeTrafficCountryKey），Loc 与 country_name 不得各自
	// 归一（历史形态：两处逐案等价，加新别名时单侧漏改会让两个头的口径分裂）。
	out.Loc = geoipLocFor(out.Country, out.Province, out.City)
	return out, true
}

// geoipLocFor 由**已归一**的国家列与规范化省/市列计算 X-LB-GeoIP-Loc 值：
// 国内（country == 中国）→ 省 或 省/市；海外 → 归一化国名（域 G，历史——
// 已解析海外行细化到国家，与选项树 Countries 同源同归一）；国家列不可解析为
// 国名（空/0/Reserved/中国空白异形经归一折叠空串）→「海外」哨兵，与
// fail-closed 哨兵同口径（deny+海外仍拦此类客户端）。
func geoipLocFor(country, province, city string) string {
	if country == "中国" {
		if city != "" {
			return province + "/" + city
		}
		return province
	}
	if country != "" {
		return country
	}
	return "海外"
}

// realClientIP 取真实客户端 IP：优先 Caddy client_ip 变量（v2.3.x）——
// trusted_proxies 启用时它经「回源网段 + 有序请求头」校验，伪造头不改变
// 判定；X-Forwarded-For 仅在 Caddy 配置 trusted_proxies 时被采信（此
// handler 运行在边缘，未经 Caddy 受信代理判定的头不可信）。变量缺席
// （非 Caddy 上下文）回退 RemoteAddr 解析——直连部署行为不变。
func realClientIP(r *http.Request) string {
	if ip, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if net.ParseIP(r.RemoteAddr) != nil {
			return r.RemoteAddr
		}
		return ""
	}
	return host
}

// 规范化四张表（省别名/台湾城市/拼音城市/自治州）单源在
// lazy-balancer-v2/geoipnames（收敛——此前与
// internal/services 手工镜像双份，靠解析对侧源文本的镜像测试防漂移；
// 中立叶模块经根/caddygeoip 双 replace 接线，与 wafiplist 同模式）。

// normalizeProvince 发射侧省列规范化——单源 geoipnames.ProvinceForEmit
// （下沉：此前与 internal/services.normalizeIP2Province 是
// 两份手工镜像，语义分叉靠调用点补偿）。台湾城市误入省列时省变量按台湾省
// 发射、城市变量改发省列值（见 setGeoIPPlaceholders——该类段的城市列是
// 乱码值）；无效值（空/"0"）→ 空串；别名归一；不可识别（乱码）原样返回
// （不出现在选项树中，策略不会配置）。
func normalizeProvince(raw string) string {
	return geoipnames.ProvinceForEmit(raw)
}

// normalizeCity 发射侧城市列规范化——单源 geoipnames.CityForEmit：表映射
// 命中返回规范中文；无效值（空/"0"）→ 空串；未映射的 ASCII 城市原样返回
// （选项树侧会过滤、策略不会配置，发射原值恒不命中——与 normalizeProvince
// 的不可识别语义一致）；中文城市原样通过。
func normalizeCity(raw string) string {
	return geoipnames.CityForEmit(raw)
}
