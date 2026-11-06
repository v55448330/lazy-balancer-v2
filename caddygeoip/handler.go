// Package caddygeoip provides a Caddy HTTP handler module that resolves the
// client IP against an ip2region xdb database and publishes the resulting
// country as placeholders for downstream handlers and matchers, mirrored as
// X-LB-GeoIP-* request headers for downstream coraza SecRules (v2.2.0 GeoIP
// 区域拦截匹配目标；同名客户端头在入口剥离，防伪造）。
package caddygeoip

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
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

	// XdbV6Path 是 IPv6 xdb 的路径：渲染侧仅在面板 v6 开关开启时发射（插件
	// 无路径兜底默认——空=v6 禁用）。禁用/文件缺失/损坏（健康门降级）时
	// IPv6 客户端查询返回空串，维持既有「海外」fail-closed 哨兵语义（仅
	// 作用于不可解析形态，见 setGeoIPPlaceholders）；开启且健康时 IPv6 与
	// v4 同语义解析（海外精确到国家、国内精确到省）。
	XdbV6Path string `json:"xdb_v6_path,omitempty"`

	searcher *geoipSearcher
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
	searcher, err := sharedGeoIPSearcher(h.XdbPath, h.XdbV6Path)
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

// —— xdb 全量内容缓存 + 池化 buffer searcher ——
//
// geoipSearcher 是本模块的双协议查询器：v4 必选、v6 可选。每族 = xdb 全量
// 内容字节（BufferCache 策略，查询零 syscall）+ 自建 20-searcher 池
// （channel 借还，与绑定库 SearcherPool 同构）。
//
// 为什么不用绑定库 NewIp2RegionWithPath / NewIp2Region(BufferCache)：
//   - NewIp2RegionWithPath 硬编码 VIndexCache——每查询 1-2 次 pread（热路径
//     syscall，before 基准 5710ns/op@5 allocs）；
//   - NewIp2Region 的 BufferCache 分支只建**单个** in-mem Searcher——
//     xdb.Searcher.Search 每次入口复写 ioCount 诊断字段（库内注释明示
//     not thread safe；根服务 internal/services/ip2region.go 对同一事实的
//     处置是全局互斥串行化）——并发下 -race 必红；
//   - SearcherPool 只能经 Config 构造（Config 字段不导出、无注入构造器），
//     无法复用进程级共享的内容字节。
//
// 因此自建池：内容字节进程内按（路径+文件形态）共享一份（geoipContentCache），
// N 个池的 20 只 searcher 全部引用同一字节数组（xdb.NewWithBuffer 是引用持有
// 非复制——绑定库源码 searcher.go NewSearcher cBuff 分支零拷贝）；并发查询各
// 借各还，零共享可变状态（ioCount 属 searcher 私有）。内存代价 = live v4
// xdb 大小 + v6 大小（各 ×1），换库重载窗口内新旧两份内容并存 ≤
// geoipOldInstanceCloseDelay（旧实例延迟关闭，在途查询保护），窗口过后旧
// 字节随实例一起 GC。
type geoipSearcher struct {
	v4 *geoipSearcherPool
	// v6 为 nil = v6 禁用族（Search 对 16 字节 IP 返回空串，哨兵语义，
	// 与绑定库双协议 API 的禁用形态一致）。
	v6 *geoipSearcherPool
}

// geoipSearcherPoolSize 是每族池深（与绑定库 NewIp2RegionWithPath 的默认
// 20 同值——借空时借还路径退化为 channel 阻塞等待，20 深对应此前 fd 形态
// 的并发容量，行为等价）。
const geoipSearcherPoolSize = 20

// Search 按 IP 字节长度分发到对应族（与 service.Ip2Region.Search 同形：
// string 走 ParseIP，[]byte 直查，其它类型报错）。
func (g *geoipSearcher) Search(ip any) (string, error) {
	var ipBytes []byte
	switch v := ip.(type) {
	case string:
		parsed, err := xdb.ParseIP(v)
		if err != nil {
			return "", fmt.Errorf("parse ip %s: %w", v, err)
		}
		ipBytes = parsed
	case []byte:
		ipBytes = v
	default:
		return "", fmt.Errorf("invalid ip value type %s", v)
	}

	if l := len(ipBytes); l == 4 {
		return g.v4.search(ipBytes)
	} else if l == 16 {
		if g.v6 == nil {
			// v6 禁用族：绑定库双协议 API 同形返回空串（哨兵语义由发射侧
			// setGeoIPPlaceholders 维持）。
			return "", nil
		}
		return g.v6.search(ipBytes)
	}
	return "", fmt.Errorf("invalid byte ip address with len=%d", len(ipBytes))
}

// Close 满足延迟回收路径的默认超时语义（与绑定库 Ip2Region.Close 同值 10s）。
func (g *geoipSearcher) Close() { g.CloseTimeout(10 * time.Second) }

// CloseTimeout 关闭两族池（等待借出的 searcher 归还或超时）。
func (g *geoipSearcher) CloseTimeout(d time.Duration) {
	if g.v4 != nil {
		g.v4.CloseTimeout(d)
	}
	if g.v6 != nil {
		g.v6.CloseTimeout(d)
	}
}

// geoipSearcherPool 是单族 buffer searcher 池（镜像绑定库 SearcherPool 的
// channel 借还 + 关闭等待语义；差别仅在 searcher 由全量内容字节构造、不持
// fd——借空时 channel 接收阻塞，同绑定库形态）。
type geoipSearcherPool struct {
	searchers chan *xdb.Searcher
	closing   chan struct{}
	loanCount atomic.Int32
}

// newGeoipSearcherPool 构造单族池：校验链与绑定库 newConfig 同强度
// （VerifyFromFile 结构自检 → 共享内容字节 → 头版本门），任一步失败返回
// error（调用方走 fail-stale 保旧实例，语义不变）。
func newGeoipSearcherPool(version *xdb.Version, path string) (*geoipSearcherPool, error) {
	if err := xdb.VerifyFromFile(path); err != nil {
		return nil, err
	}
	cBuffer, err := geoipContentBuffer(path)
	if err != nil {
		return nil, err
	}
	header, err := xdb.LoadHeaderFromBuff(cBuffer)
	if err != nil {
		return nil, err
	}
	got, err := xdb.VersionFromHeader(header)
	if err != nil {
		return nil, err
	}
	if got.Id != version.Id {
		return nil, fmt.Errorf("ip verison not match: xdb file %s with ip version=%s, as %s expected", path, got.Name, version.Name)
	}
	p := &geoipSearcherPool{
		searchers: make(chan *xdb.Searcher, geoipSearcherPoolSize+1),
		closing:   make(chan struct{}, 1),
	}
	for range geoipSearcherPoolSize {
		s, err := xdb.NewWithBuffer(version, cBuffer)
		if err != nil {
			p.CloseTimeout(0)
			return nil, fmt.Errorf("failed to create the %dth searcher: %w", len(p.searchers)+1, err)
		}
		p.searchers <- s
	}
	return p, nil
}

// search 借一只 searcher 查询并归还。借侧先选 closing（池关闭后空池借还
// 不再排队——与绑定库 BorrowSearcher 同形）；借空时 channel 接收阻塞等待
// 归还（并发容量 = 池深，同绑定库形态）。归还遇已关闭池（CloseTimeout 排空
// 后迟到归还）：丢引用让内容字节可回收，与绑定库 ReturnSearcher 关闭分支同形。
func (p *geoipSearcherPool) search(ipBytes []byte) (string, error) {
	p.loanCount.Add(1)
	defer func() {
		p.loanCount.Add(-1)
	}()
	var s *xdb.Searcher
	select {
	case <-p.closing:
		return "", fmt.Errorf("searcher pool already closed")
	case s = <-p.searchers:
	}
	defer func() {
		select {
		case <-p.closing:
			s.Close()
		default:
			p.searchers <- s
		}
	}()
	return s.Search(ipBytes)
}

// CloseTimeout 关闭池：close(closing) 后排空余量（丢引用让内容字节可回收），
// 限时等待借出的 searcher 归还（与绑定库 SearcherPool.CloseTimeout 同形）。
func (p *geoipSearcherPool) CloseTimeout(d time.Duration) {
	close(p.closing)
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		if p.loanCount.Load() == 0 && len(p.searchers) == 0 {
			return
		}
		select {
		case s := <-p.searchers:
			s.Close() // buffer searcher 无 fd，Close 仅为丢引用
		case <-timer.C:
			return
		}
	}
}

// geoipContentEntry 是内容缓存条目：字节 + 装载时的文件形态（modTime/size
// ——与共享实例的缓存判定同键口径，形态变化即换字节）。
type geoipContentEntry struct {
	buf     []byte
	modTime time.Time
	size    int64
	ino     int64
}

var (
	geoipContentMu    sync.Mutex
	geoipContentCache = map[string]geoipContentEntry{}
)

// geoipContentBuffer 返回 path 的 xdb 全量内容字节（进程内共享）：同路径且
// 磁盘形态未变 → 复用已装载字节（多实例/多池共享同一字节数组）；形态变化
// → 重新装载并替换条目（旧字节仍被旧实例 searcher 引用，随旧实例关闭 GC）。
// 装载源是文件本身——构造调用方（sharedGeoIPSearcher 重建分支）已由
// geoipSharedMu 串行化，无并发重复装载面；本锁为独立使用方兜底。
func geoipContentBuffer(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	// 缓存键 = 路径 + modTime + size + inode：带外 rsync -a 替换（新 inode、
	// 保留 mtime/size）可被 inode 差异检出；cp -p 原地覆写仍同形态（残余边角，
	// 生产更新走 rename 流不可达）。
	ino := int64(0)
	if stt, ok := st.Sys().(*syscall.Stat_t); ok {
		ino = int64(stt.Ino)
	}
	geoipContentMu.Lock()
	if e, ok := geoipContentCache[path]; ok && e.modTime.Equal(st.ModTime()) && e.size == st.Size() && e.ino == ino {
		geoipContentMu.Unlock()
		return e.buf, nil
	}
	geoipContentMu.Unlock()
	buf, err := xdb.LoadContentFromFile(path)
	if err != nil {
		return nil, err
	}
	geoipContentMu.Lock()
	geoipContentCache[path] = geoipContentEntry{buf: buf, modTime: st.ModTime(), size: st.Size(), ino: ino}
	geoipContentMu.Unlock()
	return buf, nil
}

// newGeoipSearcher 构造双协议查询器（v4 必选；v6Effective 非空时附加 v6
// 池，构造失败收敛已建的 v4 池不留半构造实例）。
func newGeoipSearcher(path, v6Effective string) (*geoipSearcher, error) {
	v4Pool, err := newGeoipSearcherPool(xdb.IPv4, path)
	if err != nil {
		return nil, err
	}
	g := &geoipSearcher{v4: v4Pool}
	if v6Effective != "" {
		v6Pool, err := newGeoipSearcherPool(xdb.IPv6, v6Effective)
		if err != nil {
			v4Pool.CloseTimeout(time.Second)
			return nil, err
		}
		g.v6 = v6Pool
	}
	return g, nil
}

// geoipSharedSearcher：按（XdbPath, v6 有效路径）进程级共享的查询器单例
// 条目。每条 GeoIP 规则各建一份查询器（20-searcher 池 ×2 族），同路径跨
// handler 共享一份即可——查询器本身无 fd（全量内容缓存 + buffer searcher），
// 共享动机从「fd 预算」演进为「内存预算」：50 条规则各建一份 = 50×xdb 字节
// 驻留，共享后 = 1×xdb 字节。modTime/size 记录建库时的文件形态：xdb 更新
// 流程 rename 换库后 Caddy 随 reloader 重载，纯路径键缓存会让新配置继续
// 持有旧字节、更新静默失效（更新任务依赖「Caddy 侧 geoip 随 reloader 收敛」），
// 文件形态变化即重建。v6 同构：v6ModTime/v6Size 记录 v6 库形态（双源更新
// 单任务内先 v4 后 v6，两次 rename 分属同一 reload 窗口，两形态都必须进
// 缓存判定）。needsRebuild 标记「文件形态曾不可 stat」：下一次 Provision
// 即使 stat 形态与缓存一致也必须重建（rsync -a 保留 mtime+size 的重铺形态），
// 防被删 inode 的旧库被无限期当有效数据服务。重建成功后由新条目清除。
type geoipSharedSearcher struct {
	searcher  *geoipSearcher
	modTime   time.Time
	size      int64
	v6ModTime time.Time
	v6Size    int64
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
// 配置的 handler 仍可能持旧实例在途查询（借空阻塞或判「海外」误拦——恰是要
// 修的问题），故不立即关闭；但旧实例也不再「保留至进程退出」（每次 xdb 更新
// 遗留一份旧内容字节 + 池），延迟窗口过后 CloseTimeout 收敛（排空池丢引用，
// 旧内容字节随实例 GC）。测试可缩短。
var geoipOldInstanceCloseDelay = 60 * time.Second

// sharedGeoIPSearcher 返回按（v4 路径, v6 有效路径）共享的单例：文件形态未变时
// 命中缓存，变化时重建；曾因不可 stat 被标记的条目（needsRebuild）即使形态未变
// 也重建。被替换的旧实例经 geoipOldInstanceCloseDelay 延迟关闭——新实例先接管
// （下方缓存替换完成后 Provision 返回，新配置随之重载），旧实例在窗口内继续服务
// 在途查询，窗口过后由定时器 CloseTimeout（等待借出的 searcher 归还，在途查询
// 不受截断）。v6Path 为空或健康门（healthyV6Path 头校验）不过时按「v6 禁用」
// 构造——双协议 API 对禁用族的 Search 返回空串，setGeoIPPlaceholders 维持
// 「海外」哨兵（fail-closed 语义不变，仅作用于不可解析形态），v4 链不受影响。
func sharedGeoIPSearcher(path, v6Path string) (*geoipSearcher, error) {
	v6Effective := healthyV6Path(v6Path, path)
	key := path + "\x00" + v6Effective
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
		cached, ok := geoipSharedSearchers[key]
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
	if cached, ok := geoipSharedSearchers[key]; ok && !cached.needsRebuild &&
		cached.modTime.Equal(st.ModTime()) && cached.size == st.Size() &&
		v6FormUnchanged(cached, v6Effective) {
		clearGeoIPWarnLogs(path)
		return cached.searcher, nil
	}
	searcher, err := newGeoipSearcher(path, v6Effective)
	if err != nil {
		// 重建失败（带外损坏的 xdb 等）不回退缓存旧实例，则
		// Provision 收到 error → handler 降级 pass-through → 全部客户端判
		// 「海外」→ deny 海外策略全量误拦（与 wafiplist 的 fail-stale 不对称）。
		// 正常更新走 rename（文件形态变化即命中成功重建），失败分支只可能是
		// 带外损坏：保留旧实例继续服务（fail-stale），文件修复后的下一次
		// Provision/reload 再重建。缓存条目保持旧形态，不驱逐。
		if cached, ok := geoipSharedSearchers[key]; ok {
			geoipWarnThrottled("rebuild", path, "ip2region rebuild failed, serving the previous database instance",
				zap.String("xdb_path", path), zap.Error(err))
			return cached.searcher, nil
		}
		// 无缓存的重建失败同样按（原因|路径）节流上报，与有缓存分支同族。
		geoipWarnThrottled("rebuild-unavailable", path, "ip2region database unavailable, geoip disabled",
			zap.String("xdb_path", path), zap.Error(err))
		return nil, err
	}
	entry := &geoipSharedSearcher{searcher: searcher, modTime: st.ModTime(), size: st.Size()}
	if v6Effective != "" {
		if v6st, v6err := os.Stat(v6Effective); v6err == nil {
			entry.v6ModTime, entry.v6Size = v6st.ModTime(), v6st.Size()
		}
	}
	if replaced, ok := geoipSharedSearchers[key]; ok {
		old := replaced.searcher
		time.AfterFunc(geoipOldInstanceCloseDelay, func() { old.Close() })
	}
	geoipSharedSearchers[key] = entry
	clearGeoIPWarnLogs(path)
	return searcher, nil
}

// healthyV6Path 是 v6 文件健康门：空值=禁用直接放行空串；非空时读 256B 头
// 校验（xdb.LoadHeaderFromFile + VersionFromHeader 必须判定为 IPv6 库），
// 失败按「v6 禁用」降级（节流 WARN；v4Path 仅作告警键归属）。
func healthyV6Path(v6Path, v4Path string) string {
	if v6Path == "" {
		return ""
	}
	header, err := xdb.LoadHeaderFromFile(v6Path)
	if err != nil {
		geoipWarnThrottled("v6-unavailable", v4Path, "ip2region v6 database unavailable, v6 lookups degrade to disabled",
			zap.String("xdb_v6_path", v6Path), zap.Error(err))
		return ""
	}
	version, verr := xdb.VersionFromHeader(header)
	if verr != nil || version != xdb.IPv6 {
		geoipWarnThrottled("v6-invalid", v4Path, "ip2region v6 database is not an IPv6 xdb, v6 lookups degrade to disabled",
			zap.String("xdb_v6_path", v6Path))
		return ""
	}
	return v6Path
}

// v6FormUnchanged 报告缓存条目的 v6 形态是否仍与磁盘一致：v6 禁用（空路径）
// 恒一致；启用时 v6 文件被换库（rename 换 mtime/size）即失效重建——与 v4
// 的 modTime/size 判定同构（双源更新依赖「Caddy 侧 geoip 随 reloader 收敛」，
// v6 换库同样依赖本判定）。
func v6FormUnchanged(cached *geoipSharedSearcher, v6Effective string) bool {
	if v6Effective == "" {
		return cached.v6ModTime.IsZero() && cached.v6Size == 0
	}
	v6st, err := os.Stat(v6Effective)
	if err != nil {
		return false
	}
	return cached.v6ModTime.Equal(v6st.ModTime()) && cached.v6Size == v6st.Size()
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
	// （裁决：fail-closed 哨兵）：不可解析客户端（v6 禁用/缺库时的全部 IPv6
	// 流量、查询失败、残缺 region）此前不发任何变量 → geoip CEL 对未设置变量
	// 求值出错 → match=false → deny 模式地域拦截对 IPv6 静默零强制。现恒发
	// 全部变量，空串哨兵下：海外项 country_name != "中国" 对空串成立（IPv6
	// 按海外处理，与 fail-closed 立场一致）；省/市项对空串恒不匹配（不误伤）。
	// v6 开关开启且库健康时 IPv6 客户端经双协议 API 正常解析（海外精确到
	// 国家、国内精确到省），「海外」哨兵兜底面随之收窄到真正的不可解析形态
	// （库缺失/损坏/查询失败/禁用）——两链失败语义裁定不变。
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
