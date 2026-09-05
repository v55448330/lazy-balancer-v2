// Package caddygeoip provides a Caddy HTTP handler module that resolves the
// client IP against an ip2region xdb database and publishes the resulting
// country as placeholders for downstream handlers and matchers, mirrored as
// X-GeoIP-* request headers for downstream coraza SecRules (v2.2.0 GeoIP
// 区域拦截匹配目标；同名客户端头在入口剥离，防伪造）。
package caddygeoip

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/lionsoul2014/ip2region/binding/golang/service"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(GeoIPHandler{})
}

// GeoIPHandler looks up the client IP in the ip2region database and sets the
// geoip.country_code and geoip.country_name placeholders on the request
// replacer. Blocking decisions belong to downstream matchers; this handler
// always passes the request through.
type GeoIPHandler struct {
	// XdbPath is the path to the ip2region xdb database. When empty it
	// defaults to /app/data/ip2region.xdb.
	XdbPath string `json:"xdb_path,omitempty"`

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
	searcher, err := sharedGeoIPSearcher(h.XdbPath)
	if err != nil {
		ctx.Logger().Warn("geoip2region: ip2region database unavailable, geoip disabled",
			zap.String("xdb_path", h.XdbPath), zap.Error(err))
		return nil
	}
	h.searcher = searcher
	return nil
}

// geoipSharedSearcher（审计 M2）：按 XdbPath 进程级共享的 Ip2Region 单例条目。
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
}

var (
	geoipSharedMu        sync.Mutex
	geoipSharedSearchers = map[string]*geoipSharedSearcher{}
)

// sharedGeoIPSearcher 返回按路径共享的单例：文件形态未变时命中缓存，变化时重建。
// 被替换的旧实例不关闭——重载窗口内旧配置的 handler 仍在用它查询，关闭会使
// BorrowSearcher 落空、查询失败被判「海外」（恰是 M2 要修的误拦）；旧实例的
// 20 个 fd 保留至进程退出（每次 xdb 更新至多一份，可忽略）。
func sharedGeoIPSearcher(path string) (*service.Ip2Region, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	geoipSharedMu.Lock()
	defer geoipSharedMu.Unlock()
	if cached, ok := geoipSharedSearchers[path]; ok &&
		cached.modTime.Equal(st.ModTime()) && cached.size == st.Size() {
		return cached.searcher, nil
	}
	searcher, err := service.NewIp2RegionWithPath(path, "")
	if err != nil {
		return nil, err
	}
	geoipSharedSearchers[path] = &geoipSharedSearcher{searcher: searcher, modTime: st.ModTime(), size: st.Size()}
	return searcher, nil
}

// geoipCorazaHeaders lists the request headers this module owns. v2.2.0 地域
// 拦截改走 coraza（BuildCorazaDirectives 的 GeoIP SecRule 在 phase:1 读取
// X-GeoIP-Loc），这些头是 geoip.* 变量的镜像；客户端伪造的同名头在
// ServeHTTP 入口无条件删除（先删后设，防伪造绕过/误伤）。
var geoipCorazaHeaders = []string{
	"X-GeoIP-Country", "X-GeoIP-Country-Code", "X-GeoIP-Region",
	"X-GeoIP-Province", "X-GeoIP-City", "X-GeoIP-Loc",
}

// ServeHTTP publishes the client country and always delegates to the next
// handler in the chain.
func (h *GeoIPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 无论 xdb 是否可用都先剥掉客户端伪造的 X-GeoIP-* 头：xdb 缺失时
	// setGeoIPPlaceholders 不执行，伪造头若残留会直接喂给下游 coraza 的
	// 地域规则（伪造 X-GeoIP-Loc=某 allow 名单省份即可绕过 allow 模式拦截）。
	for _, name := range geoipCorazaHeaders {
		r.Header.Del(name)
	}
	if h.searcher != nil {
		h.setGeoIPPlaceholders(r)
	} else {
		// xdb 缺失/损坏（Provision 降级 pass-through）：coraza 的地域规则读
		// REQUEST_HEADERS:X-GeoIP-Loc，缺失变量在 coraza 连取反算子都不产生
		// 匹配（rule.go evaluate 按值循环）——不置哨兵则 deny/allow 两模式的
		// id:8 恒不命中，地域拦截静默 fail-open。与查询失败同口径发「海外」，
		// 恢复文档化 fail-closed 语义。
		r.Header.Set("X-GeoIP-Loc", "海外")
	}
	return next.ServeHTTP(w, r)
}

// Cleanup releases the handler's reference to the shared singleton (审计 M2)：
// 单例按 XdbPath 进程级共享、生命周期与进程相同——关闭会打断仍在使用同路径的
// 其他 handler（重载窗口内新旧配置并存），故此处不 Close。
func (h *GeoIPHandler) Cleanup() error {
	h.searcher = nil
	return nil
}

// setGeoIPPlaceholders resolves the client IP against the database and
// publishes the country fields on the request replacer. v2.2.0 起同值镜像为
// X-GeoIP-* 请求头（含 fail-closed 空串哨兵），供下游 coraza 的 GeoIP
// SecRule 匹配；X-GeoIP-Loc 是地域规则匹配键：海外/省/省-市（详见下方）。
func (h *GeoIPHandler) setGeoIPPlaceholders(r *http.Request) {
	ctx := r.Context()
	// R72 二十六次 D1（裁决：fail-closed 哨兵）：不可解析客户端（全部 IPv6 流量、
	// 查询失败、残缺 region）此前不发任何变量 → geoip CEL 对未设置变量求值出
	// 错 → match=false → deny 模式地域拦截对 IPv6 静默零强制。现恒发全部变量，
	// 空串哨兵下：海外项 country_name != "中国" 对空串成立（IPv6 按海外处理，
	// 与 R57 fail-closed 立场一致）；省/市项对空串恒不匹配（不误伤）。
	// 头镜像同语义：X-GeoIP-Loc 哨兵恒为「海外」（承载 fail-closed 海外裁决），
	// 省/市空串对 coraza 锚定正则（^(?:...)$）恒不匹配。
	caddyhttp.SetVar(ctx, "geoip.country_code", "")
	caddyhttp.SetVar(ctx, "geoip.country_name", "")
	caddyhttp.SetVar(ctx, "geoip.region", "")
	caddyhttp.SetVar(ctx, "geoip.province", "")
	caddyhttp.SetVar(ctx, "geoip.city", "")
	r.Header.Set("X-GeoIP-Country", "")
	r.Header.Set("X-GeoIP-Country-Code", "")
	r.Header.Set("X-GeoIP-Region", "")
	r.Header.Set("X-GeoIP-Province", "")
	r.Header.Set("X-GeoIP-City", "")
	r.Header.Set("X-GeoIP-Loc", "海外")
	province, city := "", ""
	ip := realClientIP(r)
	if ip == "" {
		return
	}
	region, err := h.searcher.Search(ip)
	if err != nil || region == "" {
		return
	}
	fields := strings.Split(region, "|")
	if len(fields) < 5 {
		return
	}
	caddyhttp.SetVar(ctx, "geoip.country_code", fields[4])
	caddyhttp.SetVar(ctx, "geoip.country_name", fields[0])
	caddyhttp.SetVar(ctx, "geoip.region", region)
	r.Header.Set("X-GeoIP-Country", fields[0])
	r.Header.Set("X-GeoIP-Country-Code", fields[4])
	r.Header.Set("X-GeoIP-Region", region)
	if len(fields) >= 3 {
		if raw := fields[1]; raw != "" && raw != "0" {
			// R72 二十三次：省列规范化——xdb 存在双形态（上海/上海市）与
			// 台湾城市误入省列；策略选项树（internal/services/ip2region.go
			// normalizeIP2Province，两侧同款表需同步维护）用规范名，发射
			// 变量同规范化后 CEL 等值匹配才成立。
			province = normalizeProvince(raw)
		}
		caddyhttp.SetVar(ctx, "geoip.province", province)
		r.Header.Set("X-GeoIP-Province", province)
	}
	// R72 二十三次：市级粒度——region 第 3 列为城市；无效值（空/0）置空串，
	// 使 CEL {http.vars.geoip.city} == X 对无城市段恒不命中。
	// R72 二十五次：城市列经 normalizeCity 规范化——xdb 部分段城市列为拼音/
	// 英文（Guangzhou Shi/Taipei City），策略树侧已映射为中文，发射侧不映射
	// 会导致「广东省/广州市」类城市级规则对这些段恒不命中。
	// 台湾城市误入省列的段：城市名在省列（城市列是该段的乱码罗马化值）——
	// 城市变量改发省列值，与树侧归并语义一致，使「台湾省/台中市」可命中。
	if len(fields) >= 3 {
		if rawProv := strings.TrimSpace(fields[1]); taiwanCities[rawProv] {
			city = rawProv
		} else if c := strings.TrimSpace(fields[2]); c != "" && c != "0" {
			city = normalizeCity(c)
		}
		caddyhttp.SetVar(ctx, "geoip.city", city)
		r.Header.Set("X-GeoIP-City", city)
	}
	// X-GeoIP-Loc：地域规则匹配键（coraza SecRule 的锚定正则全值目标）。
	// 国家列非「中国」（含空/0/海外国名，与 D1 fail-closed 哨兵同口径）→
	// 「海外」；国内 → 省 或 省/市（均为规范化值，与策略选项树同源，
	// BuildCorazaDirectives 的 geoipLocOperator 按同形态编译条目）。
	if fields[0] != "中国" {
		r.Header.Set("X-GeoIP-Loc", "海外")
	} else if city != "" {
		r.Header.Set("X-GeoIP-Loc", province+"/"+city)
	} else {
		r.Header.Set("X-GeoIP-Loc", province)
	}
}

// realClientIP extracts the client IP from RemoteAddr only. X-Forwarded-For /
// X-Real-IP are deliberately ignored: this handler runs on the edge proxy, so
// honoring client-supplied headers would let attackers spoof their region.
func realClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if net.ParseIP(r.RemoteAddr) != nil {
			return r.RemoteAddr
		}
		return ""
	}
	return host
}

// provinceAliases 与 internal/services/ip2region.go 的 ip2ProvinceAliases 同款
// （叶子 Caddy 模块不可 import internal 包，小表复制，修改需两侧同步）。
var provinceAliases = map[string]string{
	// R72 二十六次 W3-4：与 internal/services/ip2region.go 的 ip2ProvinceAliases
	// 逐条镜像（此前缺 11 条恒等映射与港澳台——无行为分歧但同步不变量破坏；
	// 修改需两侧同步）。
	// (UEruemqi, Wulumuqi) 段的省列乱码转写——按新疆发射（与树侧同步）。
	"UEruemqi": "新疆维吾尔自治区",
	"北京":       "北京市", "上海市": "上海市", "上海": "上海市", "天津市": "天津市", "天津": "天津市",
	"重庆市": "重庆市", "重庆": "重庆市",
	"广西壮族自治区": "广西壮族自治区", "广西": "广西壮族自治区",
	"内蒙古自治区": "内蒙古自治区", "内蒙古": "内蒙古自治区",
	"西藏自治区": "西藏自治区", "西藏": "西藏自治区",
	"宁夏回族自治区": "宁夏回族自治区", "宁夏": "宁夏回族自治区",
	"新疆维吾尔自治区": "新疆维吾尔自治区", "新疆": "新疆维吾尔自治区",
	"台湾省": "台湾省", "台湾": "台湾省",
	"香港特别行政区": "香港特别行政区", "澳门特别行政区": "澳门特别行政区",
}

var taiwanCities = map[string]bool{
	"台北市": true, "新北市": true, "台中市": true, "台南市": true, "高雄市": true,
	"基隆市": true, "新竹市": true, "嘉义市": true, "新竹县": true, "彰化县": true,
	"桃园市": true, "云林县": true, "苗栗县": true,
}

// normalizeProvince 规范 xdb 省列原始值；不可识别（乱码）原样返回（不出现在
// 选项树中，策略不会配置）；台湾城市误入省列时省变量按台湾省发射、城市变量
// 改发省列值（见 setGeoIPPlaceholders——该类段的城市列是乱码值）。
// cityPinyinFixes 与 internal/services/ip2region.go 的 ip2PinyinCityFixes 同款
// （叶子 Caddy 模块不可 import internal 包，表复制，修改需两侧同步）。xdb 部分
// 段的城市列为拼音/英文形态，发射前映射为规范中文名，使城市级 CEL 规则可命中。
var cityPinyinFixes = map[string]string{
	"Wulumuqi": "乌鲁木齐市", "Shanghai": "上海市", "Beijing": "北京市",
	"Fengyuan": "丰原市", "Taipei City": "台北市", "Zhongli District": "中坜区",
	"Changchun Shi": "长春市", "Chengdu Shi": "成都市", "Tianjin": "天津市",
	"Fuyang Shi": "阜阳市", "Hefei Shi": "合肥市", "Heze Shi": "菏泽市",
	"Jining Shi": "济宁市", "Linyi Xian": "临沂县", "Weifang Shi": "潍坊市",
	"Dongguan Shi": "东莞市", "Foshan Shi": "佛山市", "Guangzhou Shi": "广州市",
	"Maoming Shi": "茂名市", "Shenzhen": "深圳市", "Zhuhai Shi": "珠海市",
	"Nanning Shi": "南宁市", "Nanjing Shi": "南京市", "Nantong Shi": "南通市",
	"Tongshan": "铜山区", "Yancheng Shi": "盐城市", "Ganzhou Shi": "赣州市",
	"Baoding Shi": "保定市", "Hanshan Qu": "含山区", "Langfang Shi": "廊坊市",
	"Shijiazhuang Shi": "石家庄市", "Nanyang Shi": "南阳市", "Zhengzhou Shi": "郑州市",
	"Zhoukou Shi": "周口市", "Zhumadian Shi": "驻马店市", "Ningbo Shi": "宁波市",
	"Wuhan Shi": "武汉市", "Xiangyang": "襄阳市", "Changsha Shi": "长沙市",
	"Hengyang Xian": "衡阳县", "Shenyang Shi": "沈阳市", "Chongqing": "重庆市",
	"Guozhen": "郭镇", "Xi'an Shi": "西安市", "Kowloon": "九龙",
}

// normalizeCity 规范 xdb 城市列原始值：拼音映射表命中返回规范中文；未映射的
// ASCII 城市原样返回（选项树侧会过滤、策略不会配置，发射原值恒不命中——与
// normalizeProvince 的不可识别语义一致）；中文城市原样通过。
func normalizeCity(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "0" {
		return ""
	}
	if fixed, ok := cityPinyinFixes[trimmed]; ok {
		return fixed
	}
	// R72 二十八次：少数民族自治州简称 → 全称（与树侧同款表同步）。
	if full, ok := autonomousPrefectures[trimmed]; ok {
		return full
	}
	return trimmed
}

func normalizeProvince(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if canonical, ok := provinceAliases[trimmed]; ok {
		return canonical
	}
	if taiwanCities[trimmed] {
		return "台湾省"
	}
	return trimmed
}

// autonomousPrefectures（与 internal/services/ip2region.go 的 ip2AutonomousPrefectures
// 同款表同步维护；R72 二十八次，用户反馈：「大理/怒江/凉山缺市字」——
// 实为少数民族自治州的简称）xdb 对自治州存简称、对普通地级市存全称
// （如「呼和浩特市」），选项树里「大理」与「呼和浩特市」并列显得缺字。
// 简称 → 全称 映射；与 internal/services/ip2region.go 的 ip2AutonomousPrefectures 同款表同步维护。
// 注意不可盲加「市」：「大理市」是另一个县级市，全称是「大理白族自治州」。
// 港澳的「九龙/将军澳/新界/香港岛/澳门」是地区名非城市，不在此表（保持原值）。
var autonomousPrefectures = map[string]string{
	// 云南（8 个自治州）
	"大理": "大理白族自治州", "怒江": "怒江傈僳族自治州", "楚雄": "楚雄彝族自治州",
	"红河": "红河哈尼族彝族自治州", "文山": "文山壮族苗族自治州", "西双版纳": "西双版纳傣族自治州",
	"德宏": "德宏傣族景颇族自治州", "迪庆": "迪庆藏族自治州",
	// 四川（3）
	"凉山": "凉山彝族自治州", "甘孜": "甘孜藏族自治州", "阿坝": "阿坝藏族羌族自治州",
	// 贵州（3）
	"黔东南": "黔东南苗族侗族自治州", "黔南": "黔南布依族苗族自治州", "黔西南": "黔西南布依族苗族自治州",
	// 湖南/湖北/吉林（3）
	"湘西": "湘西土家族苗族自治州", "恩施": "恩施土家族苗族自治州", "延边": "延边朝鲜族自治州",
	// 新疆（5）
	"伊犁": "伊犁哈萨克自治州", "昌吉": "昌吉回族自治州", "巴音郭楞": "巴音郭楞蒙古自治州",
	"克孜勒苏": "克孜勒苏柯尔克孜自治州", "博尔塔拉": "博尔塔拉蒙古自治州",
	// 青海（6）
	"海西": "海西蒙古族藏族自治州", "海北": "海北藏族自治州", "黄南": "黄南藏族自治州",
	"海南": "海南藏族自治州", "果洛": "果洛藏族自治州", "玉树": "玉树藏族自治州",
	// 甘肃（2）
	"临夏": "临夏回族自治州", "甘南": "甘南藏族自治州",
	// 地区（1：xdb 缺「地区」后缀）
	"大兴安岭": "大兴安岭地区",
}
