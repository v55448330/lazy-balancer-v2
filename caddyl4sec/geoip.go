// Package caddyl4sec 提供 L4（TCP）安全链路的 Caddy 模块：
//
//   - layer4.handlers.lb_l4_sec：TCP 安全路由的事件合成/上报与连接计数
//     （阶段 0/1 IP 控制在 L4 的消费端，路由形状见 L4 阶段契约 C2）；
//   - layer4.matchers.lb_geoip：连接级 GeoIP 匹配器（查库失败/缺库 fail-open，
//     用户已裁定）；
//   - admin.api.lb_l4_conn_stats：GET /lb/l4-conn-stats 连接计数端点（契约
//     C3）+ GET /lb/l4-shipper-stats 投递/丢弃计数端点（丢弃可观测）。
//
// 与 caddygeoip（HTTP 侧）共享同一跨进程契约：合成审计事件行经 Unix socket
// IPC 投递面板 POST /security-events/ingest（换行分隔 JSON，204=本批 DB
// commit 完成），失败整批落 fallback spool 供补采。两条事件线互不复用实现
// （跨 Go module 无共享包；本包是 caddygeoip auditwriter 的 L4 子集移植：
// 无 coraza 快照、无审计文件兜底层）。
package caddyl4sec

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/lionsoul2014/ip2region/binding/golang/service"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
	"lazy-balancer-v2/geoipnames"
)

// l4DefaultXdbPath 与 caddygeoip GeoIPHandler 的容器默认一致（自定义 data_dir
// 部署由渲染侧显式发射 xdb_path）。
const l4DefaultXdbPath = "/app/data/ip2region.xdb"

// locOverseas 是地域匹配哨兵：与 HTTP 侧 X-LB-GeoIP-Loc 的 fail-closed 兜底
// 值同值（「海外」）。
const locOverseas = "海外"

// normalizeCountryKey 国家列归一（与 caddygeoip normalizeTrafficCountryKey
// 同口径：「中国」保留为国内判定键，其余经 geoipnames.NormalizeCountry 异体
// 折叠——Reserved/空/0 归空串，海外行发规范英文名）。跨模块无共享包，漂移由
// 两侧对 geoipnames 单源表依赖约束。
func normalizeCountryKey(country string) string {
	country = strings.TrimSpace(country)
	if country == "中国" {
		return country
	}
	return geoipnames.NormalizeCountry(country)
}

// regionRow 是 xdb region 行的解析投影（caddygeoip geoIPRegionFields 的 L4
// 子集：GeoIP 匹配与国家桶只需要 country/province/city/loc）。
type regionRow struct {
	country  string
	province string
	city     string
	loc      string
}

// parseRegionRow 解析 xdb 行：国家列归一；省/市列经 geoipnames 发射侧规范化
// （台湾城市误入省列时城市列取省列值）；省列归一为空时城市一律置空（树不变
// 式，不得发射树侧不可表达的「/城市」Loc）；Loc 与 HTTP 侧 geoipLocFor 同构：
// 国内=省 或 省/市，海外=归一国名，国家列不可解析=「海外」哨兵。少于 5 列的
// 残行判解析失败（false）。
func parseRegionRow(region string) (regionRow, bool) {
	fields := strings.Split(region, "|")
	if len(fields) < 5 {
		return regionRow{}, false
	}
	out := regionRow{country: normalizeCountryKey(fields[0])}
	if raw := fields[1]; raw != "" && raw != "0" {
		out.province = geoipnames.ProvinceForEmit(raw)
	}
	if geoipnames.IsTaiwanCity(strings.TrimSpace(fields[1])) {
		out.city = strings.TrimSpace(fields[1])
	} else if c := strings.TrimSpace(fields[2]); c != "" && c != "0" {
		out.city = geoipnames.CityForEmit(c)
	}
	if out.province == "" {
		out.city = ""
	}
	switch {
	case out.country == "中国":
		if out.city != "" {
			out.loc = out.province + "/" + out.city
		} else {
			out.loc = out.province
		}
	case out.country != "":
		out.loc = out.country
	default:
		out.loc = locOverseas
	}
	return out, true
}

// geoipLocMatches 地域条目匹配：与 HTTP 侧 geoipLocOperator 的锚定正则语义
// 同构（跨模块无共享包，L4 用等价字符串判定）——
//   - 「海外」条目：已解析海外行（归一国名或 Reserved 兜底哨兵）命中，国内不命中
//     （HTTP 侧哨兵∪树全集展开在本判定下等价：海外行 Loc 恒为裸国名，无「/」后缀）；
//   - 含「/」条目：精确匹配（省-市）；
//   - 其余条目：前缀匹配（省条目命中省 或 省/市 形态的 Loc）。
//
// 国家列不可解析的行（regionRow 解析失败/查库失败）在 Match 入口已 fail-open
// 返回，不进入本函数——与 HTTP 侧 fail-closed 哨兵的差异为契约裁定的 L4
// fail-open 语义。
func geoipLocMatches(country, loc string, countries []string) bool {
	for _, entry := range countries {
		if entry == locOverseas {
			if country != "中国" {
				return true
			}
			continue
		}
		if strings.Contains(entry, "/") {
			if loc == entry {
				return true
			}
			continue
		}
		if loc == entry || strings.HasPrefix(loc, entry+"/") {
			return true
		}
	}
	return false
}

// —— 共享 searcher 单例（caddygeoip sharedGeoIPSearcher 的移植）——
//
// 每条 GeoIP 规则各开一份 Ip2Region 会各持 xdb fd + vIndex 缓冲，重载期新旧
// 并存再翻倍；fd 耗尽 → Provision 降级 fail-open。同路径进程级共享一份，
// modTime/size 记录建库形态（xdb rename 换库后文件形态变化即重建），被替换
// 旧实例延迟关闭（重载窗口内在途查询继续服务，窗口过后 Close 收敛）。
// stat 失败/重建失败按 fail-stale 返回旧实例（返回 error 会让 matcher 全量
// 降级 fail-open——比短暂旧数据更伤），并标记下次 Provision 强制重建。
type sharedSearcherEntry struct {
	searcher     *service.Ip2Region
	modTime      time.Time
	size         int64
	needsRebuild bool
}

var (
	sharedSearcherMu       sync.Mutex
	sharedSearchers        = map[string]*sharedSearcherEntry{}
	sharedOldInstanceDelay = 60 * time.Second
)

// keyedWarnThrottle 同键同原因告警节流：首次立即，其后每窗口一条。每条地域
// 规则各调一次 sharedGeoIPSearcher，不节流会按规则数放大重复 WARN。
type keyedWarnThrottle struct {
	mu      sync.Mutex
	last    map[string]time.Time
	window  time.Duration
	nowFunc func() time.Time
}

func newKeyedWarnThrottle(window time.Duration) *keyedWarnThrottle {
	return &keyedWarnThrottle{last: map[string]time.Time{}, window: window, nowFunc: time.Now}
}

func (t *keyedWarnThrottle) allow(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.nowFunc()
	if last, ok := t.last[key]; ok && now.Sub(last) < t.window {
		return false
	}
	t.last[key] = now
	return true
}

func (t *keyedWarnThrottle) clearPrefix(prefix string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.last {
		if strings.HasPrefix(k, prefix) {
			delete(t.last, k)
		}
	}
}

var searcherWarnThrottle = newKeyedWarnThrottle(time.Minute)

func searcherWarn(reason, path, msg string, fields ...zap.Field) {
	if !searcherWarnThrottle.allow(path + "|" + reason) {
		return
	}
	caddy.Log().Named("l4sec").Warn(msg, fields...)
}

// sharedGeoIPSearcher 返回按路径共享的单例（fail-stale 语义见类型注释）。
func sharedGeoIPSearcher(path string) (*service.Ip2Region, error) {
	st, err := os.Stat(path)
	if err != nil {
		sharedSearcherMu.Lock()
		cached, ok := sharedSearchers[path]
		if ok {
			cached.needsRebuild = true
		}
		sharedSearcherMu.Unlock()
		if !ok {
			searcherWarn("unavailable", path, "l4sec: ip2region database unavailable, geoip matcher fails open",
				zap.String("xdb_path", path), zap.Error(err))
			return nil, err
		}
		searcherWarn("stat", path, "l4sec: ip2region database is not stat-able, serving the previous instance",
			zap.String("xdb_path", path), zap.Error(err))
		return cached.searcher, nil
	}
	sharedSearcherMu.Lock()
	defer sharedSearcherMu.Unlock()
	if cached, ok := sharedSearchers[path]; ok && !cached.needsRebuild &&
		cached.modTime.Equal(st.ModTime()) && cached.size == st.Size() {
		searcherWarnThrottle.clearPrefix(path + "|")
		return cached.searcher, nil
	}
	searcher, err := service.NewIp2RegionWithPath(path, "")
	if err != nil {
		// 重建失败不驱逐旧实例（fail-stale，与 stat 失败同理由）。
		if cached, ok := sharedSearchers[path]; ok {
			searcherWarn("rebuild", path, "l4sec: ip2region rebuild failed, serving the previous instance",
				zap.String("xdb_path", path), zap.Error(err))
			return cached.searcher, nil
		}
		searcherWarn("rebuild-unavailable", path, "l4sec: ip2region database unavailable, geoip matcher fails open",
			zap.String("xdb_path", path), zap.Error(err))
		return nil, err
	}
	if replaced, ok := sharedSearchers[path]; ok {
		old := replaced.searcher
		time.AfterFunc(sharedOldInstanceDelay, func() { old.Close() })
	}
	sharedSearchers[path] = &sharedSearcherEntry{searcher: searcher, modTime: st.ModTime(), size: st.Size()}
	searcherWarnThrottle.clearPrefix(path + "|")
	return searcher, nil
}

// —— layer4.matchers.lb_geoip ——

// L4GeoIPMatcher 按客户端归属地匹配连接。查库失败/库未加载/IP 不可解析
// 一律返回 (false, nil)——fail-open 放行（用户裁定；匹配失败不应扩大为断连）。
type L4GeoIPMatcher struct {
	// Countries 是地域条目，值域与 HTTP 侧策略 geoip_countries 同域：
	// 国名/省/省-市/「海外」哨兵（见 geoipLocMatches）。
	Countries []string `json:"countries,omitempty"`

	// XdbPath 可选：自定义 data_dir 部署由渲染侧发射；空值用容器默认路径。
	XdbPath string `json:"xdb_path,omitempty"`

	countries []string
	xdbPath   string
	searcher  *service.Ip2Region
}

// CaddyModule returns the Caddy module information.
func (*L4GeoIPMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.lb_geoip",
		New: func() caddy.Module { return new(L4GeoIPMatcher) },
	}
}

// Provision 编译条目并打开共享 searcher；库不可用降级 fail-open（不拒绝
// 配置加载——地域库缺失不应阻断整个 L4 站点，与用户裁定的 fail-open 同向）。
func (m *L4GeoIPMatcher) Provision(ctx caddy.Context) error {
	if len(m.Countries) == 0 {
		return fmt.Errorf("lb_geoip: countries 不能为空（空名单在渲染侧应被内容门控拦截）")
	}
	entries := make([]string, 0, len(m.Countries))
	for _, c := range m.Countries {
		trimmed := strings.TrimSpace(c)
		if trimmed == "" {
			return fmt.Errorf("lb_geoip: countries 不能包含空条目")
		}
		entries = append(entries, trimmed)
	}
	m.countries = entries
	if m.XdbPath == "" {
		m.XdbPath = l4DefaultXdbPath
	}
	m.xdbPath = m.XdbPath
	searcher, err := sharedGeoIPSearcher(m.xdbPath)
	if err != nil {
		// 告警已在 sharedGeoIPSearcher 内按（原因|路径）节流。
		ctx.Logger().Debug("lb_geoip: ip2region unavailable, matcher fails open",
			zap.String("xdb_path", m.xdbPath), zap.Error(err))
		m.searcher = nil
		return nil
	}
	m.searcher = searcher
	return nil
}

// Match 实现层4.ConnMatcher：命中=true。所有失败形态（缺库/查库错/IP 不可
// 解析/残行）fail-open 返回 false（无 error——error 在 MatcherSet 语义下同样
// 是不匹配，但显式 false 让「放行」成为唯一出口，不放大为路由错误）。
func (m *L4GeoIPMatcher) Match(cx *layer4.Connection) (bool, error) {
	if m.searcher == nil {
		return false, nil
	}
	ip := clientIPFromConn(cx)
	if ip == "" {
		return false, nil
	}
	region, err := m.searcher.Search(ip)
	if err != nil || region == "" {
		return false, nil
	}
	row, ok := parseRegionRow(region)
	if !ok {
		return false, nil
	}
	return geoipLocMatches(row.country, row.loc, m.countries), nil
}

// clientIPFromConn 取连接客户端 IP：cx.RemoteAddr 的 host 部分。规则开
// PROXY protocol 时，渲染侧在 lb_l4_sec/lb_geoip 之前放置
// layer4.handlers.proxy_protocol，该 handler 会把连接包装为 PROXY 头里的
// 源地址（caddy-l4 v0.1.2 行为），本模块经 RemoteAddr 自然取得真实客户端，
// 无需额外配置；PROXY handler 未渲染（规则未开/头缺失）时即 socket 对端——
// 降级形态与契约披露一致。
func clientIPFromConn(cx *layer4.Connection) string {
	if cx == nil {
		return ""
	}
	addr := cx.RemoteAddr()
	if addr == nil {
		return ""
	}
	raw := addr.String()
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host
	}
	if net.ParseIP(raw) != nil {
		return raw
	}
	return ""
}
