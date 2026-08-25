// Package caddygeoip provides a Caddy HTTP handler module that resolves the
// client IP against an ip2region xdb database and publishes the resulting
// country as placeholders for downstream handlers and matchers.
package caddygeoip

import (
	"net"
	"net/http"
	"strings"

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
	searcher, err := service.NewIp2RegionWithPath(h.XdbPath, "")
	if err != nil {
		ctx.Logger().Warn("geoip2region: ip2region database unavailable, geoip disabled",
			zap.String("xdb_path", h.XdbPath), zap.Error(err))
		return nil
	}
	h.searcher = searcher
	return nil
}

// ServeHTTP publishes the client country and always delegates to the next
// handler in the chain.
func (h *GeoIPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h.searcher != nil {
		h.setGeoIPPlaceholders(r)
	}
	return next.ServeHTTP(w, r)
}

// Cleanup releases the ip2region database handle.
func (h *GeoIPHandler) Cleanup() error {
	if h.searcher != nil {
		h.searcher.Close()
		h.searcher = nil
	}
	return nil
}

// setGeoIPPlaceholders resolves the client IP against the database and
// publishes the country fields on the request replacer.
func (h *GeoIPHandler) setGeoIPPlaceholders(r *http.Request) {
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
	ctx := r.Context()
	caddyhttp.SetVar(ctx, "geoip.country_code", fields[4])
	caddyhttp.SetVar(ctx, "geoip.country_name", fields[0])
	caddyhttp.SetVar(ctx, "geoip.region", region)
	if len(fields) >= 3 {
		if province := fields[1]; province != "" && province != "0" {
			// R72 二十三次：省列规范化——xdb 存在双形态（上海/上海市）与
			// 台湾城市误入省列；策略选项树（internal/services/ip2region.go
			// normalizeIP2Province，两侧同款表需同步维护）用规范名，发射
			// 变量同规范化后 CEL 等值匹配才成立。
			caddyhttp.SetVar(ctx, "geoip.province", normalizeProvince(province))
		} else {
			caddyhttp.SetVar(ctx, "geoip.province", "")
		}
	}
	// R72 二十三次：市级粒度——region 第 3 列为城市；无效值（空/0）置空串，
	// 使 CEL {http.vars.geoip.city} == X 对无城市段恒不命中。
	if len(fields) >= 3 {
		if city := fields[2]; city != "" && city != "0" {
			caddyhttp.SetVar(ctx, "geoip.city", city)
		} else {
			caddyhttp.SetVar(ctx, "geoip.city", "")
		}
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
	"北京": "北京市", "上海": "上海市", "天津": "天津市", "重庆": "重庆市",
	"广西": "广西壮族自治区", "内蒙古": "内蒙古自治区", "西藏": "西藏自治区",
	"宁夏": "宁夏回族自治区", "新疆": "新疆维吾尔自治区", "台湾": "台湾省",
}

var taiwanCities = map[string]bool{
	"台北市": true, "新北市": true, "台中市": true, "台南市": true, "高雄市": true,
	"基隆市": true, "新竹市": true, "嘉义市": true, "新竹县": true, "彰化县": true,
}

// normalizeProvince 规范 xdb 省列原始值；不可识别（乱码）原样返回（不出现在
// 选项树中，策略不会配置）；台湾城市误入省列时省变量按台湾省发射、城市变量
// 照常发原值，使「台湾省/台中市」条目可命中。
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
