package lbhuman

import (
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// HumanConfig lb_human 渲染配置（LB 按规则注入；字段与 DB/模型同源）。
type HumanConfig struct {
	Mode        string   `json:"mode"`          // off | auto | force（off 时不渲染）
	Type        string   `json:"type"`          // js（M1）| slider（M2）
	TTLMinutes  int      `json:"ttl"`           // 验证通过有效期（分钟）
	Secret      string   `json:"secret"`        // cookie 签名密钥（hex，LB 注入）
	CCRPSLimit  int      `json:"cc_rps_limit"`  // CC 突刺阈值（次/窗口）
	CCWindowSec int      `json:"cc_window_sec"` // CC 窗口秒数
	CC4xxRatio  int      `json:"cc_4xx_ratio"`  // 4xx 比例触发阈值（%）
	CCSession   bool     `json:"cc_session"`    // 会话异常检测开关
	CCSessionUA int      `json:"cc_session_ua"` // 会话异常 UA 数阈值
	CCResponse  string   `json:"cc_response"`   // verify | ban
	CCEnabled   bool     `json:"cc_enabled"`    // 突刺/4xx/多UA 触发开关（关闭时仅 force 模式挑战）
	ExemptPaths []string `json:"exempt_paths"`  // 豁免路径前缀
	ExemptIPs   []string `json:"exempt_ips"`    // 豁免 IP/CIDR 列表
	RuleID      string   `json:"rule_id"`       // 规则 caddy_id（计数器 key 前缀）
}

// HumanHandler lb_human 主处理器（无实例状态，配置即全部）。
type HumanHandler struct {
	HumanConfig
	exemptPrefixes []netip.Prefix // Provision 时预编译+排序（二分匹配）
}

// CaddyModule returns the Caddy module information.
func (HumanHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.lb_human",
		New: func() caddy.Module { return new(HumanHandler) },
	}
}

// Provision implements caddy.Provisioner.
func (h *HumanHandler) Provision(caddy.Context) error {
	// 豁免 IP 聚合前缀集（排序+二分，与 IP 预检 wafiplist.AggregateParsedPrefixes
	// 同算法）：内联 IP/CIDR + 名单展开项统一为 netip.Prefix，匹配 O(log n)。
	h.exemptPrefixes = nil
	seen := map[string]struct{}{}
	for _, entry := range h.ExemptIPs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		var prefix netip.Prefix
		if strings.Contains(entry, "/") {
			p, err := netip.ParsePrefix(entry)
			if err != nil {
				continue
			}
			prefix = p.Masked()
		} else if ip, err := netip.ParseAddr(entry); err == nil {
			bits := 32
			if ip.Is6() {
				bits = 128
			}
			prefix = netip.PrefixFrom(ip, bits)
		} else {
			continue
		}
		key := prefix.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		h.exemptPrefixes = append(h.exemptPrefixes, prefix)
	}
	sort.Slice(h.exemptPrefixes, func(a, b int) bool { return h.exemptPrefixes[a].Addr().Less(h.exemptPrefixes[b].Addr()) })
	return nil
}

// Validate implements caddy.Validator.
func (h *HumanHandler) Validate() error {
	if h.Mode != "auto" && h.Mode != "force" {
		return fmt.Errorf("lb_human mode must be auto or force")
	}
	if h.Secret == "" {
		return fmt.Errorf("lb_human secret required")
	}
	if h.TTLMinutes <= 0 {
		h.TTLMinutes = 30
	}
	if h.CCWindowSec <= 0 {
		h.CCWindowSec = 10
	}
	return nil
}

// isExempt 豁免判定：路径前缀+IP（精确/CIDR）。
func (h *HumanHandler) isExempt(ip, path string) bool {
	for _, p := range h.ExemptPaths {
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	// 前缀二分匹配（O(log n)）
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	idx := sort.Search(len(h.exemptPrefixes), func(i int) bool {
		return !h.exemptPrefixes[i].Addr().Less(addr)
	})
	// 命中=该地址落在排序后首个不小于它的前缀内，或前一前缀（前缀跨度覆盖）
	for _, i := range []int{idx, idx - 1} {
		if i >= 0 && i < len(h.exemptPrefixes) && h.exemptPrefixes[i].Contains(addr) {
			return true
		}
	}
	return false
}

// ServeHTTP 人机验证主流程：
//
//	有效 cookie → 直通
//	豁免 → 直通
//	force / CC 触发 → 挑战页（JS 挑战）
//	否则直通并记录计数
func (h *HumanHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := clientIPFrom(r.RemoteAddr, r.Header.Get("X-Forwarded-For"))
	path := r.URL.Path

	// 挑战校验端点（优先处理，不经过豁免/cookie 判定）
	if path == humanVerifyPath {
		h.serveJSVerify(w, r, ip)
		return nil
	}
	if path == humanSliderVerifyPath {
		h.serveSliderVerify(w, r, ip)
		return nil
	}

	// 豁免优先
	if h.isExempt(ip, path) {
		return next.ServeHTTP(w, r)
	}

	// 有效 cookie 直通
	if c, err := r.Cookie(cookieName); err == nil && verifyCookie([]byte(h.Secret), c.Value, ip, r.UserAgent(), timeNow()) {
		return next.ServeHTTP(w, r)
	}

	// force 模式：未验证一律挑战（方式按策略配置：slider=滑块，js=PoW）
	if h.Mode == "force" {
		h.serveChallengeByType(w, r, ip)
		return nil
	}

	// auto 模式：先查当前窗口统计判定是否触发（触发则本次请求即挑战），
	// 再放行并在响应完成后记录（4xx 比例需要响应状态）。
	// cc_enabled=false（策略未启用 CC 检测）时不做阈值触发——避免"关闭开关
	// 仍在按默认阈值挑战"的装饰性开关；始终验证(force)不受此门影响。
	key := h.RuleID + "|" + normalizeIP(ip)
	if h.CCEnabled {
		current := ccPeek(key, h.CCWindowSec)
		trig := evalCC(current, h.CCRPSLimit, h.CCWindowSec, h.CC4xxRatio, h.CCSessionUA, h.CCSession)
		if trig.Triggered {
			h.serveChallengeByType(w, r, ip)
			return nil
		}
	}
	sw := &statusCapture{ResponseWriter: w, status: 0}
	err := next.ServeHTTP(sw, r)
	uaFp := uaHash(r.UserAgent())
	ccRecord(key, h.CCWindowSec, sw.status >= 400 && sw.status < 500, uaFp)
	return err
}

// Interface guards（编译期契约）。
var (
	_ caddy.Module                = (*HumanHandler)(nil)
	_ caddy.Provisioner           = (*HumanHandler)(nil)
	_ caddy.Validator             = (*HumanHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*HumanHandler)(nil)
)

// timeNow 时间源（测试可替换）。
var timeNow = func() time.Time { return time.Now() }

// statusCapture 最小状态捕获（4xx 比例计数）。
type statusCapture struct {
	http.ResponseWriter
	status int
}

func (w *statusCapture) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCapture) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// banResponse CC 触发且响应=ban：直接 403（封禁由 LB 自动封禁管线另行处理，
// 插件侧立即拦截当次请求）。
func (h *HumanHandler) banResponse(w http.ResponseWriter, r *http.Request, ip, reason string) {
	humanStats.Bans.Add(1)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprintf(w, "请求已被 CC 防护拦截（%s）\nRequest blocked by CC protection (%s)\n", reason, reason)
}
