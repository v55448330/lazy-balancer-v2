package lbhuman

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// HumanConfig lb_human 渲染配置（LB 按规则注入；字段与 DB/模型同源）。
type HumanConfig struct {
	Mode              string   `json:"mode"`          // off | auto | force（off 时不渲染）
	Type              string   `json:"type"`          // js（M1）| slider（M2）
	TTLMinutes        int      `json:"ttl"`           // 验证通过有效期（分钟）
	Secret            string   `json:"secret"`        // cookie 签名密钥（hex，LB 注入）
	CCRPSLimit        int      `json:"cc_rps_limit"`  // CC 突刺阈值（次/窗口）
	CCWindowSec       int      `json:"cc_window_sec"` // CC 窗口秒数
	CC4xxRatio        int      `json:"cc_4xx_ratio"`  // 4xx 比例触发阈值（%）
	CCSession         bool     `json:"cc_session"`    // 会话异常检测开关
	CCSessionUA       int      `json:"cc_session_ua"` // 会话异常 UA 数阈值
	CCEnabled         bool     `json:"cc_enabled"`    // 突刺/4xx/多UA 触发开关（关闭时仅 force 模式挑战）
	ChallengePageHTML string   `json:"challenge_page_html,omitempty"`
	ExemptPaths       []string `json:"exempt_paths"` // 豁免路径前缀
	RuleID            string   `json:"rule_id"`      // 规则 caddy_id（计数器 key 前缀）
}

// HumanHandler lb_human 主处理器（无实例状态，配置即全部）。
type HumanHandler struct {
	HumanConfig
}

// CaddyModule returns the Caddy module information.
func (HumanHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.lb_human",
		New: func() caddy.Module { return new(HumanHandler) },
	}
}

// Provision implements caddy.Provisioner.
func (h *HumanHandler) Provision(caddy.Context) error { return nil }

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

// isExempt 豁免判定：路径前缀（IP 级放行唯一入口=阶段 0 信任名单，
// human_exempt_ips 已退役，此处不再提供第二套放行口径）。
func (h *HumanHandler) isExempt(path string) bool {
	for _, p := range h.ExemptPaths {
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// wantsJSONRequest 判定 API/XHR 客户端（Accept: application/json、
// X-Requested-With，或 Sec-Fetch-Mode=cors）：这类请求不能拿 HTML 挑战页。
func wantsJSONRequest(r *http.Request) bool {
	if v := r.Header.Get("X-Requested-With"); v != "" {
		return true
	}
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Mode"), "cors") {
		return true
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json")
}

// isIdempotentMethod 只对 GET/HEAD 走浏览器挑战页；其余方法返回 403 JSON，
// 避免重定向把请求体静默丢掉（表单提交变 GET 是数据丢失事故）。
func isIdempotentMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

// serveChallengeForRequest 按请求类型分流挑战响应：
//   - 文档导航（幂等 + 非 JSON）→ 挑战页（HTML）；
//   - API/XHR 或非幂等请求 → JSON（401/403 + X-Human-Challenge 头）。
func (h *HumanHandler) serveChallengeForRequest(w http.ResponseWriter, r *http.Request, ip string) {
	if isIdempotentMethod(r.Method) && !wantsJSONRequest(r) {
		h.serveChallengeByType(w, r, ip)
		return
	}
	humanStats.Challenges.Add(1)
	reportHumanEvent(h.RuleID, ip, r.Method, r.URL.RequestURI(), r.UserAgent(), "challenge")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Human-Challenge", "1")
	status := http.StatusUnauthorized
	if !isIdempotentMethod(r.Method) {
		status = http.StatusForbidden
	}
	w.WriteHeader(status)
	payload, _ := json.Marshal(map[string]string{
		"code":       "human_challenge",
		"message":    "human verification required; open the URL in a browser to complete the challenge",
		"verify_url": r.URL.RequestURI(),
	})
	_, _ = w.Write(payload)
}

// ServeHTTP 人机验证主流程：
//
//	有效 cookie → 直通
//	豁免 → 直通
//	force / CC 触发 → 挑战页（JS 挑战）
//	否则直通并记录计数
func (h *HumanHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := clientIPFrom(r)
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
	if h.isExempt(path) {
		return next.ServeHTTP(w, r)
	}

	// 有效 cookie 直通
	if c, err := r.Cookie(cookieName); err == nil && verifyCookie([]byte(h.Secret), c.Value, ip, r.UserAgent(), timeNow()) {
		return next.ServeHTTP(w, r)
	}

	// force 模式：未验证一律挑战（方式按策略配置：slider=滑块，js=PoW）
	if h.Mode == "force" {
		h.serveChallengeForRequest(w, r, ip)
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
			recordCCTrigger(trig.Reason)
			h.serveChallengeForRequest(w, r, ip)
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

// Unwrap 暴露底层 ResponseWriter：http.ResponseController 依赖 Unwrap 链
// 找到 Hijacker/Flusher（缺此方法则全站 WebSocket 升级报 not supported）。
func (w *statusCapture) Unwrap() http.ResponseWriter { return w.ResponseWriter }
