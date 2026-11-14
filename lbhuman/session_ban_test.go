package lbhuman

// 会话级执法点钉测（自动封禁 NAT 态会话封禁的 HTTP 执法出口）：
//   - ServeHTTP 入口查会话封禁（归一 IP×会话指纹），命中直接 403 拒绝，
//     不发挑战、不放行——即使持有效 cookie（封禁语义优先于 bearer 放行）；
//   - 未命中走现有挑战链（force 挑战/cookie 直通零变化）；
//   - 交换文件 TTL 到期自动解封（执法点按条目 expires_at_ms 判定）；
//   - 无指纹请求不受会话封禁影响（IP 级执法仍由名单通道承担，L4 不动）；
//   - 交换文件缺席/损坏 fail-open（不阻断正常请求）；
//   - 本地态：只读本机交换文件，无任何跨节点拉取。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// sessionBanTestEnv 交换文件指到临时目录 + 冻结时钟 + 清空执法缓存。
func sessionBanTestEnv(t *testing.T) (path string, frozen *time.Time) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "autoban-session-bans.json")
	oldFile := sessionBanFile
	sessionBanFile = path
	t.Cleanup(func() { sessionBanFile = oldFile })
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	oldNow := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = oldNow })
	resetSessionBanCacheForTest()
	t.Cleanup(resetSessionBanCacheForTest)
	return path, &now
}

// writeSessionBanFile 写交换载荷（与面板侧 services 载荷同契约：
// {"bans":[{"key":"归一IP|指纹","expires_at_ms":unix毫秒}]}）。
func writeSessionBanFile(t *testing.T, path string, keys []string, expiresAtMS int64) {
	t.Helper()
	type ban struct {
		Key         string `json:"key"`
		ExpiresAtMS int64  `json:"expires_at_ms"`
	}
	payload := struct {
		Bans []ban `json:"bans"`
	}{}
	for _, k := range keys {
		payload.Bans = append(payload.Bans, ban{Key: k, ExpiresAtMS: expiresAtMS})
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func sessionBanTestHandler() *HumanHandler {
	return &HumanHandler{HumanConfig: HumanConfig{
		Mode: "force", Type: "js", TTLMinutes: 30, RuleID: "lb-sb",
		Secret: "session-ban-secret", CCEnabled: false,
	}}
}

func sessionBanTestNext() caddyhttp.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}
}

// Given 会话封禁命中（归一 IP×UA 兜底指纹，未来到期）。
// When force 模式 ServeHTTP（浏览器导航）。
// Then 403 拒绝：不发挑战页、不放行；同 IP 不同指纹（无辜会话）照常挑战。
func TestServeHTTP_sessionBanHitRejectsWithoutChallenge(t *testing.T) {
	path, now := sessionBanTestEnv(t)
	ip, ua := "203.0.113.200", "evil-agent/1.0"
	fp := sessionFingerprint("", ua, "")
	writeSessionBanFile(t, path, []string{normalizeIP(ip) + "|" + fp}, now.Add(10*time.Minute).UnixMilli())

	h := sessionBanTestHandler()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/page", nil)
	req.RemoteAddr = ip + ":4321"
	req.Header.Set("User-Agent", ua)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, sessionBanTestNext()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("命中会话封禁必须 403 拒绝, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "Security Check") || rec.Header().Get("X-Human-Challenge") != "" {
		t.Fatalf("封禁会话不得发放挑战: headers=%v body=%s", rec.Header(), rec.Body.String())
	}

	// 无辜会话（同 IP 不同 UA → 不同指纹）不受影响：走现有挑战链。
	req2 := httptest.NewRequest(http.MethodGet, "https://example.test/page", nil)
	req2.RemoteAddr = ip + ":4322"
	req2.Header.Set("User-Agent", "innocent-agent/2.0")
	rec2 := httptest.NewRecorder()
	if err := h.ServeHTTP(rec2, req2, sessionBanTestNext()); err != nil {
		t.Fatalf("serve innocent: %v", err)
	}
	if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), "Security Check") {
		t.Fatalf("未命中会话必须走现有挑战链, got %d body=%s", rec2.Code, rec2.Body.String()[:min(200, len(rec2.Body.String()))])
	}
}

// Given 会话封禁命中且请求携带有效 cookie（bearer 凭证）。
// When ServeHTTP。
// Then 仍 403 拒绝——会话封禁优先于 cookie 直通（封禁语义不是「未验证」）。
func TestServeHTTP_sessionBanOverridesValidCookie(t *testing.T) {
	path, now := sessionBanTestEnv(t)
	ip, ua := "203.0.113.201", "cookie-agent/1.0"
	secret := []byte("session-ban-secret")
	cookie, _ := signCookie(secret, ip, ua, 30*time.Minute)
	fp := sessionFingerprint(cookie, ua, "")
	writeSessionBanFile(t, path, []string{normalizeIP(ip) + "|" + fp}, now.Add(10*time.Minute).UnixMilli())

	h := sessionBanTestHandler()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/page", nil)
	req.RemoteAddr = ip + ":4321"
	req.Header.Set("User-Agent", ua)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, sessionBanTestNext()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("有效 cookie 不得绕过会话封禁, got %d", rec.Code)
	}
}

// Given 会话封禁条目已到期（expires_at_ms 早于当前时钟）。
// When ServeHTTP。
// Then 放行到挑战链（到期自动解封，执法点按条目时间判定，无需面板清理）。
func TestServeHTTP_sessionBanExpiredEntryPasses(t *testing.T) {
	path, now := sessionBanTestEnv(t)
	ip, ua := "203.0.113.202", "expired-agent/1.0"
	fp := sessionFingerprint("", ua, "")
	writeSessionBanFile(t, path, []string{normalizeIP(ip) + "|" + fp}, now.Add(-time.Minute).UnixMilli())

	h := sessionBanTestHandler()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/page", nil)
	req.RemoteAddr = ip + ":4321"
	req.Header.Set("User-Agent", ua)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, sessionBanTestNext()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Security Check") {
		t.Fatalf("到期会话封禁必须解封走挑战链, got %d", rec.Code)
	}
}

// Given 会话封禁在役，请求无任何会话标识（UA 与 Accept-Language 均空）。
// When ServeHTTP。
// Then 不命中会话封禁（无指纹无法归属会话）——IP 级执法仍由名单通道承担。
func TestServeHTTP_fingerprintlessRequestNotSessionBanned(t *testing.T) {
	path, now := sessionBanTestEnv(t)
	ip := "203.0.113.203"
	writeSessionBanFile(t, path, []string{normalizeIP(ip) + "|u:0123456789abcdef"}, now.Add(10*time.Minute).UnixMilli())

	h := sessionBanTestHandler()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/page", nil)
	req.RemoteAddr = ip + ":4321"
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, sessionBanTestNext()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("无指纹请求不得被会话封禁拦截（IP 级走名单通道）, got %d", rec.Code)
	}
}

// Given IPv6 客户端：封禁键锚定 /64，请求来自同 /64 的不同接口 ID。
// When ServeHTTP。
// Then 命中（与面板侧归一粒度一致，隐私扩展轮换不逃逸）。
func TestServeHTTP_sessionBanAnchorsIPv6Per64(t *testing.T) {
	path, now := sessionBanTestEnv(t)
	ua := "v6-agent/1.0"
	fp := sessionFingerprint("", ua, "")
	writeSessionBanFile(t, path, []string{normalizeIP("2001:db8:77::1") + "|" + fp}, now.Add(10*time.Minute).UnixMilli())

	h := sessionBanTestHandler()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/page", nil)
	req.RemoteAddr = "[2001:db8:77::9999]:4321"
	req.Header.Set("User-Agent", ua)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, sessionBanTestNext()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("同 /64 轮换地址必须命中会话封禁, got %d", rec.Code)
	}
}

// Given 交换文件缺席或内容损坏。
// When ServeHTTP。
// Then fail-open 走现有挑战链（执法数据源故障不阻断正常请求）。
func TestServeHTTP_sessionBanFileMissingOrCorruptFailsOpen(t *testing.T) {
	path, _ := sessionBanTestEnv(t)
	h := sessionBanTestHandler()
	mkReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "https://example.test/page", nil)
		req.RemoteAddr = "203.0.113.204:4321"
		req.Header.Set("User-Agent", "fo-agent/1.0")
		return req
	}
	// 缺席
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, mkReq(), sessionBanTestNext()); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("文件缺席必须 fail-open: code=%d err=%v", rec.Code, err)
	}
	// 损坏
	if err := os.WriteFile(path, []byte("{corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	resetSessionBanCacheForTest()
	rec = httptest.NewRecorder()
	if err := h.ServeHTTP(rec, mkReq(), sessionBanTestNext()); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("文件损坏必须 fail-open: code=%d err=%v", rec.Code, err)
	}
}

// Given 会话封禁在役且缓存已加载。
// When 面板更新交换文件（新增封禁）后再次请求。
// Then ≤stat 热感知窗口内收敛（mtime 变化触发重读，无需 Caddy 重载）。
func TestServeHTTP_sessionBanHotReloadOnFileChange(t *testing.T) {
	path, now := sessionBanTestEnv(t)
	ip, ua := "203.0.113.205", "hot-agent/1.0"
	fp := sessionFingerprint("", ua, "")
	h := sessionBanTestHandler()
	mkReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "https://example.test/page", nil)
		req.RemoteAddr = ip + ":4321"
		req.Header.Set("User-Agent", ua)
		return req
	}
	// 首次请求：无封禁 → 挑战。
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, mkReq(), sessionBanTestNext()); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("given: code=%d err=%v", rec.Code, err)
	}
	// 面板写入封禁（mtime 前进）。
	writeSessionBanFile(t, path, []string{normalizeIP(ip) + "|" + fp}, now.Add(10*time.Minute).UnixMilli())
	future := now.Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	*now = future
	rec = httptest.NewRecorder()
	if err := h.ServeHTTP(rec, mkReq(), sessionBanTestNext()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("交换文件更新必须热感知生效, got %d", rec.Code)
	}
}

// Given API/XHR 请求命中会话封禁。
// When ServeHTTP。
// Then 403 JSON（与挑战链的 API 分流同形，但 code 标识封禁而非挑战）。
func TestServeHTTP_sessionBanJSONForAPIRequests(t *testing.T) {
	path, now := sessionBanTestEnv(t)
	ip, ua := "203.0.113.206", "api-agent/1.0"
	fp := sessionFingerprint("", ua, "")
	writeSessionBanFile(t, path, []string{normalizeIP(ip) + "|" + fp}, now.Add(10*time.Minute).UnixMilli())

	h := sessionBanTestHandler()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/api/x", nil)
	req.RemoteAddr = ip + ":4321"
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, sessionBanTestNext()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("API 命中会话封禁必须 403, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type=%q, want JSON", ct)
	}
	if !strings.Contains(rec.Body.String(), "session_banned") {
		t.Fatalf("body=%s, want session_banned code", rec.Body.String())
	}
}

// 交换文件路径契约：缺省与面板侧容器默认逐字节一致（跨进程双锚，
// 与 humanEventSocketEnv 同族）；自定义路径经渲染配置键下发。
func TestSessionBanFile_defaultPathContract(t *testing.T) {
	if defaultSessionBanFile != "/app/data/autoban-session-bans.json" {
		t.Fatalf("defaultSessionBanFile=%q, want /app/data/autoban-session-bans.json（与面板侧写路径同值）", defaultSessionBanFile)
	}
	oldFile := sessionBanFile
	t.Cleanup(func() { sessionBanFile = oldFile })
	resetSessionBanCacheForTest()
	t.Cleanup(resetSessionBanCacheForTest)
	h := &HumanHandler{HumanConfig: HumanConfig{SessionBanFile: "/custom/data/autoban-session-bans.json"}}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if sessionBanFile != "/custom/data/autoban-session-bans.json" {
		t.Fatalf("Provision 必须应用配置路径, got %q", sessionBanFile)
	}
}
