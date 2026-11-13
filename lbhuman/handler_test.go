package lbhuman

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCookieSignAndVerify(t *testing.T) {
	secret := []byte("test-secret-32-bytes-for-hmac-sha256")
	ip := "203.0.113.7"
	ua := "Mozilla/5.0 Chrome/120"

	value, exp := signCookie(secret, ip, ua, 30*time.Minute)
	if exp.Before(time.Now()) {
		t.Fatal("cookie expiry must be in the future")
	}
	if !verifyCookie(secret, value, ip, ua, time.Now()) {
		t.Fatal("valid cookie must verify")
	}
	// IP 绑定：换 IP 必须失败
	if verifyCookie(secret, value, "203.0.113.8", ua, time.Now()) {
		t.Fatal("cookie must be IP-bound")
	}
	// UA 绑定：换 UA 必须失败
	if verifyCookie(secret, value, ip, "Different UA", time.Now()) {
		t.Fatal("cookie must be UA-bound")
	}
	// 过期拒绝
	if verifyCookie(secret, value, ip, ua, exp.Add(time.Second)) {
		t.Fatal("expired cookie must reject")
	}
	// 篡改拒绝
	if verifyCookie(secret, value+"x", ip, ua, time.Now()) {
		t.Fatal("tampered cookie must reject")
	}
}

func TestIPv6Normalization(t *testing.T) {
	// /64 归一：同 /64 前缀的不同地址视为同一身份
	a := "2001:db8:1234:5678::1"
	b := "2001:db8:1234:5678::9999"
	if normalizeIP(a) != normalizeIP(b) {
		t.Fatalf("same /64 must normalize equal: %s vs %s", normalizeIP(a), normalizeIP(b))
	}
	// 不同 /64 不归一
	c := "2001:db8:9999::1"
	if normalizeIP(a) == normalizeIP(c) {
		t.Fatal("different /64 must differ")
	}
}

func TestChallengeTokenOneTime(t *testing.T) {
	token := issueChallengeToken()
	if !consumeChallengeToken(token) {
		t.Fatal("fresh token must consume")
	}
	if consumeChallengeToken(token) {
		t.Fatal("used token must reject (one-time)")
	}
}

func TestPoWValidity(t *testing.T) {
	// 找一个合法 nonce（难度 4 前导零，命中概率 1/65536）——上限取 2000000
	// 使期望命中 ~30 次，消除小上限（200k）的概率性 flaky。
	token := "test-token"
	for i := 0; i < 2000000; i++ {
		nonce := string(rune(i))
		if powValid(token, nonce) {
			if !powValid(token, nonce) {
				t.Fatal("pow must be deterministic")
			}
			return
		}
	}
	t.Fatal("no valid nonce found within 2M iterations")
}

func TestCCWindowAndTrigger(t *testing.T) {
	key := "rule1|203.0.113.99"
	// 突刺触发：40 次/10s
	for i := 0; i < 45; i++ {
		ccRecord(key, 10, false, "ua1")
	}
	stats := ccPeek(key, 10)
	if stats.Count != 45 {
		t.Fatalf("count=%d want 45", stats.Count)
	}
	trig := evalCC(stats, 40, 10, 0, 0, false)
	if !trig.Triggered || trig.Reason != "rps_spike" {
		t.Fatalf("rps spike must trigger: %+v", trig)
	}

	// 4xx 比例触发：70% 且请求≥20
	key2 := "rule1|203.0.113.100"
	for i := 0; i < 25; i++ {
		ccRecord(key2, 10, i < 20, "ua1") // 20 个 4xx，5 个正常
	}
	stats2 := ccPeek(key2, 10)
	trig2 := evalCC(stats2, 1000, 10, 70, 0, false)
	if !trig2.Triggered || trig2.Reason != "4xx_ratio" {
		t.Fatalf("4xx ratio must trigger: %+v", trig2)
	}

	// 会话异常：多 UA + RPS 超阈
	key3 := "rule1|203.0.113.101"
	for i := 0; i < 50; i++ {
		ccRecord(key3, 10, false, string(rune('a'+i%8)))
	}
	stats3 := ccPeek(key3, 10)
	trig3 := evalCC(stats3, 1000, 10, 0, 5, true)
	if !trig3.Triggered || trig3.Reason != "session_anomaly" {
		t.Fatalf("session anomaly must trigger: %+v", trig3)
	}
}

func TestExemptPaths(t *testing.T) {
	h := &HumanHandler{HumanConfig: HumanConfig{
		ExemptPaths: []string{"/api/", "/static/"},
		ExemptIPs:   []string{"10.0.0.1", "192.168.0.0/16"},
	}}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	if !h.isExempt("10.0.0.1", "/") {
		t.Fatal("exact IP exempt")
	}
	if !h.isExempt("192.168.1.5", "/") {
		t.Fatal("CIDR exempt")
	}
	if !h.isExempt("1.2.3.4", "/api/users") {
		t.Fatal("path prefix exempt")
	}
	if h.isExempt("1.2.3.4", "/admin") {
		t.Fatal("non-exempt path must not match")
	}
}

// 挑战请求类型分流（2026-11-12 用户裁定）：API/XHR 与非幂等请求不得拿 HTML
// 挑战页——前者解析失败，后者重定向会丢请求体。
func TestChallengeResponseSplitsByRequestType(t *testing.T) {
	h := &HumanHandler{HumanConfig: HumanConfig{
		Mode: "force", Type: "js", TTLMinutes: 30, RuleID: "lb-rt",
		Secret: "test-secret", CCEnabled: true,
	}}
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	cases := []struct {
		name       string
		method     string
		headers    map[string]string
		wantStatus int
		wantJSON   bool
	}{
		{"browser navigation", http.MethodGet, map[string]string{"Accept": "text/html,application/xhtml+xml"}, http.StatusOK, false},
		{"api accept json", http.MethodGet, map[string]string{"Accept": "application/json"}, http.StatusUnauthorized, true},
		{"xhr header", http.MethodGet, map[string]string{"X-Requested-With": "XMLHttpRequest"}, http.StatusUnauthorized, true},
		{"fetch cors", http.MethodGet, map[string]string{"Sec-Fetch-Mode": "cors"}, http.StatusUnauthorized, true},
		{"post no body loss", http.MethodPost, map[string]string{"Accept": "text/html"}, http.StatusForbidden, true},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, "https://example.test/path?q=1", nil)
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		if err := h.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("%s: serve: %v", tc.name, err)
		}
		if rec.Code != tc.wantStatus {
			t.Fatalf("%s: status=%d, want %d (body=%s)", tc.name, rec.Code, tc.wantStatus, rec.Body.String())
		}
		ct := rec.Header().Get("Content-Type")
		if tc.wantJSON {
			if !strings.Contains(ct, "application/json") {
				t.Fatalf("%s: content-type=%q, want JSON", tc.name, ct)
			}
			if rec.Header().Get("X-Human-Challenge") != "1" {
				t.Fatalf("%s: 缺少 X-Human-Challenge 头", tc.name)
			}
			if !strings.Contains(rec.Body.String(), "human_challenge") {
				t.Fatalf("%s: body=%s, want human_challenge code", tc.name, rec.Body.String())
			}
		} else if !strings.Contains(ct, "text/html") {
			t.Fatalf("%s: content-type=%q, want HTML challenge page", tc.name, ct)
		}
	}
}
