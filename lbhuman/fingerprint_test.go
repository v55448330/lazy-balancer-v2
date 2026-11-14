package lbhuman

// 会话指纹采集钉测（自动封禁 NAT 检测的会话身份证据）：
//   - cookie 签名段优先：同 cookie 同指纹、异 nonce 异指纹、畸形回落；
//   - UA+Accept-Language 兜底稳定；
//   - 与面板侧 services.autobanSessionFingerprint 逐形等价（跨模块对拍）；
//   - 人机事件上报携带指纹（session_fp 字段）。

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// panelSessionFingerprintReference 是 services.autobanSessionFingerprint 的
// 语义参照（逐行同算法）：lbhuman 是依赖 Caddy 的独立插件模块，面板主模块
// 不引入其依赖树，等价性由本对拍钉测锁定——修改任一侧必须同步另一侧。
func panelSessionFingerprintReference(cookieValue, ua, acceptLanguage string) string {
	if cookieValue != "" {
		parts := strings.SplitN(cookieValue, ".", 2)
		if len(parts) == 2 && len(parts[1]) == 64 {
			if _, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
				if _, err := hex.DecodeString(parts[1]); err == nil {
					return "c:" + parts[1][:16]
				}
			}
		}
	}
	if ua == "" && acceptLanguage == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ua + "\x00" + acceptLanguage))
	return "u:" + hex.EncodeToString(sum[:8])
}

func fpTestCookie(ip, ua string, exp int64) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d|%s", exp, "nonce0123456789ab")))
	sum := sha256.Sum256([]byte(ip + "|" + ua + "|" + payload))
	return payload + "." + hex.EncodeToString(sum[:])
}

// Given 同一 cookie/同一 UA+语言组合。
// When 多次提取指纹。
// Then 稳定；cookie 签名段优先；畸形回落；与面板侧参照逐形等价。
func TestSessionFingerprint_stabilityAndPanelEquivalence(t *testing.T) {
	cookieA := fpTestCookie("203.0.113.7", "ua-A", 1700000001)
	cookieB := fpTestCookie("203.0.113.7", "ua-A", 1700000002)
	cases := []struct{ cookie, ua, lang string }{
		{cookieA, "ua-A", "zh-CN"},
		{cookieA, "other-ua", "en"}, // cookie 在场 UA 变化不改指纹
		{cookieB, "ua-A", "zh-CN"},
		{"", "ua-A", "zh-CN"},
		{"", "ua-A", "en"},
		{"", "ua-B", "zh-CN"},
		{"", "", ""},
		{"garbage", "ua-A", "zh-CN"},
		{"payload.not-hex!", "ua-A", "zh-CN"},
		{"a.b", "ua-A", "zh-CN"},
		{".", "ua-A", "zh-CN"},
		{"c29tZQ.zzzz", "ua-A", "zh-CN"},
	}
	for _, tc := range cases {
		got := sessionFingerprint(tc.cookie, tc.ua, tc.lang)
		want := panelSessionFingerprintReference(tc.cookie, tc.ua, tc.lang)
		if got != want {
			t.Fatalf("sessionFingerprint(%q,%q,%q)=%q, 面板参照=%q（两侧必须同步）", tc.cookie, tc.ua, tc.lang, got, want)
		}
		if again := sessionFingerprint(tc.cookie, tc.ua, tc.lang); again != got {
			t.Fatalf("指纹漂移: %q != %q", again, got)
		}
	}
	// 前缀形态：cookie 强证据 c:、UA 弱证据 u:、空身份空串。
	if fp := sessionFingerprint(cookieA, "ua-A", "zh-CN"); !strings.HasPrefix(fp, "c:") {
		t.Fatalf("cookie 指纹必须 c: 前缀, got %q", fp)
	}
	if fp := sessionFingerprint("", "ua-A", "zh-CN"); !strings.HasPrefix(fp, "u:") {
		t.Fatalf("UA 兜底必须 u: 前缀, got %q", fp)
	}
	if fp := sessionFingerprint("", "", ""); fp != "" {
		t.Fatalf("无会话标识必须空串, got %q", fp)
	}
	if sessionFingerprint(cookieA, "ua-A", "zh-CN") == sessionFingerprint(cookieB, "ua-A", "zh-CN") {
		t.Fatal("不同 nonce 的 cookie 必须产出不同指纹")
	}
}

// Given 真实签发的 __lb_human cookie（signCookie 产物）。
// When 提取指纹。
// Then c: 前缀稳定（签发形态与指纹形态门兼容）。
func TestSessionFingerprint_realSignedCookie(t *testing.T) {
	secret := []byte("fp-secret-32-bytes-for-hmac-sha256!")
	value, _ := signCookie(secret, "203.0.113.80", "fp-agent/1.0", 30*time.Minute)
	fp1 := sessionFingerprint(value, "fp-agent/1.0", "zh-CN")
	fp2 := sessionFingerprint(value, "fp-agent/1.0", "zh-CN")
	if !strings.HasPrefix(fp1, "c:") || fp1 != fp2 {
		t.Fatalf("真实 cookie 指纹必须稳定 c: 前缀: %q %q", fp1, fp2)
	}
}

// Given 请求携带 __lb_human cookie 与 UA/Accept-Language。
// When requestSessionFingerprint 提取。
// Then 与直接传值同口径（cookie 精确名匹配）。
func TestRequestSessionFingerprint_extractsFromRequest(t *testing.T) {
	cookie := fpTestCookie("203.0.113.81", "ua-R", 1700000003)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Cookie", "other=1; "+cookieName+"="+cookie+"; tail=2")
	r.Header.Set("User-Agent", "ua-R")
	r.Header.Set("Accept-Language", "zh-CN")
	want := sessionFingerprint(cookie, "ua-R", "zh-CN")
	if got := requestSessionFingerprint(r); got != want {
		t.Fatalf("requestSessionFingerprint=%q, want %q", got, want)
	}
	// 无 cookie 请求 → UA 兜底。
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("User-Agent", "ua-R")
	if got := requestSessionFingerprint(r2); got != sessionFingerprint("", "ua-R", "") {
		t.Fatalf("无 cookie 必须 UA 兜底, got %q", got)
	}
}

// Given 人机事件上报。
// When 投递到摄入端点。
// Then payload 携带 session_fp（与请求指纹同值）。
func TestHumanEventDelivery_carriesSessionFingerprint(t *testing.T) {
	var gotFP string
	var gotPayload []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotPayload)
		if len(gotPayload) > 0 {
			gotFP, _ = gotPayload[0]["session_fp"].(string)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	resetHumanEventPosterForTest(t, srv.URL)

	cookie := fpTestCookie("203.0.113.82", "ua-E", 1700000004)
	want := sessionFingerprint(cookie, "ua-E", "zh-CN")
	reportHumanEvent("lb-fp", "203.0.113.82", http.MethodGet, "/", "ua-E", "challenge", want)
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain")
	}
	if gotFP != want {
		t.Fatalf("投递 session_fp=%q, want %q", gotFP, want)
	}
}
