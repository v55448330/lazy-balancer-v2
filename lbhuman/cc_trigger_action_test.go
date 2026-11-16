package lbhuman

// CC 触发动作三态分流钉测：challenge=现行挑战页（存量冻结）；queue=等待页
// （200+HTML+queue_widget 倒计时）；reject=429+Retry-After。API/XHR 客户端
// queue/reject 均拿 JSON 429+Retry-After。等待秒数 0=自动取 CC 窗口。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ccTriggerFixture 构造已触发 CC 的 handler（窗口计数灌满）+ 请求。
func ccTriggerFixture(t *testing.T, action string, waitSec int) (*HumanHandler, *http.Request) {
	t.Helper()
	h := &HumanHandler{HumanConfig{
		Mode: "auto", Type: "js", TTLMinutes: 30, Secret: "0123456789abcdef0123456789abcdef",
		CCEnabled: true, CCRPSLimit: 5, CCWindowSec: 10,
		CCTriggerAction: action, CCQueueWaitSec: waitSec,
		RuleID: "rule-action-" + action,
	}}
	key := h.RuleID + "|" + normalizeIP("203.0.113.50")
	for range 10 {
		ccRecord(key, h.CCWindowSec, false, "ua1")
	}
	r := httptest.NewRequest(http.MethodGet, "https://example.com/page", nil)
	r.RemoteAddr = "203.0.113.50:1234"
	r.Header.Set("Accept", "text/html")
	return h, r
}

func TestCCTriggerAction_challengeDefault(t *testing.T) {
	// 缺省动作（空串）= challenge：现行挑战页行为冻结。
	h, r := ccTriggerFixture(t, "", 0)
	w := httptest.NewRecorder()
	if err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { t.Fatal("触发后不得直通"); return nil })); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("challenge 页 status=%d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "lb-hv-js") && !strings.Contains(w.Body.String(), "human") {
		t.Fatal("challenge 动作必须发挑战页")
	}
}

func TestCCTriggerAction_queueWaitPage(t *testing.T) {
	h, r := ccTriggerFixture(t, "queue", 0)
	w := httptest.NewRecorder()
	if err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { t.Fatal("触发后不得直通"); return nil })); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("queue 等待页 status=%d, want 200（与挑战页同语义）", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "lb-queue") {
		t.Fatal("queue 等待页必须含倒计时组件")
	}
	// 等待秒数 0=自动取 CC 窗口（10s）
	if !strings.Contains(body, "10") {
		t.Fatal("queue 等待页必须披露等待秒数（自动=CC 窗口 10）")
	}
	if w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("queue Content-Type=%q", w.Header().Get("Content-Type"))
	}
}

func TestCCTriggerAction_queueExplicitWait(t *testing.T) {
	h, r := ccTriggerFixture(t, "queue", 45)
	w := httptest.NewRecorder()
	if err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.Body.String(), "45") {
		t.Fatal("显式等待秒数 45 必须披露")
	}
}

func TestCCTriggerAction_queueCustomPage(t *testing.T) {
	h, r := ccTriggerFixture(t, "queue", 20)
	h.ChallengePageHTML = `<html><body>自定义等待页 {{queue_widget}} 尾</body></html>`
	w := httptest.NewRecorder()
	if err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })); err != nil {
		t.Fatal(err)
	}
	body := w.Body.String()
	if !strings.Contains(body, "自定义等待页") || !strings.Contains(body, "lb-queue") {
		t.Fatal("策略页含 {{queue_widget}} 必须注入倒计时组件")
	}
	if strings.Contains(body, "{{queue_widget}}") {
		t.Fatal("占位符必须被替换")
	}
}

func TestCCTriggerAction_reject429(t *testing.T) {
	h, r := ccTriggerFixture(t, "reject", 0)
	w := httptest.NewRecorder()
	if err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { t.Fatal("触发后不得直通"); return nil })); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("reject status=%d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("reject 必须带 Retry-After")
	}
}

func TestCCTriggerAction_jsonClient429(t *testing.T) {
	for _, action := range []string{"queue", "reject"} {
		t.Run(action, func(t *testing.T) {
			h, r := ccTriggerFixture(t, action, 15)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			if err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("API 客户端 %s status=%d, want 429", action, w.Code)
			}
			if w.Header().Get("Retry-After") != "15" {
				t.Fatalf("API Retry-After=%q, want 15", w.Header().Get("Retry-After"))
			}
			if !strings.Contains(w.Body.String(), "rate_limited") {
				t.Fatal("API 响应必须含 rate_limited code")
			}
		})
	}
}

func TestCCTriggerAction_forceStillChallenge(t *testing.T) {
	// force 模式（始终验证）不受 CC 动作影响——恒挑战。
	h := &HumanHandler{HumanConfig{
		Mode: "force", Type: "js", TTLMinutes: 30, Secret: "0123456789abcdef0123456789abcdef",
		CCTriggerAction: "reject", RuleID: "rule-force",
	}}
	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.RemoteAddr = "203.0.113.51:1234"
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	if err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("force 模式必须恒挑战页，status=%d", w.Code)
	}
}
