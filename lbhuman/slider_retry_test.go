package lbhuman

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// 用户裁定（2026-11-13）：滑块失败原地重试，服务端必须区分「可重试」与「拼图失效」，
// 并披露剩余次数；成功后拼图一次性消费，不得在 TTL 内重放。

func sliderTestTrack() string { return "0,3,8,14,21,29,38,47" }

func postSliderVerify(t *testing.T, h *HumanHandler, pid string, x int) *httptest.ResponseRecorder {
	t.Helper()
	body := url.Values{}
	body.Set("puzzle_id", pid)
	body.Set("x", itoa(x))
	body.Set("track", sliderTestTrack())
	body.Set("duration_ms", "700")
	req := httptest.NewRequest(http.MethodPost, "/__lb/human/slider-verify", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.serveSliderVerify(rec, req, "203.0.113.80")
	return rec
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

func issueSliderPuzzle(t *testing.T, h *HumanHandler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	h.serveSliderChallenge(rec, req, "203.0.113.80")
	m := regexp.MustCompile(`var pid="([0-9a-f]+)"`).FindStringSubmatch(rec.Body.String())
	if len(m) != 2 {
		t.Fatalf("challenge page missing pid: %s", rec.Body.String()[:min(300, rec.Body.Len())])
	}
	return m[1]
}

func TestServeSliderVerify_failureResponseDistinguishesRetry(t *testing.T) {
	sliderPuzzlesMu.Lock()
	sliderPuzzles = map[string]*sliderPuzzle{}
	sliderPuzzlesMu.Unlock()
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-retry", Secret: "test-secret", TTLMinutes: 30}}
	pid := issueSliderPuzzle(t, h)

	for attempt := 1; attempt <= sliderMaxAttempts; attempt++ {
		rec := postSliderVerify(t, h, pid, 1) // 远离缺口，必失败
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d status=%d, want 400", attempt, rec.Code)
		}
		var payload struct {
			OK           bool `json:"ok"`
			Retryable    bool `json:"retryable"`
			AttemptsLeft int  `json:"attempts_left"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("attempt %d decode: %v body=%s", attempt, err, rec.Body.String())
		}
		wantLeft := sliderMaxAttempts - attempt
		if payload.Retryable != (wantLeft > 0) || payload.AttemptsLeft != wantLeft {
			t.Fatalf("attempt %d retryable=%v left=%d, want retryable=%v left=%d", attempt, payload.Retryable, payload.AttemptsLeft, wantLeft > 0, wantLeft)
		}
	}
}

func TestServeSliderVerify_successConsumesPuzzle(t *testing.T) {
	sliderPuzzlesMu.Lock()
	sliderPuzzles = map[string]*sliderPuzzle{}
	sliderPuzzlesMu.Unlock()
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-once", Secret: "test-secret", TTLMinutes: 30}}
	pid := issueSliderPuzzle(t, h)
	sliderPuzzlesMu.Lock()
	gapX := sliderPuzzles[pid].gapX
	sliderPuzzlesMu.Unlock()

	rec := postSliderVerify(t, h, pid, gapX)
	if rec.Code != http.StatusOK {
		t.Fatalf("first verify status=%d body=%s", rec.Code, rec.Body.String())
	}
	// 成功后一次性消费：同 pid 重放必须失败（不得在 TTL 内再发 cookie）。
	rec2 := postSliderVerify(t, h, pid, gapX)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("replay status=%d, want 400 (puzzle must be consumed on success)", rec2.Code)
	}
}

func TestServeSliderChallenge_redirectJSONEscaped(t *testing.T) {
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-redirect", Secret: "test-secret", TTLMinutes: 30}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected?a=1&b=2", nil)
	h.serveSliderChallenge(rec, req, "203.0.113.80")
	body := rec.Body.String()
	if strings.Contains(body, "&amp;") {
		t.Fatal("redirect 不得用 HTML 实体注入 JS 字符串（& 会被错误编码）")
	}
	if !strings.Contains(body, "redirect=") {
		t.Fatal("missing redirect assignment")
	}
}

func TestSliderWidgetInteractionAndAccessibilityMarkers(t *testing.T) {
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-ux", Secret: "test-secret", TTLMinutes: 30}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	h.serveSliderChallenge(rec, req, "203.0.113.80")
	body := rec.Body.String()
	for _, want := range []string{
		"setPointerCapture",
		"pointercancel",
		`role="slider"`,
		`tabindex="0"`,
		"aria-live",
		"<noscript>",
		"attempts_left",
		"retryable",
		"data-lb-gap",
		"resize",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("滑块组件缺少交互/可达性标记: %q", want)
		}
	}
}

func TestSliderFallbackEnglishAndReusesWidget(t *testing.T) {
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-fallback", Secret: "test-secret", TTLMinutes: 30}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	h.serveSliderChallenge(rec, req, "203.0.113.80")
	body := rec.Body.String()
	if !strings.Contains(body, "Security Check") {
		t.Fatal("内置回退页必须为英文 Security Check")
	}
	if strings.Contains(body, "安全验证") {
		t.Fatal("内置回退页不得残留中文（与内置拦截页英文口径一致）")
	}
	if !strings.Contains(body, "lb-hv-widget") {
		t.Fatal("内置回退页必须复用同一滑块组件（消除两套视觉/交互）")
	}
}
