package lbhuman

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

type humanLiveSessionJSON struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
	LastResult  string `json:"last_result"`
	RuleID      string `json:"rule_id"`
	ClientIP    string `json:"client_ip"`
	Method      string `json:"method"`
	URI         string `json:"uri"`
	UserAgent   string `json:"user_agent"`
	IssuedAtMS  int64  `json:"issued_at_ms"`
	ExpiresAtMS int64  `json:"expires_at_ms"`
	RemainingMS int64  `json:"remaining_ms"`
	Attempts    int    `json:"attempts"`
	MaxAttempts int    `json:"max_attempts"`
}

type humanLiveResponseJSON struct {
	NowMS       int64                  `json:"now_ms"`
	ActiveCount int                    `json:"active_count"`
	Sessions    []humanLiveSessionJSON `json:"sessions"`
}

func fetchHumanLive(t *testing.T, scope string) humanLiveResponseJSON {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/lb/human/live?scope="+scope, nil)
	rec := httptest.NewRecorder()
	if err := serveHumanLive(rec, req); err != nil {
		t.Fatalf("serveHumanLive: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out humanLiveResponseJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode live payload: %v", err)
	}
	return out
}

func findLiveSession(out humanLiveResponseJSON, id string) (humanLiveSessionJSON, bool) {
	for _, s := range out.Sessions {
		if s.ID == id {
			return s, true
		}
	}
	return humanLiveSessionJSON{}, false
}

// 实时挑战视图的消费契约：发放即登记请求上下文，失败尝试保留等待状态，
// 通过/过期有终态；active 只返回仍在 TTL 内等待验证的挑战。
func TestHumanLiveEndpoint_tracksInteractiveChallengeLifecycle(t *testing.T) {
	challengeSessionsMu.Lock()
	challengeSessions = map[string]*challengeSession{}
	challengeSessionsMu.Unlock()
	sliderPuzzlesMu.Lock()
	sliderPuzzles = map[string]*sliderPuzzle{}
	sliderPuzzlesMu.Unlock()
	challengeTokensMu.Lock()
	challengeTokens = map[string]challengeToken{}
	challengeTokensMu.Unlock()

	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-live"}}
	req := httptest.NewRequest(http.MethodGet, "/protected?trace=live", nil)
	req.Header.Set("User-Agent", "LiveTestAgent/1.0")
	rec := httptest.NewRecorder()
	h.serveSliderChallenge(rec, req, "203.0.113.20")
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge status=%d", rec.Code)
	}
	match := regexp.MustCompile(`var (?:pid|puzzleID) ?= ?"([0-9a-f]+)"`).FindStringSubmatch(rec.Body.String())
	if len(match) != 2 {
		t.Fatalf("challenge page missing puzzle id: %s", rec.Body.String()[min(500, rec.Body.Len()):min(1600, rec.Body.Len())])
	}
	puzzleID := match[1]

	active := fetchHumanLive(t, "active")
	if active.ActiveCount != 1 || len(active.Sessions) != 1 {
		t.Fatalf("active live sessions=(%d,%d), want (1,1)", active.ActiveCount, len(active.Sessions))
	}
	got := active.Sessions[0]
	if got.ID != puzzleID || got.Kind != "slider" || got.Status != "waiting" || got.LastResult != "" {
		t.Fatalf("issued session=(%s,%s,%s,%s), want (%s,slider,waiting,)", got.ID, got.Kind, got.Status, got.LastResult, puzzleID)
	}
	if got.RuleID != "lb-live" || got.ClientIP != "203.0.113.20" || got.Method != http.MethodGet || got.URI != "/protected?trace=live" || got.UserAgent != "LiveTestAgent/1.0" {
		t.Fatalf("issued context mismatch: %+v", got)
	}
	if got.MaxAttempts != sliderMaxAttempts || got.Attempts != 0 {
		t.Fatalf("attempts=(%d/%d), want 0/%d", got.Attempts, got.MaxAttempts, sliderMaxAttempts)
	}
	if got.RemainingMS <= 0 || got.ExpiresAtMS <= got.IssuedAtMS || got.ExpiresAtMS-time.Now().UnixMilli() > int64(sliderPuzzleTTL/time.Millisecond) {
		t.Fatalf("slider expiry mismatch: issued=%d expires=%d remaining=%d", got.IssuedAtMS, got.ExpiresAtMS, got.RemainingMS)
	}

	// 第一次失败：拼图仍在（可重试），会话状态=等待，但记录尝试与失败结果。
	fail := httptest.NewRequest(http.MethodPost, "/__lb/human/slider-verify", strings.NewReader("puzzle_id="+puzzleID+"&x=1&track=0,1,2,4,7,11,16,22&duration_ms=600"))
	fail.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	failRec := httptest.NewRecorder()
	h.serveSliderVerify(failRec, fail, "203.0.113.20")
	if failRec.Code != http.StatusBadRequest {
		t.Fatalf("wrong slider verify status=%d", failRec.Code)
	}
	active = fetchHumanLive(t, "active")
	if active.ActiveCount != 1 {
		t.Fatalf("retryable failed attempt must remain active, got %d", active.ActiveCount)
	}
	if got, _ = findLiveSession(active, puzzleID); got.Status != "waiting" || got.Attempts != 1 || got.LastResult != "fail" {
		t.Fatalf("after failed attempt=(%s,%d,%s), want (waiting,1,fail)", got.Status, got.Attempts, got.LastResult)
	}

	// 正确滑动：终态=通过，不再出现在 active。
	sliderPuzzlesMu.Lock()
	gapX := sliderPuzzles[puzzleID].gapX
	sliderPuzzlesMu.Unlock()
	passBody := fmt.Sprintf("puzzle_id=%s&x=%d&track=0,3,8,14,21,29,38,47&duration_ms=700", puzzleID, gapX)
	pass := httptest.NewRequest(http.MethodPost, "/__lb/human/slider-verify", strings.NewReader(passBody))
	pass.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	passRec := httptest.NewRecorder()
	h.serveSliderVerify(passRec, pass, "203.0.113.20")
	if passRec.Code != http.StatusOK {
		t.Fatalf("valid slider verify status=%d body=%s", passRec.Code, passRec.Body.String())
	}
	active = fetchHumanLive(t, "active")
	if _, ok := findLiveSession(active, puzzleID); ok {
		t.Fatal("passed challenge must leave active scope")
	}
	recent := fetchHumanLive(t, "recent")
	got, ok := findLiveSession(recent, puzzleID)
	if !ok || got.Status != "passed" || got.LastResult != "pass" || got.Attempts != 2 {
		t.Fatalf("passed session=(%v,%v), want (passed,pass,2)", got.Status, got.LastResult)
	}
}

// JS PoW 挑战：错误 nonce 消耗一次性 token，终态=失败；TTL 到期未验证=过期。
func TestHumanLiveEndpoint_marksJSFailureAndExpiry(t *testing.T) {
	challengeSessionsMu.Lock()
	challengeSessions = map[string]*challengeSession{}
	challengeSessionsMu.Unlock()
	challengeTokensMu.Lock()
	challengeTokens = map[string]challengeToken{}
	challengeTokensMu.Unlock()

	h := &HumanHandler{HumanConfig: HumanConfig{Type: "js", RuleID: "lb-live-js"}}
	req := httptest.NewRequest(http.MethodGet, "/js-protected", nil)
	req.Header.Set("User-Agent", "JSLiveAgent/1.0")
	rec := httptest.NewRecorder()
	h.serveJSChallenge(rec, req, "203.0.113.21")
	match := regexp.MustCompile(`var token ?= ?"([0-9a-f]+)"`).FindStringSubmatch(rec.Body.String())
	if len(match) != 2 {
		t.Fatal("JS challenge page missing token")
	}
	token := match[1]

	wrong := httptest.NewRequest(http.MethodPost, "/__lb/human/verify", strings.NewReader("token="+token+"&nonce=not-a-number"))
	wrong.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wrongRec := httptest.NewRecorder()
	h.serveJSVerify(wrongRec, wrong, "203.0.113.21")
	if wrongRec.Code != http.StatusBadRequest {
		t.Fatalf("wrong JS verify status=%d", wrongRec.Code)
	}
	recent := fetchHumanLive(t, "recent")
	got, ok := findLiveSession(recent, token)
	if !ok || got.Kind != "js" || got.Status != "failed" || got.LastResult != "fail" || got.Attempts != 1 {
		t.Fatalf("failed JS session=(%s,%s,%s,%d), want (js,failed,fail,1)", got.Kind, got.Status, got.LastResult, got.Attempts)
	}

	rec2 := httptest.NewRecorder()
	h.serveJSChallenge(rec2, req, "203.0.113.22")
	match = regexp.MustCompile(`var token ?= ?"([0-9a-f]+)"`).FindStringSubmatch(rec2.Body.String())
	if len(match) != 2 {
		t.Fatal("second JS challenge page missing token")
	}
	challengeSessionsMu.Lock()
	for _, session := range challengeSessions {
		if session.Kind == "js" && session.Status == "waiting" {
			session.ExpiresAtMS = time.Now().Add(-time.Second).UnixMilli()
		}
	}
	challengeSessionsMu.Unlock()
	active := fetchHumanLive(t, "active")
	if active.ActiveCount != 0 || len(active.Sessions) != 0 {
		t.Fatalf("expired challenge must leave active scope: count=%d rows=%d", active.ActiveCount, len(active.Sessions))
	}
	recent = fetchHumanLive(t, "recent")
	foundExpired := false
	for _, session := range recent.Sessions {
		if session.Kind == "js" && session.Status == "expired" {
			foundExpired = true
		}
	}
	if !foundExpired {
		t.Fatalf("expired JS session missing from recent scope: %+v", recent.Sessions)
	}
}
