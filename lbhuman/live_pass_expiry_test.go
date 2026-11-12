package lbhuman

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 用户裁定（2026-11-13）：实时挑战弹框要能看到「已通过挑战的请求多久过期」。
// 放行到期时刻 = 签发 cookie 的真实 exp（策略 human_verify_ttl），不是挑战材料
// TTL；已通过会话按放行到期保留（否则放行期内该行提前消失）。

func resetLiveSessionsForTest() {
	challengeSessionsMu.Lock()
	challengeSessions = map[string]*challengeSession{}
	challengeSessionsMu.Unlock()
	sliderPuzzlesMu.Lock()
	sliderPuzzles = map[string]*sliderPuzzle{}
	sliderPuzzlesMu.Unlock()
	challengeTokensMu.Lock()
	challengeTokens = map[string]challengeToken{}
	challengeTokensMu.Unlock()
}

// 通过成功后：会话登记真实放行到期时刻，快照下发 pass_expires_at_ms /
// pass_remaining_ms（与 Set-Cookie 的 Expires 同源，非挑战材料 TTL）。
func TestSliderPass_recordsCredentialExpiry(t *testing.T) {
	resetLiveSessionsForTest()
	const ttlMinutes = 30
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-pass-exp", Secret: "test-secret", TTLMinutes: ttlMinutes}}
	pid := issueSliderPuzzle(t, h)
	sliderPuzzlesMu.Lock()
	gapX := sliderPuzzles[pid].gapX
	sliderPuzzlesMu.Unlock()

	before := time.Now()
	rec := postSliderVerify(t, h, pid, gapX)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", rec.Code, rec.Body.String())
	}
	// Set-Cookie 的 Expires 是权威放行到期时刻。
	cookieHeader := rec.Header().Get("Set-Cookie")
	idx := strings.Index(cookieHeader, "Expires=")
	if idx < 0 {
		t.Fatalf("missing Expires in Set-Cookie: %s", cookieHeader)
	}
	expRaw := cookieHeader[idx+len("Expires="):]
	if i := strings.Index(expRaw, ";"); i >= 0 {
		expRaw = expRaw[:i]
	}
	cookieExp, err := time.Parse(http.TimeFormat, expRaw)
	if err != nil {
		t.Fatalf("parse cookie Expires %q: %v", expRaw, err)
	}

	snap := snapshotChallengeSessions("recent")
	var row *challengeSessionJSON
	for i := range snap.Sessions {
		if snap.Sessions[i].ID == pid {
			row = &snap.Sessions[i]
			break
		}
	}
	if row == nil {
		t.Fatal("passed session missing from recent snapshot")
	}
	if row.Status != challengeStatusPassed {
		t.Fatalf("status=%s, want passed", row.Status)
	}
	// Set-Cookie 的 Expires 是 HTTP 日期格式（秒精度），会话登记毫秒（更精确）：
	// 按秒比对同源，且毫秒余量必须落在同一秒内。
	if row.PassExpiresAtMS/1000 != cookieExp.Unix() {
		t.Fatalf("pass_expires_at_ms=%d 与 cookie exp %d 非同源（秒级）", row.PassExpiresAtMS, cookieExp.Unix())
	}
	// 放行剩余必须按放行到期算（30min），不得退化成挑战材料 TTL（2min）。
	wantRemaining := row.PassExpiresAtMS - snap.NowMS
	if row.PassRemainingMS != wantRemaining {
		t.Fatalf("pass_remaining_ms=%d, want %d", row.PassRemainingMS, wantRemaining)
	}
	if row.PassRemainingMS <= int64((sliderPuzzleTTL)/time.Millisecond) {
		t.Fatalf("pass_remaining_ms=%d 退化为挑战材料 TTL", row.PassRemainingMS)
	}
	if row.PassExpiresAtMS <= before.UnixMilli() {
		t.Fatal("pass expiry must be in the future")
	}
	// 未通过的会话不得携带放行到期（避免前端误显示）。
	other := issueSliderPuzzle(t, h)
	for _, s := range snapshotChallengeSessions("recent").Sessions {
		if s.ID == other && (s.PassExpiresAtMS != 0 || s.PassRemainingMS != 0) {
			t.Fatalf("waiting session must not carry pass expiry: %+v", s)
		}
	}
}

// JS PoW 通过同样登记放行到期。
func TestJSPass_recordsCredentialExpiry(t *testing.T) {
	resetLiveSessionsForTest()
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "js", RuleID: "lb-js-exp", Secret: "test-secret", TTLMinutes: 15}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/js", nil)
	h.serveJSChallenge(rec, req, "203.0.113.95")
	tokenMatch := regexp.MustCompile(`var token ?= ?"([0-9a-f]+)"`).FindStringSubmatch(rec.Body.String())
	if len(tokenMatch) != 2 {
		t.Fatalf("JS challenge page missing token: %s", rec.Body.String()[:min(300, len(rec.Body.String()))])
	}
	token := tokenMatch[1]
	nonce := ""
	for i := range 200000 {
		candidate := strconv.Itoa(i)
		if powValid(token, candidate) {
			nonce = candidate
			break
		}
	}
	if nonce == "" {
		t.Fatal("no valid PoW nonce found")
	}

	body := url.Values{}
	body.Set("token", token)
	body.Set("nonce", nonce)
	vreq := httptest.NewRequest(http.MethodPost, "/__lb/human/verify", strings.NewReader(body.Encode()))
	vreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vrec := httptest.NewRecorder()
	h.serveJSVerify(vrec, vreq, "203.0.113.95")
	if vrec.Code != http.StatusOK {
		t.Fatalf("js verify status=%d body=%s", vrec.Code, vrec.Body.String())
	}
	snap := snapshotChallengeSessions("recent")
	found := false
	for _, s := range snap.Sessions {
		if s.ID == token {
			found = true
			if s.Status != challengeStatusPassed || s.PassExpiresAtMS <= snap.NowMS {
				t.Fatalf("js passed session missing future pass expiry: %+v", s)
			}
			if s.PassRemainingMS != s.PassExpiresAtMS-snap.NowMS {
				t.Fatalf("js pass_remaining_ms=%d inconsistent", s.PassRemainingMS)
			}
		}
	}
	if !found {
		t.Fatal("js passed session missing")
	}
}

// 保留窗：已通过会话按放行到期保留——挑战材料 TTL 早已过期，但放行仍有效时
// 该行必须仍在（否则用户在放行期内看不到倒计时）。
func TestPassedSession_retainedUntilCredentialExpiry(t *testing.T) {
	resetLiveSessionsForTest()
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-retain", Secret: "test-secret", TTLMinutes: 60}}
	pid := issueSliderPuzzle(t, h)
	sliderPuzzlesMu.Lock()
	gapX := sliderPuzzles[pid].gapX
	sliderPuzzlesMu.Unlock()
	if rec := postSliderVerify(t, h, pid, gapX); rec.Code != http.StatusOK {
		t.Fatalf("verify status=%d", rec.Code)
	}
	// 把挑战材料到期与更新时刻推到很久以前（远超 5min 保留窗），放行到期仍在未来。
	challengeSessionsMu.Lock()
	s := challengeSessions[pid]
	s.ExpiresAtMS = time.Now().Add(-2 * time.Hour).UnixMilli()
	s.UpdatedAtMS = s.ExpiresAtMS
	passExp := s.PassExpiresAtMS
	challengeSessionsMu.Unlock()

	snap := snapshotChallengeSessions("recent")
	found := false
	for _, row := range snap.Sessions {
		if row.ID == pid {
			found = true
			if row.PassExpiresAtMS != passExp || row.PassRemainingMS <= 0 {
				t.Fatalf("retained row lost pass expiry: %+v", row)
			}
		}
	}
	if !found {
		t.Fatal("已通过会话在放行有效期内被提前清理（应按放行到期保留）")
	}

	// 放行到期后超过保留窗 → 清理。
	challengeSessionsMu.Lock()
	challengeSessions[pid].PassExpiresAtMS = time.Now().Add(-2 * time.Hour).UnixMilli()
	challengeSessionsMu.Unlock()
	for _, row := range snapshotChallengeSessions("recent").Sessions {
		if row.ID == pid {
			t.Fatal("放行到期且超保留窗的会话必须被清理")
		}
	}
}

// 上限提高（用户裁定：内存不是瓶颈，但不得影响转发/WAF 性能）：
// 上限必须显著大于旧值 200，且仍为有限值（热路径不得无界增长）。
func TestChallengeSessionCap_raisedButBounded(t *testing.T) {
	if challengeSessionCap <= 200 {
		t.Fatalf("challengeSessionCap=%d，用户裁定要求提高上限", challengeSessionCap)
	}
	if challengeSessionCap > 100000 {
		t.Fatalf("challengeSessionCap=%d 过大，热路径内存必须有界", challengeSessionCap)
	}
	resetLiveSessionsForTest()
	for i := range challengeSessionCap + 50 {
		registerChallengeSession(itoa(i), "slider", "lb-cap", "203.0.113.1", http.MethodGet, "/", "ua", time.Minute, 3)
	}
	challengeSessionsMu.Lock()
	n := len(challengeSessions)
	challengeSessionsMu.Unlock()
	if n > challengeSessionCap {
		t.Fatalf("sessions=%d 超上限 %d（热路径必须有界）", n, challengeSessionCap)
	}
}
