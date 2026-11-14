package lbhuman

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// timeNow 缝隙全接线：替换时间源后 cookie 校验/挑战 token/CC 窗口/实时会话
// 的判时必须一致推进（半接线时部分面仍走真实时钟，冻结/推进时间产生分叉）。
func TestTimeNow_seamDrivesAllTimeDecisions(t *testing.T) {
	resetLiveSessionsForTest()
	frozen := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	saved := timeNow
	timeNow = func() time.Time { return frozen }
	t.Cleanup(func() { timeNow = saved })

	secret := []byte("time-seam-secret")
	ip, ua := "203.0.113.150", "seam-agent/1.0"

	// cookie：frozen 时刻签发，frozen+TTL 内有效、越界拒绝（真实时钟下
	// 2026-01-01 早已过期——仍通过即证明校验走缝隙）。
	value, exp := signCookie(secret, ip, ua, 30*time.Minute)
	if !exp.Equal(frozen.Add(30 * time.Minute)) {
		t.Fatalf("cookie exp=%v, want frozen+30m", exp)
	}
	h := &HumanHandler{HumanConfig: HumanConfig{Mode: "force", Type: "js", RuleID: "lb-seam", Secret: string(secret), TTLMinutes: 30}}
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "http://example.test/p", nil)
	req.RemoteAddr = ip + ":4321"
	req.Header.Set("User-Agent", ua)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: value})
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, next); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("frozen-time cookie must pass: code=%d err=%v", rec.Code, err)
	}
	frozen = frozen.Add(31 * time.Minute)
	rec = httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("expired-cookie serve: %v", err)
	}
	// 挑战页也是 200——以内容区分：过期 cookie 必须重新发放挑战。
	if !strings.Contains(rec.Body.String(), "Security Check") {
		t.Fatalf("expired cookie must re-challenge, body=%s", rec.Body.String()[:min(200, len(rec.Body.String()))])
	}

	// 挑战 token：frozen 时刻签发，推进过 TTL 后消费必须拒绝。
	token := issueChallengeToken()
	frozen = frozen.Add(challengeTokenTTL + time.Minute)
	if consumeChallengeToken(token) {
		t.Fatal("token issued at frozen time must expire when seam advances past TTL")
	}

	// CC 窗口：frozen 时刻记录，推进过窗口后 peek 必须归零。
	key := "seam-rule|" + ip
	ccRecord(key, 10, false, "ua-seam")
	if got := ccPeek(key, 10).Count; got != 1 {
		t.Fatalf("cc count=%d, want 1 at frozen time", got)
	}
	frozen = frozen.Add(11 * time.Second)
	if got := ccPeek(key, 10).Count; got != 0 {
		t.Fatalf("cc window must expire when seam advances: count=%d", got)
	}

	// 实时会话：frozen 时刻登记，推进过 TTL 后快照按 expired 呈现。
	registerChallengeSession("seam-session", "js", "lb-seam", ip, http.MethodGet, "/p", ua, challengeTokenTTL, 1)
	frozen = frozen.Add(challengeTokenTTL + time.Minute)
	snap := snapshotChallengeSessions("recent")
	found := false
	for _, s := range snap.Sessions {
		if s.ID == "seam-session" {
			found = true
			if s.Status != challengeStatusExpired {
				t.Fatalf("session status=%q, want expired after seam advance", s.Status)
			}
		}
	}
	if !found {
		t.Fatal("seam session missing from snapshot")
	}
}
