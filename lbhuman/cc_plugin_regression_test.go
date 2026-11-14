package lbhuman

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// 受信代理判定缺席时伪造 XFF 不得改变客户端身份；var 在场时用 var 值。
func TestClientIPFrom_ignoresForgedXFF(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		varIP      string
		want       string
	}{
		{"forged xff falls back to remote", "198.51.100.7:4321", "9.9.9.9", "", "198.51.100.7"},
		{"forged xff chain falls back to remote", "198.51.100.7:4321", "9.9.9.9, 10.0.0.1", "", "198.51.100.7"},
		{"trusted var wins over forged xff", "198.51.100.7:4321", "9.9.9.9", "1.2.3.4", "1.2.3.4"},
		{"ipv6 remote host", "[2001:db8::1]:4321", "", "", "2001:db8::1"},
		{"bare remote addr", "203.0.113.5", "", "", "203.0.113.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.varIP != "" {
				ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{})
				caddyhttp.SetVar(ctx, caddyhttp.ClientIPVarKey, tc.varIP)
				r = r.WithContext(ctx)
			}
			if got := clientIPFrom(r); got != tc.want {
				t.Fatalf("clientIPFrom=%q, want %q (xff=%q var=%q)", got, tc.want, tc.xff, tc.varIP)
			}
		})
	}
}

// ServeHTTP 端到端：伪造 XFF 不得顶替 RemoteAddr 身份（挑战上下文）。
func TestServeHTTP_forgedXFFDoesNotChangeClientIdentity(t *testing.T) {
	h := &HumanHandler{HumanConfig: HumanConfig{
		Mode: "force", Type: "js", TTLMinutes: 30, RuleID: "lb-xff", Secret: "test-secret",
	}}
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.RemoteAddr = "198.51.100.7:4321"
	r.Header.Set("X-Forwarded-For", "9.9.9.9")
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, r, next); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want challenge page 200", rec.Code)
	}
	snap := snapshotChallengeSessions("recent")
	found := false
	for _, s := range snap.Sessions {
		if s.RuleID == "lb-xff" {
			found = true
			if s.ClientIP != "198.51.100.7" {
				t.Fatalf("challenge context ip=%q, want RemoteAddr host 198.51.100.7 (forged XFF must be ignored)", s.ClientIP)
			}
		}
	}
	if !found {
		t.Fatal("challenge session missing")
	}
}

// 窗口统计快照不得携带共享 map：并发写（ccRecord）与锁外读（ccPeek+evalCC）
// 必须 -race 干净。
func TestCCStats_concurrentRecordAndPeek(t *testing.T) {
	key := "race-rule|203.0.113.200"
	const goroutines = 8
	const iterations = 300
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(2)
		go func(g int) {
			defer wg.Done()
			for i := range iterations {
				ccRecord(key, 10, false, "ua-"+strconv.Itoa((g*iterations+i)%64))
			}
		}(g)
		go func() {
			defer wg.Done()
			for range iterations {
				stats := ccPeek(key, 10)
				_ = evalCC(stats, 100000, 10, 0, 5, true)
			}
		}()
	}
	wg.Wait()
}

// janitor 必须感知窗口长度：长窗口的活计数器不得被 5 分钟固定 cutoff 误删；
// 短窗口（≤300s）行为不变。
func TestCCJanitor_respectsLongWindow(t *testing.T) {
	longKey := "janitor-long|203.0.113.201"
	shortKey := "janitor-short|203.0.113.202"
	ccRecord(longKey, 3600, false, "ua1")
	ccRecord(shortKey, 10, false, "ua1")
	shard := ccShardFor(longKey)
	shard.mu.Lock()
	shard.m[longKey].WindowStart = time.Now().Unix() - 400
	shard.mu.Unlock()
	shard2 := ccShardFor(shortKey)
	shard2.mu.Lock()
	shard2.m[shortKey].WindowStart = time.Now().Unix() - 300
	shard2.mu.Unlock()

	ccJanitor()

	if got := ccPeek(longKey, 3600); got.Count != 1 {
		t.Fatalf("long-window live counter deleted by janitor: count=%d, want 1", got.Count)
	}
	if got := ccPeek(shortKey, 10); got.Count != 0 {
		t.Fatalf("short-window idle entry must be deleted: count=%d, want 0", got.Count)
	}
}

// 边界：长窗口计数器活到窗口到期（age=WindowSec）即删——保留不是无限期。
func TestCCJanitor_longWindowExpiresAtWindowEnd(t *testing.T) {
	key := "janitor-expire|203.0.113.203"
	ccRecord(key, 3600, false, "ua1")
	shard := ccShardFor(key)
	shard.mu.Lock()
	shard.m[key].WindowStart = time.Now().Unix() - 3600
	shard.mu.Unlock()
	ccJanitor()
	if got := ccPeek(key, 3600); got.Count != 0 {
		t.Fatalf("expired long-window counter must be deleted: count=%d, want 0", got.Count)
	}
}

// 过期拼图提交必须 retryable=false（客户端换新图），不得按活拼图计次重试。
func TestServeSliderVerify_expiredPuzzleNotRetryable(t *testing.T) {
	resetLiveSessionsForTest()
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-expired", Secret: "test-secret", TTLMinutes: 30}}
	pid := issueSliderPuzzle(t, h)
	sliderPuzzlesMu.Lock()
	sliderPuzzles[pid].createdAt = time.Now().Add(-sliderPuzzleTTL - time.Minute)
	gapX := sliderPuzzles[pid].gapX
	sliderPuzzlesMu.Unlock()

	rec := postSliderVerify(t, h, pid, gapX)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expired puzzle status=%d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"retryable":false`) {
		t.Fatalf("expired puzzle must be retryable=false, body=%s", rec.Body.String())
	}
	sliderPuzzlesMu.Lock()
	_, still := sliderPuzzles[pid]
	sliderPuzzlesMu.Unlock()
	if still {
		t.Fatal("expired puzzle must be deleted on submission")
	}
}

// 匿名校验端点请求体硬上限：超大 body 必须 400，不得全量读入。
func TestServeSliderVerify_oversizedBodyRejected(t *testing.T) {
	resetLiveSessionsForTest()
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-body", Secret: "test-secret", TTLMinutes: 30}}
	pid := issueSliderPuzzle(t, h)
	// track 全为 1（非匀速性缺失）：旧实现即使读完超大 body 也必失败 400，
	// 但 puzzle_id 位于 body 前部已被解析——断言拼图未被计次证明 body 被拒。
	body := "puzzle_id=" + pid + "&x=1&track=" + strings.Repeat("1,", 40000) + "&duration_ms=700"
	req := httptest.NewRequest(http.MethodPost, humanSliderVerifyPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.serveSliderVerify(rec, req, "203.0.113.80")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body status=%d, want 400", rec.Code)
	}
	sliderPuzzlesMu.Lock()
	attempts := sliderPuzzles[pid].attempts
	sliderPuzzlesMu.Unlock()
	if attempts != 0 {
		t.Fatalf("oversized body must be rejected before puzzle consumption, attempts=%d", attempts)
	}
}

// 代理 TLS 终止（r.TLS=nil + XFP=https）：通过 cookie 必须带 Secure。
func TestVerifyCookie_secureBehindTLSProxy(t *testing.T) {
	resetLiveSessionsForTest()
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-xfp", Secret: "test-secret", TTLMinutes: 30}}
	pid := issueSliderPuzzle(t, h)
	sliderPuzzlesMu.Lock()
	gapX := sliderPuzzles[pid].gapX
	sliderPuzzlesMu.Unlock()
	body := "puzzle_id=" + pid + "&x=" + strconv.Itoa(gapX) + "&track=" + sliderTestTrack() + "&duration_ms=700"
	req := httptest.NewRequest(http.MethodPost, humanSliderVerifyPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	h.serveSliderVerify(rec, req, "203.0.113.80")
	if rec.Code != http.StatusOK {
		t.Fatalf("slider verify status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "; Secure") {
		t.Fatalf("Set-Cookie missing Secure behind TLS-terminating proxy: %s", rec.Header().Get("Set-Cookie"))
	}

	// JS 路径同病同修。
	h2 := &HumanHandler{HumanConfig: HumanConfig{Type: "js", RuleID: "lb-xfp-js", Secret: "test-secret", TTLMinutes: 30}}
	rec2 := httptest.NewRecorder()
	h2.serveJSChallenge(rec2, httptest.NewRequest(http.MethodGet, "/js", nil), "203.0.113.95")
	m := regexp.MustCompile(`var token ?= ?"([0-9a-f]+)"`).FindStringSubmatch(rec2.Body.String())
	if len(m) != 2 {
		t.Fatalf("JS challenge page missing token: %s", rec2.Body.String()[:min(300, rec2.Body.Len())])
	}
	token := m[1]
	nonce := findPoWNonce(t, token)
	vbody := "token=" + token + "&nonce=" + nonce
	vreq := httptest.NewRequest(http.MethodPost, humanVerifyPath, strings.NewReader(vbody))
	vreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vreq.Header.Set("X-Forwarded-Proto", "https")
	vrec := httptest.NewRecorder()
	h2.serveJSVerify(vrec, vreq, "203.0.113.95")
	if vrec.Code != http.StatusOK {
		t.Fatalf("js verify status=%d body=%s", vrec.Code, vrec.Body.String())
	}
	if !strings.Contains(vrec.Header().Get("Set-Cookie"), "; Secure") {
		t.Fatalf("JS Set-Cookie missing Secure behind TLS-terminating proxy: %s", vrec.Header().Get("Set-Cookie"))
	}
}

func findPoWNonce(t *testing.T, token string) string {
	t.Helper()
	for i := range 2000000 {
		candidate := strconv.Itoa(i)
		if powValid(token, candidate) {
			return candidate
		}
	}
	t.Fatal("no valid PoW nonce found")
	return ""
}

// 材料表硬上限：超量发放后表大小不得越界，最旧条目被淘汰（新材料仍可消费）。
func TestChallengeTokenTable_hardCap(t *testing.T) {
	resetLiveSessionsForTest()
	first := issueChallengeToken()
	for range challengeMaterialCap + 100 {
		issueChallengeToken()
	}
	challengeTokensMu.Lock()
	n := len(challengeTokens)
	challengeTokensMu.Unlock()
	if n > challengeMaterialCap {
		t.Fatalf("challenge tokens=%d exceed hard cap %d", n, challengeMaterialCap)
	}
	if consumeChallengeToken(first) {
		t.Fatal("oldest token must be evicted when table is over cap")
	}
	fresh := issueChallengeToken()
	if !consumeChallengeToken(fresh) {
		t.Fatal("fresh token must remain consumable")
	}
}

func TestSliderPuzzleTable_hardCap(t *testing.T) {
	resetLiveSessionsForTest()
	first := newSliderPuzzle()
	for range challengeMaterialCap + 100 {
		newSliderPuzzle()
	}
	sliderPuzzlesMu.Lock()
	n := len(sliderPuzzles)
	sliderPuzzlesMu.Unlock()
	if n > challengeMaterialCap {
		t.Fatalf("slider puzzles=%d exceed hard cap %d", n, challengeMaterialCap)
	}
	if consumeSliderPuzzle(first.id) != nil {
		t.Fatal("oldest puzzle must be evicted when table is over cap")
	}
	fresh := newSliderPuzzle()
	if consumeSliderPuzzle(fresh.id) == nil {
		t.Fatal("fresh puzzle must remain consumable")
	}
}

// 边界：恰好等于上限不触发淘汰（首个 token 仍可消费）。
func TestChallengeTokenTable_exactCapKeepsOldest(t *testing.T) {
	resetLiveSessionsForTest()
	first := issueChallengeToken()
	for range challengeMaterialCap - 1 {
		issueChallengeToken()
	}
	challengeTokensMu.Lock()
	n := len(challengeTokens)
	challengeTokensMu.Unlock()
	if n != challengeMaterialCap {
		t.Fatalf("tokens=%d, want exactly cap %d", n, challengeMaterialCap)
	}
	if !consumeChallengeToken(first) {
		t.Fatal("at exact cap the oldest token must not be evicted")
	}
}

// track 点数帽：超限点数必须 400（不得无界 Split 后静默丢弃）。
func TestServeSliderVerify_trackPointCap(t *testing.T) {
	resetLiveSessionsForTest()
	h := &HumanHandler{HumanConfig: HumanConfig{Type: "slider", RuleID: "lb-track", Secret: "test-secret", TTLMinutes: 30}}
	pid := issueSliderPuzzle(t, h)
	track := strings.Repeat("1,", sliderTrackMaxPoints+1)
	body := "puzzle_id=" + pid + "&x=1&track=" + track + "&duration_ms=700"
	req := httptest.NewRequest(http.MethodPost, humanSliderVerifyPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.serveSliderVerify(rec, req, "203.0.113.80")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("over-cap track status=%d, want 400", rec.Code)
	}
	sliderPuzzlesMu.Lock()
	attempts := sliderPuzzles[pid].attempts
	sliderPuzzlesMu.Unlock()
	if attempts != 0 {
		t.Fatalf("over-cap track must be rejected before puzzle consumption, attempts=%d", attempts)
	}
}

// 事件上报改缓冲 channel+单 worker：超容量丢弃有计数、不阻塞请求路径；
// worker 把队列内事件全部送达（失败静默语义不变）。
func TestHumanEventDelivery_boundedQueueDrains(t *testing.T) {
	received := make(chan struct{}, 4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// 注入投递地址到既有 poster（worker 持有同一实例；不得替换全局指针——
	// 常驻 worker 会并发读它）。测试结束还原 UDS 默认配置。
	poster.initClientWithURL(srv.URL)
	defer func() {
		poster.mu.Lock()
		poster.client = nil
		poster.url = ""
		poster.mu.Unlock()
	}()

	// 隔离全局计数器与队列残留：shuffle 顺序下前序测试可能留下 dropped 计数
	// 或队列事件，绝对值守恒（got+dropped==total）须从 clean 态起算。
	humanEventDropped.Store(0)
	for pending := true; pending; {
		select {
		case <-humanEventQueue:
		default:
			pending = false
		}
	}

	const total = 200
	for range total {
		reportHumanEvent("lb-evt", "203.0.113.9", http.MethodGet, "/", "ua", "challenge")
	}
	// 宽限 30s：并行测试负载下 200 次本地投递可能远超常态耗时，
	// 等待语义以排空探针为准而非固定短截止。
	drained := drainHumanEventsForTest(30 * time.Second)
	got := 0
loop:
	for {
		select {
		case <-received:
			got++
		default:
			break loop
		}
	}
	dropped := humanEventDropped.Load()
	if got+int(dropped) != total {
		t.Fatalf("delivered=%d dropped=%d, want sum %d (no silent loss without counter)", got, dropped, total)
	}
	if got == 0 {
		t.Fatal("worker must deliver queued events")
	}
	if !drained {
		t.Fatal("queue must drain within deadline")
	}
}

// statusCapture 不得断开 ResponseController 的 Unwrap 链：
// 底层支持 Hijack 时，包装后的 Hijack 必须可用（全站 WS 依赖）。
func TestStatusCapture_unwrapPreservesHijack(t *testing.T) {
	base := &hijackableRecorder{ResponseWriter: httptest.NewRecorder()}
	w := &statusCapture{ResponseWriter: base}
	_, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		t.Fatalf("ResponseController.Hijack through statusCapture: %v (Unwrap chain broken)", err)
	}
}

type hijackableRecorder struct {
	http.ResponseWriter
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}
