package lbhuman

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// CC 检测统计：UA 集合必须有界（distinct-UA 洪峰不得无界增长）；
// 触发原因与事件丢弃计数必须经 stats 端点可观测。

func ccTriggerStatsSnapshot(t *testing.T) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/lb/human/stats", nil)
	if err := serveHumanStats(rec, req); err != nil {
		t.Fatalf("serveHumanStats: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	return payload
}

// 目标形状：UA 指纹数超帽后不再存新键，UASetSize 饱和在帽上；
// 会话异常判定仍触发（evalCC 语义不倒退）。
func TestCCRecord_uaSetBoundedAtCap(t *testing.T) {
	key := "ua-cap-rule|203.0.113.210"
	for i := range ccUASetCap + 500 {
		ccRecord(key, 600, false, "ua-"+itoa(i))
	}
	stats := ccPeek(key, 600)
	if stats.UASetSize > ccUASetCap {
		t.Fatalf("UASetSize=%d exceeds cap %d (unbounded distinct-UA growth)", stats.UASetSize, ccUASetCap)
	}
	if stats.UASetSize != ccUASetCap {
		t.Fatalf("UASetSize=%d, want saturated at cap %d", stats.UASetSize, ccUASetCap)
	}
	trig := evalCC(stats, 0, 600, 0, 5, true)
	if !trig.Triggered || trig.Reason != "session_anomaly" {
		t.Fatalf("saturated UA set must still trigger session_anomaly: %+v", trig)
	}
}

// 边界形状：恰好等于帽不丢键（第 cap 个 UA 必须被记录）。
func TestCCRecord_uaSetExactCapKeepsAllKeys(t *testing.T) {
	key := "ua-exact-rule|203.0.113.211"
	for i := range ccUASetCap {
		ccRecord(key, 600, false, "ua-"+itoa(i))
	}
	if got := ccPeek(key, 600).UASetSize; got != ccUASetCap {
		t.Fatalf("UASetSize=%d, want exactly %d distinct keys kept", got, ccUASetCap)
	}
}

// 回归形状：饱和后已知 UA 重复出现仍正常计数（不新增键、不 panic）。
func TestCCRecord_saturatedKnownUAStillCounts(t *testing.T) {
	key := "ua-known-rule|203.0.113.212"
	for i := range ccUASetCap + 10 {
		ccRecord(key, 600, false, "ua-"+itoa(i))
	}
	before := ccPeek(key, 600)
	ccRecord(key, 600, true, "ua-0") // 已知键
	after := ccPeek(key, 600)
	if after.UASetSize != before.UASetSize {
		t.Fatalf("known UA must not grow set: before=%d after=%d", before.UASetSize, after.UASetSize)
	}
	if after.Count != before.Count+1 || after.Status4xx != before.Status4xx+1 {
		t.Fatalf("request/4xx counters must keep counting at saturation: %+v -> %+v", before, after)
	}
}

// 回归形状：窗口过期重置后 UA 集合清空（帽不跨窗口累积）。
func TestCCRecord_windowResetClearsUASet(t *testing.T) {
	key := "ua-reset-rule|203.0.113.213"
	for i := range ccUASetCap + 10 {
		ccRecord(key, 600, false, "ua-"+itoa(i))
	}
	shard := ccShardFor(key)
	shard.mu.Lock()
	shard.m[key].WindowStart -= 601
	shard.mu.Unlock()
	ccRecord(key, 600, false, "fresh-ua")
	if got := ccPeek(key, 600).UASetSize; got != 1 {
		t.Fatalf("window reset must clear UA set: UASetSize=%d, want 1", got)
	}
}

// 触发原因分布：auto 模式 CC 触发必须按原因计数并经 stats 端点下发。
func TestServeHTTP_ccTriggerReasonsReported(t *testing.T) {
	resetLiveSessionsForTest()
	beforeRPS, before4xx, beforeUA := humanCCTriggers.RPSSpike.Load(), humanCCTriggers.Ratio4xx.Load(), humanCCTriggers.SessionAnomaly.Load()
	pass := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	// rps_spike：窗口计数超阈后的下一次请求即挑战。
	h := &HumanHandler{HumanConfig: HumanConfig{
		Mode: "auto", Type: "js", RuleID: "trig-rps", Secret: "test-secret", TTLMinutes: 30,
		CCEnabled: true, CCRPSLimit: 2, CCWindowSec: 600,
	}}
	for i := range 3 {
		req := httptest.NewRequest(http.MethodGet, "/rps", nil)
		req.RemoteAddr = "203.0.113.220:5555"
		if err := h.ServeHTTP(httptest.NewRecorder(), req, pass); err != nil {
			t.Fatalf("rps serve %d: %v", i, err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/rps", nil)
	req.RemoteAddr = "203.0.113.220:5555"
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, pass); err != nil {
		t.Fatalf("rps trigger serve: %v", err)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("rps trigger must serve challenge page, got content-type=%q", rec.Header().Get("Content-Type"))
	}
	if got := humanCCTriggers.RPSSpike.Load() - beforeRPS; got < 1 {
		t.Fatalf("rps_spike trigger counter delta=%d, want >=1", got)
	}

	// 4xx_ratio：25 次请求 20 次 4xx（80% >= 70%），下一次请求触发。
	h4 := &HumanHandler{HumanConfig: HumanConfig{
		Mode: "auto", Type: "js", RuleID: "trig-4xx", Secret: "test-secret", TTLMinutes: 30,
		CCEnabled: true, CCRPSLimit: 100000, CCWindowSec: 600, CC4xxRatio: 70,
	}}
	status4xx := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusNotFound)
		return nil
	})
	for i := range 25 {
		req := httptest.NewRequest(http.MethodGet, "/missing", nil)
		req.RemoteAddr = "203.0.113.221:5555"
		next := pass
		if i < 20 {
			next = status4xx
		}
		if err := h4.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
			t.Fatalf("4xx serve %d: %v", i, err)
		}
	}
	req = httptest.NewRequest(http.MethodGet, "/missing", nil)
	req.RemoteAddr = "203.0.113.221:5555"
	if err := h4.ServeHTTP(httptest.NewRecorder(), req, pass); err != nil {
		t.Fatalf("4xx trigger serve: %v", err)
	}
	if got := humanCCTriggers.Ratio4xx.Load() - before4xx; got < 1 {
		t.Fatalf("4xx_ratio trigger counter delta=%d, want >=1", got)
	}

	// session_anomaly：8 个不同 UA（>5 阈值）+ 请求量>=20。
	hs := &HumanHandler{HumanConfig: HumanConfig{
		Mode: "auto", Type: "js", RuleID: "trig-ua", Secret: "test-secret", TTLMinutes: 30,
		CCEnabled: true, CCRPSLimit: 100000, CCWindowSec: 600, CCSession: true, CCSessionUA: 5,
	}}
	for i := range 25 {
		req := httptest.NewRequest(http.MethodGet, "/ua", nil)
		req.RemoteAddr = "203.0.113.222:5555"
		req.Header.Set("User-Agent", "ua-agent-"+itoa(i%8))
		if err := hs.ServeHTTP(httptest.NewRecorder(), req, pass); err != nil {
			t.Fatalf("session serve %d: %v", i, err)
		}
	}
	req = httptest.NewRequest(http.MethodGet, "/ua", nil)
	req.RemoteAddr = "203.0.113.222:5555"
	req.Header.Set("User-Agent", "ua-agent-0")
	if err := hs.ServeHTTP(httptest.NewRecorder(), req, pass); err != nil {
		t.Fatalf("session trigger serve: %v", err)
	}
	if got := humanCCTriggers.SessionAnomaly.Load() - beforeUA; got < 1 {
		t.Fatalf("session_anomaly trigger counter delta=%d, want >=1", got)
	}

	payload := ccTriggerStatsSnapshot(t)
	triggers, ok := payload["cc_triggers"].(map[string]any)
	if !ok {
		t.Fatalf("stats payload missing cc_triggers breakdown: %v", payload)
	}
	for _, reason := range []string{"rps_spike", "4xx_ratio", "session_anomaly"} {
		v, ok := triggers[reason].(float64)
		if !ok || v < 1 {
			t.Fatalf("cc_triggers[%s]=%v, want >=1 (reason distribution must be observable)", reason, triggers[reason])
		}
	}
}

// 回归形状：force 模式挑战不是 CC 触发，不得产生触发原因计数。
func TestServeHTTP_forceModeNoCCTriggerCount(t *testing.T) {
	beforeRPS, before4xx, beforeUA := humanCCTriggers.RPSSpike.Load(), humanCCTriggers.Ratio4xx.Load(), humanCCTriggers.SessionAnomaly.Load()
	h := &HumanHandler{HumanConfig: HumanConfig{
		Mode: "force", Type: "js", RuleID: "trig-force", Secret: "test-secret", TTLMinutes: 30,
		CCEnabled: true, CCRPSLimit: 1, CCWindowSec: 600,
	}}
	pass := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/force", nil)
	req.RemoteAddr = "203.0.113.223:5555"
	if err := h.ServeHTTP(httptest.NewRecorder(), req, pass); err != nil {
		t.Fatalf("force serve: %v", err)
	}
	if humanCCTriggers.RPSSpike.Load() != beforeRPS ||
		humanCCTriggers.Ratio4xx.Load() != before4xx ||
		humanCCTriggers.SessionAnomaly.Load() != beforeUA {
		t.Fatal("force-mode challenge must not count as CC trigger")
	}
}

// 事件队列饱和丢弃计数必须经 stats 端点可观测（生产静默丢事件的对账源）。
func TestServeHumanStats_reportsDroppedEvents(t *testing.T) {
	before := humanEventDropped.Load()
	humanEventDropped.Add(3)
	defer humanEventDropped.Add(-3)

	payload := ccTriggerStatsSnapshot(t)
	dropped, ok := payload["events_dropped"].(float64)
	if !ok {
		t.Fatalf("stats payload missing events_dropped: %v", payload)
	}
	if int64(dropped) != before+3 {
		t.Fatalf("events_dropped=%v, want %d", dropped, before+3)
	}
}
