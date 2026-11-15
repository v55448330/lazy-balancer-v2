package lbhuman

// CC 触发原因透传钉：会话异常等 CC 触发的挑战发放事件必须携带触发原因
// （自动封禁条目备注「会话异常」归因数据源）。暂存-消费形态：触发点按
// ruleID|IP 暂存原因，reportHumanEvent 发放事件入队时消费（一次性），
// 非 CC 触发（force/滑块/JS 直发）不带原因。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Given CC 触发点暂存 session_anomaly 原因。
// When 同 ruleID|IP 发放挑战事件上报。
// Then 投递 payload 携带 reason=session_anomaly（一次性消费）。
func TestHumanEventDelivery_ccTriggerReasonCarried(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	resetHumanEventPosterForTest(t, srv.URL)

	stashCCTriggerReason("lb-cc", "203.0.113.90", "session_anomaly")
	reportHumanEvent("lb-cc", "203.0.113.90", http.MethodGet, "/", "ua", "challenge")
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain")
	}
	if len(got) != 1 || got[0]["reason"] != "session_anomaly" {
		t.Fatalf("payload=%v, want reason=session_anomaly", got)
	}
}

// Given 暂存原因已被消费。
// When 同 ruleID|IP 再次上报（无新触发）。
// Then 不带 reason（一次性消费，不滞留）。
func TestHumanEventDelivery_ccTriggerReasonConsumedOnce(t *testing.T) {
	var batches [][]map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var batch []map[string]any
		_ = json.Unmarshal(raw, &batch)
		batches = append(batches, batch)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	resetHumanEventPosterForTest(t, srv.URL)

	stashCCTriggerReason("lb-cc2", "203.0.113.91", "rps_spike")
	reportHumanEvent("lb-cc2", "203.0.113.91", http.MethodGet, "/", "ua", "challenge")
	reportHumanEvent("lb-cc2", "203.0.113.91", http.MethodGet, "/", "ua", "challenge")
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain")
	}
	if len(batches) != 2 {
		t.Fatalf("batches=%d, want 2", len(batches))
	}
	if batches[0][0]["reason"] != "rps_spike" {
		t.Fatalf("首批=%v, want reason=rps_spike", batches[0])
	}
	if _, has := batches[1][0]["reason"]; has {
		t.Fatalf("第二批不得携带已消费原因: %v", batches[1])
	}
}

// Given 无 CC 触发暂存（force 模式直发）。
// When 上报挑战事件。
// Then payload 不含 reason 键（非 CC 触发不污染归因）。
func TestHumanEventDelivery_noStashNoReason(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	resetHumanEventPosterForTest(t, srv.URL)

	reportHumanEvent("lb-force", "203.0.113.92", http.MethodGet, "/", "ua", "challenge")
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain")
	}
	if _, has := got[0]["reason"]; has {
		t.Fatalf("非 CC 触发不得携带 reason: %v", got)
	}
}
