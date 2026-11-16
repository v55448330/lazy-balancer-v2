package lbhuman

// CC 触发原因仅发放族事件消费：pass/fail 是验证流程事件，跨 kind 并发
// 同键不得窃取待发放挑战的原因；rate_reject 消费但不携带（blocked 口径
// 不做挑战归因，且即消防止滞留污染后续挑战归因）。
// 另钉 socket env 契约（与 caddygeoip/caddyl4sec 同口径）：未设置=默认
// socket；显式空串/纯空白=关闭上报（不建客户端、不拨号）。

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Given CC 触发点暂存原因。
// When 同键验证失败事件先上报（并发验证流程），随后挑战发放上报。
// Then fail 不携带原因，且原因保留给挑战发放（不被跨 kind 窃取）。
func TestCCTriggerReason_failDoesNotSteal(t *testing.T) {
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

	stashCCTriggerReason("lb-kind-fail", "203.0.113.93", "session_anomaly")
	reportHumanEvent("lb-kind-fail", "203.0.113.93", http.MethodGet, "/", "fail")
	reportHumanEvent("lb-kind-fail", "203.0.113.93", http.MethodGet, "/", "challenge")
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain")
	}
	if len(batches) != 2 {
		t.Fatalf("batches=%d, want 2", len(batches))
	}
	if _, has := batches[0][0]["reason"]; has {
		t.Fatalf("fail 事件不得携带 CC 触发原因: %v", batches[0])
	}
	if batches[1][0]["reason"] != "session_anomaly" {
		t.Fatalf("挑战发放必须拿到保留的原因（不被 fail 窃取）: %v", batches[1])
	}
}

// Given CC 触发点暂存原因。
// When 同键验证通过事件先上报，随后挑战发放上报。
// Then pass 不携带原因，且原因保留给挑战发放。
func TestCCTriggerReason_passDoesNotSteal(t *testing.T) {
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

	stashCCTriggerReason("lb-kind-pass", "203.0.113.94", "rps_spike")
	reportHumanEvent("lb-kind-pass", "203.0.113.94", http.MethodGet, "/", "pass")
	reportHumanEvent("lb-kind-pass", "203.0.113.94", http.MethodGet, "/", "challenge")
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain")
	}
	if len(batches) != 2 {
		t.Fatalf("batches=%d, want 2", len(batches))
	}
	if _, has := batches[0][0]["reason"]; has {
		t.Fatalf("pass 事件不得携带 CC 触发原因: %v", batches[0])
	}
	if batches[1][0]["reason"] != "rps_spike" {
		t.Fatalf("挑战发放必须拿到保留的原因（不被 pass 窃取）: %v", batches[1])
	}
}

// Given CC 触发点暂存原因（action=reject 形态）。
// When rate_reject 上报，随后同键挑战上报。
// Then rate_reject 不携带原因（blocked 口径），且原因已被即消——
// 后续挑战不携带滞留原因（不污染归因）。
func TestCCTriggerReason_rateRejectConsumesWithoutCarrying(t *testing.T) {
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

	stashCCTriggerReason("lb-kind-reject", "203.0.113.95", "4xx_ratio")
	reportHumanEvent("lb-kind-reject", "203.0.113.95", http.MethodGet, "/", "rate_reject")
	reportHumanEvent("lb-kind-reject", "203.0.113.95", http.MethodGet, "/", "challenge")
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain")
	}
	if len(batches) != 2 {
		t.Fatalf("batches=%d, want 2", len(batches))
	}
	if _, has := batches[0][0]["reason"]; has {
		t.Fatalf("rate_reject 属 blocked 口径，不得携带挑战归因原因: %v", batches[0])
	}
	if _, has := batches[1][0]["reason"]; has {
		t.Fatalf("rate_reject 必须即消暂存原因，后续挑战不得携带滞留原因: %v", batches[1])
	}
}

// socket env 解析四形态：未设置=容器默认 socket；显式空串/纯空白=关闭；
// 有效值 TrimSpace 后拨号（不得拨向带空白的原值或回落默认）。
func TestHumanEventSocket_envResolution(t *testing.T) {
	cases := []struct {
		name string
		set  bool
		val  string
		want string // 期望 socket（""=关闭，client 必须为 nil）
	}{
		{"unset_default", false, "", "/app/data/security-events.sock"},
		{"explicit_empty_disables", true, "", ""},
		{"whitespace_disables", true, " \t ", ""},
		{"value_trimmed", true, "  /tmp/lb-events.sock  ", "/tmp/lb-events.sock"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(humanEventSocketEnv, tc.val)
			} else {
				os.Unsetenv(humanEventSocketEnv)
			}
			p := &humanEventPoster{}
			p.initClient()
			if tc.want == "" {
				if p.client != nil {
					t.Fatalf("显式空串/空白=关闭：不得建立客户端, client=%v", p.client)
				}
				return
			}
			if p.client == nil {
				t.Fatal("未设置/有效值必须建立客户端")
			}
			// 真实拨号观测：目标无监听，dial 错误必须命中解析出的 socket 路径。
			_, err := p.client.Transport.(*http.Transport).DialContext(context.Background(), "unix", "unix")
			if err == nil {
				t.Fatalf("目标 socket 无监听，dial 必须失败: %s", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("dial 目标=%v, want 包含 %q（TrimSpace 后的解析值）", err, tc.want)
			}
			if tc.val != "" && tc.val != tc.want && strings.Contains(err.Error(), tc.val) {
				t.Fatalf("dial 目标含未 trim 原值 %q（必须 TrimSpace 后拨号）: %v", tc.val, err)
			}
		})
	}
}

// Given env 显式空串（关闭上报）。
// When 事件入队并被 worker 处理。
// Then 不拨号不投递，不计投递失败（关闭≠故障），worker 不阻塞。
func TestHumanEventDelivery_disabledEnvSkipsDial(t *testing.T) {
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain before test start")
	}
	poster.mu.Lock()
	poster.client = nil
	poster.url = ""
	poster.mu.Unlock()
	t.Cleanup(func() {
		if !drainHumanEventsForTest(10 * time.Second) {
			t.Error("event queue must drain before poster restore")
		}
		poster.mu.Lock()
		poster.client = nil
		poster.url = ""
		poster.disabled = false
		poster.mu.Unlock()
	})
	t.Setenv(humanEventSocketEnv, "")
	humanEventDeliverFailed.Store(0)

	reportHumanEvent("lb-disabled", "203.0.113.96", http.MethodGet, "/", "challenge")
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain (disabled skip must not block worker)")
	}
	if got := humanEventDeliverFailed.Load(); got != 0 {
		t.Fatalf("关闭≠投递失败: deliver_failed=%d, want 0", got)
	}
}

// Given env 指向真实 UDS 监听（带前后空白，必须 TrimSpace）。
// When 事件入队并被 worker 处理。
// Then 经解析 socket 真实投递成功（204），零失败计数。
func TestHumanEventDelivery_envSocketDialsTrimmedPath(t *testing.T) {
	// UDS 路径受 sun_path 104 字节限制（macOS）：t.TempDir 前缀过长，用短目录。
	sockDir, err := os.MkdirTemp("/tmp", "lbh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "e.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	received := make(chan []map[string]any, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var batch []map[string]any
		_ = json.Unmarshal(raw, &batch)
		w.WriteHeader(http.StatusNoContent)
		select {
		case received <- batch:
		default:
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()

	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain before test start")
	}
	poster.mu.Lock()
	poster.client = nil
	poster.url = ""
	poster.mu.Unlock()
	t.Cleanup(func() {
		if !drainHumanEventsForTest(10 * time.Second) {
			t.Error("event queue must drain before poster restore")
		}
		poster.mu.Lock()
		poster.client = nil
		poster.url = ""
		poster.disabled = false
		poster.mu.Unlock()
	})
	t.Setenv(humanEventSocketEnv, "  "+sockPath+"  ")
	humanEventDeliverFailed.Store(0)

	reportHumanEvent("lb-uds", "203.0.113.97", http.MethodGet, "/", "challenge")
	// 排空探针只证明 worker 处理完毕；handler 写入经 channel 交接，
	// 避免与 Serve goroutine 的数据竞争。
	var got []map[string]any
	select {
	case got = <-received:
	case <-time.After(10 * time.Second):
		t.Fatal("UDS 端点未收到投递")
	}
	if len(got) != 1 || got[0]["rule_id"] != "lb-uds" {
		t.Fatalf("UDS 投递 payload=%v, want rule_id=lb-uds", got)
	}
	if n := humanEventDeliverFailed.Load(); n != 0 {
		t.Fatalf("deliver_failed=%d, want 0", n)
	}
}
