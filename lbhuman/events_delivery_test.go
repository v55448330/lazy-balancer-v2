package lbhuman

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// resetHumanEventPosterForTest 注入投递地址并隔离计数器/队列残留（测试结束
// 还原 UDS 默认配置；不得替换全局 poster 指针——常驻 worker 并发读它）。
func resetHumanEventPosterForTest(t *testing.T, rawURL string) {
	t.Helper()
	// 先排空既有队列（前序测试的残留事件不得打进本测试的端点/计数），
	// 再注入地址与清零计数——绝对值断言从 clean 态起算。
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("event queue must drain before test start")
	}
	poster.initClientWithURL(rawURL)
	humanEventDropped.Store(0)
	humanEventDeliverFailed.Store(0)
	t.Cleanup(func() {
		// 先排空再还原配置：在途投递若落在还原之后会拿 nil client 计失败，
		// 污染后续测试的绝对值断言。
		if !drainHumanEventsForTest(10 * time.Second) {
			t.Error("event queue must drain before poster restore")
		}
		poster.mu.Lock()
		poster.client = nil
		poster.url = ""
		poster.mu.Unlock()
	})
}

// 投递失败必须计数并经 stats 端点可观测：真实连接拒绝（监听已关闭）不得
// 静默蒸发——面板重启/DB busy 窗口的挑战事件丢失量是对账源。
func TestHumanEventDelivery_failureCountedAndObservable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	url := srv.URL
	srv.Close() // 真实失败机制：端口不再监听 → 连接拒绝
	resetHumanEventPosterForTest(t, url)

	reportHumanEvent("lb-fail", "203.0.113.60", http.MethodGet, "/", "challenge")
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain")
	}
	if got := humanEventDeliverFailed.Load(); got != 1 {
		t.Fatalf("deliver_failed=%d, want 1 (connection refusal must be counted)", got)
	}
	// 终态断言：stats 端点下发该计数（不是只看内部计数器）。
	payload := ccTriggerStatsSnapshot(t)
	v, ok := payload["events_deliver_failed"].(float64)
	if !ok || v != 1 {
		t.Fatalf("stats events_deliver_failed=%v, want 1 (payload=%v)", v, payload)
	}
}

// 非 204 应答=入库未完成（跨进程契约：204=DB commit 完成）：503 必须计失败。
func TestHumanEventDelivery_non204CountedAsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	resetHumanEventPosterForTest(t, srv.URL)

	reportHumanEvent("lb-503", "203.0.113.61", http.MethodGet, "/", "fail")
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain")
	}
	if got := humanEventDeliverFailed.Load(); got != 1 {
		t.Fatalf("deliver_failed=%d, want 1 (503 must count as delivery failure)", got)
	}
}

// 回归形状：204 成功投递不计失败（计数不膨胀）。
func TestHumanEventDelivery_successNotCounted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	resetHumanEventPosterForTest(t, srv.URL)

	reportHumanEvent("lb-ok", "203.0.113.62", http.MethodGet, "/", "pass")
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain")
	}
	if got := humanEventDeliverFailed.Load(); got != 0 {
		t.Fatalf("deliver_failed=%d, want 0 on successful delivery", got)
	}
}

// 事件 ts 必须是发生（入队）时刻而非投递时刻：队列积压/投递阻塞时
// security_events 时间戳不得系统性漂移到未来。
func TestHumanEvent_tsIsEnqueueTimeNotDeliveryTime(t *testing.T) {
	var mu sync.Mutex
	var timestamps []int64
	gate := make(chan struct{})
	started := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var rows []map[string]any
		_ = json.Unmarshal(raw, &rows)
		mu.Lock()
		for _, row := range rows {
			if ts, ok := row["ts"].(float64); ok {
				timestamps = append(timestamps, int64(ts))
			}
		}
		mu.Unlock()
		if len(timestamps) == 1 {
			started <- struct{}{}
			<-gate // 阻塞首条投递，制造积压窗口
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	resetHumanEventPosterForTest(t, srv.URL)

	// 首条占住 worker；第二条在已知时刻入队。
	reportHumanEvent("lb-ts", "203.0.113.63", http.MethodGet, "/first", "challenge")
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("first event must reach the server")
	}
	enqueueBefore := time.Now().UnixMilli()
	reportHumanEvent("lb-ts", "203.0.113.63", http.MethodGet, "/second", "challenge")
	enqueueAfter := time.Now().UnixMilli()

	time.Sleep(150 * time.Millisecond) // 投递时刻必然晚于入队窗口
	close(gate)
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain")
	}
	// 退出前等待两条投递全部落地（探针只保证 worker 处理完，handler 收尾
	// 可能仍在途）——残留投递会污染后续测试的全局 poster 状态。
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := len(timestamps)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(timestamps) != 2 {
		t.Fatalf("delivered timestamps=%d, want 2", len(timestamps))
	}
	second := timestamps[1]
	if second < enqueueBefore || second > enqueueAfter {
		t.Fatalf("second event ts=%d outside enqueue window [%d,%d] (ts must be occurrence time, not delivery time)", second, enqueueBefore, enqueueAfter)
	}
}

// panic 隔离必须计数：deliver 内部 panic（真实故障机制——注入的 Transport
// RoundTrip panic，模拟序列化/网络栈异常）被 recover 吞掉时，丢失量必须
// 经 events_deliver_failed 可对账（旧实现 recover 分支零计数，监控盲区）。
// worker 不得因 panic 退出：后续事件照常投递。
type panicRoundTripper struct{}

func (panicRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	panic("injected transport panic")
}

func TestHumanEventDelivery_panicCountedAndWorkerSurvives(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	resetHumanEventPosterForTest(t, srv.URL)
	// 真实 panic 注入：替换 client.Transport（RoundTrip panic 经 client.Post
	// 传导到 deliver 的 recover 分支）。
	poster.mu.Lock()
	poster.client = &http.Client{Timeout: 2 * time.Second, Transport: panicRoundTripper{}}
	poster.mu.Unlock()

	reportHumanEvent("lb-panic", "203.0.113.64", http.MethodGet, "/", "challenge")
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain (worker must survive the panic)")
	}
	if got := humanEventDeliverFailed.Load(); got != 1 {
		t.Fatalf("deliver_failed=%d, want 1 (panic must be counted as delivery failure)", got)
	}
	// 终态断言：stats 端点下发该计数。
	payload := ccTriggerStatsSnapshot(t)
	if v, ok := payload["events_deliver_failed"].(float64); !ok || v != 1 {
		t.Fatalf("stats events_deliver_failed=%v, want 1 (payload=%v)", v, payload)
	}

	// worker 存活：恢复 transport 后下一条事件照常投递成功（不再计失败）。
	poster.mu.Lock()
	poster.client = &http.Client{Timeout: 2 * time.Second}
	poster.mu.Unlock()
	reportHumanEvent("lb-after-panic", "203.0.113.65", http.MethodGet, "/", "pass")
	if !drainHumanEventsForTest(10 * time.Second) {
		t.Fatal("queue must drain after recovery")
	}
	if got := humanEventDeliverFailed.Load(); got != 1 {
		t.Fatalf("deliver_failed=%d, want 1 (recovered delivery must not add failures)", got)
	}
}
