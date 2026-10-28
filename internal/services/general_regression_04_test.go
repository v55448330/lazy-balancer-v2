package services

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 上游健康聚合必须有整体 deadline（而不是每路独立的 3×client 超时，合计 90s）。
func TestGetUpstreamHealthDetailed_AggregateDeadline(t *testing.T) {
	saved := upstreamHealthAggregateTimeout
	upstreamHealthAggregateTimeout = 120 * time.Millisecond
	t.Cleanup(func() { upstreamHealthAggregateTimeout = saved })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)

	service := NewCaddyService(server.URL)
	started := time.Now()
	_, err := service.GetUpstreamHealthDetailed()
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("三路读取整体超时后应返回错误（config 读取不可判定）")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("健康聚合耗时 %s，want 受整体 deadline 约束", elapsed)
	}
}

func TestLogStateTransition_GenericKeys(t *testing.T) {
	metricsStateMu.Lock()
	saved := metricsStateFailed
	metricsStateFailed = map[string]bool{}
	metricsStateMu.Unlock()
	t.Cleanup(func() {
		metricsStateMu.Lock()
		metricsStateFailed = saved
		metricsStateMu.Unlock()
	})

	if lvl := logStateTransition("timezone-refresh", true); lvl != "warn" {
		t.Fatalf("首次失败 lvl=%q, want warn", lvl)
	}
	if lvl := logStateTransition("timezone-refresh", true); lvl != "" {
		t.Fatalf("持续失败 lvl=%q, want 静默", lvl)
	}
	// 不同子系统键空间独立。
	if lvl := logStateTransition("runtime-log-size-refresh", true); lvl != "warn" {
		t.Fatalf("独立键首次失败 lvl=%q, want warn", lvl)
	}
	if lvl := logStateTransition("timezone-refresh", false); lvl != "info" {
		t.Fatalf("恢复 lvl=%q, want info", lvl)
	}
	if lvl := logStateTransition("timezone-refresh", false); lvl != "" {
		t.Fatalf("持续成功 lvl=%q, want 静默", lvl)
	}
}
