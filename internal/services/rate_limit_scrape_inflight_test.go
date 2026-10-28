package services

// 限流指标抓取的单飞在途清理必须 panic 安全：抓取/解析 panic 时 inflight 条目
// 不得残留（否则同 URL 的后续调用永久阻塞在 <-call.done = 限流卡片钉死到进程
// 重启）。panic 照常向上传播，等待方收到 error 而非挂死。

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func metricsOKResponse() *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(strings.NewReader("")),
	}
}

func TestScrapeRateLimitBlocks_panicClearsInflightForWaiters(t *testing.T) {
	resetOverviewMetricsCacheForTest()
	oldClient := overviewMetricsHTTPClient
	t.Cleanup(func() {
		overviewMetricsHTTPClient = oldClient
		resetOverviewMetricsCacheForTest()
	})

	const metricsURL = "http://metrics.example/metrics"
	roundTripStarted := make(chan struct{})
	allowPanic := make(chan struct{})
	var startOnce sync.Once
	overviewMetricsHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		startOnce.Do(func() { close(roundTripStarted) })
		<-allowPanic
		panic("injected scrape panic")
	})}

	// Given 首个调用在抓取中 panic，第二个调用挂在同一 URL 的单飞等待上。
	panicResult := make(chan any, 1)
	go func() {
		defer func() { panicResult <- recover() }()
		_, _ = ScrapeRateLimitBlocks(metricsURL)
	}()
	waitForSignal(t, roundTripStarted, "抓取未开始")

	waiterEntered := make(chan struct{})
	var waiterOnce sync.Once
	oldHook := overviewMetricsWaiterHook
	overviewMetricsWaiterHook = func() { waiterOnce.Do(func() { close(waiterEntered) }) }
	t.Cleanup(func() { overviewMetricsWaiterHook = oldHook })

	waiterResult := make(chan error, 1)
	go func() {
		// 等待方若因单飞失效而自行抓取，注入 panic 会让整个测试二进制崩溃；
		// 捕获后转成失败信息（同包其他用例得以保留）。
		defer func() {
			if r := recover(); r != nil {
				waiterResult <- fmt.Errorf("waiter panicked（单飞未覆盖等待方）: %v", r)
			}
		}()
		_, err := ScrapeRateLimitBlocks(metricsURL)
		waiterResult <- err
	}()
	waitForSignal(t, waiterEntered, "等待方未进入单飞等待（单飞机制失效）")

	// When 抓取 panic 向上传播。
	close(allowPanic)

	// Then panic 未被吞掉，等待方收到 error（不挂死）。
	select {
	case recovered := <-panicResult:
		if recovered == nil {
			t.Fatal("抓取 panic 被吞掉，必须向上传播")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("panic 路径未在超时内返回")
	}
	select {
	case err := <-waiterResult:
		if err == nil || !strings.Contains(err.Error(), "panic") {
			t.Fatalf("等待方 err=%v, want panic 转递的 error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("等待方永久阻塞（inflight 未清理）")
	}

	// Then 后续调用可正常执行（inflight 已清空、失败结果未缓存）。
	overviewMetricsHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return metricsOKResponse(), nil
	})}
	done := make(chan error, 1)
	go func() {
		_, err := ScrapeRateLimitBlocks(metricsURL)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("panic 后重试 err=%v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("panic 后重试永久阻塞（inflight 残留）")
	}
}

func waitForSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal(message)
	}
}

// 重载（/load 成功）会作废限流抓取缓存：计数据自最近一次重载以来累计，缓存
// 不感知就会在窗口内继续展示重载前的累计值。作废时若仍有在途抓取，它抓到的是
// 重载前 registry 的计数——完成时不得回填到作废后的缓存（否则下一次请求直接
// 命中旧计数，作废形同无效）。
func TestScrapeRateLimitBlocks_staleInflightDoesNotRepopulateCache(t *testing.T) {
	resetOverviewMetricsCacheForTest()
	oldClient := overviewMetricsHTTPClient
	t.Cleanup(func() {
		overviewMetricsHTTPClient = oldClient
		resetOverviewMetricsCacheForTest()
	})

	const metricsURL = "http://metrics.example/metrics"
	var hits atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	var startOnce sync.Once
	overviewMetricsHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		hits.Add(1)
		startOnce.Do(func() { close(entered) })
		<-release
		return metricsOKResponse(), nil
	})}

	// Given 一次抓取在途（尚未返回）。
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, _ = ScrapeRateLimitBlocks(metricsURL)
	}()
	waitForSignal(t, entered, "抓取未开始")

	// When 重载窗口内缓存被作废，随后在途抓取才返回。
	InvalidateOverviewMetricsCache()
	close(release)
	<-firstDone

	// Then 下一次调用必须重新抓取（在途旧结果不得回填作废后的缓存）。
	if _, err := ScrapeRateLimitBlocks(metricsURL); err != nil {
		t.Fatalf("作废后重抓 err=%v, want nil", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("抓取次数=%d, want 2（在途旧结果回填了作废后的缓存，作废形同无效）", got)
	}
}
