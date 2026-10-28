package handlers

// 系统指标的采样/命令执行契约：
//   - CPU% 与实时流量按固定窗口差分（窗口内多客户端/多页签共享同一次采样与
//     同一速率），不再以「上一次 HTTP 请求」为基线互相污染；
//   - df/netstat 外部命令带超时（宿主卡住时读路径不得无限阻塞），并发刷新合并；
//   - 分项失败只降级该项，HTTP 层 200 + degraded 披露。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

func resetDiskUsageCacheForTest(t *testing.T) {
	t.Helper()
	diskUsageCache.Lock()
	diskUsageCache.total, diskUsageCache.used, diskUsageCache.expiresAt = 0, 0, time.Time{}
	diskUsageCache.negativeUntil, diskUsageCache.negativeErr = time.Time{}, nil
	diskUsageCache.Unlock()
	t.Cleanup(func() {
		diskUsageCache.Lock()
		diskUsageCache.total, diskUsageCache.used, diskUsageCache.expiresAt = 0, 0, time.Time{}
		diskUsageCache.negativeUntil, diskUsageCache.negativeErr = time.Time{}, nil
		diskUsageCache.Unlock()
	})
}

func resetConnectionStatsCacheForTest(t *testing.T) {
	t.Helper()
	connectionStatsCache.Lock()
	connectionStatsCache.stats = models.ConnectionStats{}
	connectionStatsCache.expiresAt = time.Time{}
	connectionStatsCache.negativeUntil, connectionStatsCache.negativeErr = time.Time{}, nil
	connectionStatsCache.Unlock()
	t.Cleanup(func() {
		connectionStatsCache.Lock()
		connectionStatsCache.stats = models.ConnectionStats{}
		connectionStatsCache.expiresAt = time.Time{}
		connectionStatsCache.negativeUntil, connectionStatsCache.negativeErr = time.Time{}, nil
		connectionStatsCache.Unlock()
	})
}

func resetCPUSampleStateForTest(t *testing.T) {
	t.Helper()
	lastCPUStats.mu.Lock()
	lastCPUStats.snapshot = cpuSnapshot{}
	lastCPUStats.percent = 0
	lastCPUStats.sampledAt = time.Time{}
	lastCPUStats.hasValue = false
	lastCPUStats.mu.Unlock()
	t.Cleanup(func() {
		lastCPUStats.mu.Lock()
		lastCPUStats.snapshot = cpuSnapshot{}
		lastCPUStats.percent = 0
		lastCPUStats.sampledAt = time.Time{}
		lastCPUStats.hasValue = false
		lastCPUStats.mu.Unlock()
	})
}

func disableCPUSampleWindowForTest(t *testing.T) {
	t.Helper()
	withIsolatedGlobal(t)
	old := cpuSampleWindow
	cpuSampleWindow = 0
	t.Cleanup(func() { cpuSampleWindow = old })
}

func disableNetSampleWindowForTest(t *testing.T) {
	t.Helper()
	withIsolatedGlobal(t)
	old := netSampleWindow
	netSampleWindow = 0
	t.Cleanup(func() { netSampleWindow = old })
}

// 窗口内共享采样：多页签/多客户端同时轮询只读一次 /proc/stat，得到同一速率
// （旧实现每次请求都推进基线，短间隔差分噪声放大成尖峰或归零）。
func TestGetCPUPercent_sharesOneSampleWithinWindow(t *testing.T) {
	withIsolatedGlobal(t)
	resetCPUSampleStateForTest(t)
	oldWindow := cpuSampleWindow
	cpuSampleWindow = 50 * time.Millisecond
	t.Cleanup(func() { cpuSampleWindow = oldWindow })

	original := systemMetricsReadFile
	reads := 0
	samples := [][]byte{
		[]byte("cpu 100 0 0 100 0\n"),
		[]byte("cpu 200 0 0 200 0\n"),
	}
	systemMetricsReadFile = func(path string) ([]byte, error) {
		if path != "/proc/stat" {
			return original(path)
		}
		sample := samples[reads%len(samples)]
		reads++
		return sample, nil
	}
	t.Cleanup(func() { systemMetricsReadFile = original })

	// 首轮：建立基线（0，无历史样本可比）。
	if percent, err := getCPUPercent(); err != nil || percent != 0 {
		t.Fatalf("首轮 percent=%v err=%v, want 0/nil", percent, err)
	}
	// 窗口内再读：共享同一采样（不再读 /proc/stat），也不推进基线。
	if _, err := getCPUPercent(); err != nil {
		t.Fatalf("窗口内读取 err=%v", err)
	}
	if reads != 1 {
		t.Fatalf("窗口内读取 /proc/stat %d 次, want 1（窗口内必须共享采样）", reads)
	}
	// 窗口过期后：重新采样并在新窗口上差分（200-100 总增量、100-50 空闲增量 → 50%）。
	time.Sleep(70 * time.Millisecond)
	percent, err := getCPUPercent()
	if err != nil {
		t.Fatalf("窗口过期后读取 err=%v", err)
	}
	if percent != 50 {
		t.Fatalf("percent=%v, want 50（固定窗口差分）", percent)
	}
	if reads != 2 {
		t.Fatalf("窗口过期后 /proc/stat 读取累计 %d 次, want 2", reads)
	}
}

func TestGetRealtimeTraffic_sharesOneSampleWithinWindow(t *testing.T) {
	withIsolatedGlobal(t)
	oldWindow := netSampleWindow
	netSampleWindow = 50 * time.Millisecond
	t.Cleanup(func() { netSampleWindow = oldWindow })
	lastNetStats.mu.Lock()
	lastNetStats.bytesIn, lastNetStats.bytesOut = 0, 0
	lastNetStats.time = time.Time{}
	lastNetStats.rateIn, lastNetStats.rateOut = 0, 0
	lastNetStats.hasValue = false
	lastNetStats.mu.Unlock()
	t.Cleanup(func() {
		lastNetStats.mu.Lock()
		lastNetStats.bytesIn, lastNetStats.bytesOut = 0, 0
		lastNetStats.time = time.Time{}
		lastNetStats.rateIn, lastNetStats.rateOut = 0, 0
		lastNetStats.hasValue = false
		lastNetStats.mu.Unlock()
	})

	original := systemMetricsReadFile
	reads := 0
	systemMetricsReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/net/route":
			return []byte("Iface Destination Gateway Flags\neth0 00000000 0100000A 0003\n"), nil
		case "/proc/net/dev":
			reads++
			if reads == 1 {
				return []byte("Inter-| Receive | Transmit\neth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n"), nil
			}
			return []byte("Inter-| Receive | Transmit\neth0: 2000 0 0 0 0 0 0 0 4000 0 0 0 0 0 0 0\n"), nil
		default:
			return original(path)
		}
	}
	t.Cleanup(func() { systemMetricsReadFile = original })

	// 首轮建立基线。
	if traffic, err := getRealtimeTraffic(); err != nil || traffic.BytesIn != 0 || traffic.BytesOut != 0 {
		t.Fatalf("首轮 traffic=%+v err=%v, want 0/0", traffic, err)
	}
	// 窗口内：只读一次 /proc/net/dev，速率=0（基线刚建立）。
	time.Sleep(20 * time.Millisecond)
	if _, err := getRealtimeTraffic(); err != nil {
		t.Fatalf("窗口内读取 err=%v", err)
	}
	if reads != 1 {
		t.Fatalf("窗口内读取 /proc/net/dev %d 次, want 1（窗口内必须共享采样）", reads)
	}
	// 窗口过期：新样本差分（1000 字节 / ~70ms 仍远小于 1000*... 只断言非零且同值）。
	time.Sleep(60 * time.Millisecond)
	traffic, err := getRealtimeTraffic()
	if err != nil {
		t.Fatalf("窗口过期后读取 err=%v", err)
	}
	if traffic.BytesIn <= 0 || traffic.BytesOut <= 0 {
		t.Fatalf("traffic=%+v, want 正速率", traffic)
	}
	if reads != 2 {
		t.Fatalf("/proc/net/dev 读取累计 %d 次, want 2", reads)
	}
}

// df 卡死时读路径必须按超时返回错误，而非无限期阻塞（旧实现无 context）。
func TestGetCachedDiskUsage_commandTimeoutBoundsWait(t *testing.T) {
	withIsolatedGlobal(t)
	oldTimeout, oldCommand := systemMetricsCommandTimeout, systemMetricsDFCommand
	systemMetricsCommandTimeout = 40 * time.Millisecond
	systemMetricsDFCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "sleep 5")
	}
	resetDiskUsageCacheForTest(t)
	t.Cleanup(func() {
		systemMetricsCommandTimeout = oldTimeout
		systemMetricsDFCommand = oldCommand
	})

	start := time.Now()
	_, _, err := getCachedDiskUsage(time.Now())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("命令超时必须返回错误（不得以零值冒充磁盘用量）")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("等待 %v, want 受 %v 超时约束", elapsed, systemMetricsCommandTimeout)
	}
}

// netstat 卡死时连接统计同样受超时约束。
func TestGetConnectionStats_commandTimeoutBoundsWait(t *testing.T) {
	withIsolatedGlobal(t)
	oldTimeout, oldCommand := systemMetricsCommandTimeout, netstatCommand
	systemMetricsCommandTimeout = 40 * time.Millisecond
	netstatCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "sleep 5")
	}
	resetConnectionStatsCacheForTest(t)
	t.Cleanup(func() {
		systemMetricsCommandTimeout = oldTimeout
		netstatCommand = oldCommand
	})

	start := time.Now()
	if _, err := getConnectionStats(); err == nil {
		t.Fatal("命令超时必须返回错误")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("等待 %v, want 受 %v 超时约束", elapsed, systemMetricsCommandTimeout)
	}
}

// HTTP 层：分项失败仍 200，响应携带 degraded 披露（消费方可区分「真的是 0」）。
func TestGetSystemMetrics_endpointDisclosesDegradedParts(t *testing.T) {
	withIsolatedGlobal(t)
	originalReadFile, originalDFCommand := systemMetricsReadFile, systemMetricsDFCommand
	resetDiskUsageCacheForTest(t)
	resetCPUSampleStateForTest(t)
	systemMetricsReadFile = func(path string) ([]byte, error) {
		if path == "/proc/stat" {
			return nil, context.DeadlineExceeded
		}
		return originalReadFile(path)
	}
	systemMetricsDFCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf 'Filesystem 1B-blocks Used Available Use%% Mounted on\\n/dev/x 2000 500 1500 25%% /\\n'")
	}
	t.Cleanup(func() {
		systemMetricsReadFile = originalReadFile
		systemMetricsDFCommand = originalDFCommand
	})

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/system/metrics", (&Handlers{}).GetSystemMetrics)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/system/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（磁盘可用时 CPU 失败只降级）", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data struct {
			Degraded  []string `json:"degraded"`
			DiskTotal uint64   `json:"disk_total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	foundCPU := false
	for _, part := range payload.Data.Degraded {
		if part == "cpu" {
			foundCPU = true
		}
	}
	if !foundCPU {
		t.Fatalf("degraded=%v, want 含 cpu", payload.Data.Degraded)
	}
	if payload.Data.DiskTotal != 2000 {
		t.Fatalf("disk_total=%d, want 2000（CPU 失败不得连带丢失磁盘）", payload.Data.DiskTotal)
	}
}
