package handlers

// 系统采样形状契约：
//   - 规则指标（HTTP/TCP/空）键集一致，且不得携带恒假 healthy 键——健康
//     语义只由 /config/health 通道承载；
//   - /proc/meminfo 缺 MemAvailable 时必须显式报错走分项降级，不得按
//     「可用=0」输出恒 100% 使用率。

import (
	"context"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

func TestRuleMetrics_shapeHasNoFakeHealthField(t *testing.T) {
	httpShape := ruleMetricsAggregate{requestsTotal: 3, bytesIn: 10, bytesOut: 20}.ruleMetrics()
	tcpShape := prometheusMetricsIndex{}.tcpRuleMetrics(nil)
	emptyShape := emptyRuleMetrics()

	for name, shape := range map[string]map[string]any{
		"http":  httpShape,
		"tcp":   tcpShape,
		"empty": emptyShape,
	} {
		if _, exists := shape["healthy"]; exists {
			t.Fatalf("%s 规则指标仍携带 healthy（恒假死字段）: %v", name, shape)
		}
		if len(shape) != len(emptyShape) {
			t.Fatalf("%s 键数=%d, want %d（HTTP/TCP/空同键集）: %v", name, len(shape), len(emptyShape), shape)
		}
		for key := range emptyShape {
			if _, ok := shape[key]; !ok {
				t.Fatalf("%s 缺键 %q", name, key)
			}
		}
	}
	if httpShape["requests_total"] != int64(3) {
		t.Fatalf("HTTP requests_total=%v, want 3", httpShape["requests_total"])
	}
}

func TestParseMemInfo_missingMemAvailableIsError(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr string
		total   uint64
		used    uint64
	}{
		{
			name:    "missing-available",
			input:   "MemTotal: 8000000 kB\n",
			wantErr: "缺少 MemAvailable",
		},
		{
			name:    "missing-available-with-other-lines",
			input:   "MemTotal: 8000000 kB\nMemFree: 1000 kB\nBuffers: 10 kB\n",
			wantErr: "缺少 MemAvailable",
		},
		{
			name:    "missing-total",
			input:   "MemAvailable: 4000000 kB\n",
			wantErr: "缺少 MemTotal",
		},
		{
			name:  "available-zero-is-valid",
			input: "MemTotal: 8000000 kB\nMemAvailable: 0 kB\n",
			total: 8000000 * 1024,
			used:  8000000 * 1024,
		},
		{
			name:    "available-greater-than-total",
			input:   "MemTotal: 100 kB\nMemAvailable: 200 kB\n",
			wantErr: "MemAvailable 大于 MemTotal",
		},
		{
			name:  "normal",
			input: "MemTotal: 8000000 kB\nMemAvailable: 6000000 kB\n",
			total: 8000000 * 1024,
			used:  2000000 * 1024,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			total, used, err := parseMemInfo(tt.input)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err=%v, want contains %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if total != tt.total || used != tt.used {
				t.Fatalf("(total,used)=(%d,%d), want (%d,%d)", total, used, tt.total, tt.used)
			}
		})
	}
}

func TestGetSystemMetrics_missingMemAvailableDegradesMemory(t *testing.T) {
	withIsolatedGlobal(t)
	originalReadFile, originalDFCommand := systemMetricsReadFile, systemMetricsDFCommand
	resetDiskUsageCacheForTest(t)
	resetCPUSampleStateForTest(t)
	systemMetricsReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/meminfo":
			return []byte("MemTotal: 8000000 kB\nMemFree: 1000 kB\n"), nil
		case "/proc/stat":
			return []byte("cpu 100 0 0 100 0\n"), nil
		default:
			return originalReadFile(path)
		}
	}
	systemMetricsDFCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf 'Filesystem 1B-blocks Used Available Use%% Mounted on\n/dev/x 1000 250 750 25%% /\n'")
	}
	t.Cleanup(func() {
		systemMetricsReadFile = originalReadFile
		systemMetricsDFCommand = originalDFCommand
	})

	metrics, err := getSystemMetrics()
	if err != nil {
		t.Fatalf("仅内存缺行不得让整次采集失败: %v", err)
	}
	if !slices.Contains(metrics.Degraded, "memory") {
		t.Fatalf("degraded=%v, want 含 memory", metrics.Degraded)
	}
	if metrics.MemoryTotal != 0 || metrics.MemoryUsed != 0 || metrics.MemoryPercent != 0 {
		t.Fatalf("内存指标=%+v, want 零值（缺 MemAvailable 不得伪造 100%% 使用率）", metrics)
	}
	if metrics.DiskTotal != 1000 || metrics.DiskUsed != 250 {
		t.Fatalf("磁盘指标=%d/%d, want 1000/250（内存失败不得连带丢失）", metrics.DiskTotal, metrics.DiskUsed)
	}
}
