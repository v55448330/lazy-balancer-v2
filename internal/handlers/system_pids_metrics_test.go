package handlers

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"testing"
)

func TestParsePidsLimit(t *testing.T) {
	cases := []struct {
		raw     string
		want    int
		wantErr bool
	}{
		{"4096\n", 4096, false},
		{"max\n", 0, false},
		{"0", 0, false},
		{"nonsense", 0, true},
		{"-1", 0, true},
	}
	for _, tc := range cases {
		got, err := parsePidsLimit(tc.raw)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Fatalf("parsePidsLimit(%q)=%d,%v want %d,err=%v", tc.raw, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestParseNprocLimit(t *testing.T) {
	unlimited := "Max processes              unlimited            unlimited            processes\n"
	if got := parseNprocLimit(unlimited); got != 0 {
		t.Fatalf("unlimited=%d, want 0", got)
	}
	numeric := "Max processes              4096                 8192                 processes\n"
	if got := parseNprocLimit(numeric); got != 4096 {
		t.Fatalf("numeric=%d, want 4096（取软限）", got)
	}
	if got := parseNprocLimit("Max open files 1024 4096 files\n"); got != 0 {
		t.Fatalf("缺失行=%d, want 0", got)
	}
}

func TestReadPidsUsage_v2AndLimitSource(t *testing.T) {
	original := systemMetricsReadFile
	t.Cleanup(func() { systemMetricsReadFile = original })
	files := map[string]string{
		"/sys/fs/cgroup/pids.current": "2368\n",
		"/sys/fs/cgroup/pids.max":     "4096\n",
		"/proc/self/limits":           "Max processes              4096                 4096                 processes\n",
	}
	systemMetricsReadFile = func(path string) ([]byte, error) {
		if v, ok := files[path]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("not found")
	}

	current, max, nproc, err := readPidsUsage()
	if err != nil {
		t.Fatalf("readPidsUsage: %v", err)
	}
	if current != 2368 || max != 4096 || nproc != 4096 {
		t.Fatalf("got %d/%d nproc=%d, want 2368/4096 nproc=4096", current, max, nproc)
	}
}

// cgroup v1 落点在 /sys/fs/cgroup/pids/ 子目录：v2 文件缺失时必须回落。
func TestReadPidsUsage_v1Fallback(t *testing.T) {
	original := systemMetricsReadFile
	t.Cleanup(func() { systemMetricsReadFile = original })
	files := map[string]string{
		"/sys/fs/cgroup/pids/pids.current": "12\n",
		"/sys/fs/cgroup/pids/pids.max":     "max\n",
	}
	systemMetricsReadFile = func(path string) ([]byte, error) {
		if v, ok := files[path]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("not found")
	}

	current, max, nproc, err := readPidsUsage()
	if err != nil {
		t.Fatalf("readPidsUsage: %v", err)
	}
	if current != 12 || max != 0 || nproc != 0 {
		t.Fatalf("got %d/%d nproc=%d, want 12/0（无限）nproc=0", current, max, nproc)
	}
}

// pids 采集失败只降级该分项：其余指标照常返回，PIDs 值置零由展示层标注。
func TestGetSystemMetrics_pidsFailureDegradesOnlyThatPart(t *testing.T) {
	originalReadFile, originalDF := systemMetricsReadFile, systemMetricsDFCommand
	resetDiskUsageCacheForTest(t)
	resetCPUSampleStateForTest(t)
	systemMetricsReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/meminfo":
			return []byte("MemTotal: 1000 kB\nMemAvailable: 400 kB\n"), nil
		case "/proc/stat":
			return []byte("cpu 100 0 0 100 0\n"), nil
		default:
			// pids.current/pids.max（v2 与 v1）均缺失
			return nil, errors.New("unavailable")
		}
	}
	systemMetricsDFCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf 'Filesystem 1B-blocks Used Available Use%% Mounted on\n/dev/x 1000 250 750 25%% /\n'")
	}
	t.Cleanup(func() {
		systemMetricsReadFile = originalReadFile
		systemMetricsDFCommand = originalDF
	})

	metrics, err := getSystemMetrics()
	if err != nil {
		t.Fatalf("pids 单点失败不得让整次采集失败: %v", err)
	}
	if !slices.Contains(metrics.Degraded, "pids") {
		t.Fatalf("degraded=%v, want 含 pids", metrics.Degraded)
	}
	if metrics.PidsCurrent != 0 || metrics.PidsMax != 0 || metrics.PidsPercent != 0 {
		t.Fatalf("pids=%d/%d %.2f%%, want 零值（失败分项不伪造数据）", metrics.PidsCurrent, metrics.PidsMax, metrics.PidsPercent)
	}
	if metrics.MemoryTotal != 1024000 || metrics.DiskTotal != 1000 {
		t.Fatalf("其余分项不得受 pids 失败影响: mem=%d disk=%d", metrics.MemoryTotal, metrics.DiskTotal)
	}
}

func TestGetSystemMetrics_reportsPidsPercent(t *testing.T) {
	originalReadFile, originalDF := systemMetricsReadFile, systemMetricsDFCommand
	resetDiskUsageCacheForTest(t)
	resetCPUSampleStateForTest(t)
	systemMetricsReadFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/meminfo":
			return []byte("MemTotal: 1000 kB\nMemAvailable: 400 kB\n"), nil
		case "/proc/stat":
			return []byte("cpu 100 0 0 100 0\n"), nil
		case "/sys/fs/cgroup/pids.current":
			return []byte("2048\n"), nil
		case "/sys/fs/cgroup/pids.max":
			return []byte("4096\n"), nil
		case "/proc/self/limits":
			return []byte("Max processes              8192                 8192                 processes\n"), nil
		default:
			return nil, errors.New("unexpected path " + path)
		}
	}
	systemMetricsDFCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf 'Filesystem 1B-blocks Used Available Use%% Mounted on\n/dev/x 1000 250 750 25%% /\n'")
	}
	t.Cleanup(func() {
		systemMetricsReadFile = originalReadFile
		systemMetricsDFCommand = originalDF
	})

	metrics, err := getSystemMetrics()
	if err != nil {
		t.Fatalf("getSystemMetrics: %v", err)
	}
	if metrics.PidsCurrent != 2048 || metrics.PidsMax != 4096 || metrics.NprocLimit != 8192 {
		t.Fatalf("pids=%d/%d nproc=%d, want 2048/4096/8192", metrics.PidsCurrent, metrics.PidsMax, metrics.NprocLimit)
	}
	if metrics.PidsPercent < 49.9 || metrics.PidsPercent > 50.1 {
		t.Fatalf("pids percent=%.2f, want 50", metrics.PidsPercent)
	}
	if slices.Contains(metrics.Degraded, "pids") {
		t.Fatalf("degraded=%v, pids 不应在降级列表", metrics.Degraded)
	}
}
