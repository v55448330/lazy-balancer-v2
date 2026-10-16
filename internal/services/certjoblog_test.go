package services

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/taskengine"
)

// useCertJobLogTestEnv 经 taskengine.SetLogDir 注入临时任务日志目录（U1-66-03：
// 目录已惰性化——旧的 certJobLogDir 变量覆写接缝随 IIFE 一并退役）并直接注入
// 大小阈值（绕过 task_log_size_mb 的 DB 读取与 5 分钟缓存），返回后恢复原状。
func useCertJobLogTestEnv(t *testing.T, thresholdBytes int64) {
	t.Helper()
	oldDir := taskengine.LogDir()
	oldCached, oldCachedAt := certJobLogSizeCached.Load(), certJobLogSizeCachedAt.Load()
	taskengine.SetLogDir(filepath.Join(t.TempDir(), "logs", "tasks"))
	taskengine.SetTaskLogSizeBytesFn(func() int64 { return thresholdBytes })
	certJobLogSizeCached.Store(thresholdBytes)
	certJobLogSizeCachedAt.Store(time.Now().UnixNano())
	t.Cleanup(func() {
		taskengine.SetLogDir(oldDir)
		taskengine.SetTaskLogSizeBytesFn(nil)
		certJobLogSizeCached.Store(oldCached)
		certJobLogSizeCachedAt.Store(oldCachedAt)
	})
}

// U1-66-03≡L1-66-02：目录惰性求值——SetLogDir 注入后 CertJobLogPath 落
// {任务日志目录}/certjobs/。曾为包初始化 IIFE 固化（LogDir 注入恒晚于包
// 初始化），生产恒回退 /app/logs 根、脱离 housekeeping 清理面。
func TestCertJobLogPath_followsTaskLogDir(t *testing.T) {
	base := t.TempDir()
	old := taskengine.LogDir()
	taskengine.SetLogDir(filepath.Join(base, "logs", "tasks"))
	t.Cleanup(func() { taskengine.SetLogDir(old) })
	want := filepath.Join(base, "logs", "tasks", "certjobs", "certjob-lb_x.log")
	if got := CertJobLogPath("lb_x"); got != want {
		t.Fatalf("CertJobLogPath=%q, want %q（须随 SetLogDir 注入落 certjobs 子目录）", got, want)
	}
}

// 一次性迁移（best-effort）：pre-B3/固化期写入 {LogDir 父目录}（容器=/app/logs）
// 的 certjob-*.log 搬入新目录——旧文件残留会脱离清理面；目标已存在不覆盖。
func TestCertJobLogDir_migratesLegacyFilesOnce(t *testing.T) {
	base := t.TempDir()
	legacyDir := filepath.Join(base, "logs")
	tasksDir := filepath.Join(legacyDir, "tasks")
	if err := os.MkdirAll(tasksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := taskengine.LogDir()
	oldMigrated := certJobLogMigrated.Load()
	taskengine.SetLogDir(tasksDir)
	certJobLogMigrated.Store(false) // 每进程一次的迁移在本测试内重放
	t.Cleanup(func() {
		taskengine.SetLogDir(old)
		certJobLogMigrated.Store(oldMigrated)
	})
	legacy := filepath.Join(legacyDir, "certjob-lb_old.log")
	if err := os.WriteFile(legacy, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := CertJobLogDir()
	if dir != filepath.Join(tasksDir, "certjobs") {
		t.Fatalf("CertJobLogDir=%q, want %q", dir, filepath.Join(tasksDir, "certjobs"))
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("旧文件应已迁移出父目录, stat err=%v", err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "certjob-lb_old.log")); err != nil || string(data) != "old\n" {
		t.Fatalf("新目录应收到迁移文件且内容一致: data=%q err=%v", data, err)
	}
}

// captureCertJobLogWarns 捕获轮转失败告警（测试缝），返回读取快照的函数。
func captureCertJobLogWarns(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var warned []string
	original := certJobLogWarnf
	certJobLogWarnf = func(format string, args ...any) {
		mu.Lock()
		warned = append(warned, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	t.Cleanup(func() { certJobLogWarnf = original })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), warned...)
	}
}

// C-11（2026-09-05 证书域审计裁定）：轮转失败不得静默吞没——此前
// os.Remove/os.Rename 的错误全部丢弃，坏轮转（如备份槽位被非空目录占据）无任何
// 留痕。确定性触发：.5 槽位放非空目录，os.Remove 报 ENOTEMPTY（非 IsNotExist）。
func TestCertJobFileLogger_rotation_failure_is_surfaced(t *testing.T) {
	// Given：阈值 1 字节（现存文件必触发轮转），当前日志已存在，.5 槽位被占
	useCertJobLogTestEnv(t, 1)
	base := CertJobLogPath("lb_rotfail")
	if err := os.MkdirAll(filepath.Dir(base), 0755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.WriteFile(base, []byte("old line\n"), 0644); err != nil {
		t.Fatalf("seed current log: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(base+".5", "occupied"), 0755); err != nil {
		t.Fatalf("block .5 slot: %v", err)
	}
	warns := captureCertJobLogWarns(t)

	// When
	NewCertJobFileLogger("lb_rotfail").Log("stage", "message")

	// Then：轮转失败被留痕（含路径/规则标识），不再静默吞没
	got := warns()
	if len(got) == 0 {
		t.Fatal("rotation failure was swallowed: want warn log entry")
	}
	if !strings.Contains(got[0], "lb_rotfail") {
		t.Fatalf("warn=%q, want ruleID/path in message", got[0])
	}
}

// C-11 并发守护：每次写日志都新建实例（Issue 的 jobLogger / WriteCertJobLog* 是
// 真实调用形态），8 实例并发写同 ruleID、阈值 1 字节使每次写都触发轮转。锁定后
// check-rotate-append 原子化；断言全部落盘行完整无撕裂、代际集合不越界。
// 注：并发交错本身概率性，本测试为回归守护（配合 -race），确定性红由
// rotation_failure_is_surfaced 承担。
func TestCertJobFileLogger_concurrent_writers_keep_lines_intact(t *testing.T) {
	// Given
	useCertJobLogTestEnv(t, 1)
	const writers, writesPerWriter = 8, 25
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			logger := NewCertJobFileLogger(fmt.Sprintf("lb_concurrent"))
			for i := 0; i < writesPerWriter; i++ {
				logger.Log("stage", fmt.Sprintf("writer-%d-msg-%d", id, i))
			}
		}(w)
	}
	wg.Wait()

	// Then：current + .1-.5 全部存在的代际文件中，每行都是完整日志行
	base := CertJobLogPath("lb_concurrent")
	linePattern := regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[INFO\] stage - writer-\d+-msg-\d+$`)
	complete := 0
	for i := 0; i <= maxRotatedFiles; i++ {
		path := base
		if i > 0 {
			path = fmt.Sprintf("%s.%d", base, i)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read generation %s: %v", path, err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			if !linePattern.MatchString(line) {
				t.Fatalf("torn/foreign line %q in %s", line, path)
			}
			complete++
		}
	}
	if complete == 0 {
		t.Fatal("no complete log lines survived concurrent writes")
	}
}

// L1-P4-1（第 67 轮）：写入侧 5 代移位轮转与 log-cleanup housekeeping（tasks/
// 主流水，logrotate.go taskLogsHousekeeping）的「rename → .1」单代覆盖式轮转双轨
// 并存——活动文件被追加推过阈值后、下一次写入前的窗口内，housekeeping 节拍把
// 活动文件 rename 覆盖既有 .1，5 代链中最新一代历史整代丢失。
// Given 阈值 1000 字节、每行约 602 字节，写入序列制造「代际存在 + 活动文件已
// 超阈值」的双轨窗口态。
// When housekeeping 节拍运行。
// Then 全部已写入内容仍在活动文件或 .1-.5 代际链内（无任何一代丢失）。
func TestCertJobFileLogger_housekeepingTickNeverDropsGeneration(t *testing.T) {
	useCertJobLogTestEnv(t, 1000)
	logger := NewCertJobFileLogger("lb_dualtrack")
	payload := strings.Repeat("x", 560) // 行全长 ≈602 字节：两行必超 1000 阈值
	write := func(tag string) { logger.Log("stage", tag+payload) }

	// Given：旧实现下第 2/4 次写入把活动文件推过阈值而不轮转（窗口态），
	// 第 3 次写入触发 5 代移位使 .1=[GEN-1,GEN-2]。
	write("GEN-1-")
	write("GEN-2-")
	write("GEN-3-")
	write("GEN-4-")

	// When：log-cleanup housekeeping 节拍（tasks/ 主流水第二轮转轨）。
	logFile := filepath.Join(filepath.Dir(taskengine.LogDir()), "lazy-balancer.log")
	taskLogsHousekeeping(logFile)

	// Then：全部四代内容须仍在活动文件或 .1-.5 代际链内。
	var b strings.Builder
	base := CertJobLogPath("lb_dualtrack")
	for i := 0; i <= maxRotatedFiles; i++ {
		p := base
		if i > 0 {
			p = fmt.Sprintf("%s.%d", base, i)
		}
		if data, err := os.ReadFile(p); err == nil {
			b.Write(data)
		}
	}
	all := b.String()
	for _, tag := range []string{"GEN-1-", "GEN-2-", "GEN-3-", "GEN-4-"} {
		if !strings.Contains(all, tag) {
			t.Fatalf("housekeeping 后历史内容 %q 丢失（双轨 .1 覆盖丢史），链内容=\n%s", tag, all)
		}
	}
}

// 回归钉（L1-P4-1 配套）：单轨超尺寸轮转保持 5 代上限——7 次写入（每次写入前
// 判定超阈即轮转）后活动文件存最新一代，.1-.5 存最近 5 代，最老一代退役，
// 不产生 .6。
func TestCertJobFileLogger_singleTrackRotationKeepsFiveGenerations(t *testing.T) {
	useCertJobLogTestEnv(t, 1000)
	logger := NewCertJobFileLogger("lb_fivegen")
	payload := strings.Repeat("y", 560)
	for i := 1; i <= 7; i++ {
		logger.Log("stage", fmt.Sprintf("GEN-%d-%s", i, payload))
	}

	base := CertJobLogPath("lb_fivegen")
	if _, err := os.Stat(base + ".6"); !os.IsNotExist(err) {
		t.Fatalf("不应存在第 6 代轮转文件（5 代上限）: stat err=%v", err)
	}
	readGen := func(i int) string {
		p := base
		if i > 0 {
			p = fmt.Sprintf("%s.%d", base, i)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("读取代际 %s: %v", p, err)
		}
		return string(data)
	}
	// 活动文件=GEN-7，.1-.5=GEN-6..GEN-2，GEN-1 已退役。
	want := map[int]string{0: "GEN-7-", 1: "GEN-6-", 2: "GEN-5-", 3: "GEN-4-", 4: "GEN-3-", 5: "GEN-2-"}
	for i, tag := range want {
		if got := readGen(i); !strings.Contains(got, tag) {
			t.Fatalf("代际 .%d 应含 %q，内容=\n%s", i, tag, got)
		}
	}
	var b strings.Builder
	for i := 0; i <= maxRotatedFiles; i++ {
		b.WriteString(readGen(i))
	}
	if strings.Contains(b.String(), "GEN-1-") {
		t.Fatal("最老一代 GEN-1 应随 5 代上限退役")
	}
}
