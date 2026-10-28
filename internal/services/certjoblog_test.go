package services

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/taskengine"
)

// useCertJobLogTestEnv 经 taskengine.SetLogDir 注入临时任务日志目录
// 目录已惰性化——旧的 certJobLogDir 变量覆写接缝随 IIFE 一并退役）并直接注入
// 大小阈值（绕过 task_log_size_mb 的 DB 读取与 5 分钟缓存），返回后恢复原状。
func useCertJobLogTestEnv(t *testing.T, thresholdBytes int64) {
	t.Helper()
	oldDir := taskengine.LogDir()
	taskengine.SetLogDir(filepath.Join(t.TempDir(), "logs", "tasks"))
	// 阈值注入缝直接替换 taskengine 的读取函数，绕过 getTaskLogSizeBytes/缓存
	// （后缓存内部结构不可直接写入；本注入缝已完全覆盖阈值取值）。
	taskengine.SetTaskLogSizeBytesFn(func() int64 { return thresholdBytes })
	t.Cleanup(func() {
		taskengine.SetLogDir(oldDir)
		taskengine.SetTaskLogSizeBytesFn(nil)
	})
}

// ≡：目录惰性求值——SetLogDir 注入后 CertJobLogPath 落
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

// 一次性迁移：/固化期写入 {LogDir 父目录}（容器=/app/logs）
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

// 升级场景的不可逆保护：目标文件已存在时不得覆盖。
// 迁移是一次性且不可逆（os.Rename 覆盖），若目标目录已写入新日志（本轮重启
// 后已产生），旧根残留的同名文件覆盖它即内容错乱，且只在首次启动发生、
// 事后无法复现。守卫 `if _, err := os.Stat(dst); err == nil { continue }`
// （certjoblog.go 迁移循环）必须被这条用例钉住：删掉守卫即红。
func TestCertJobLogDir_migrationDoesNotOverwriteExistingTarget(t *testing.T) {
	base := t.TempDir()
	legacyDir := filepath.Join(base, "logs")
	tasksDir := filepath.Join(legacyDir, "tasks")
	target := filepath.Join(tasksDir, "certjobs")
	if err := os.MkdirAll(target, 0o755); err != nil {
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
	const name = "certjob-lb_old.log"
	fresh := []byte("fresh target line\n")
	stale := []byte("stale legacy line\n")
	if err := os.WriteFile(filepath.Join(target, name), fresh, 0o644); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(legacyDir, name)
	if err := os.WriteFile(legacy, stale, 0o644); err != nil {
		t.Fatal(err)
	}

	if dir := CertJobLogDir(); dir != target {
		t.Fatalf("CertJobLogDir=%q, want %q", dir, target)
	}

	if data, err := os.ReadFile(filepath.Join(target, name)); err != nil || string(data) != string(fresh) {
		t.Fatalf("目标已存在的文件被迁移覆盖: data=%q err=%v, want 保留 %q", data, err, fresh)
	}
	if data, err := os.ReadFile(legacy); err != nil || string(data) != string(stale) {
		t.Fatalf("目标已存在时旧文件应留在原处（跳过迁移）: data=%q err=%v, want %q", data, err, stale)
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

// 删除规则时必须同时清掉当前日志、.N 轮转副本、.gz 整文件归档与历史
// 压缩代（.N.gz，外部 logrotate 形态）；同目录其他规则文件不受影响。
func TestRemoveCertJobLogFiles_removesCompressedAndRotatedGenerations(t *testing.T) {
	useCertJobLogTestEnv(t, 1<<20)
	base := CertJobLogPath("lb_remove_all")
	if err := os.MkdirAll(filepath.Dir(base), 0755); err != nil {
		t.Fatal(err)
	}
	paths := []string{base, base + ".gz"}
	for i := 1; i <= maxRotatedFiles; i++ {
		paths = append(paths, fmt.Sprintf("%s.%d", base, i), fmt.Sprintf("%s.%d.gz", base, i))
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("log\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	unrelated := base + ".other"
	if err := os.WriteFile(unrelated, []byte("keep\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := RemoveCertJobLogFiles("lb_remove_all"); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("certificate log generation remains %s: %v", path, err)
		}
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated file removed: %v", err)
	}
}

// （2026-09-05 证书域审计裁定）：轮转失败不得静默吞没——此前
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

// 并发守护：每次写日志都新建实例（Issue 的 jobLogger / WriteCertJobLog* 是
// 真实调用形态），8 实例并发写同 ruleID。阈值取约 60 行/代——200 行只跨约
// 3 次轮转，全部行都应落在 current + .1-.5 的保留面内；锁定后
// check-rotate-append 原子化，故断言「每行完整无撕裂」+「200 条消息各出现
// 恰一次」+「代际不越界」。轮转互斥失效时两实例会 rename 覆盖同一代，整代
// 消失仍能产生完整行，只有集合等价断言能发现。
// 注：并发交错本身概率性，本测试为回归守护（配合 -race），确定性红由
// rotation_failure_is_surfaced 承担。
func TestCertJobFileLogger_concurrent_writers_keep_lines_intact(t *testing.T) {
	// Given
	useCertJobLogTestEnv(t, 3000)
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

	// Then：current + .1-.5 代际内每行完整，且消息集合恰为全部写入
	base := CertJobLogPath("lb_concurrent")
	linePattern := regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[INFO\] stage - (writer-\d+-msg-\d+)$`)
	seen := make(map[string]int, writers*writesPerWriter)
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
			match := linePattern.FindStringSubmatch(line)
			if match == nil {
				t.Fatalf("torn/foreign line %q in %s", line, path)
			}
			seen[match[1]]++
		}
	}
	if _, err := os.Stat(fmt.Sprintf("%s.%d", base, maxRotatedFiles+1)); !os.IsNotExist(err) {
		t.Fatalf("rotation beyond retention window: stat .%d err=%v", maxRotatedFiles+1, err)
	}
	for w := range writers {
		for i := range writesPerWriter {
			msg := fmt.Sprintf("writer-%d-msg-%d", w, i)
			if seen[msg] != 1 {
				t.Fatalf("message %q appears %d time(s), want exactly 1（整代被覆盖或重复写入）", msg, seen[msg])
			}
		}
	}
	if len(seen) != writers*writesPerWriter {
		t.Fatalf("distinct messages=%d, want %d", len(seen), writers*writesPerWriter)
	}
}

// taskLogsHousekeeping 的唯一职责是保留期清理——尺寸轮转
// 已归写入侧 RotateTaskLogBeforeWrite，旧用例（调 housekeeping 后断言四代不丢）
// 对被测逻辑零耦合，是无 RED 能力的空转。现注入「过期」与「活跃」两个证书任务
// 日志：只删过期文件、活跃文件必须保留；保留期删除被移除/阈值失效即红。
func TestCertJobFileLogger_housekeepingDeletesOnlyExpiredFiles(t *testing.T) {
	// Given：certjobs 目录下有过期（10 年前）与活跃（现在）两个日志文件
	// 保留期删除需要「口径已知」的库（nil 库=口径未知，一律不删——本用例
	// 的断言面是保留期删除本身，必须先装配库）。
	initServicesDB(t)
	useCertJobLogTestEnv(t, 1<<20)
	dir := CertJobLogDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("seed certjobs dir: %v", err)
	}
	expiredPath := CertJobLogPath("lb_retention_expired")
	activePath := CertJobLogPath("lb_retention_active")
	for _, path := range []string{expiredPath, activePath} {
		if err := os.WriteFile(path, []byte("line\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
	}
	stale := time.Now().AddDate(-10, 0, 0)
	if err := os.Chtimes(expiredPath, stale, stale); err != nil {
		t.Fatalf("backdate expired log: %v", err)
	}
	if err := os.Chtimes(activePath, time.Now(), time.Now()); err != nil {
		t.Fatalf("touch active log: %v", err)
	}

	// When：log-cleanup housekeeping 节拍
	logFile := filepath.Join(filepath.Dir(taskengine.LogDir()), "lazy-balancer.log")
	result := taskLogsHousekeeping(logFile)

	// Then：过期文件被删（且进入 Deleted 清单），活跃文件原样保留
	if _, err := os.Stat(expiredPath); !os.IsNotExist(err) {
		t.Fatalf("expired log still present (stat err=%v)：保留期清理未生效", err)
	}
	deletedExpired := false
	for _, name := range result.Deleted {
		if name == filepath.Base(expiredPath) {
			deletedExpired = true
		}
	}
	if !deletedExpired {
		t.Fatalf("Deleted=%v, want %s", result.Deleted, filepath.Base(expiredPath))
	}
	if _, err := os.Stat(activePath); err != nil {
		t.Fatalf("active log must survive retention cleanup: %v", err)
	}
}

// 回归钉：单轨超尺寸轮转保持 5 代上限——7 次写入（每次写入前
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
	// 活动文件=最新代际，.1-.5=依次更老代际；旧剔除式命名已退役。
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

// failingCertJobLogWriter 注入写/关闭失败（磁盘配额/只读降级时
// OpenFile(O_APPEND) 可成功而后续 write 失败，此前 fmt.Fprint 与 Close 错误全被丢弃）。
type failingCertJobLogWriter struct {
	writeErr error
	closeErr error
}

func (w *failingCertJobLogWriter) Write([]byte) (int, error) { return 0, w.writeErr }
func (w *failingCertJobLogWriter) Close() error              { return w.closeErr }

// 写/关闭错误必须经 Logf 留痕（error/warn），不得静默吞没——
// 任务日志是证书域业务留痕的唯一文件源，磁盘故障时无告警会让日志与 DB 状态分叉。
func TestCertJobFileLogger_writeAndCloseErrorsAreSurfaced(t *testing.T) {
	// Given：捕获标准日志输出（Logf 经 log.Printf）
	var buf strings.Builder
	var mu sync.Mutex
	oldWriter := log.Writer()
	log.SetOutput(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		buf.Write(p)
		return len(p), nil
	}))
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	// When：写入与关闭均失败
	writeCertJobLogLine(&failingCertJobLogWriter{
		writeErr: errors.New("no space left on device"),
		closeErr: errors.New("close failed"),
	}, "/tmp/certjob-lb_fail.log", "line\n")

	// Then：两条告警均留痕且包含路径与原因
	mu.Lock()
	defer mu.Unlock()
	got := buf.String()
	if !strings.Contains(got, "write /tmp/certjob-lb_fail.log failed") || !strings.Contains(got, "no space left on device") {
		t.Fatalf("write failure not surfaced, log=%q", got)
	}
	if !strings.Contains(got, "close /tmp/certjob-lb_fail.log failed") || !strings.Contains(got, "close failed") {
		t.Fatalf("close failure not surfaced, log=%q", got)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// 证书任务日志文件名主体必须与规则访问日志同构
// （可逆编码）。旧实现 sanitizePathComponent 剔除非法字符：`lb.dot` 与 `lbdot`
// 落到同一 certjob-lbdot.log 与同一写锁——签发日志跨规则混写、保留期清理互相
// 删除（housekeeping 从文件名反推 ID 的前提在字母表外不成立）。
func TestCertJobLogFileName_reversibleForDottedIDs(t *testing.T) {
	useCertJobLogTestEnv(t, 1<<20)

	// 共文件形状：含 '.' 的 ID 必须与剔除后的同名 ID 落不同文件
	if dotted, plain := CertJobLogPath("lb.dot"), CertJobLogPath("lbdot"); dotted == plain {
		t.Fatalf("lb.dot 与 lbdot 共用日志文件 %q（剔除字符不可逆）", dotted)
	}

	// 往返：路径 → 文件名 → certJobLogRuleIDFromName 必须还原原始 ID，
	// 且 housekeeping 反推出的写锁键与写侧同源（同一 mutex）。锁键用
	// certJobLogFileComponent 口径直接比较——lockCertJobLog 是只 acquire
	// 不释放的取锁入口，在此调用会给每个 ID 在进程级锁表留下永不复位的
	// 引用（与 TestLockCertJobLog_reclaimsEntryAfterRelease 的「可回收」契约
	// 互斥），且与被比较的对象是同一函数取值、无额外语义。
	roundtripIDs := []string{"lb.dot", "lbdot", "lb_x-1", "lb.dot.rule", "lb..dot", "lb.dot中"}
	for _, ruleID := range roundtripIDs {
		name := filepath.Base(CertJobLogPath(ruleID))
		parsed, ok := certJobLogRuleIDFromName(name)
		if !ok || parsed != ruleID {
			t.Fatalf("roundtrip %q: parsed=%q ok=%v（文件名 %q）", ruleID, parsed, ok, name)
		}
		if certJobLogFileComponent(parsed) != certJobLogFileComponent(ruleID) {
			t.Fatalf("roundtrip %q: housekeeping 与写侧锁键不同源（文件组件 %q != %q）",
				ruleID, certJobLogFileComponent(parsed), certJobLogFileComponent(ruleID))
		}
		// 轮转代（.N/.gz）反推同样成立（taskLogsHousekeeping 扫描的形态）。
		for _, suffix := range []string{".log.1", ".log.5", ".log.gz"} {
			rotated, rok := certJobLogRuleIDFromName(strings.TrimSuffix(name, ".log") + suffix)
			if !rok || rotated != ruleID {
				t.Fatalf("roundtrip %q%s: parsed=%q ok=%v", ruleID, suffix, rotated, rok)
			}
		}
	}
	// 本用例不得在进程级写锁表留下条目：旧实现经 lockCertJobLog 取锁
	// （acquire 后无 Unlock），6 个 ID 的引用恒不为 0，锁表按用例无界增长。
	for _, ruleID := range roundtripIDs {
		component := certJobLogFileComponent(ruleID)
		if _, exists := certJobLogWriteLocks.locks.Load(component); exists {
			t.Fatalf("roundtrip %q 在进程级写锁表留下条目 %q（锁取用后未释放）", ruleID, component)
		}
	}

	// 向后兼容：旧实现产出的文件名（剔除非法字符）仍可解析——存量部署的
	// 历史文件继续参与 housekeeping 清理与写锁串行化。
	for name, want := range map[string]string{
		"certjob-lbdot.log":        "lbdot",
		"certjob-lbdot.log.3":      "lbdot",
		"certjob-lbdot.log.gz":     "lbdot",
		"certjob-lb_x.log":         "lb_x",
		"certjob-badrule.log.1.gz": "badrule",
	} {
		got, ok := certJobLogRuleIDFromName(name)
		if !ok || got != want {
			t.Fatalf("legacy name %q parsed=%q ok=%v, want %q", name, got, ok, want)
		}
	}
}

// 日志写锁条目在最后一个持有者释放后回收：规则可反复创建/删除，只增不删的
// 锁表会按历史规则总数无界增长（旧实现注释以「规则量级」为由不回收）。
func TestLockCertJobLog_reclaimsEntryAfterRelease(t *testing.T) {
	const ruleID = "lb_reclaim_log_lock"
	component := certJobLogFileComponent(ruleID)
	lock := lockCertJobLog(ruleID)
	lock.Lock()
	if _, exists := certJobLogWriteLocks.locks.Load(component); !exists {
		t.Fatal("在途持锁时日志写锁条目必须存在")
	}
	lock.Unlock()
	if _, exists := certJobLogWriteLocks.locks.Load(component); exists {
		t.Fatal("日志写锁条目未回收（键空间随历史规则无界增长）")
	}
}
