package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
)

var runtimeLogSizeMB atomic.Int64

var runtimeLogSizeRefresh struct {
	sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

var runtimeLogCleanup struct {
	sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func init() {
	runtimeLogSizeMB.Store(100)
	StartLogRotate(context.Background())
}

func StartLogRotate(ctx context.Context) <-chan struct{} {
	runtimeLogSizeRefresh.Lock()
	defer runtimeLogSizeRefresh.Unlock()
	if runtimeLogSizeRefresh.cancel != nil {
		runtimeLogSizeRefresh.cancel()
		<-runtimeLogSizeRefresh.done
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	runtimeLogSizeRefresh.cancel = cancel
	runtimeLogSizeRefresh.done = done
	go func() {
		defer close(done)
		refresh := func() {
			database := db.GetDB()
			if database == nil {
				return
			}
			var mb int
			if err := database.QueryRow("SELECT COALESCE(runtime_log_size_mb,100) FROM global_config WHERE id=1").Scan(&mb); err != nil {
				Logf("info", "refresh runtime log size: %v", err)
			} else if mb > 0 {
				runtimeLogSizeMB.Store(int64(mb))
			}
		}
		refresh()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				refresh()
			case <-workerCtx.Done():
				return
			}
		}
	}()
	return done
}

func StopLogRotate() {
	runtimeLogSizeRefresh.Lock()
	defer runtimeLogSizeRefresh.Unlock()
	if runtimeLogSizeRefresh.cancel == nil {
		return
	}
	runtimeLogSizeRefresh.cancel()
	<-runtimeLogSizeRefresh.done
	runtimeLogSizeRefresh.cancel = nil
	runtimeLogSizeRefresh.done = nil
}

// RotatingFileWriter writes to a log file and rotates it once it exceeds the
// size limit. Rotated files are suffixed with a timestamp and are subject to
// retention cleanup (log-cleanup 任务体的 RuntimeLogCleanupOnce——旧启动器
// StartRuntimeLogCleanup 已随 M2 任务引擎化退役).
type RotatingFileWriter struct {
	path string
	mu   sync.Mutex
	file *os.File
	size int64
}

func NewRotatingFileWriter(path string) (*RotatingFileWriter, error) {
	w := &RotatingFileWriter{path: path}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *RotatingFileWriter) open() error {
	// SECLB23-P3-1(第 23 轮审计):LogFileEnabled 恒 true 后裸二进制部署
	// /app/logs 不存在——open 必须建父目录,否则恒回退 stdout 轮转失效。
	if err := os.MkdirAll(filepath.Dir(w.path), 0o755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	var size int64
	if info, err := f.Stat(); err == nil {
		size = info.Size()
	}
	w.file = f
	w.size = size
	return nil
}

func (w *RotatingFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		if err := w.open(); err != nil {
			return 0, fmt.Errorf("reopen log file: %w", err)
		}
	}
	if w.size+int64(len(p)) > runtimeLogSizeMB.Load()*1024*1024 {
		if err := w.rotateLocked(); err != nil {
			return 0, fmt.Errorf("rotate log file: %w", err)
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *RotatingFileWriter) rotateLocked() error {
	if err := w.file.Close(); err != nil {
		return err
	}
	w.file = nil
	stamp := time.Now().Format("20060102-150405")
	rotated := fmt.Sprintf("%s.%s", w.path, stamp)
	// SYSB44-2(第 44 轮审计 P3):同秒多次轮转的碰撞后缀原为 UnixNano()%1000
	// 随机数——撞上既有副本名时 os.Rename 静默覆盖,吞掉上一份轮转日志。
	// 改循环递增 -2/-3/...(与 autobackup 同秒序号 -2..-201 同模式)直至文件名
	// 不存在,确定性避让;stat 出非「不存在」错误时按可选用(与原 lenient
	// 口径一致,rename 失败仍走下方回退)。
	for n := 2; ; n++ {
		if _, err := os.Stat(rotated); err != nil {
			break
		}
		rotated = fmt.Sprintf("%s.%s-%d", w.path, stamp, n)
	}
	if err := os.Rename(w.path, rotated); err != nil {
		// Rename failed (e.g. cross-device); keep appending to the old file.
		return w.open()
	}
	return w.open()
}

func (w *RotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	return w.file.Close()
}

// RuntimeCleanupResult 单轮运行日志清理结果（log-cleanup 任务日志展示明细——
// 2026-10-01 用户裁定：清理了哪个文件必须可见；单轮执行体=
// RuntimeLogCleanupOnce，由任务引擎 log-cleanup 族按 24h 节拍驱动）。
type RuntimeCleanupResult struct {
	AppRemoved int // 应用日志过期副本删除数（app.log.*）
	TaskLogs   TaskLogHousekeepingResult
	WafAudit   []string // waf-audit 目录兜底动作明细（daemon 停机时的超阈轮转/截断）
}

// TaskLogHousekeepingResult 任务日志清理明细。
type TaskLogHousekeepingResult struct {
	Deleted   []string // 超保留期删除（文件名）
	Rotated   []string // 超大小上限轮转（文件名+大小对比，如 "threat.log 11.3MB>10MB"）
	SizeCapMB int      // 生效的大小上限（task_log_size_mb）
}

// Summary 一行明细摘要（列表超 5 个收敛为「等 N 个」；空=「无」）。
func (r TaskLogHousekeepingResult) Summary() string {
	list := func(names []string) string {
		if len(names) == 0 {
			return "无"
		}
		if len(names) > 5 {
			return strings.Join(names[:5], "、") + fmt.Sprintf(" 等 %d 个", len(names))
		}
		return strings.Join(names, "、")
	}
	return fmt.Sprintf("任务日志：超期删除 %d 个[%s]、超限轮转 %d 个[%s]（大小上限 %dMB）",
		len(r.Deleted), list(r.Deleted), len(r.Rotated), list(r.Rotated), r.SizeCapMB)
}

// RuntimeLogCleanupOnce 单轮清理：应用日志过期副本删除 + 任务日志统一
// 清理轮转（taskLogsHousekeeping）。由任务引擎 log-cleanup 族驱动（M2 起
// 无独立启动器）。
func RuntimeLogCleanupOnce(logFile string) RuntimeCleanupResult {
	result := RuntimeCleanupResult{TaskLogs: taskLogsHousekeeping(logFile), WafAudit: wafAuditHousekeeping()}
	months := 3
	database := db.GetDB()
	if database == nil {
		return result
	}
	// LBS-B-U2（第 69 轮）：统一经 auditRetentionMonths——读取失败回退默认
	// 3 月 + warn 留痕（曾三消费点三态分裂，此处为静默默认形态）。
	months = auditRetentionMonths()
	cutoff := time.Now().AddDate(0, -months, 0)

	dir := filepath.Dir(logFile)
	base := filepath.Base(logFile) + "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return result
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), base) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				Logf("error", "清理过期运行日志失败 %s: %v", e.Name(), err)
			} else {
				removed++
				Logf("info", "已清理过期运行日志 %s", e.Name())
			}
		}
	}
	result.AppRemoved = removed
	return result
}

// wafAuditHousekeeping waf-audit 目录超阈兜底（F-L3-68-01，第 68 轮审计）——
// audit.log 轮转与 security-timing.log 读后截断的正常驱动面是
// security-events-ingestion daemon 的 2s tick（SecurityEventsPollOnce）；
// daemon 停机（任务被禁用/取消）时两文件无守护无界增长——写侧（Coraza
// 审计流/caddygeoip 耗时侧车）在 Caddy 进程内持续追加，本进程不消费即
// 只增不减。此处按 audit_log_size_mb 阈值在 log-cleanup 任务体（24h 节拍）
// 内兜底：
//
//   - audit.log 超阈 → SecurityEventsPollOnce()（与 daemon tick 同锁同路径，
//     摄取+pending-delta+copytruncate 全套安全链——绝不无补采截断；daemon
//     在场时文件本不会积到阈值，触发即等价一次普通 tick，无竞争）。
//   - security-timing.log 超阈 → 直接截断。侧车仅是耗时增强数据，超阈即读侧
//     长期未消费、残留行本不会被任何消费者读取；与正常「读后截断」同形语义
//     （既有注释已接受读后写入的丢行窗口）。
//
// 返回动作明细（log-cleanup 任务日志与运行日志双写——清理了哪个文件必须
// 可见，2026-10-01 用户裁定口径）。
func wafAuditHousekeeping() []string {
	var actions []string
	maxBytes := auditLogSizeBytes()
	if info, err := os.Stat(auditLogPath); err == nil && info.Size() >= maxBytes {
		sizeBefore := info.Size()
		SecurityEventsPollOnce()
		if after, aerr := os.Stat(auditLogPath); aerr == nil && after.Size() < sizeBefore {
			actions = append(actions, fmt.Sprintf("audit.log %.1fMB≥%dMB（摄取+轮转）",
				float64(sizeBefore)/1024/1024, maxBytes/1024/1024))
		}
	}
	// 耗时侧车：上方 audit.log 触发 poll 时 daemon tick 的 securityTimingLoad
	// 已「读后截断」一并收敛；此处仍超阈 = 侧车独立积压（audit 静默请求流或
	// daemon 停机），直接截断。
	if info, err := os.Stat(securityTimingLogPath); err == nil && info.Size() >= maxBytes {
		if terr := os.Truncate(securityTimingLogPath, 0); terr == nil {
			actions = append(actions, fmt.Sprintf("security-timing.log %.1fMB≥%dMB（截断）",
				float64(info.Size())/1024/1024, maxBytes/1024/1024))
		} else {
			Logf("error", "waf-audit 兜底：截断 %s 失败: %v", securityTimingLogPath, terr)
		}
	}
	for _, action := range actions {
		Logf("info", "waf-audit 兜底轮转：%s", action)
		TaskLogf("log-cleanup", "waf-audit", "兜底轮转：%s", action)
	}
	return actions
}

// taskLogsHousekeeping 任务日志统一清理与轮转（log-cleanup 任务体）——
// 返回清理明细（哪个文件被删/轮转——用户可见）。
func taskLogsHousekeeping(logFile string) TaskLogHousekeepingResult {
	result := TaskLogHousekeepingResult{SizeCapMB: int(getTaskLogSizeBytes() / 1024 / 1024)}
	// B3：tasks 根 + certjobs 子目录统一扫描（证书任务日志并入任务日志体系）
	dir := filepath.Join(filepath.Dir(logFile), "tasks")
	certDir := filepath.Join(dir, "certjobs")
	dirs := []string{dir}
	if certDir != dir {
		dirs = append(dirs, certDir)
	}
	type fileInfo struct {
		path string
		name string
		info os.FileInfo
	}
	var all []fileInfo
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			all = append(all, fileInfo{path: filepath.Join(d, e.Name()), name: e.Name(), info: info})
		}
	}
	if len(all) == 0 {
		return result
	}
	// LBS-B-U2（第 69 轮）：统一经 auditRetentionMonths（读取失败回退默认
	// 3 月 + warn 留痕；nil DB 时静默默认——与既有形态一致）。
	months := auditRetentionMonths()
	cutoff := time.Now().AddDate(0, -months, 0)
	// R63-P2-1：任务日志大小遵循「任务日志大小」配置项（task_log_size_mb，
	// 默认 10MB——曾硬编码 5MB 与配置/统计三方分裂）。
	sizeCap := getTaskLogSizeBytes()
	for _, f := range all {
		if f.info.ModTime().Before(cutoff) {
			if os.Remove(f.path) == nil {
				result.Deleted = append(result.Deleted, f.name)
			}
			continue
		}
		// L1-P4-1（第 67 轮）：certjobs/ 尺寸轮转归写入侧预写入轮转单一负责
		// （5 代移位）；housekeeping 对其只做保留期清理——否则孤儿超阈活动
		// 文件会被 rename 覆盖 .1 代际（双轨覆盖丢史窗口残留面）。
		if f.info.Size() > sizeCap && filepath.Dir(f.path) != certDir {
			if os.Rename(f.path, f.path+".1") == nil { // 轮转保一份
				result.Rotated = append(result.Rotated, fmt.Sprintf("%s %.1fMB>%dMB", f.name, float64(f.info.Size())/1024/1024, sizeCap/1024/1024))
			}
		}
	}
	return result
}
