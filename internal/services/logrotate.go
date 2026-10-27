package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

var runtimeLogSizeMB atomic.Int64

var runtimeLogSizeRefresh backgroundWorker

const runtimeLogSizeRefreshLogLabel = "logrotate refresh"

// init 只落兜底阈值（100MB）。worker 不再随包初始化自启
// init 先于 main 的 db.Initialize，首次 refresh 必撞 nil 库空转，启动后
// 最长 30s 按兜底 100MB 滚动）——首次刷新由 main 在 db.Initialize 后
// 显式 StartLogRotate 触发，首读即真实库值。
func init() {
	runtimeLogSizeMB.Store(db.DefaultRuntimeLogSizeMB)
}

// logRotateRestartWaitMax 是 StartLogRotate 重启路径等待旧 worker 退出的预算
// （与关停路径 StopLogRotateWithin 的 1s 段预算同量级）。旧 worker 卡在 DB
// busy_timeout 时不得无界挂起刷新链启动——超时放弃等待并 warn，残留 goroutine
// 由下一次 Stop/进程退出收尾（与 StopLogRotateWithin 的可重启语义一致）。
const logRotateRestartWaitMax = 1 * time.Second

// StartLogRotate 启动运行日志尺寸刷新 worker（幂等：重复调用先停旧 worker）。
// 不返回 done 通道：唯一生产调用方（main 启动链）与测试都不消费——关停同步
// 语义由 StopLogRotateWithin 承担，返回一个无人读取的通道只会诱导误用。
func StartLogRotate(ctx context.Context) {
	workerCtx, done := runtimeLogSizeRefresh.replace(ctx, logRotateRestartWaitMax, runtimeLogSizeRefreshLogLabel)
	go func() {
		defer close(done)
		refresh := func() {
			database := db.GetDB()
			if database == nil {
				return
			}
			var mb int
			if err := database.QueryRow("SELECT COALESCE(runtime_log_size_mb,?) FROM global_config WHERE id=1", db.DefaultRuntimeLogSizeMB).Scan(&mb); err != nil {
				// 持久失败（如迁移窗口缺列）不再每 30s 一行 info。
				if logStateTransition("runtime-log-size-refresh", true) != "" {
					Logf("warn", "refresh runtime log size: %v", err)
				}
				return
			}
			if logStateTransition("runtime-log-size-refresh", false) != "" {
				Logf("info", "refresh runtime log size recovered")
			}
			if mb > 0 {
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
}

// StopLogRotateWithin 有界停止日志尺寸刷新 worker：cancel 后最多等待 within
// （within<=0=无界）。超时放弃等待并 warn——进程
// 退出路径用：残留 goroutine 随进程消亡，cancel/done 字段保留，worker 最终
// 退出后可再次调用完成清零（可重启语义不变）。返回 true=worker 已退出且
// 状态清零。
func StopLogRotateWithin(within time.Duration) bool {
	return runtimeLogSizeRefresh.stopWithin(within, runtimeLogSizeRefreshLogLabel)
}

// RotatingFileWriter writes to a log file and rotates it once it exceeds the
// size limit. Rotated files are suffixed with a timestamp and are subject to
// retention cleanup (log-cleanup 任务体的 RuntimeLogCleanupOnce——旧启动器
// StartRuntimeLogCleanup 已随任务引擎化退役).
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
	// LogFileEnabled 恒 true 后裸二进制部署
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

// rotatedLogTimeLayout 是轮转副本文件名的时间戳布局。测试用同一常量预建「同
// 秒碰撞」文件集——布局变更后若测试仍手抄旧布局，碰撞集与实际文件名不再重叠，
// 「恰一个副本」的断言会静默失去意义。
const rotatedLogTimeLayout = "20060102-150405"

func (w *RotatingFileWriter) rotateLocked() error {
	file := w.file
	w.file = nil // Close 失败后运行时描述符也已关闭；下轮 Write 必须能重开。
	if err := file.Close(); err != nil {
		return err
	}
	stamp := time.Now().Format(rotatedLogTimeLayout)
	rotated := fmt.Sprintf("%s.%s", w.path, stamp)
	// 同秒多次轮转的碰撞后缀原为 UnixNano()%1000
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
	err := w.file.Close()
	// 关停顺序/热切换中 Close 可能先于最后几条日志：不弃句柄时后续 Write
	// 命中 file already closed 且标准 log 会丢弃该错误（静默丢日志），也不自愈。
	// 置 nil 让 Write 走 open() 重开（与 rotateLocked 同口径）。
	w.file = nil
	return err
}

// appLogEntryInfo 是应用日志副本元数据采集的注入点（测试可注入失败形态；
// 与 auditLogCopyFile 同款测试缝）。默认即 os.DirEntry.Info。
var appLogEntryInfo = func(entry os.DirEntry) (os.FileInfo, error) { return entry.Info() }

// RuntimeCleanupResult 单轮运行日志清理结果（log-cleanup 任务日志展示明细——
// 2026-10-01 用户裁定：清理了哪个文件必须可见；单轮执行体=
// RuntimeLogCleanupOnce，由任务引擎 log-cleanup 族按 24h 节拍驱动）。
type RuntimeCleanupResult struct {
	AppRemoved int // 应用日志过期副本删除数（app.log.*）
	// AppCleanupError 应用日志副本清理的目录读取失败原因（空=正常）。
	// 目录不可读时曾静默返回 AppRemoved=0——任务日志称「删除 0 个」，
	// 与「无过期副本」不可区分；失败原因必须随摘要行与任务日志可见。
	AppCleanupError string
	// AppRemoveFailed 应用日志副本单文件删除失败数（权限/占用/IO）。
	// 曾只打应用日志、不进结果——摘要行仍称「删除 N 个」而实际残留。
	AppRemoveFailed int
	// AppInfoFailed 应用日志副本元数据读取失败数（无法判定是否过期，本轮
	// 未删除）。与任务日志侧 TaskLogHousekeepingResult.InfoFailed 同口径——
	// 此前静默跳过，失败数与正常「无过期副本」不可区分。
	AppInfoFailed int
	// RetentionMonths 本轮生效的保留月数（单一来源 auditRetentionMonths 回填，
	// 任务日志摘要行直接展示本字段——此前 wire 处自行查库复算，
	// 同值两实现会在默认值/钳位逻辑变更时与实际清理口径分裂）。
	RetentionMonths int
	// RetentionError 保留月数读取失败原因（空=正常）。非空表示本轮所有保留期
	// 删除（应用日志副本 + 任务日志）被跳过——不可逆删除不得在口径未知时
	// 按更短默认执行。
	RetentionError string
	TaskLogs       TaskLogHousekeepingResult
	// RuleLogs 孤儿规则访问日志清理明细（规则已不存在的活动文件+轮转副本）。
	// 不依赖保留期口径（按「规则是否还存活」判定），故保留月数读取失败时照常
	// 执行——规则日志此前只有事件型删除入口，失败即永久残留。
	RuleLogs RuleLogHousekeepingResult
	WafAudit []string // waf-audit 目录兜底动作明细（daemon 停机时的超阈轮转）
	// WafAuditError waf-audit 兜底轮转失败原因（空=正常）。曾完全丢弃
	// SecurityEventsPollOnce 的轮转错误——daemon 停机时审计文件无界增长这一
	// 兜底场景失效，任务日志仍称「日志清理完成」。
	WafAuditError string
}

// Err 聚合本轮全部清理失败（nil=一轮内每个清理动作都成功）。
// log-cleanup 任务体据此落 failed 终态并停用「完成」措辞——此前清理失败
// 只打应用日志、Run 恒返回 nil，任务监控恒绿（与同族 audit-retention /
// security-events-retention / metrics-orphan-cleanup 的失败上抛口径不对称）。
func (r RuntimeCleanupResult) Err() error {
	var errs []error
	if r.RetentionError != "" {
		errs = append(errs, fmt.Errorf("保留月数读取失败，本轮跳过保留期删除: %s", r.RetentionError))
	}
	if r.AppCleanupError != "" {
		errs = append(errs, fmt.Errorf("应用日志副本目录读取失败: %s", r.AppCleanupError))
	}
	if r.AppRemoveFailed > 0 {
		errs = append(errs, fmt.Errorf("应用日志副本删除失败 %d 个", r.AppRemoveFailed))
	}
	if r.AppInfoFailed > 0 {
		errs = append(errs, fmt.Errorf("应用日志副本元数据读取失败 %d 个", r.AppInfoFailed))
	}
	if r.TaskLogs.RemoveFailed > 0 {
		errs = append(errs, fmt.Errorf("任务日志删除失败 %d 个", r.TaskLogs.RemoveFailed))
	}
	if r.TaskLogs.ScanError != "" {
		errs = append(errs, fmt.Errorf("任务日志目录读取失败: %s", r.TaskLogs.ScanError))
	}
	if r.TaskLogs.InfoFailed > 0 {
		errs = append(errs, fmt.Errorf("任务日志元数据读取失败 %d 个", r.TaskLogs.InfoFailed))
	}
	if r.RuleLogs.purgedErr() != nil {
		errs = append(errs, r.RuleLogs.purgedErr())
	}
	if r.WafAuditError != "" {
		errs = append(errs, fmt.Errorf("waf-audit 兜底轮转失败: %s", r.WafAuditError))
	}
	return errors.Join(errs...)
}

// TaskLogHousekeepingResult 任务日志清理明细。
type TaskLogHousekeepingResult struct {
	Deleted []string // 超保留期删除（文件名）
	// RemoveFailed 单文件删除失败数（权限/占用/IO）。曾 `err != nil` 直接
	// 忽略——失败文件既不出现在 Deleted 也不进任何结果字段，摘要看起来
	// 只是「没有过期文件」。
	RemoveFailed int
	// ScanError 任务日志目录读取失败原因（首个；空=正常）。os.ErrNotExist
	// 视为正常空目录（首次运行/尚未创建）。此前读取失败直接 continue，
	// 任务日志称「超期删除 0 个」且任务恒 success——目录不可读与「无过期
	// 文件」不可区分，与应用日志侧 AppCleanupError 口径对齐。
	ScanError string
	// InfoFailed 文件元数据读取失败数（无法判定是否过期，本轮未删除）。
	// 此前同形静默跳过，失败数与正常「未过期」不可区分。
	InfoFailed int
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
	summary := fmt.Sprintf("任务日志：超期删除 %d 个[%s]（尺寸滚动由写入侧统一执行）", len(r.Deleted), list(r.Deleted))
	var failures []string
	if r.RemoveFailed > 0 {
		failures = append(failures, fmt.Sprintf("删除失败 %d 个", r.RemoveFailed))
	}
	if r.InfoFailed > 0 {
		failures = append(failures, fmt.Sprintf("元数据读取失败 %d 个", r.InfoFailed))
	}
	if r.ScanError != "" {
		failures = append(failures, "目录读取失败"+r.ScanError)
	}
	if len(failures) > 0 {
		summary = fmt.Sprintf("任务日志：超期删除 %d 个[%s]、%s（尺寸滚动由写入侧统一执行）",
			len(r.Deleted), list(r.Deleted), strings.Join(failures, "、"))
	}
	return summary
}

// RuntimeLogCleanupOnce 单轮清理：应用日志过期副本删除 + 任务日志统一
// 清理轮转（taskLogsHousekeeping）+ waf-audit 兜底。由任务引擎 log-cleanup
// 族驱动（自此无独立启动器）。所有失败聚合进 RuntimeCleanupResult（Err()），
// 由任务体决定 failed 终态与摘要措辞。
func RuntimeLogCleanupOnce(ctx context.Context, logFile string) RuntimeCleanupResult {
	result := RuntimeCleanupResult{}
	// waf-audit 兜底不依赖保留期口径，先独立执行（失败也照常尝试其余清理）。
	wafActions, wafErr := wafAuditHousekeeping()
	result.WafAudit = wafActions
	if wafErr != nil {
		result.WafAuditError = wafErr.Error()
	}
	// 规则访问日志孤儿兜底同样不依赖保留期口径（按「规则是否还存活」判定），
	// 先于保留期门执行——事件型删除失败后残留的规则日志不再永久占盘。
	result.RuleLogs = PurgeOrphanRuleLogs(ctx)
	// 保留期口径未知（含 nil 库）时跳过保留期删除，但不清屏其余清理：
	// 上面的 waf-audit 兜底与规则日志孤儿清理已先执行（它们不依赖保留期），
	// 库里读不到口径就一条都不删——不可逆删除不得按默认 3 月执行（用户设 12
	// 月时那是 9 个月的日志证据）。nil 库覆盖关停后 db.Close() 的形态：排空
	// 放弃的在途轮仍可能跑到这里。
	months, monthsErr := auditRetentionMonths(ctx)
	result.RetentionMonths = months
	result.TaskLogs = taskLogsHousekeepingWithRetention(logFile, months, monthsErr)
	if monthsErr != nil {
		// taskLogsHousekeepingWithRetention 内部同口径跳过删除，此处只需
		// 记录失败原因。
		result.RetentionError = monthsErr.Error()
		return result
	}
	cutoff := time.Now().AddDate(0, -months, 0)

	dir := filepath.Dir(logFile)
	base := filepath.Base(logFile) + "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		Logf("warn", "应用日志副本清理失败：读取目录 %s 失败: %v", dir, err)
		result.AppCleanupError = err.Error()
		return result
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), base) {
			continue
		}
		info, err := appLogEntryInfo(e)
		if err != nil {
			// 元数据不可读＝无法判定是否过期，本轮未删除；必须可见（与任务
			// 日志侧 InfoFailed 同口径），否则与「无过期副本」同形。
			Logf("warn", "应用日志副本清理：读取 %s 元数据失败（本轮未删除）: %v", e.Name(), err)
			result.AppInfoFailed++
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				Logf("error", "清理过期运行日志失败 %s: %v", e.Name(), err)
				result.AppRemoveFailed++
			} else {
				removed++
				Logf("info", "已清理过期运行日志 %s", e.Name())
			}
		}
	}
	result.AppRemoved = removed
	return result
}

// logCleanupRound 执行单轮清理并返回结果与任务日志摘要行——摘要行在存在任何
// 清理失败时不得称「完成」（失败轮谎报完成会把排障方向带偏，与
// audit-retention 同口径）。logFile 为空（旋转写入器打开失败）时返回零值结果
// 与显式「未启用」摘要。
func logCleanupRound(ctx context.Context, logFile string) (RuntimeCleanupResult, string) {
	// 旋转写入器打开失败（runtimeLogFile 为空，
	// main.go 已有 error 留痕）时不得让 log-cleanup 静默零动作——任务监控恒绿
	// 却没有任何留痕，排障时看不出「清理为什么没跑」。
	if logFile == "" {
		// 运行日志 writer 打开失败与 waf-audit 兜底互相独立（不同目录、不同
		// 驱动）——不得因前者跳过后者：daemon 停机时审计文件无界增长正是本
		// 兜底的存在理由。应用日志副本与任务日志仍无从扫描（需要运行日志
		// 目录），保持显式「跳过」措辞。
		res := RuntimeCleanupResult{}
		wafActions, wafErr := wafAuditHousekeeping()
		res.WafAudit = wafActions
		if wafErr != nil {
			res.WafAuditError = wafErr.Error()
		}
		// 规则访问日志孤儿兜底只需要规则日志目录与存活规则清单（与运行日志
		// 目录无关），运行日志 writer 打开失败时照常执行。
		res.RuleLogs = PurgeOrphanRuleLogs(ctx)
		line := "日志清理未启用：运行日志文件未打开（应用日志副本清理与任务日志清理跳过）"
		if len(res.WafAudit) > 0 {
			line += "；waf-audit 兜底：" + strings.Join(res.WafAudit, "、")
		}
		if len(res.RuleLogs.Purged) > 0 || res.RuleLogs.RemoveFailed > 0 || res.RuleLogs.ScanError != "" || res.RuleLogs.Remaining > 0 {
			line += "；" + res.RuleLogs.Summary()
		}
		if wafErr != nil || res.RuleLogs.purgedErr() != nil {
			return res, "日志清理未完成：" + line + "；错误：" + res.Err().Error()
		}
		return res, line
	}
	res := RuntimeLogCleanupOnce(ctx, logFile)
	if err := res.Err(); err != nil {
		return res, "日志清理未完成：" + logCleanupDetail(res) + "；错误：" + err.Error()
	}
	return res, "日志清理完成：" + logCleanupDetail(res)
}

// logCleanupDetail 摘要行的明细段（各自独立失败原因可见）。
func logCleanupDetail(res RuntimeCleanupResult) string {
	// 保留月数取 RuntimeCleanupResult 的单源回填值（与实际删除口径
	// 同源），不再在本层复算。
	var appPart string
	switch {
	case res.RetentionError != "":
		appPart = "应用日志副本未清理（保留月数读取失败，本轮跳过删除）"
	case res.AppCleanupError != "":
		// 目录不可读不得呈现为「删除 0 个」——任务日志必须留痕失败原因。
		appPart = fmt.Sprintf("应用日志副本未清理（保留 %d 月）：读取目录失败 %s", res.RetentionMonths, res.AppCleanupError)
	case res.AppRemoveFailed > 0 || res.AppInfoFailed > 0:
		failures := make([]string, 0, 2)
		if res.AppRemoveFailed > 0 {
			failures = append(failures, fmt.Sprintf("删除失败 %d 个", res.AppRemoveFailed))
		}
		if res.AppInfoFailed > 0 {
			failures = append(failures, fmt.Sprintf("元数据读取失败 %d 个", res.AppInfoFailed))
		}
		appPart = fmt.Sprintf("应用日志副本删除 %d 个、%s（保留 %d 月）", res.AppRemoved, strings.Join(failures, "、"), res.RetentionMonths)
	default:
		appPart = fmt.Sprintf("应用日志副本删除 %d 个（保留 %d 月，无过期为 0）", res.AppRemoved, res.RetentionMonths)
	}
	summary := appPart + "；" + res.TaskLogs.Summary()
	// 规则访问日志孤儿清理只在有动作/失败/积压时进摘要——每日零动作的轮次
	// 不为此加一段噪音（与 waf-audit 兜底同口径）。
	if len(res.RuleLogs.Purged) > 0 || res.RuleLogs.RemoveFailed > 0 || res.RuleLogs.ScanError != "" || res.RuleLogs.Remaining > 0 {
		summary += "；" + res.RuleLogs.Summary()
	}
	// daemon 停机时的 waf-audit 兜底动作如实进
	// 任务日志（2026-10-01 用户裁定：清理了哪个文件必须可见）；无动作时不加
	// 尾段，日志行形态不变。
	if len(res.WafAudit) > 0 {
		summary += "；waf-audit 兜底：" + strings.Join(res.WafAudit, "、")
	}
	return summary
}

// wafAuditHousekeeping waf-audit 目录超阈兜底——
// audit.log 轮转的正常驱动面是 security-events-ingestion daemon 的 2s tick
// （SecurityEventsPollOnce）；daemon 停机（任务被禁用/取消）时文件无守护
// 无界增长——写侧（Coraza 审计流，经 caddygeoip 审计写插件异步批量落盘）
// 在 Caddy 进程内持续追加，本进程不消费即只增不减。此处按 audit_log_size_mb
// 阈值在 log-cleanup 任务体（24h 节拍）内兜底：
//
//   - audit.log 超阈 → SecurityEventsPollOnce()（与 daemon tick 同锁同路径，
//     摄取+pending-delta+copytruncate 全套安全链——绝不无补采截断；daemon
//     在场时文件本不会积到阈值，触发即等价一次普通 tick，无竞争）。
//
// （耗时侧车退役——耗时随审计行内嵌流转，
// 本目录仅剩 audit.log 家族文件，无需独立截断兜底。）
//
// 返回动作明细（log-cleanup 任务日志与运行日志双写——清理了哪个文件必须
// 可见，2026-10-01 用户裁定口径）与兜底错误：SecurityEventsPollOnce 的轮转
// 错误此前被完全丢弃——daemon 停机 + 轮转失败（pending 标记损坏/复制失败）
// 时审计文件继续无界增长，而任务日志仍称「日志清理完成」、task_runs 恒绿。
func wafAuditHousekeeping() ([]string, error) {
	var actions []string
	// 任务体（24h 节拍）不在关停/导入排空预算内：无 ctx 形态读取阈值即可
	// （摄取 tick 侧的同一读必须走 ctx 版，见 getAuditLogSizeBytesContext）。
	maxBytes := auditLogSizeBytes(context.Background())
	info, statErr := os.Stat(auditLogPath)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			// 审计文件不存在（从未产生审计/已迁移）不是失败形态。
			return nil, nil
		}
		return nil, fmt.Errorf("stat %s: %w", auditLogPath, statErr)
	}
	if info.Size() < maxBytes {
		return nil, nil
	}
	sizeBefore := info.Size()
	if _, rotErr := SecurityEventsPollOnce(); rotErr != nil {
		if errors.Is(rotErr, errAuditRotationDeferred) {
			// 轮转未完成 ≠ 无需轮转：归档已就位但活文件未截断（尾部未收敛），
			// 空间未回收。摘要必须写「延迟」而不是「清理完成」——下次兜底只在
			// 24h 后，误导性完成文案会把排障方向引向别处。
			return nil, fmt.Errorf("超阈兜底轮转延迟（audit.log %d 字节 ≥ %d 字节，尾部尚未摄取，下次清理重试）: %w", sizeBefore, maxBytes, rotErr)
		}
		return nil, fmt.Errorf("超阈兜底轮转失败（audit.log %d 字节 ≥ %d 字节）: %w", sizeBefore, maxBytes, rotErr)
	}
	if after, aerr := os.Stat(auditLogPath); aerr != nil {
		return nil, fmt.Errorf("轮转后 stat %s: %w", auditLogPath, aerr)
	} else if after.Size() < sizeBefore {
		actions = append(actions, fmt.Sprintf("audit.log %.1fMB≥%dMB（摄取+轮转）",
			float64(sizeBefore)/1024/1024, maxBytes/1024/1024))
	} else if after.Size() >= maxBytes {
		// poll 成功但未回收空间（阈值缓存/外部写入使活文件仍在阈上）：不得
		// 以「无动作」呈现为完成。
		return nil, fmt.Errorf("超阈兜底轮转延迟（audit.log %d 字节仍 ≥ %d 字节，本轮未回收空间）", after.Size(), maxBytes)
	}
	for _, action := range actions {
		Logf("info", "waf-audit 兜底轮转：%s", action)
		TaskLogf("log-cleanup", "waf-audit", "兜底轮转：%s", action)
	}
	return actions, nil
}

// taskLogsHousekeepingWithRetention 以调用方给定的保留期执行任务日志清理。
// monthsErr 非空时跳过全部保留期删除（不可逆删除不得在口径未知时按更短默认
// 执行）——不变量：本函数永不在保留期未知时删除任何文件。
func taskLogsHousekeepingWithRetention(logFile string, months int, monthsErr error) TaskLogHousekeepingResult {
	result := TaskLogHousekeepingResult{}
	// tasks 根 + certjobs 子目录统一扫描（证书任务日志并入任务日志体系）
	dir := filepath.Join(filepath.Dir(logFile), "tasks")
	certDir := filepath.Join(dir, "certjobs")
	dirs := []string{dir, certDir}
	type fileInfo struct {
		path string
		dir  string
		name string
		info os.FileInfo
	}
	var all []fileInfo
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			// 目录不存在＝尚未产生任务日志（首次运行/未启用），正常空目录；
			// 其余读失败（权限/挂载/IO）必须进结果错误面，否则任务日志称
			// 「超期删除 0 个」而任务恒 success。
			if !errors.Is(err, os.ErrNotExist) {
				Logf("warn", "任务日志清理：读取目录 %s 失败: %v", d, err)
				if result.ScanError == "" {
					result.ScanError = fmt.Sprintf("%s: %v", d, err)
				}
			}
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				result.InfoFailed++
				continue
			}
			all = append(all, fileInfo{path: filepath.Join(d, e.Name()), dir: d, name: e.Name(), info: info})
		}
	}
	if len(all) == 0 {
		return result
	}
	// 保留期读取失败：本轮一个文件都不删（调用方已把错误聚合进结果）。
	if monthsErr != nil {
		return result
	}
	cutoff := time.Now().AddDate(0, -months, 0)
	// 尺寸滚动已统一归 taskengine 写入前检查（tasks/*.log 与 certjobs/ 同一
	// RotateTaskLogBeforeWrite）；本清理任务只处理保留期，不再二次滚动。
	for _, f := range all {
		if !f.info.ModTime().Before(cutoff) {
			continue
		}
		if f.dir == certDir {
			// certjobs 子目录的证书任务日志与写入侧共用 ruleID 粒度写锁
			// （certjoblog.go lockCertJobLog）——删除必须在同一把锁内重新
			// stat 再 remove。锁外拿到的 FileInfo 可能已被写侧的
			// 「stat→轮转移位→append」改写：移位后该名字指向新一代文件，无锁
			// 删除会吞掉未过期的一代（写侧并发下丢行）。
			if ruleID, ok := certJobLogRuleIDFromName(f.name); ok {
				lock := lockCertJobLog(ruleID)
				lock.Lock()
				info, statErr := os.Stat(f.path)
				removed := false
				switch {
				case statErr != nil:
					// 文件在扫描后消失＝已删除，不算失败；其余 stat 错误＝无法
					// 确认/删除，必须留痕（旧实现与「未过期」同形，静默吞掉）。
					if !errors.Is(statErr, os.ErrNotExist) {
						result.RemoveFailed++
					}
				case info.ModTime().Before(cutoff):
					if removeErr := os.Remove(f.path); removeErr != nil {
						result.RemoveFailed++
					} else {
						removed = true
					}
				}
				lock.Unlock()
				if removed {
					result.Deleted = append(result.Deleted, f.name)
				}
				continue
			}
		}
		removed, err := taskengine.RemoveTaskLogIfModifiedBefore(f.path, cutoff)
		if err != nil {
			result.RemoveFailed++
			continue
		}
		if removed {
			result.Deleted = append(result.Deleted, f.name)
		}
	}
	return result
}

// certJobLogRuleIDFromName 从证书任务日志文件名（certjob-<component>.log 及
// .N/.gz 轮转副本）解析 ruleID——与写入侧 lockCertJobLog 的键空间同源
// （写入端 ruleID 经 certJobLogFileComponent 可逆编码落文件名，这里解码回
// 原始 ID，再由 lockCertJobLog 重新编码取同一把锁）。
// 向后兼容：旧实现剔除非法字符的文件名（如 certjob-lbdot.log）不含 '%'，解码为
// 字面值返回——存量文件继续参与保留期清理与写锁串行化。
func certJobLogRuleIDFromName(name string) (string, bool) {
	if !strings.HasPrefix(name, "certjob-") {
		return "", false
	}
	stem := name
	if idx := strings.IndexByte(stem, '.'); idx >= 0 {
		stem = stem[:idx]
	}
	ruleID := strings.TrimPrefix(stem, "certjob-")
	if ruleID == "" {
		return "", false
	}
	return decodeFileComponent(ruleID), true
}
