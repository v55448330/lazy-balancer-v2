package services

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// B3（第 65 轮后裁定）：证书任务日志并入任务日志体系——挂靠
// {任务日志目录}/certjobs/（与 tasks/*.log 同根：大小上限共用
// task_log_size_mb、保留清理由 log-cleanup housekeeping 统一扫描）。
// U1-66-03≡L1-66-02：目录**惰性求值**——taskengine.LogDir() 注入恒晚于包
// 初始化，曾以包级 IIFE 固化致生产恒回退 /app/logs 根（脱离 housekeeping
// 清理面）。LogDir 未注入（测试环境）回退 /app/logs。
const legacyCertJobLogRoot = "/app/logs"

// certJobLogMigrated 旧目录一次性迁移门（U1-66-03）：SetLogDir 后首次
// 使用时把固化期写入旧根的 certjob-*.log（含轮转代 .1-.5/.gz）搬入新目录。
// atomic 而非 sync.Once：测试可复位重放（Once 值拷贝触发 vet noCopy）。
var certJobLogMigrated atomic.Bool

// CertJobLogDir 证书任务日志目录（读侧同源入口——logstats 统计与
// GetCertJobLogs 均经 CertJobLogPath/CertJobLogDir 取值）。
func CertJobLogDir() string {
	dir := taskengine.LogDir()
	if dir == "" {
		return legacyCertJobLogRoot
	}
	target := filepath.Join(dir, "certjobs")
	if certJobLogMigrated.CompareAndSwap(false, true) {
		migrateLegacyCertJobLogs(filepath.Dir(dir), target)
	}
	return target
}

// migrateLegacyCertJobLogs 一次性迁移：源=任务日志目录的父目录（容器内即
// /app/logs——tasks 的宿主根，pre-B3 与固化期 certjob-* 的实际落点）。
// best-effort：扫描/搬移失败记日志继续（旧文件残留无害——读侧已切新目录，
// 清理面按新目录扫描）；目标同名文件已存在视为新数据，跳过不覆盖。
func migrateLegacyCertJobLogs(legacyRoot, target string) {
	entries, err := os.ReadDir(legacyRoot)
	if err != nil {
		return // 旧目录不存在（全新部署）——零迁移
	}
	moved := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "certjob-") || !strings.Contains(name, ".log") {
			continue
		}
		if moved == 0 {
			// 首个待迁文件出现才建目标目录（全新部署零建目录副作用）
			if mkErr := os.MkdirAll(target, 0o755); mkErr != nil {
				certJobLogWarnf("cert job log: migrate mkdir %s failed: %v", target, mkErr)
				return
			}
		}
		dst := filepath.Join(target, name)
		if _, err := os.Stat(dst); err == nil {
			continue // 新目录已有同名文件（升级后已写入）——不覆盖
		}
		if err := os.Rename(filepath.Join(legacyRoot, name), dst); err != nil {
			certJobLogWarnf("cert job log: migrate legacy %s failed: %v", name, err)
			continue
		}
		moved++
	}
	if moved > 0 {
		Logf("info", "证书任务日志迁移完成：旧目录 %s → %s 共 %d 个文件", legacyRoot, target, moved)
	}
}

const maxRotatedFiles = 5

// certJobLogWarnf 是轮转失败告警的测试接缝（var 而非直接 log.Printf，镜像
// finalizeTimeout 等先例：测试捕获告警调用，生产代码不得改写）。
var certJobLogWarnf = log.Printf

// CertJobFileLogger writes certificate issuance logs to
// {任务日志目录}/certjobs/certjob-{ruleID}.log with size-based rotation.
// Keeps up to 5 rotated backups (.1 through .5).
type CertJobFileLogger struct {
	ruleID string
}

// certJobLogWriteLocks 按 ruleID 串行化写与轮转（C-11，2026-09-05 证书域审计
// 裁定）：每次写日志都新建实例（Issue 的 jobLogger / WriteCertJobLog*），实例级
// 锁防不了跨实例并发轮转的 check-then-rename 交错——两个实例同时越过大小阈值
// 时，后者的 os.Rename(path, path+".1") 会覆盖前者刚轮转出的 .1，丢一整代
// 历史。键空间以 ruleID 为界（规则量级），无需回收。
var certJobLogWriteLocks sync.Map // ruleID -> *sync.Mutex

func lockCertJobLog(ruleID string) *sync.Mutex {
	lock, _ := certJobLogWriteLocks.LoadOrStore(ruleID, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

// NewCertJobFileLogger creates a logger bound to a specific rule.
func NewCertJobFileLogger(ruleID string) *CertJobFileLogger {
	return &CertJobFileLogger{ruleID: ruleID}
}

// CertJobLogPath returns the log file path for the given rule ID.
func CertJobLogPath(ruleID string) string {
	return filepath.Join(CertJobLogDir(), fmt.Sprintf("certjob-%s.log", sanitizePathComponent(ruleID)))
}

func sanitizePathComponent(value string) string {
	out := make([]rune, 0, len(value))
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			out = append(out, r)
		}
	}
	return string(out)
}

func (l *CertJobFileLogger) write(level, stage, message string) {
	// C-11：跨实例按 ruleID 串行化（见 certJobLogWriteLocks 注释）。
	unlock := lockCertJobLog(l.ruleID)
	unlock.Lock()
	defer unlock.Unlock()

	path := CertJobLogPath(l.ruleID)

	timestamp := time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05")
	line := fmt.Sprintf("%s [%s] %s - %s\n", timestamp, level, stage, message)

	// L1-P4-1（第 67 轮）：轮转判定计入待写入行——size+len(line) 超阈即在写入
	// 前轮转，磁盘上活动文件恒 ≤ 上限。log-cleanup housekeeping（tasks/ 主流水，
	// taskLogsHousekeeping）对超阈文件做「rename → .1」单代覆盖式轮转：此前本
	// 写入侧仅在 size≥阈值时轮转，追加把活动文件推过阈值后、下一次写入前的窗
	// 口内，housekeeping 节拍会把活动文件 rename 覆盖既有 .1（5 代链最新一代
	// 整代丢失）。活动文件恒 ≤ 上限后 housekeeping 尺寸分支永不命中证书任务
	// 日志，轮转唯一负责方归本写入侧（5 代移位），双轨覆盖窗口根除；
	// housekeeping 的保留期清理语义不变。
	if _, err := taskengine.RotateTaskLogBeforeWrite(path, int64(len(line)), maxRotatedFiles); err != nil {
		certJobLogWarnf("cert job log: rotate %s failed: %v", path, err)
	}

	if err := os.MkdirAll(CertJobLogDir(), 0755); err != nil {
		Logf("error", "cert job log: failed to create dir: %v", err)
		return
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		Logf("error", "cert job log: failed to open %s: %v", path, err)
		return
	}
	defer f.Close()

	fmt.Fprint(f, line)
}

// Log implements the acme.Logger interface (info level).
func (l *CertJobFileLogger) Log(stage, message string) {
	l.write("INFO", stage, message)
}

// WriteCertJobLog is a package-level helper for code paths that only have a
// jobID (e.g. failJob, markJobWaitingCA). It resolves the ruleID from the
// database and delegates to a CertJobFileLogger.
func WriteCertJobLog(jobID int, level, stage, message string) {
	var ruleID string
	if err := db.DB.QueryRow("SELECT rule_id FROM cert_jobs WHERE id=?", jobID).Scan(&ruleID); err != nil {
		Logf("error", "cert job log: failed to lookup rule_id for job %d: %v", jobID, err)
		return
	}
	NewCertJobFileLogger(ruleID).write(level, stage, message)
}

func WriteCertJobLogByRule(ruleID, level, stage, message string) {
	if ruleID == "" {
		return
	}
	NewCertJobFileLogger(ruleID).write(level, stage, message)
}

func RemoveCertJobLogFiles(ruleID string) error {
	// Cert-新1(第 2 轮审计):持写锁——写路径 C-11 串行化写与轮转,但删除路径
	// 此前无锁:删除时在途签发 goroutine 尾部日志重建孤儿文件(certjob-<rule>.log)。
	lockCertJobLog(ruleID).Lock()
	defer lockCertJobLog(ruleID).Unlock()
	path := CertJobLogPath(ruleID)
	var cleanupErrors []error
	for index := 0; index <= maxRotatedFiles; index++ {
		candidate := path
		if index > 0 {
			candidate = fmt.Sprintf("%s.%d", path, index)
		}
		if err := os.Remove(candidate); err != nil && !os.IsNotExist(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("删除证书任务日志 %s: %w", candidate, err))
		}
	}
	return errors.Join(cleanupErrors...)
}
