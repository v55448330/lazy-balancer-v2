package services

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
)

var certJobLogDir = "/app/logs"

const maxRotatedFiles = 5

// certJobLogWarnf 是轮转失败告警的测试接缝（var 而非直接 log.Printf，镜像
// finalizeTimeout 等先例：测试捕获告警调用，生产代码不得改写）。
var certJobLogWarnf = log.Printf

// CertJobFileLogger writes certificate issuance logs to
// /app/logs/certjob-{ruleID}.log with size-based rotation.
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
	return filepath.Join(certJobLogDir, fmt.Sprintf("certjob-%s.log", sanitizePathComponent(ruleID)))
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

// Round 35 I-17: 缓存 cert_job_log_size_mb 配置，避免每条日志写入都查 DB。
// 缓存有效期 5 分钟，过期后下一次调用触发刷新。
var (
	certJobLogSizeCached     atomic.Int64
	certJobLogSizeCachedAt   atomic.Int64
	certJobLogSizeCacheTTLNs = int64(5 * time.Minute)
	certJobLogSizeRefreshMu  sync.Mutex
)

func getCertJobLogSizeBytes() int64 {
	now := time.Now().UnixNano()
	cachedAt := certJobLogSizeCachedAt.Load()
	if cachedAt != 0 && now-cachedAt < certJobLogSizeCacheTTLNs {
		return certJobLogSizeCached.Load()
	}
	certJobLogSizeRefreshMu.Lock()
	defer certJobLogSizeRefreshMu.Unlock()
	// Double-check after acquiring lock to avoid thundering herd.
	if cachedAt = certJobLogSizeCachedAt.Load(); cachedAt != 0 && time.Now().UnixNano()-cachedAt < certJobLogSizeCacheTTLNs {
		return certJobLogSizeCached.Load()
	}
	var sizeMB int
	if err := db.DB.QueryRow("SELECT COALESCE(cert_job_log_size_mb, 10) FROM global_config WHERE id = 1").Scan(&sizeMB); err != nil {
		sizeMB = 10
	}
	if sizeMB <= 0 {
		sizeMB = 10
	}
	bytes := int64(sizeMB) * 1024 * 1024
	certJobLogSizeCached.Store(bytes)
	certJobLogSizeCachedAt.Store(now)
	return bytes
}

func (l *CertJobFileLogger) write(level, stage, message string) {
	// C-11：跨实例按 ruleID 串行化（见 certJobLogWriteLocks 注释）。
	unlock := lockCertJobLog(l.ruleID)
	unlock.Lock()
	defer unlock.Unlock()

	path := CertJobLogPath(l.ruleID)

	if info, err := os.Stat(path); err == nil && info.Size() >= getCertJobLogSizeBytes() {
		// 轮转失败不再吞没（C-11）：留痕告警后继续追加，维持原写入可用性。
		if err := rotateCertJobLogFiles(path); err != nil {
			certJobLogWarnf("cert job log: rotate %s failed: %v", path, err)
		}
	}

	if err := os.MkdirAll(certJobLogDir, 0755); err != nil {
		log.Printf("cert job log: failed to create dir: %v", err)
		return
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("cert job log: failed to open %s: %v", path, err)
		return
	}
	defer f.Close()

	timestamp := time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05")
	fmt.Fprintf(f, "%s [%s] %s - %s\n", timestamp, level, stage, message)
}

// rotateCertJobLogFiles 把 current 逐代下移到 .1（.1→.2 … .4→.5，删除旧 .5）。
// 缺失的中间代（备份不足 maxRotatedFiles 份时的常态）按 IsNotExist 静默跳过；
// 其余错误收集上抛，由调用方留痕——此前全部丢弃，坏轮转零迹可循（C-11）。
func rotateCertJobLogFiles(path string) error {
	var errs []error
	if err := os.Remove(fmt.Sprintf("%s.%d", path, maxRotatedFiles)); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("remove %s.%d: %w", filepath.Base(path), maxRotatedFiles, err))
	}
	for i := maxRotatedFiles - 1; i >= 1; i-- {
		oldPath := fmt.Sprintf("%s.%d", path, i)
		newPath := fmt.Sprintf("%s.%d", path, i+1)
		if err := os.Rename(oldPath, newPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("shift %s.%d: %w", filepath.Base(path), i, err))
		}
	}
	if err := os.Rename(path, path+".1"); err != nil {
		errs = append(errs, fmt.Errorf("rotate current %s: %w", filepath.Base(path), err))
	}
	return errors.Join(errs...)
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
		log.Printf("cert job log: failed to lookup rule_id for job %d: %v", jobID, err)
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
