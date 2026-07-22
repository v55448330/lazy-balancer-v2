package services

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

const certJobLogDir = "/app/logs"

const maxRotatedFiles = 5

// CertJobFileLogger writes certificate issuance logs to
// /app/logs/certjob-{ruleID}.log with size-based rotation.
// Keeps up to 5 rotated backups (.1 through .5).
type CertJobFileLogger struct {
	ruleID string
	mu     sync.Mutex
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

// getCertJobLogSizeBytes reads the configured max size (MB) from global_config.
// Returns 10 MB when unset or invalid.
func getCertJobLogSizeBytes() int64 {
	var sizeMB int
	if err := db.DB.QueryRow("SELECT COALESCE(cert_job_log_size_mb, 10) FROM global_config WHERE id = 1").Scan(&sizeMB); err != nil {
		sizeMB = 10
	}
	if sizeMB <= 0 {
		sizeMB = 10
	}
	return int64(sizeMB) * 1024 * 1024
}

func (l *CertJobFileLogger) write(level, stage, message string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	path := CertJobLogPath(l.ruleID)

	if info, err := os.Stat(path); err == nil && info.Size() >= getCertJobLogSizeBytes() {
		os.Remove(fmt.Sprintf("%s.%d", path, maxRotatedFiles))
		for i := maxRotatedFiles - 1; i >= 1; i-- {
			oldPath := fmt.Sprintf("%s.%d", path, i)
			newPath := fmt.Sprintf("%s.%d", path, i+1)
			os.Rename(oldPath, newPath)
		}
		os.Rename(path, path+".1")
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

// Log implements the acme.Logger interface (info level).
func (l *CertJobFileLogger) Log(stage, message string) {
	l.write("INFO", stage, message)
}

// LogError writes an error-level entry.
func (l *CertJobFileLogger) LogError(stage, message string) {
	l.write("ERROR", stage, message)
}

// LogWarning writes a warning-level entry.
func (l *CertJobFileLogger) LogWarning(stage, message string) {
	l.write("WARN", stage, message)
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
