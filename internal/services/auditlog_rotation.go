package services

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

const (
	auditLogPath          = "/app/waf/audit/audit.log"
	auditLogCheckInterval = 5 * time.Minute
)

var auditLogRotationOnce sync.Once

func StartAuditLogRotation(ctx context.Context) {
	auditLogRotationOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(auditLogCheckInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					rotateAuditLogIfNeeded()
				}
			}
		}()
	})
}

func rotateAuditLogIfNeeded() {
	info, err := os.Stat(auditLogPath)
	if err != nil || info.Size() == 0 {
		return
	}
	maxBytes := getAuditLogSizeBytes()
	if info.Size() < maxBytes {
		return
	}
	dir := filepath.Dir(auditLogPath)
	for i := 4; i >= 1; i-- {
		old := filepath.Join(dir, auditLogBaseName()+fmt.Sprintf(".%d", i))
		newer := filepath.Join(dir, auditLogBaseName()+fmt.Sprintf(".%d", i+1))
		if _, err := os.Stat(old); err == nil {
			os.Rename(old, newer)
		}
	}
	current := filepath.Join(dir, auditLogBaseName()+".1")
	if err := os.Rename(auditLogPath, current); err != nil {
		log.Printf("audit log rotation: rename failed: %v", err)
		return
	}
	log.Printf("audit log rotation: rotated %s (%d bytes → %s.1)", auditLogPath, info.Size(), auditLogBaseName())
}

func auditLogBaseName() string {
	return filepath.Base(auditLogPath)
}

func getAuditLogSizeBytes() int64 {
	var sizeMB int
	if err := db.DB.QueryRow("SELECT COALESCE(audit_log_size_mb, 10) FROM global_config WHERE id = 1").Scan(&sizeMB); err != nil {
		sizeMB = 10
	}
	if sizeMB <= 0 {
		sizeMB = 10
	}
	return int64(sizeMB) * 1024 * 1024
}
