package services

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	auditLogPath         = "/app/waf/audit/audit.log"
	auditLogCheckInterval = 5 * time.Minute
)

func StartAuditLogRotation(ctx context.Context) {
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
}

func rotateAuditLogIfNeeded() {
	info, err := os.Stat(auditLogPath)
	if err != nil || info.Size() == 0 {
		return
	}
	maxBytes := getCertJobLogSizeBytes()
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
