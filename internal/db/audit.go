package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"path/filepath"
	"sync"
)

const auditDBFilename = "lazy-balancer-audit.db"

func InitializeAuditDB(dataDir string) error {
	if err := secureDataDirectory(dataDir); err != nil {
		return fmt.Errorf("failed to create audit data directory: %w", err)
	}
	path := filepath.Join(dataDir, auditDBFilename)
	if err := prepareSQLiteDatabase(path); err != nil {
		return fmt.Errorf("failed to secure audit database: %w", err)
	}
	auditDB, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=30000&_synchronous=NORMAL")
	if err != nil {
		return fmt.Errorf("failed to open audit database: %w", err)
	}
	auditDB.SetMaxOpenConns(5)
	auditDB.SetMaxIdleConns(2)
	if err := auditDB.Ping(); err != nil {
		auditDB.Close()
		return fmt.Errorf("failed to ping audit database: %w", err)
	}
	if _, err := auditDB.Exec(`
		CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username VARCHAR(100),
			action VARCHAR(50) NOT NULL,
			resource VARCHAR(100),
			detail TEXT,
			ip_address VARCHAR(45),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
		CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
	`); err != nil {
		auditDB.Close()
		return fmt.Errorf("failed to create audit schema: %w", err)
	}
	if err := secureSQLiteArtifacts(path); err != nil {
		auditDB.Close()
		return fmt.Errorf("failed to secure audit database artifacts: %w", err)
	}
	AuditDB = auditDB
	if err := migrateLegacyAuditLogs(DB, path); err != nil {
		return err
	}
	flushSystemAuditLogs()
	return nil
}

// R45 F-2: 启动迁移跑在 InitializeAuditDB 之前，且 db 不能反向依赖
// services.RecordAuditLog（import 环）——迁移期的系统事件先入内存缓冲，审计库
// 就绪后统一落 audit_log 表，与 UI 操作日志同源。
type systemAuditEntry struct {
	action   string
	resource string
	detail   string
}

var systemAuditBuffer struct {
	mu      sync.Mutex
	entries []systemAuditEntry
}

func recordSystemAudit(action, resource, detail string) {
	systemAuditBuffer.mu.Lock()
	defer systemAuditBuffer.mu.Unlock()
	systemAuditBuffer.entries = append(systemAuditBuffer.entries, systemAuditEntry{action, resource, detail})
}

// flushSystemAuditLogs 将缓冲的系统事件写入审计库并清空缓冲；写失败仅留痕不阻断
// 启动，与 services.RecordAuditLog 的 best-effort 语义一致。
func flushSystemAuditLogs() {
	systemAuditBuffer.mu.Lock()
	entries := systemAuditBuffer.entries
	systemAuditBuffer.entries = nil
	systemAuditBuffer.mu.Unlock()
	if len(entries) == 0 || AuditDB == nil {
		return
	}
	for _, entry := range entries {
		if _, err := AuditDB.Exec("INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES ('system', ?, ?, ?, '')",
			entry.action, entry.resource, entry.detail); err != nil {
			log.Printf("system audit log write failed: %v", err)
		}
	}
}

func migrateLegacyAuditLogs(mainDB *sql.DB, auditPath string) error {
	if mainDB == nil {
		return nil
	}
	ctx := context.Background()
	conn, err := mainDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	var tableCount int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_log'").Scan(&tableCount); err != nil {
		return err
	}
	if tableCount == 0 {
		return nil
	}
	if _, err := conn.ExecContext(ctx, "ATTACH DATABASE ? AS audit_migration", auditPath); err != nil {
		return fmt.Errorf("failed to attach audit database: %w", err)
	}
	defer conn.ExecContext(ctx, "DETACH DATABASE audit_migration")

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO audit_migration.audit_log
		(id, username, action, resource, detail, ip_address, created_at)
		SELECT id, username, action, resource, detail, ip_address, created_at FROM main.audit_log`); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to copy audit logs: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	var mismatch int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM main.audit_log src
		WHERE NOT EXISTS (
			SELECT 1 FROM audit_migration.audit_log dst
			WHERE dst.id = src.id
			  AND dst.username IS src.username
			  AND dst.action IS src.action
			  AND dst.resource IS src.resource
			  AND dst.detail IS src.detail
			  AND dst.ip_address IS src.ip_address
			  AND dst.created_at IS src.created_at
		)`).Scan(&mismatch); err != nil {
		return fmt.Errorf("failed to verify audit migration: %w", err)
	}
	if mismatch > 0 {
		return fmt.Errorf("audit migration conflict: %d source rows differ from destination", mismatch)
	}
	if _, err := mainDB.Exec("DROP TABLE audit_log"); err != nil {
		return fmt.Errorf("failed to remove legacy audit table: %w", err)
	}
	return nil
}
