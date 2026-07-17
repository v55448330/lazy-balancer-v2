package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
)

const auditDBFilename = "lazy-balancer-audit.db"

func InitializeAuditDB(dataDir string) error {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create audit data directory: %w", err)
	}
	path := filepath.Join(dataDir, auditDBFilename)
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
	AuditDB = auditDB
	return migrateLegacyAuditLogs(DB, path)
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
