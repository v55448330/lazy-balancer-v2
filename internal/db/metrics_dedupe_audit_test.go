package db

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitMetricsSchema_duplicateEventsLeaveSystemAudit(t *testing.T) {
	metrics, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = metrics.Close() })
	if err := initMetricsSchema(metrics); err != nil {
		t.Fatalf("initialize schema: %v", err)
	}
	if _, err := metrics.Exec(`DROP INDEX idx_security_events_transaction;
		INSERT INTO security_events (transaction_id,client_ip) VALUES
		('duplicate-transaction','10.0.0.1'),('duplicate-transaction','10.0.0.2'),
		('second-duplicate','10.0.0.3'),('second-duplicate','10.0.0.4')`); err != nil {
		t.Fatalf("seed duplicates: %v", err)
	}
	drainSystemAuditBuffer()
	t.Cleanup(func() { drainSystemAuditBuffer() })

	if err := initMetricsSchema(metrics); err != nil {
		t.Fatalf("dedupe: %v", err)
	}

	entries := drainSystemAuditBuffer()
	if len(entries) != 1 {
		t.Fatalf("system audit entries=%d, want 1: %+v", len(entries), entries)
	}
	entry := entries[0]
	if entry.action != "启动迁移" || entry.resource != "安全事件" {
		t.Fatalf("audit identity=%q/%q, want 启动迁移/安全事件", entry.action, entry.resource)
	}
	for _, want := range []string{"删除 2 行", "duplicate-transaction", "second-duplicate", "最早"} {
		if !strings.Contains(entry.detail, want) {
			t.Fatalf("audit detail=%q, missing %q", entry.detail, want)
		}
	}

	if err := initMetricsSchema(metrics); err != nil {
		t.Fatalf("idempotent rerun: %v", err)
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("idempotent rerun added audit: %+v", entries)
	}
}
