package db

// 池尺寸常量与 applySQLitePool 实配对账（RollbackLeakedTx 遍历上界依赖
// 常量=池实际 maxOpen；常量漂移即补发覆盖面缺口）。

import (
	"path/filepath"
	"testing"
)

func TestPoolSizeConstants_matchAppliedPools(t *testing.T) {
	dir := t.TempDir()
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize main: %v", err)
	}
	t.Cleanup(func() { _ = Close() })
	if got := DB.Stats().MaxOpenConnections; got != MainPoolMaxOpen {
		t.Fatalf("主库 maxOpen=%d, want 常量 %d", got, MainPoolMaxOpen)
	}
	if err := InitializeMetricsDB(dir); err != nil {
		t.Fatalf("initialize metrics: %v", err)
	}
	if got := MetricsDB.Stats().MaxOpenConnections; got != MetricsPoolMaxOpen {
		t.Fatalf("metrics maxOpen=%d, want 常量 %d", got, MetricsPoolMaxOpen)
	}
	if err := InitializeAuditDB(filepath.Join(dir, "audit")); err != nil {
		t.Fatalf("initialize audit: %v", err)
	}
	if got := AuditDB.Stats().MaxOpenConnections; got != AuditPoolMaxOpen {
		t.Fatalf("audit maxOpen=%d, want 常量 %d", got, AuditPoolMaxOpen)
	}
}
