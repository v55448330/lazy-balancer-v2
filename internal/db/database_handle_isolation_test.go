package db

import (
	"database/sql"
	"testing"
)

// preserveDatabaseHandles 关闭本用例初始化的三库，再恢复进入前的全部
// 句柄（含 GetDB 的原子视图），避免清理顺序关闭旧库或遗留新库。
func preserveDatabaseHandles(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	oldCurrent := GetDB()
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
		SetDB(oldCurrent)
	})
}

// Initialize/SetDB 系列测试必须同时恢复三个包级句柄与原子 currentDB，
// 且只能关闭本用例新建的句柄；非 nil 哨兵可确定性暴露顺序依赖。
func TestDatabaseFixtures_restoreAllHandlesAndCloseOnlyTemporaryDBs(t *testing.T) {
	originalDB, originalMetricsDB, originalAuditDB := DB, MetricsDB, AuditDB
	originalCurrent := GetDB()
	restoreOriginal := func() {
		DB, MetricsDB, AuditDB = originalDB, originalMetricsDB, originalAuditDB
		SetDB(originalCurrent)
	}
	t.Cleanup(restoreOriginal)

	cases := []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "initialize migration", run: TestInitialize_migrates_cluster_columns_and_token_table},
		{name: "repeated initialize", run: TestInitialize_normalizesAutobanPresetDescription},
		{name: "direct SetDB", run: TestFlushAPIKeyLastUsedBatchesDirtyKeys},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mainSentinel, err := sql.Open("sqlite", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			metricsSentinel, err := sql.Open("sqlite", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			auditSentinel, err := sql.Open("sqlite", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			DB, MetricsDB, AuditDB = mainSentinel, metricsSentinel, auditSentinel
			SetDB(mainSentinel)
			t.Run("fixture", tc.run)

			if DB != mainSentinel || MetricsDB != metricsSentinel || AuditDB != auditSentinel || GetDB() != mainSentinel {
				t.Errorf("句柄恢复分叉：DB=%p/%p MetricsDB=%p/%p AuditDB=%p/%p GetDB=%p/%p",
					DB, mainSentinel, MetricsDB, metricsSentinel, AuditDB, auditSentinel, GetDB(), mainSentinel)
			}
			if err := mainSentinel.Ping(); err != nil {
				t.Errorf("进入用例前的主库哨兵被关闭: %v", err)
			}
			if err := metricsSentinel.Ping(); err != nil {
				t.Errorf("进入用例前的指标库哨兵被关闭: %v", err)
			}
			if err := auditSentinel.Ping(); err != nil {
				t.Errorf("进入用例前的审计库哨兵被关闭: %v", err)
			}

			if DB != nil && DB != mainSentinel && DB != originalDB {
				_ = DB.Close()
			}
			if MetricsDB != nil && MetricsDB != metricsSentinel && MetricsDB != originalMetricsDB {
				_ = MetricsDB.Close()
			}
			if AuditDB != nil && AuditDB != auditSentinel && AuditDB != originalAuditDB {
				_ = AuditDB.Close()
			}
			_ = mainSentinel.Close()
			_ = metricsSentinel.Close()
			_ = auditSentinel.Close()
			restoreOriginal()
		})
	}
}
