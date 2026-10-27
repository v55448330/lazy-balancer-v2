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

// reopenHandlesForTest 记录 reopenDatabaseForTest 上一次开出的句柄集（包内
// 测试串行，单一槽即可）：下一次重开只关闭这套句柄，用例入口的哨兵/外层
// 夹具句柄不受影响。最后一个句柄由 preserveDatabaseHandles 的收尾 Close()
// 关闭，故辅助本身不再注册 cleanup——否则子用例收尾会关掉后续子用例还要用的
// 句柄。
var reopenHandlesForTest []*sql.DB

// reopenDatabaseForTest 模拟进程重启：重新 Initialize，并关闭上一次由本辅助
// 开出的句柄集。Initialize 只把新句柄写入全局、不关闭进入前那一套，同一用例
// 内不关闭直接再 Initialize 会把上一套 *sql.DB（池连接与 -wal/-shm 文件句柄）
// 遗弃到进程结束——清理协议出现例外，排障噪声放大。
func reopenDatabaseForTest(t *testing.T, dir string) {
	t.Helper()
	for _, handle := range reopenHandlesForTest {
		if handle != nil {
			_ = handle.Close()
		}
	}
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	reopenHandlesForTest = []*sql.DB{DB, MetricsDB, AuditDB}
}

// 重开辅助必须真的关掉上一套句柄（否则「重复 Initialize 泄漏中间句柄」
// 只是换了调用形态）：第一次重开前的句柄在第二次重开后必须不可用。
func TestReopenDatabaseForTest_closesSupersededHandles(t *testing.T) {
	preserveDatabaseHandles(t)
	reopenDatabaseForTest(t, t.TempDir())
	first := DB
	if err := first.Ping(); err != nil {
		t.Fatalf("首次重开后的句柄不可用: %v", err)
	}
	reopenDatabaseForTest(t, t.TempDir())
	if DB == first {
		t.Fatal("第二次重开未替换全局句柄")
	}
	if err := first.Ping(); err == nil {
		t.Fatal("被替换的中间句柄未关闭（连接与 wal/shm 句柄泄漏到进程结束）")
	}
}
