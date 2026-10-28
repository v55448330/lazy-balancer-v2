package db

import (
	"database/sql"
	"os"
	"path/filepath"
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

// InitializeAuditDB 中途失败（旧审计表迁移报错）时必须关闭刚开出的句柄并把
// 包级 AuditDB 恢复原值：半初始化的句柄留在全局变量上会让后续调用方对着
// 迁移失败/已关闭的库写入，且仍占着连接与 -wal 文件句柄。同一进程内随后
// 再次初始化必须成功——失败不得污染文件/句柄生命周期。
func TestInitializeAuditDB_restoresHandleWhenMigrationFails(t *testing.T) {
	preserveDatabaseHandles(t)
	dir := t.TempDir()
	// 主库句柄不可用是迁移首步（取连接）的确定失败形态；DATA 目录仍合法。
	closedMain, err := sql.Open("sqlite", filepath.Join(dir, "main.db"))
	if err != nil {
		t.Fatalf("open temp main database: %v", err)
	}
	if err := closedMain.Close(); err != nil {
		t.Fatalf("close temp main database: %v", err)
	}
	DB = closedMain
	AuditDB = nil

	if err := InitializeAuditDB(dir); err == nil {
		t.Fatal("审计库迁移失败必须上抛")
	}
	if AuditDB != nil {
		t.Fatalf("失败后 AuditDB 仍指向半初始化句柄 %p, want nil（恢复进入前的值）", AuditDB)
	}
	// 句柄已关闭的代理证据：WAL 模式库的 last-close 会 checkpoint 并删除 -wal，
	// 残留 -wal 说明还有连接持着该库文件。
	auditPath := filepath.Join(dir, AuditDBFilename)
	if _, err := os.Stat(auditPath + "-wal"); !os.IsNotExist(err) {
		t.Fatalf("失败后残留 %s-wal（句柄未关闭）: %v", auditPath, err)
	}

	// 同一进程内二次初始化必须成功（失败未污染库文件/全局态）。
	DB = nil
	if err := InitializeAuditDB(dir); err != nil {
		t.Fatalf("失败后的再次初始化必须成功: %v", err)
	}
	if AuditDB == nil {
		t.Fatal("再次初始化后 AuditDB 仍为 nil")
	}
	if _, err := AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES ('system','测试','操作日志','','')`); err != nil {
		t.Fatalf("再次初始化后的审计库不可写: %v", err)
	}
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
