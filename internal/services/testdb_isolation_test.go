package services

// 测试用 DB 夹具：一个用例一个临时库，退出时把全局句柄还原到用例前的身份。
//
// 三处状态必须一起还原：db.DB / db.MetricsDB / db.AuditDB（同步侧读取）以及
// db.SetDB 注册的原子句柄（后台刷新循环经 db.GetDB 读取）。db.Close 内部会
// 调 SetDB(nil)，只写回三个包级变量的旧写法会让清理后仍在跑的后台循环看到
// nil 句柄——与 tz_test 的夹具同理。

import (
	"database/sql"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// setupIsolatedDB 初始化临时库并把全部全局句柄在 t.Cleanup 中还原，
// 返回新库句柄（调用方不需要时可直接忽略返回值）。
func setupIsolatedDB(t *testing.T) *sql.DB {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB, oldCurrent := db.DB, db.MetricsDB, db.AuditDB, db.GetDB()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	database := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldCurrent)
	})
	return database
}

func TestSecurityDBFixtures_restoreEveryGlobalHandle(t *testing.T) {
	originalDB, originalMetrics, originalAudit, originalCurrent := db.DB, db.MetricsDB, db.AuditDB, db.GetDB()
	t.Cleanup(func() {
		db.DB, db.MetricsDB, db.AuditDB = originalDB, originalMetrics, originalAudit
		db.SetDB(originalCurrent)
	})
	fixtures := []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "geoip helper", run: setupGeoipConfigTestDB},
		{name: "auto backup helper", run: setupAutoBackupTestDB},
		{name: "services regression helper", run: setupU05ServicesDB},
		{name: "audit cleanup helper", run: func(t *testing.T) { newAuditCleanupFixture(t, 0, 3) }},
		{name: "policy context direct init", run: func(t *testing.T) { TestLoadSecurityPolicyContext_carriesTriStateGateFields(t) }},
		{name: "reconcile direct init", run: func(t *testing.T) { TestReconcileCRSState_versionReadFailureSkipsWrites(t) }},
		{name: "task log retention direct init", run: func(t *testing.T) { TestTaskLogsHousekeeping_retentionOnlyDoesNotRotate(t) }},
		{name: "task log certjobs direct init", run: func(t *testing.T) { TestTaskLogsHousekeeping_certjobsExemptFromSizeRotation(t) }},
		{name: "security events helper", run: func(t *testing.T) {
			if err := initSecurityEventsTestDB(t, t.TempDir()); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "security enum helper", run: setupSecurityEnumTestDB},
		{name: "retention helper", run: setupSecurityEventsRetentionTestDB},
		{name: "stall helper", run: func(t *testing.T) { stallSetup(t) }},
		{name: "library sentinel direct init", run: func(t *testing.T) { TestArmSecurityLibraryFirstSlots_healsImportSentinelRow(t) }},
		{name: "rate limit direct init", run: func(t *testing.T) { TestSecurityEnumNormalizedChanges_reportsRateLimitShutdown(t) }},
		{name: "commit recovery direct init", run: func(t *testing.T) { TestSecurityEventsIngestion_commitFailureReleasesLeakedTransaction(t) }},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			sentinelDB, sentinelMetrics, sentinelAudit, sentinelCurrent := &sql.DB{}, &sql.DB{}, &sql.DB{}, &sql.DB{}
			db.DB, db.MetricsDB, db.AuditDB = sentinelDB, sentinelMetrics, sentinelAudit
			db.SetDB(sentinelCurrent)
			t.Run("fixture", fixture.run)
			if db.DB != sentinelDB || db.MetricsDB != sentinelMetrics || db.AuditDB != sentinelAudit || db.GetDB() != sentinelCurrent {
				t.Fatalf("global handles were not restored: DB=%p/%p metrics=%p/%p audit=%p/%p current=%p/%p",
					db.DB, sentinelDB, db.MetricsDB, sentinelMetrics, db.AuditDB, sentinelAudit, db.GetDB(), sentinelCurrent)
			}
		})
	}
}
