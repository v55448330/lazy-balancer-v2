package middleware

import (
	"database/sql"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// restoreTestDBHandles 复位夹具数据库句柄（夹具清理的单源序列）。
//
// db.Close() 内部会 SetDB(nil)，只还原 db.DB/MetricsDB/AuditDB 三个包级变量
// 会让 db.GetDB()（后台刷新循环等原子句柄消费方）与 db.DB（守卫装配期捕获）
// 在测试间分叉——两条读取路径可能读到不同库。任何夹具清理都必须走本函数，
// 钉测见 TestDatabaseHandleParityAfterFixtureRestore。
func restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB *sql.DB) {
	db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	db.SetDB(oldDB)
}

// newIsolatedTestDB 打开一个临时 SQLite 库并装配为进程库（db.DB + GetDB 原子
// 视图），用例结束只关闭本夹具开出的句柄、经 restoreTestDBHandles 还原进入前
// 的全部句柄。表结构/种子由各用例自行执行（不同认证链所需最小表不同）。
func newIsolatedTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", t.TempDir()+"/test.db")
	if err != nil {
		t.Fatal(err)
	}
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	db.DB = database
	db.SetDB(database)
	t.Cleanup(func() {
		_ = database.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	return database
}

// withIsolatedRateLimitBuckets 保存-清空-恢复全局限流桶表。
//
// 限流桶是进程级全局状态：用例「直接替换 entries」会让计数跨用例继承
// （-count=2 时第二轮因首轮残留计数假红），替换后不恢复又会污染后续用例。
// 本 helper 统一三种语义：用例开始前空表（确定性计数）、结束时恢复调用前
// 的表（不外泄、不吞别人状态）。
func withIsolatedRateLimitBuckets(t *testing.T) {
	t.Helper()
	loginRateBuckets.Lock()
	saved := loginRateBuckets.entries
	loginRateBuckets.entries = make(map[string]*loginRateBucket)
	loginRateBuckets.Unlock()
	t.Cleanup(func() {
		loginRateBuckets.Lock()
		loginRateBuckets.entries = saved
		loginRateBuckets.Unlock()
	})
}

// withIsolatedAPIKeyWhitelistCache 保存-清空-恢复进程级白名单解析缓存。
// 缓存是自定义有界缓存 apiKeyWhitelistCIDRCache（Range 走快照、条目有硬上限，
// 见 middleware.go），逐键快照保存现场；cleanup 先清掉用例写入再恢复调用前
// 现场，避免整表清扫类用例吞掉其他用例的预热条目。
func withIsolatedAPIKeyWhitelistCache(t *testing.T) {
	t.Helper()
	saved := make(map[string]any)
	apiKeyWhitelistCache.Range(func(key string, value any) bool {
		saved[key] = value
		return true
	})
	PurgeAllAPIKeyWhitelistCache()
	t.Cleanup(func() {
		PurgeAllAPIKeyWhitelistCache()
		for key, value := range saved {
			apiKeyWhitelistCache.Store(key, value)
		}
	})
}
