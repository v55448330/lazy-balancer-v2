package services

// 业务驱动任务的调度对齐：读失败（库不可读/未初始化）不得把一次读失败固化
// 为一个独立于业务开关的「调度关闭」态——保持上一次生效态并登记周期重试，
// 读恢复即收敛到库实态。tick 侧 EnabledFn 自身仍 fail-closed（本轮不跑、
// 下轮重新求值）。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// queryFailing*：一切查询 Prepare 即失败——QueryRow().Scan 恒返回 err。
type queryFailingConnector struct{}

func (queryFailingConnector) Connect(context.Context) (driver.Conn, error) {
	return queryFailingConn{}, nil
}

func (queryFailingConnector) Driver() driver.Driver { return queryFailingDriver{} }

type queryFailingDriver struct{}

func (queryFailingDriver) Open(string) (driver.Conn, error) { return queryFailingConn{}, nil }

type queryFailingConn struct{}

func (queryFailingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("注入的查询失败")
}

func (queryFailingConn) Close() error { return nil }

func (queryFailingConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

// swapBrokenDB 把 db.DB 与后台句柄（db.SetDB）一起换成恒失败驱动——后台
// 循环按契约只读 atomic 句柄，只换 db.DB 的用例不会命中故障路径。
// （LIFO：本清理先于夹具清理跑，恢复真实 DB 后再 StopTaskEngine/db.Close）。
func swapBrokenDB(t *testing.T) {
	t.Helper()
	broken := sql.OpenDB(queryFailingConnector{})
	t.Cleanup(func() { _ = broken.Close() })
	orig, origCurrent := db.DB, db.GetDB()
	db.DB = broken
	db.SetDB(broken)
	t.Cleanup(func() {
		db.DB = orig
		db.SetDB(origCurrent)
	})
}

func loopOnOf(t *testing.T, te *taskengine.Engine, id string) bool {
	t.Helper()
	m, ok := te.Lookup(id)
	if !ok {
		t.Fatalf("task %s 未注册", id)
	}
	return m.LoopOn
}

func enableAllBusinessDriversForTest(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`UPDATE global_config SET threat_auto_update=1, crawler_auto_update=1, auto_backup_enabled=1, autoban_enabled=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET auto_update=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET auto_update=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
}

var allBusinessDriverIDs = []string{"threat", "crs", "ip2region", "crawlerbot-update", "auto-backup", AutobanTaskID}

// Given 业务驱动任务的一次读失败（查询恒失败）。
// When 调度对齐。
// Then 上一次生效的调度态保持不变，并登记待重试——不得把读失败固化为关闭。
func TestTaskEngineWire_driverReadFailureKeepsPreviousLoopState(t *testing.T) {
	te := newWireTestEngine(t)
	enableAllBusinessDriversForTest(t)
	t.Cleanup(func() { businessDriverSyncPending.Store(false) })
	ids := allBusinessDriverIDs
	SyncBusinessTaskDrivers()
	before := map[string]bool{}
	for _, id := range ids {
		before[id] = loopOnOf(t, te, id)
		if !before[id] {
			t.Fatalf("前置：%s 必须处于启用且调度开启态，避免 false 假绿", id)
		}
	}

	swapBrokenDB(t)
	SyncBusinessTaskDrivers()
	for _, id := range ids {
		if got := loopOnOf(t, te, id); got != before[id] {
			t.Fatalf("%s 读失败改写了调度态：%v → %v（应保留上一次生效态）", id, before[id], got)
		}
	}
	if !businessDriverSyncPending.Load() {
		t.Fatal("读失败后应登记待重试（周期对账据此收敛）")
	}
}

// Given 一次读失败后库恢复，且故障期间业务开关改为关闭。
// When 周期重试入口再次对齐。
// Then 调度态收敛到库实态，待重试标记清除。
func TestTaskEngineWire_driverReadRecoveryConverges(t *testing.T) {
	te := newWireTestEngine(t)
	t.Cleanup(func() { businessDriverSyncPending.Store(false) })
	SyncBusinessTaskDrivers()
	if !loopOnOf(t, te, "crs") {
		t.Fatal("前置：crs 默认开启自动更新")
	}

	orig, origCurrent := db.DB, db.GetDB()
	broken := sql.OpenDB(queryFailingConnector{})
	db.DB = broken
	db.SetDB(broken)
	SyncBusinessTaskDrivers()
	if !businessDriverSyncPending.Load() {
		t.Fatal("读失败后应登记待重试")
	}
	// 恢复真实库（故障期间的业务写入由其中一行体现）。
	db.DB = orig
	db.SetDB(origCurrent)
	_ = broken.Close()
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET auto_update=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	retryPendingBusinessTaskDrivers()
	if loopOnOf(t, te, "crs") {
		t.Fatal("读恢复后应把调度态收敛到 auto_update=0（停止）")
	}
	if businessDriverSyncPending.Load() {
		t.Fatal("全部读取恢复后应清除待重试标记")
	}
}

// Given db.DB 未初始化（半初始化/降级形态）。
// When 调度对齐与元数据读取。
// Then 不 panic，且调度态保持原值（读不到 ≠ 确认关闭）。
func TestTaskEngineWire_nilDBKeepsLoopState(t *testing.T) {
	te := newWireTestEngine(t)
	enableAllBusinessDriversForTest(t)
	t.Cleanup(func() { businessDriverSyncPending.Store(false) })
	ids := allBusinessDriverIDs
	SyncBusinessTaskDrivers()
	before := map[string]bool{}
	for _, id := range ids {
		before[id] = loopOnOf(t, te, id)
		if !before[id] {
			t.Fatalf("前置：%s 必须处于启用且调度开启态，避免 false 假绿", id)
		}
	}

	orig, origCurrent := db.DB, db.GetDB()
	db.DB = nil
	db.SetDB(nil)
	t.Cleanup(func() { db.DB = orig; db.SetDB(origCurrent) })
	SyncBusinessTaskDrivers()
	for _, id := range ids {
		if got := loopOnOf(t, te, id); got != before[id] {
			t.Fatalf("%s nil 库时调度态被改写：%v → %v", id, before[id], got)
		}
	}
	if !businessDriverSyncPending.Load() {
		t.Fatal("nil 库应登记待重试")
	}
}
