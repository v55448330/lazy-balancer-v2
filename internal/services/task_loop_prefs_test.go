package services

// 调度开关持久化（节点本地）——用户显式停止的任务在
// 进程重启后不得被默认启动清单复活；业务驱动任务以业务字段为唯一事实源，
// 不写偏好。内部自动唤醒可以临时恢复运行，但不得改写用户偏好。

import (
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func taskRunCountForTest(t *testing.T, taskID string) int {
	t.Helper()
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id=?`, taskID).Scan(&n); err != nil {
		t.Fatalf("count task_runs(%s): %v", taskID, err)
	}
	return n
}

func reinitTaskEngineForTest(t *testing.T) *taskengine.Engine {
	t.Helper()
	StopTaskEngine()
	return InitTaskEngine("", t.TempDir()+"/app.log")
}

// Given 用户停止 audit-retention 并落偏好；When 重新初始化引擎；
// Then 仍为停止态，且不产生首轮执行。
func TestTaskLoopPrefs_stoppedTaskSurvivesReinitWithoutFirstRun(t *testing.T) {
	te := newWireTestEngine(t)
	te.StopLoop("audit-retention")
	if err := RecordTaskLoopPref("audit-retention", false); err != nil {
		t.Fatalf("record pref: %v", err)
	}
	before := taskRunCountForTest(t, "audit-retention")

	te2 := reinitTaskEngineForTest(t)
	if te2.IsRunning("audit-retention") {
		t.Fatal("重启后 audit-retention 应为停止态（用户显式停止不得被默认启动清单复活）")
	}
	if after := taskRunCountForTest(t, "audit-retention"); after != before {
		t.Fatalf("停止态任务不得首轮执行：task_runs %d -> %d", before, after)
	}
}

// Given 用户主动开启默认关闭的 cert-waiting-ca；When 重新初始化；
// Then 恢复为运行态。
func TestTaskLoopPrefs_userEnabledNonDefaultTaskStartsAfterReinit(t *testing.T) {
	te := newWireTestEngine(t)
	if te.IsRunning("cert-waiting-ca") {
		t.Fatal("前置态：cert-waiting-ca 默认关闭")
	}
	if err := RecordTaskLoopPref("cert-waiting-ca", true); err != nil {
		t.Fatalf("record pref: %v", err)
	}
	te2 := reinitTaskEngineForTest(t)
	if !te2.IsRunning("cert-waiting-ca") {
		t.Fatal("用户主动开启的 cert-waiting-ca 应在重启后恢复调度")
	}
}

// Given 直接写入业务驱动任务（threat）的偏好行；When 套用偏好；
// Then 不改动业务驱动任务的调度（业务字段是唯一事实源）。
func TestTaskLoopPrefs_businessDrivenTaskIgnoresPreference(t *testing.T) {
	te := newWireTestEngine(t)
	if _, err := db.DB.Exec(`INSERT INTO task_loop_prefs (task_id, enabled) VALUES ('threat', 0)
		ON CONFLICT(task_id) DO UPDATE SET enabled=excluded.enabled`); err != nil {
		t.Fatal(err)
	}
	was := te.IsRunning("threat")
	applyTaskLoopPrefs(te, loadTaskLoopPrefs())
	if got := te.IsRunning("threat"); got != was {
		t.Fatalf("业务驱动任务 threat 的调度被偏好改写：%v -> %v", was, got)
	}
}

// Given 用户停止 cert-waiting-ca 并落偏好；When 入队唤醒临时恢复运行；
// Then 偏好仍为停止，重新初始化后回到停止态（自动唤醒不得改写用户偏好）。
func TestTaskLoopPrefs_internalWakeDoesNotRewritePreference(t *testing.T) {
	te := newWireTestEngine(t)
	te.StopLoop("cert-waiting-ca")
	if err := RecordTaskLoopPref("cert-waiting-ca", false); err != nil {
		t.Fatalf("record pref: %v", err)
	}
	WakeCertWaitingCAForEnqueuedJob()
	if !te.IsRunning("cert-waiting-ca") {
		t.Fatal("有活唤醒应临时恢复运行（现有 历史问题 语义）")
	}
	if enabled, ok := loadTaskLoopPrefs()["cert-waiting-ca"]; !ok || enabled {
		t.Fatalf("内部唤醒不得改写用户偏好：enabled=%v found=%v", enabled, ok)
	}
	te2 := reinitTaskEngineForTest(t)
	if te2.IsRunning("cert-waiting-ca") {
		t.Fatal("重新初始化后应回到用户停止态")
	}
}

// Given 并发写入同一任务偏好；When 重复套用与重复初始化；
// Then 表中仅一行、状态幂等且无错误。
func TestTaskLoopPrefs_concurrentWriteAndRepeatedInitIdempotent(t *testing.T) {
	te := newWireTestEngine(t)
	const id = "log-cleanup"
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- RecordTaskLoopPref(id, false)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent record: %v", err)
		}
	}
	for range 3 {
		applyTaskLoopPrefs(te, loadTaskLoopPrefs())
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_loop_prefs WHERE task_id=?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("task_loop_prefs 行数=%d, want 1", n)
	}
	te2 := reinitTaskEngineForTest(t)
	if te2.IsRunning(id) {
		t.Fatal("重复初始化后用户停止态应保持")
	}
	te3 := reinitTaskEngineForTest(t)
	if te3.IsRunning(id) {
		t.Fatal("再次初始化后用户停止态应保持（幂等）")
	}
}

func TestTaskLoopPrefs_stoppedDaemonDoesNotStartOnReinit(t *testing.T) {
	te := newWireTestEngine(t)
	te.StopLoop("cluster-sync")
	if err := RecordTaskLoopPref("cluster-sync", false); err != nil {
		t.Fatalf("record pref: %v", err)
	}
	before := taskRunCountForTest(t, "cluster-sync")

	te2 := reinitTaskEngineForTest(t)
	if te2.IsRunning("cluster-sync") {
		t.Fatal("显式停止的 daemon 不得在重启时被默认启动清单复活")
	}
	if after := taskRunCountForTest(t, "cluster-sync"); after != before {
		t.Fatalf("停止态 daemon 不得产生启动记录：task_runs %d -> %d", before, after)
	}
}

// Given 偏好表里有注册表外的残留行（升级删任务/改名遗留）。
// When 启动期套用偏好。
// Then 残留行被清理（此前静默跳过且每次启动加载，属域外状态）；已注册任务
// 的偏好不受影响。同时 updated_at 走配置时区墙钟（非 SQLite UTC datetime）。
func TestTaskLoopPrefs_staleRowPurgedAndTimestampUsesConfigWallClock(t *testing.T) {
	te := newWireTestEngine(t)
	if _, err := db.DB.Exec(`INSERT INTO task_loop_prefs (task_id, enabled, updated_at) VALUES ('removed-task-from-old-version', 1, '2000-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	applyTaskLoopPrefs(te, loadTaskLoopPrefs())
	var stale int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_loop_prefs WHERE task_id='removed-task-from-old-version'`).Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if stale != 0 {
		t.Fatalf("注册表外残留行未被清理: %d", stale)
	}

	// 时间列与同域口径同源：写入值必须接近当前配置时区墙钟（±1 分钟），
	// 而不是 UTC datetime('now')（在非 UTC 时区下相差整小时）。
	if err := RecordTaskLoopPref("audit-retention", false); err != nil {
		t.Fatalf("record pref: %v", err)
	}
	var updatedAt string
	if err := db.DB.QueryRow(`SELECT updated_at FROM task_loop_prefs WHERE task_id='audit-retention'`).Scan(&updatedAt); err != nil {
		t.Fatal(err)
	}
	got, err := time.ParseInLocation("2006-01-02 15:04:05", updatedAt, CurrentLocation())
	if err != nil {
		t.Fatalf("updated_at=%q 不可按配置时区解析: %v", updatedAt, err)
	}
	if delta := time.Since(got); delta > time.Minute || delta < -time.Minute {
		t.Fatalf("updated_at=%q 与配置时区墙钟相差 %v（应为墙钟，非 UTC datetime('now')）", updatedAt, delta)
	}
}
