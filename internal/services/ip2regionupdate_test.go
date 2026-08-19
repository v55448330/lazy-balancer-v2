package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func newTestIP2RegionManager(t *testing.T) *IP2RegionUpdateManager {
	t.Helper()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	oldLogDir := ip2RegionUpdateLogDir
	ip2RegionUpdateLogDir = t.TempDir()
	t.Cleanup(func() { ip2RegionUpdateLogDir = oldLogDir })

	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))

	m := newIP2RegionUpdateManager(func() error { return nil })
	return m
}

func seedIP2RegionVersionRow(t *testing.T, version string, autoUpdate bool) {
	t.Helper()
	if _, err := db.DB.Exec(
		"INSERT OR REPLACE INTO security_ip2region_version (id, version, auto_update) VALUES (1, ?, ?)",
		version, autoUpdate,
	); err != nil {
		t.Fatal(err)
	}
}

func ip2RegionVersionRow(t *testing.T) (version, status, message, finishedAt, lastChecked, nextUpdate string, autoUpdate bool) {
	t.Helper()
	err := db.DB.QueryRow(`SELECT version, COALESCE(update_status,''), COALESCE(message,''),
		COALESCE(finished_at,''), COALESCE(last_checked,''), COALESCE(next_update,''), auto_update
		FROM security_ip2region_version WHERE id=1`).
		Scan(&version, &status, &message, &finishedAt, &lastChecked, &nextUpdate, &autoUpdate)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func fakeIP2RegionDownload(t *testing.T, valid bool) func(context.Context, string, string) error {
	t.Helper()
	return func(_ context.Context, _ string, dest string) error {
		if !valid {
			return os.WriteFile(dest, []byte("not an xdb"), 0644)
		}
		writeTestXDB(t, dest, testSegments)
		return nil
	}
}

func TestIP2RegionUpdateRun_success(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When a manual update runs to completion
	m.run("manual")

	// Then the DB row reflects success at the new version
	version, status, message, finishedAt, _, _, _ := ip2RegionVersionRow(t)
	if version != "v3.1.0" {
		t.Fatalf("version=%q, want v3.1.0", version)
	}
	if status != "success" {
		t.Fatalf("update_status=%q, want success", status)
	}
	if message != "" {
		t.Fatalf("message=%q, want empty", message)
	}
	if finishedAt == "" {
		t.Fatal("finished_at empty after success")
	}

	// And the new xdb is in place at the live path, searcher reloaded, staging cleaned
	if _, err := os.Stat(ip2regionLivePath); err != nil {
		t.Fatalf("live xdb missing: %v", err)
	}
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1", reloads)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(ip2regionLivePath), ".staging")); !os.IsNotExist(err) {
		t.Fatal(".staging should be cleaned up")
	}
	// R39 1.2：成功后 .bak 须清理，不残留陈旧备份
	if _, err := os.Stat(ip2regionLivePath + ".bak"); !os.IsNotExist(err) {
		t.Fatal("live xdb .bak should be cleaned after success")
	}
}

func TestIP2RegionUpdateRun_skipWhenSameVersion(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.0.0", nil }
	downloadCalled := false
	m.downloadXDB = func(context.Context, string, string) error { downloadCalled = true; return nil }
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When an update finds the same commit
	m.run("auto")

	// Then nothing is downloaded and no reload happens
	if downloadCalled {
		t.Fatal("must skip download when commit equals current version")
	}
	if reloads != 0 {
		t.Fatalf("reloads=%d, want 0", reloads)
	}
	_, status, message, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q, want success", status)
	}
	if message != "已是最新版本" {
		t.Fatalf("message=%q, want 已是最新版本", message)
	}
}

func TestIP2RegionUpdateRun_fetchFailure(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	m.fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("network error") }
	downloadCalled := false
	m.downloadXDB = func(context.Context, string, string) error { downloadCalled = true; return nil }
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When the commit check fails
	m.run("manual")

	// Then the row is marked failed, nothing downloaded or reloaded
	_, status, message, finishedAt, lastChecked, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if message == "" {
		t.Fatal("message empty after failure")
	}
	if finishedAt == "" {
		t.Fatal("finished_at empty after failure")
	}
	if lastChecked == "" {
		t.Fatal("last_checked should be recorded on fetch failure")
	}
	if downloadCalled {
		t.Fatal("download must not run when fetch fails")
	}
	if reloads != 0 {
		t.Fatalf("reloads=%d, want 0", reloads)
	}
}

func TestIP2RegionUpdateRun_invalidDownloadFails(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	oldLive := "old-live-content"
	if err := os.WriteFile(ip2regionLivePath, []byte(oldLive), 0644); err != nil {
		t.Fatal(err)
	}

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, false)
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When the downloaded file fails validation
	m.run("manual")

	// Then the update fails and the old live file is untouched
	_, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	data, err := os.ReadFile(ip2regionLivePath)
	if err != nil || string(data) != oldLive {
		t.Fatalf("live xdb was modified on failed update: %q, %v", data, err)
	}
	if reloads != 0 {
		t.Fatalf("reloads=%d, want 0", reloads)
	}
}

func TestIP2RegionUpdateRun_reloadFailureRollsBackXDB(t *testing.T) {
	// Given 一个已安装的旧 xdb 与一个必然失败一次的 reloader（镜像 CRS fail() 的
	// restoreBackup+重试路径，R39 1.2）：reloader 失败时磁盘不得停留在新库、DB
	// 记录旧版本+failed 的不一致状态
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	oldLive := "old-live-content"
	if err := os.WriteFile(ip2regionLivePath, []byte(oldLive), 0644); err != nil {
		t.Fatal(err)
	}

	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	reloads := 0
	m.reloader = func() error {
		reloads++
		if reloads == 1 {
			return errors.New("reload boom")
		}
		return nil
	}

	// When 安装后首次 reload 失败
	m.run("manual")

	// Then 旧 xdb 已还原、.bak 被回滚消费、reloader 重试一次、状态 failed
	data, err := os.ReadFile(ip2regionLivePath)
	if err != nil || string(data) != oldLive {
		t.Fatalf("live xdb not rolled back: %q, %v", data, err)
	}
	if _, err := os.Stat(ip2regionLivePath + ".bak"); !os.IsNotExist(err) {
		t.Fatal("xdb .bak should be consumed by rollback")
	}
	if reloads != 2 {
		t.Fatalf("reloads=%d, want 2 (install reload fails, rollback reload succeeds)", reloads)
	}
	_, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
}

func TestStartIP2RegionUpdate_conflictWhenRunning(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	block := make(chan struct{})
	entered := make(chan struct{})
	m.fetchLatestTag = func(context.Context) (string, error) {
		close(entered)
		<-block
		return "v3.0.0", nil
	}
	m.downloadXDB = func(context.Context, string, string) error { return nil }

	// Given a running update
	if err := m.StartUpdate("manual"); err != nil {
		t.Fatal(err)
	}
	<-entered

	// When a second update is requested
	// Then it is rejected with ErrIP2RegionUpdateRunning
	if err := m.StartUpdate("manual"); !errors.Is(err, ErrIP2RegionUpdateRunning) {
		t.Fatalf("StartUpdate()=%v, want ErrIP2RegionUpdateRunning", err)
	}
	if !m.IsRunning() {
		t.Fatal("IsRunning()=false while update in flight")
	}

	close(block)
	<-m.runDone
	if m.IsRunning() {
		t.Fatal("IsRunning()=true after run finished")
	}
}

func TestIP2RegionSchedulerTick_autoOffDoesNothing(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", false)

	fetchCalled := false
	m.fetchLatestTag = func(context.Context) (string, error) {
		fetchCalled = true
		return "v3.0.0", nil
	}

	// When the scheduler ticks with auto_update off
	m.schedulerTick(time.Now())

	// Then nothing happens and next_update stays empty
	if fetchCalled {
		t.Fatal("no update should run when auto_update is off")
	}
	_, _, _, _, _, nextUpdate, _ := ip2RegionVersionRow(t)
	if nextUpdate != "" {
		t.Fatalf("next_update=%q, want empty", nextUpdate)
	}
}

func TestIP2RegionSchedulerTick_initializesNextUpdate(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)

	fetchCalled := false
	m.fetchLatestTag = func(context.Context) (string, error) {
		fetchCalled = true
		return "v3.0.0", nil
	}

	// When the scheduler ticks with auto on and no next_update recorded
	m.schedulerTick(now)

	// Then next_update is scheduled 24h out without running immediately
	if fetchCalled {
		t.Fatal("first tick should only schedule, not run")
	}
	_, _, _, _, _, nextUpdate, _ := ip2RegionVersionRow(t)
	want := now.Add(24 * time.Hour).Format(crsTimeLayout)
	if nextUpdate != want {
		t.Fatalf("next_update=%q, want %q", nextUpdate, want)
	}
}

func TestIP2RegionSchedulerTick_runsWhenDue(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET next_update=? WHERE id=1",
		now.Add(-time.Hour).Format(crsTimeLayout)); err != nil {
		t.Fatal(err)
	}

	fetched := make(chan struct{})
	var fetchOnce func()
	fetchOnce = func() { close(fetched) }
	m.fetchLatestTag = func(context.Context) (string, error) {
		if fetchOnce != nil {
			fetchOnce()
			fetchOnce = nil
		}
		return "v3.0.0", nil // same version -> auto no-op, finishes fast
	}

	// When the scheduler ticks past next_update
	m.schedulerTick(now)

	// Then an auto update starts and next_update is pushed 24h out
	select {
	case <-fetched:
	case <-time.After(5 * time.Second):
		t.Fatal("due scheduler tick should start an auto update")
	}
	_, _, _, _, _, nextUpdate, _ := ip2RegionVersionRow(t)
	want := now.Add(24 * time.Hour).Format(crsTimeLayout)
	if nextUpdate != want {
		t.Fatalf("next_update=%q, want %q", nextUpdate, want)
	}
}

func TestIP2RegionSchedulerTick_slaveSkips(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	fetchCalled := false
	m.fetchLatestTag = func(context.Context) (string, error) {
		fetchCalled = true
		return "v3.0.0", nil
	}

	// When the scheduler ticks on a slave node
	m.schedulerTick(time.Now())

	// Then it does nothing
	if fetchCalled {
		t.Fatal("slave node must not run IP2Region updates")
	}
	_, _, _, _, _, nextUpdate, _ := ip2RegionVersionRow(t)
	if nextUpdate != "" {
		t.Fatalf("next_update=%q, want empty on slave", nextUpdate)
	}
}

func TestSetIP2RegionAutoUpdate_preservesVersion(t *testing.T) {
	m := newTestIP2RegionManager(t)
	_ = m
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	// When toggling auto update off
	if err := SetIP2RegionAutoUpdate(false); err != nil {
		t.Fatal(err)
	}

	// Then the version is preserved
	version, _, _, _, _, _, autoUpdate := ip2RegionVersionRow(t)
	if version != "v3.0.0" {
		t.Fatalf("version=%q, want preserved old-commit", version)
	}
	if autoUpdate {
		t.Fatal("auto_update should be false")
	}
}

func countIP2RegionFailedAudits(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE resource='IP2Region 数据库' AND action='更新' AND detail LIKE '%结果：失败%'").Scan(&n); err != nil {
		t.Fatalf("count failed audit entries: %v", err)
	}
	return n
}

func TestIP2RegionUpdateFail_auditsOnlyFirstFailure(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	// Given a first consecutive failure: audited once (counter 0 → 1)
	m.fail(errors.New("第一次失败"))
	if got := countIP2RegionFailedAudits(t); got != 1 {
		t.Fatalf("failed audits after 1st failure = %d, want 1", got)
	}

	// When the second consecutive failure occurs (counter 1 → 2)
	// Then no duplicate audit is written (R36 F3)
	m.fail(errors.New("第二次失败"))
	if got := countIP2RegionFailedAudits(t); got != 1 {
		t.Fatalf("failed audits after 2nd failure = %d, want 1 (no duplicate)", got)
	}
}

func TestIP2RegionUpdateFail_counterUpdateFailureDoesNotReaudit(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	// 模拟第 1 次失败已落库（计数=1、已审计）；随后计数 UPDATE 持续失败（RAISE
	// ABORT 触发器）：审计判定必须用「预读计数+1」=2，不得回退到旧计数 1 导致
	// 第 2 次失败重复写审计（R36 F3）。
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET consecutive_failures=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER ip2r_fail_counter_update BEFORE UPDATE ON security_ip2region_version
		BEGIN SELECT RAISE(ABORT, 'injected counter update failure'); END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("DROP TRIGGER IF EXISTS ip2r_fail_counter_update") })

	m.fail(errors.New("第二次失败"))

	if got := countIP2RegionFailedAudits(t); got != 0 {
		t.Fatalf("failed audits = %d, want 0（UPDATE 失败时旧代码会重复审计）", got)
	}
}

func TestWriteIP2RegionUpdateLog_rotatesAtSize(t *testing.T) {
	dir := t.TempDir()
	oldDir := ip2RegionUpdateLogDir
	ip2RegionUpdateLogDir = dir
	t.Cleanup(func() { ip2RegionUpdateLogDir = oldDir })

	path := IP2RegionUpdateLogPath()
	for i := 0; i < 2000; i++ {
		writeIP2RegionUpdateLog("INFO", "checking", "x")
	}

	// Then the primary log file exists and the size cap keeps rotation bounded
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 2*getCertJobLogSizeBytes() {
		t.Fatalf("log size=%d exceeds rotation cap", info.Size())
	}
}
