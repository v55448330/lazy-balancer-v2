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

func fakeIP2RegionDownload(t *testing.T, valid bool) func(context.Context, string) error {
	t.Helper()
	return func(_ context.Context, dest string) error {
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

	m.fetchLatestTag = func(context.Context) (string, string, error) { return "v3.1.0", "sha-new123", nil }
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
}

func TestIP2RegionUpdateRun_skipWhenSameVersion(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	m.fetchLatestTag = func(context.Context) (string, string, error) { return "v3.0.0", "sha-abc123", nil }
	downloadCalled := false
	m.downloadXDB = func(context.Context, string) error { downloadCalled = true; return nil }
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

	m.fetchLatestTag = func(context.Context) (string, string, error) { return "", "", errors.New("network error") }
	downloadCalled := false
	m.downloadXDB = func(context.Context, string) error { downloadCalled = true; return nil }
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

	m.fetchLatestTag = func(context.Context) (string, string, error) { return "v3.1.0", "sha-bad123", nil }
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

func TestStartIP2RegionUpdate_conflictWhenRunning(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)

	block := make(chan struct{})
	entered := make(chan struct{})
	m.fetchLatestTag = func(context.Context) (string, string, error) {
		close(entered)
		<-block
		return "v3.0.0", "sha-abc123", nil
	}
	m.downloadXDB = func(context.Context, string) error { return nil }

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
	m.fetchLatestTag = func(context.Context) (string, string, error) {
		fetchCalled = true
		return "v3.0.0", "sha-abc123", nil
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
	m.fetchLatestTag = func(context.Context) (string, string, error) {
		fetchCalled = true
		return "v3.0.0", "sha-abc123", nil
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
	m.fetchLatestTag = func(context.Context) (string, string, error) {
		if fetchOnce != nil {
			fetchOnce()
			fetchOnce = nil
		}
		return "v3.0.0", "sha-abc123", nil // same version -> auto no-op, finishes fast
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
	m.fetchLatestTag = func(context.Context) (string, string, error) {
		fetchCalled = true
		return "v3.0.0", "sha-abc123", nil
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
