package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func newTestCRSManager(t *testing.T) *CRSUpdateManager {
	t.Helper()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	oldLogDir := crsUpdateLogDir
	crsUpdateLogDir = t.TempDir()
	t.Cleanup(func() { crsUpdateLogDir = oldLogDir })

	root := t.TempDir()
	m := newCRSUpdateManager(func() error { return nil })
	m.crsDir = filepath.Join(root, "waf", "crs")
	return m
}

func seedCRSVersionRow(t *testing.T, version string, autoUpdate bool) {
	t.Helper()
	if _, err := db.DB.Exec(
		"INSERT OR REPLACE INTO security_crs_version (id, version, auto_update) VALUES (1, ?, ?)",
		version, autoUpdate,
	); err != nil {
		t.Fatal(err)
	}
}

func crsVersionRow(t *testing.T) (version, status, message, finishedAt, lastChecked, nextUpdate string, autoUpdate bool) {
	t.Helper()
	err := db.DB.QueryRow(`SELECT version, COALESCE(update_status,''), COALESCE(message,''),
		COALESCE(finished_at,''), COALESCE(last_checked,''), COALESCE(next_update,''), auto_update
		FROM security_crs_version WHERE id=1`).
		Scan(&version, &status, &message, &finishedAt, &lastChecked, &nextUpdate, &autoUpdate)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func fakeCRSDownload(t *testing.T, files map[string]string) func(context.Context, string, string) error {
	t.Helper()
	return func(_ context.Context, _ string, dest string) error {
		return os.WriteFile(dest, buildCRSTarball(t, files), 0644)
	}
}

func TestStartCRSUpdate_conflictWhenRunning(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)

	block := make(chan struct{})
	entered := make(chan struct{})
	m.fetchLatestTag = func(context.Context) (string, error) {
		close(entered)
		<-block
		return "v9.9.9", nil
	}
	m.downloadTarball = func(context.Context, string, string) error {
		return errors.New("no network in test")
	}

	// Given a running update
	if err := m.StartUpdate("manual"); err != nil {
		t.Fatal(err)
	}
	<-entered

	// When a second update is requested
	// Then it is rejected with ErrCRSUpdateRunning
	if err := m.StartUpdate("manual"); !errors.Is(err, ErrCRSUpdateRunning) {
		t.Fatalf("StartUpdate()=%v, want ErrCRSUpdateRunning", err)
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

func TestCRSUpdateRun_success(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# tweaked")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf":     "SecRule a\nSecRule b\n",
		"coreruleset-4.15.0/rules/REQUEST-941.conf":     "SecRule c\n",
		"coreruleset-4.15.0/rules/REQUEST-942.conf":     "# comment only\n",
		"coreruleset-4.15.0/plugins/empty-config.conf":  "# plugin\n",
	})
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When a manual update runs to completion
	m.run("manual")

	// Then the DB row reflects success at the new version
	version, status, message, finishedAt, _, _, _ := crsVersionRow(t)
	if version != "v4.15.0" {
		t.Fatalf("version=%q, want v4.15.0", version)
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

	// And the live tree was swapped; the new stock setup replaced the old one
	// while the previous content moved to the overrides file and the baseline
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-901.conf")); err != nil {
		t.Fatalf("new rules not in place: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf")); !os.IsNotExist(err) {
		t.Fatal("old rules should be replaced")
	}
	setup, _ := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.conf"))
	if string(setup) != "# new setup" {
		t.Fatalf("crs-setup.conf=%q, want new stock setup", setup)
	}
	stock, _ := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.stock.conf"))
	if string(stock) != "# new setup" {
		t.Fatalf("crs-setup.stock.conf=%q, want new stock baseline", stock)
	}
	overrides, err := os.ReadFile(filepath.Join(m.crsDir, "zz-user-overrides.conf"))
	if err != nil || !strings.Contains(string(overrides), "# tweaked") {
		t.Fatalf("zz-user-overrides.conf=%q,%v, want previous setup migrated", overrides, err)
	}

	// And Caddy was reloaded once, rule count rescanned, temp files cleaned
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1 (reload moved into install)", reloads)
	}
	if got := m.RuleCount(); got != 3 {
		t.Fatalf("RuleCount()=%d, want 3", got)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, ".staging")); !os.IsNotExist(err) {
		t.Fatal(".staging should be cleaned up")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules.bak")); !os.IsNotExist(err) {
		t.Fatal("rules.bak should be cleaned up after success")
	}
}

func TestCRSUpdateRun_fetchFailure(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")

	m.fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("boom network") }
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When the version check fails
	m.run("manual")

	// Then the row is marked failed with the cause, live files untouched
	version, status, message, finishedAt, lastChecked, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if !strings.Contains(message, "boom network") {
		t.Fatalf("message=%q, want it to contain the cause", message)
	}
	if version != "v4.14.0" {
		t.Fatalf("version=%q, want unchanged v4.14.0", version)
	}
	if finishedAt == "" {
		t.Fatal("finished_at empty after failure")
	}
	if lastChecked == "" {
		t.Fatal("last_checked should be recorded even on fetch failure")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf")); err != nil {
		t.Fatal("live rules must be untouched")
	}
	if reloads != 0 {
		t.Fatalf("reloads=%d, want 0 (nothing changed)", reloads)
	}
}

func TestCRSUpdateRun_installFailureRestoresBackup(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# tweaked")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	// Tarball without crs-setup.conf.example fails staging validation.
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/rules/REQUEST-901.conf": "SecRule a\n",
	})
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When installation fails
	m.run("manual")

	// Then status is failed and the previous tree is restored + reloaded
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if message == "" {
		t.Fatal("message empty after failure")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf")); err != nil {
		t.Fatal("backup should have been restored")
	}
	setup, _ := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.conf"))
	if string(setup) != "# tweaked" {
		t.Fatalf("crs-setup.conf=%q, want preserved", setup)
	}
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1 (reload after restore)", reloads)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules.bak")); !os.IsNotExist(err) {
		t.Fatal("rules.bak should be cleaned up after restore")
	}
}

func TestCRSUpdateRun_autoSkipsWhenTagEqualsCurrent(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.14.0", nil }
	downloadCalled := false
	m.downloadTarball = func(context.Context, string, string) error {
		downloadCalled = true
		return nil
	}

	// When an auto update finds the same version
	m.run("auto")

	// Then nothing is downloaded and the skip is recorded as success
	if downloadCalled {
		t.Fatal("auto update must skip download when tag equals current version")
	}
	_, status, message, finishedAt, lastChecked, _, _ := crsVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q, want success", status)
	}
	if message != "已是最新版本" {
		t.Fatalf("message=%q, want 已是最新版本", message)
	}
	if finishedAt == "" {
		t.Fatal("finished_at empty after skip")
	}
	if lastChecked == "" {
		t.Fatal("last_checked should be recorded")
	}
}

func TestCRSUpdate_manualTriggerAtLatestSkipsDownload(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.14.0", nil }
	downloadCalled := false
	m.downloadTarball = func(context.Context, string, string) error {
		downloadCalled = true
		return nil
	}
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When a manual update finds the same version
	m.run("manual")

	// Then nothing is downloaded and Caddy is not reloaded
	if downloadCalled {
		t.Fatal("manual update must skip download when tag equals current version")
	}
	if reloads != 0 {
		t.Fatalf("reloads=%d, want 0 (nothing changed)", reloads)
	}

	// And the in-memory state reports success with the latest-version message
	snap := m.StatusSnapshot()
	if snap.Status != "success" {
		t.Fatalf("state status=%q, want success", snap.Status)
	}
	if snap.Message != "已是最新版本" {
		t.Fatalf("state message=%q, want 已是最新版本", snap.Message)
	}
	if snap.FinishedAt == "" {
		t.Fatal("state finishedAt empty after skip")
	}

	// And the DB row is persisted as a successful no-op
	_, status, message, finishedAt, lastChecked, _, _ := crsVersionRow(t)
	if status != "success" {
		t.Fatalf("update_status=%q, want success", status)
	}
	if message != "已是最新版本" {
		t.Fatalf("message=%q, want 已是最新版本", message)
	}
	if finishedAt == "" {
		t.Fatal("finished_at empty after skip")
	}
	if lastChecked == "" {
		t.Fatal("last_checked should be recorded")
	}
}

func TestCRSSchedulerTick_autoOffDoesNothing(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", false)

	fetchCalled := false
	m.fetchLatestTag = func(context.Context) (string, error) {
		fetchCalled = true
		return "v4.15.0", nil
	}

	// When the scheduler ticks with auto_update off
	m.schedulerTick(time.Now(), nil)

	// Then nothing happens and next_update stays empty
	if fetchCalled {
		t.Fatal("no update should run when auto_update is off")
	}
	_, _, _, _, _, nextUpdate, _ := crsVersionRow(t)
	if nextUpdate != "" {
		t.Fatalf("next_update=%q, want empty", nextUpdate)
	}
}

func TestCRSSchedulerTick_initializesNextUpdate(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)

	fetchCalled := false
	m.fetchLatestTag = func(context.Context) (string, error) {
		fetchCalled = true
		return "v4.15.0", nil
	}

	// When the scheduler ticks with auto on and no next_update recorded
	m.schedulerTick(now, nil)

	// Then next_update is scheduled 24h out without running immediately
	if fetchCalled {
		t.Fatal("first tick should only schedule, not run")
	}
	_, _, _, _, _, nextUpdate, _ := crsVersionRow(t)
	want := now.Add(24 * time.Hour).Format("2006-01-02 15:04:05")
	if nextUpdate != want {
		t.Fatalf("next_update=%q, want %q", nextUpdate, want)
	}
}

func TestCRSSchedulerTick_runsWhenDue(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	if _, err := db.DB.Exec("UPDATE security_crs_version SET next_update=? WHERE id=1",
		now.Add(-time.Hour).Format("2006-01-02 15:04:05")); err != nil {
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
		return "v4.14.0", nil // same version -> auto no-op, finishes fast
	}

	// When the scheduler ticks past next_update
	m.schedulerTick(now, nil)

	// Then an auto update starts and next_update is pushed 24h out
	select {
	case <-fetched:
	case <-time.After(5 * time.Second):
		t.Fatal("due scheduler tick should start an auto update")
	}
	_, _, _, _, _, nextUpdate, _ := crsVersionRow(t)
	want := now.Add(24 * time.Hour).Format("2006-01-02 15:04:05")
	if nextUpdate != want {
		t.Fatalf("next_update=%q, want %q", nextUpdate, want)
	}
}

func TestCRSSchedulerTick_slaveSkips(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	fetchCalled := false
	m.fetchLatestTag = func(context.Context) (string, error) {
		fetchCalled = true
		return "v4.15.0", nil
	}

	// When the scheduler ticks on a slave node
	m.schedulerTick(time.Now(), nil)

	// Then it does nothing
	if fetchCalled {
		t.Fatal("slave node must not run CRS updates")
	}
	_, _, _, _, _, nextUpdate, _ := crsVersionRow(t)
	if nextUpdate != "" {
		t.Fatalf("next_update=%q, want empty on slave", nextUpdate)
	}
}

func countCRSUpdateFailedAudits(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE resource='CRS规则库' AND action='更新' AND detail LIKE '%结果：失败%'").Scan(&n); err != nil {
		t.Fatalf("count failed audit entries: %v", err)
	}
	return n
}

func TestCRSUpdateFail_auditsOnlyFirstFailure(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)

	// Given a first consecutive failure: audited once (counter 0 → 1)
	m.fail(errors.New("第一次失败"), false)
	if got := countCRSUpdateFailedAudits(t); got != 1 {
		t.Fatalf("failed audits after 1st failure = %d, want 1", got)
	}

	// When the second consecutive failure occurs (counter 1 → 2)
	// Then no duplicate audit is written (R36 F3)
	m.fail(errors.New("第二次失败"), false)
	if got := countCRSUpdateFailedAudits(t); got != 1 {
		t.Fatalf("failed audits after 2nd failure = %d, want 1 (no duplicate)", got)
	}
}

func TestCRSUpdateFail_counterUpdateFailureDoesNotReaudit(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	// 模拟第 1 次失败已落库（计数=1、已审计）；随后计数 UPDATE 持续失败（RAISE
	// ABORT 触发器）：审计判定必须用「预读计数+1」=2，不得回退到旧计数 1 导致
	// 第 2 次失败重复写审计（R36 F3）。
	if _, err := db.DB.Exec("UPDATE security_crs_version SET consecutive_failures=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER crs_fail_counter_update BEFORE UPDATE ON security_crs_version
		BEGIN SELECT RAISE(ABORT, 'injected counter update failure'); END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("DROP TRIGGER IF EXISTS crs_fail_counter_update") })

	m.fail(errors.New("第二次失败"), false)

	if got := countCRSUpdateFailedAudits(t); got != 0 {
		t.Fatalf("failed audits = %d, want 0（UPDATE 失败时旧代码会重复审计）", got)
	}
}

func TestSetCRSAutoUpdate_preservesVersion(t *testing.T) {
	m := newTestCRSManager(t)
	_ = m
	seedCRSVersionRow(t, "v4.14.0", true)

	// When toggling auto update off
	if err := SetCRSAutoUpdate(false); err != nil {
		t.Fatal(err)
	}

	// Then the version is preserved
	version, _, _, _, _, _, autoUpdate := crsVersionRow(t)
	if version != "v4.14.0" {
		t.Fatalf("version=%q, want preserved v4.14.0", version)
	}
	if autoUpdate {
		t.Fatal("auto_update should be false")
	}

	// And toggling on an empty table seeds the bundled version
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := SetCRSAutoUpdate(true); err != nil {
		t.Fatal(err)
	}
	version, _, _, _, _, _, autoUpdate = crsVersionRow(t)
	if version != CRSBundledVersion {
		t.Fatalf("version=%q, want bundled %q", version, CRSBundledVersion)
	}
	if !autoUpdate {
		t.Fatal("auto_update should be true")
	}
}
