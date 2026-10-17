package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func newTestCRSManager(t *testing.T) *CRSUpdateManager {
	stubUpdateRetrySleep(t) // 任务内重试等待即时化（30s/60s 真睡会拖垮失败路径测试）
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}

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

func fakeCRSDownload(t *testing.T, files map[string]string) func(context.Context, string, string, downloadProgressFunc) error {
	t.Helper()
	return func(_ context.Context, _ string, dest string, _ downloadProgressFunc) error {
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
	m.downloadTarball = func(context.Context, string, string, downloadProgressFunc) error {
		return errors.New("no network in test")
	}

	// Given a running update
	if _, err := m.StartUpdate("manual", nil); err != nil {
		t.Fatal(err)
	}
	<-entered

	// When a second update is requested
	// Then it is rejected with ErrCRSUpdateRunning
	if _, err := m.StartUpdate("manual", nil); !errors.Is(err, ErrCRSUpdateRunning) {
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
	m.run("manual", nil)

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
	if _, err := os.Stat(crsTransientPath(m.crsDir, ".staging")); !os.IsNotExist(err) {
		t.Fatal(".staging should be cleaned up")
	}
	if _, err := os.Stat(crsTransientPath(m.crsDir, "rules.bak")); !os.IsNotExist(err) {
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
	m.run("manual", nil)

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
	m.run("manual", nil)

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
	if _, err := os.Stat(crsTransientPath(m.crsDir, "rules.bak")); !os.IsNotExist(err) {
		t.Fatal("rules.bak should be cleaned up after restore")
	}
}

func TestCRSUpdateRun_autoSkipsWhenTagEqualsCurrent(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.14.0", nil }
	downloadCalled := false
	m.downloadTarball = func(context.Context, string, string, downloadProgressFunc) error {
		downloadCalled = true
		return nil
	}

	// When an auto update finds the same version
	m.run("auto", nil)

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
	m.downloadTarball = func(context.Context, string, string, downloadProgressFunc) error {
		downloadCalled = true
		return nil
	}
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	// When a manual update finds the same version
	m.run("manual", nil)

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

func countCRSUpdateFailedAudits(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE resource='CRS规则库' AND action='更新失败'").Scan(&n); err != nil {
		t.Fatalf("count failed audit entries: %v", err)
	}
	return n
}

// R62 U1-P3-2（2026-09-29 裁定口径）：操作审计由 run() 的 defer 每轮单记——
// fail() 本体零审计（曾内联「仅首败审计」R35 I1，与 defer 双记已撤）。
func TestCRSUpdateFail_auditRecordedByRunDeferPerRun(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)

	// fail() 直调不产生操作审计（计数器职责保留）
	m.fail(errors.New("第一次失败"), false)
	if got := countCRSUpdateFailedAudits(t); got != 0 {
		t.Fatalf("fail() 直调应零审计, got %d", got)
	}

	// 经 run() 的失败轮：每轮恰 1 条（defer 单记——手动/自动同一审计）
	m.fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("查询失败") }
	m.run("auto", nil)
	if got := countCRSUpdateFailedAudits(t); got != 1 {
		t.Fatalf("一次失败 run 应 1 条审计, got %d", got)
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

// R69（用户报告）：开关开启即写 next_update（对齐 IP2Region）——此前只翻标志，
// 「下次更新」显示 — 直到调度器首 tick；关闭清空。
func TestSetCRSAutoUpdate_schedulesNextUpdate(t *testing.T) {
	newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", false)

	if err := SetCRSAutoUpdate(true); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, _, nextUpdate, _ := crsVersionRow(t)
	if nextUpdate == "" {
		t.Fatal("开启自动更新后 next_update 为空——「下次更新」将显示 — 直到调度器首 tick")
	}

	if err := SetCRSAutoUpdate(false); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, _, nextUpdate, _ = crsVersionRow(t)
	if nextUpdate != "" {
		t.Fatalf("关闭自动更新后 next_update=%q, want 空", nextUpdate)
	}
}

// 排程槽生命周期（2026-10-11 用户裁定，取代 R69 旧口径）：手动触发成功
// **不刷新** next_update——手动执行不得改变下一次预约执行时间，空槽亦不
// 补写（预约由排程保存/启动武装路径建立）；auto_update=0 保持空。
func TestCRSRun_manualSuccessKeepsNextUpdate(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.14.0", nil }

	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	<-done

	_, status, _, _, _, nextUpdate, _ := crsVersionRow(t)
	if status != "success" {
		t.Fatalf("status=%q, want success", status)
	}
	if nextUpdate != "" {
		t.Fatalf("手动成功不得写 next_update（预约不可被手动改变，got %q）", nextUpdate)
	}

	// auto_update=0：成功不排程
	seedCRSVersionRow(t, "v4.14.0", false)
	done, err = m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	_, _, _, _, _, nextUpdate, _ = crsVersionRow(t)
	if nextUpdate != "" {
		t.Fatalf("auto_update=0 时成功不应写 next_update（got %q）", nextUpdate)
	}
}

// U2-66-05（第 66 轮审计）：demote 竞态从节点中止口径对齐威胁族——起点角色
// 复查中止须落 skipped 终态并审计「更新跳过」，不得记「更新失败」（从节点
// 中止是正常语义，非故障）。
func TestCRSUpdateRun_slaveAbortsSkipSemantics(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.14.0", nil }

	// 经 StartUpdate（生产入口）驱动：state 置 trigger 后 StatusSnapshot 读内存
	// 终态（直调 run() 时 state 无 trigger 会回退行状态，观察不到中止终态）。
	done, err := m.StartUpdate("auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	<-done

	snap := m.StatusSnapshot()
	if snap.Status != "skipped" {
		t.Fatalf("status=%q, want skipped（从节点中止是跳过语义，对齐威胁族）", snap.Status)
	}
	var failed, skipped int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE resource='CRS规则库' AND action='更新失败'").Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE resource='CRS规则库' AND detail LIKE '%更新跳过%'").Scan(&skipped); err != nil {
		t.Fatal(err)
	}
	if failed != 0 || skipped != 1 {
		t.Fatalf("failed=%d skipped=%d, want 0/1（从节点中止不得记更新失败）", failed, skipped)
	}
}

func TestCRSUpdateRun_usesTaskRunStartedAt(t *testing.T) {
	// Given：task_runs 预插行使用配置时区墙钟，期望业务表存同一瞬间的 UTC。
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	m.fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("stop after start") }
	runID, wantUTC := seedTaskRunForTime(t, "crs", "2026-10-17 14:09:17")

	// When：经生产 StartUpdate 入口运行。
	done, err := m.StartUpdate("manual", &taskengine.RunContext{Ctx: context.Background(), RunID: runID, Trigger: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	<-done

	// Then：版本行 started_at 与 task_runs 是同一瞬间，不得另取墙钟。
	var startedAt string
	if err := db.DB.QueryRow(`SELECT COALESCE(started_at,'') FROM security_crs_version WHERE id=1`).Scan(&startedAt); err != nil {
		t.Fatal(err)
	}
	if startedAt != wantUTC {
		t.Fatalf("started_at=%q, want task_runs 同源 UTC %q", startedAt, wantUTC)
	}
}
