package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// redirectUpdateTestGlobals 把更新族测试的落盘路径与 DB 句柄隔离：
//   - crsSnapshotDir / downloadIntegrityPath 重定向到临时目录——否则在
//     /app/data 可写的环境（开发容器/镜像内跑测试）会污染真实数据卷：
//     同 tag 的测试 tarball 字节各不相同会触发 TOFU mismatch 假红，测试假树
//     还会覆盖真实 CRS 快照；
//   - db 句柄（含 db.SetDB 注册的原子句柄）在 Cleanup 中还原——-shuffle 单跑
//     或跨用例也不拿到已关闭/外来库。
func redirectUpdateTestGlobals(t *testing.T) {
	t.Helper()
	oldSnapshot, oldIntegrity := crsSnapshotDir, downloadIntegrityPath
	testRoot := t.TempDir()
	crsSnapshotDir = filepath.Join(testRoot, "crs-snapshot")
	downloadIntegrityPath = filepath.Join(testRoot, ".download-integrity.json")
	setupIsolatedDB(t)
	t.Cleanup(func() {
		crsSnapshotDir, downloadIntegrityPath = oldSnapshot, oldIntegrity
	})
}

func newTestCRSManager(t *testing.T) *CRSUpdateManager {
	stubUpdateRetrySleep(t) // 任务内重试等待即时化（30s/60s 真睡会拖垮失败路径测试）
	redirectUpdateTestGlobals(t)

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
	// 重载窗口内存态：reloader 执行瞬间 StatusSnapshot 必须显示 reloading
	// （对齐 ip2region 的 setStage+日志双轨——只写更新日志不改内存态时，
	// 状态端点在重载窗口仍显示进入前的阶段）。
	reloadWindowStatus := ""
	m.reloader = func() error {
		reloads++
		reloadWindowStatus = m.StatusSnapshot().Status
		return nil
	}

	// When a manual update runs to completion——走生产入口 StartUpdate
	// （StatusSnapshot 只在 trigger/startedAt 已登记时读内存态；run() 直调
	// 路径永远回退库行，观测不到重载窗口）。
	done, serr := m.StartUpdate("manual", nil)
	if serr != nil {
		t.Fatalf("StartUpdate()=%v, want nil", serr)
	}
	<-done

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
	if reloadWindowStatus != string(CRSStatusReloading) {
		t.Fatalf("重载窗口内存态=%q, want %q（重载阶段必须随更新日志双轨写入内存态）", reloadWindowStatus, CRSStatusReloading)
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

// 下载阶段失败（备份点尚未建立、live 树未触碰）不得触发还原 + 重载：
// 旧实现按「进入安装循环」置 restore=true，每次下载/校验失败都多跑一轮
// GenerateAndApplyConfig（重试场景放大），而无任何东西可还原。
func TestCRSUpdateRun_downloadFailureDoesNotReload(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = func(context.Context, string, string, downloadProgressFunc) error {
		return errors.New("boom download")
	}
	reloads := 0
	m.reloader = func() error { reloads++; return nil }

	m.run("manual", nil)

	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if !strings.Contains(message, "boom download") {
		t.Fatalf("message=%q, want it to contain the download cause", message)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf")); err != nil {
		t.Fatal("live rules must be untouched")
	}
	if reloads != 0 {
		t.Fatalf("reloads=%d, want 0（下载失败未触碰 live 树，无需还原/重载）", reloads)
	}
}

// 校验阶段失败（备份点尚未建立、live 树未触碰）：树原样保留，且不得
// 触发还原/重载——失败重试场景否则每轮多一次全量渲染（S6 口径）。
func TestCRSUpdateRun_stagingValidationFailureLeavesLiveUntouched(t *testing.T) {
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

	// Then status is failed and the previous tree is untouched (no restore/reload)
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	if message == "" {
		t.Fatal("message empty after failure")
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf")); err != nil {
		t.Fatal("live tree must be untouched before the first backup point")
	}
	setup, _ := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.conf"))
	if string(setup) != "# tweaked" {
		t.Fatalf("crs-setup.conf=%q, want preserved", setup)
	}
	if reloads != 0 {
		t.Fatalf("reloads=%d, want 0（树未被触碰，无需还原/重载）", reloads)
	}
	if _, err := os.Stat(crsTransientPath(m.crsDir, "rules.bak")); !os.IsNotExist(err) {
		t.Fatal("rules.bak must not exist when no backup was created")
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

// （2026-09-29 裁定口径）：操作审计由 run() 的 defer 每轮单记——
// fail() 本体零审计（曾内联「仅首败审计」，与 defer 双记已撤）。
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

// 计数 UPDATE 故障（触发器 RAISE ABORT 拦死 security_crs_version 全部写）下
// 单记契约不变：fail() 的计数/状态落库失败只留 ERROR 日志，run() defer 仍
// 每轮恰记 1 条「更新失败」审计、终态 failed。防回归方向=审计被挪回 fail()
// 内联（则一轮失败产 2 条：内联+defer）或被计数故障抑制（0 条）。
func TestCRSUpdateFail_counterUpdateFailureKeepsSingleAuditPerRun(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	if _, err := db.DB.Exec(`CREATE TRIGGER crs_fail_counter_update BEFORE UPDATE ON security_crs_version
		BEGIN SELECT RAISE(ABORT, 'injected counter update failure'); END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("DROP TRIGGER IF EXISTS crs_fail_counter_update") })

	m.fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("查询失败") }
	done, err := m.StartUpdate("auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	<-done

	if got := countCRSUpdateFailedAudits(t); got != 1 {
		t.Fatalf("计数更新故障的失败 run 仍应单记 1 条审计, got %d", got)
	}
	snap := m.StatusSnapshot()
	if snap.Status != string(CRSStatusFailed) {
		t.Fatalf("status=%q, want failed（计数落库故障不得抑制终态）", snap.Status)
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

	// And toggling on an empty table seeds the bundled version（清表等价于空库，
	// 不替换包级 db 句柄——嵌套 Initialize 会让清理顺序关闭错误句柄）
	if _, err := db.DB.Exec("DELETE FROM security_crs_version"); err != nil {
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

// （用户报告）：开关开启即写 next_update（对齐 IP2Region）——此前只翻标志，
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

// 排程槽生命周期：手动触发成功不得改变**既有预约**——空槽不补写（预约由
// 排程保存/启动武装路径建立）、未来槽不回拨；已过期槽必须推进（引擎成功轮已
// 消费该槽，业务不推进=停摆，见 schedule_slot_lifecycle_test.go 的
// 「过期槽上的手动成功必须推进业务槽」用例）。auto_update=0 恒不写。
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

// 安装成功分支（tag != currentVersion，走完整下载→校验→换树→写版本行）的
// 排程槽语义与「已是最新」短路不同：后者只走 recordLatestSkip，从不经过
// versionTableSlotSuccessSQL。本用例覆盖手动触发不补写空槽、auto 触发推进
// 空槽两条真实安装路径（手动成功只推进已过期槽，见
// schedule_slot_lifecycle_test.go 的同名用例组）。
func TestCRSRun_installSuccessSlotSemantics(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	files := map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf":     "SecRule init\n",
	}
	m.downloadTarball = fakeCRSDownload(t, files)
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }

	// 手动触发：安装成功但空槽不得补写（预约由排程保存/启动武装建立）。
	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	version, status, _, _, _, nextUpdate, _ := crsVersionRow(t)
	if status != "success" || version != "v4.15.0" {
		t.Fatalf("version=%q status=%q, want v4.15.0/success（必须走完整安装分支）", version, status)
	}
	if nextUpdate != "" {
		t.Fatalf("手动安装成功不得写 next_update（got %q）", nextUpdate)
	}

	// auto 触发：把当前版本拨回旧值后同一发布包再次安装成功 → 空槽被推进。
	seedCRSVersionRow(t, "v4.14.0", true)
	done, err = m.StartUpdate("auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	version, status, _, _, _, nextUpdate, _ = crsVersionRow(t)
	if status != "success" || version != "v4.15.0" {
		t.Fatalf("auto 安装 version=%q status=%q, want v4.15.0/success", version, status)
	}
	if nextUpdate == "" {
		t.Fatal("auto 触发安装成功必须推进空排程槽（下次预约不可为空）")
	}
}

// demote 竞态从节点中止口径对齐威胁族——起点角色
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

// StartUpdate 返回前必须已登记取消函数——返回后立刻 CancelRunning
// （任务引擎 CancelHook／前端连点／自动化脚本）必须命中，不得静默返回 false。
func TestStartUpdate_registersCancelBeforeReturn(t *testing.T) {
	// Given 单 P 调度：调用方在 StartUpdate 返回后立刻取消时，旧实现因 runCancel
	// 由 run goroutine 稍后登记而存在 nil 窗口（取消静默失效）。
	oldProcs := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(oldProcs) })

	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	m.fetchLatestTag = func(ctx context.Context) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}

	// When
	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !m.CancelRunning() {
		// 旧实现：run goroutine 尚未登记取消函数。让 goroutine 推进后自行取消，
		// 避免测试挂起（失败断言即 RED 证据）。
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
			if m.CancelRunning() {
				break
			}
			time.Sleep(time.Millisecond)
		}
		<-done
		t.Fatal("StartUpdate 返回后立刻 CancelRunning=false（取消函数尚未登记，取消静默失效）")
	}

	// Then 运行以 cancelled 终态结束
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("取消后运行未退出")
	}
	if got := m.StatusSnapshot().Status; got != string(CRSStatusCancelled) {
		t.Fatalf("终态=%q, want cancelled", got)
	}
}

// /：版本读取区分「行缺失→bundled」与「读失败→错误」。
func TestReadCurrentCRSVersion_rowMissingFallsBackToBundled(t *testing.T) {
	initServicesDB(t)
	if _, err := db.DB.Exec("DELETE FROM security_crs_version"); err != nil {
		t.Fatal(err)
	}
	got, err := readCurrentCRSVersion()
	if err != nil {
		t.Fatalf("行缺失不应报错: %v", err)
	}
	if got != CRSBundledVersion {
		t.Fatalf("行缺失回落=%q, want bundled %q", got, CRSBundledVersion)
	}
}

func TestReadCurrentCRSVersion_readErrorSurfaces(t *testing.T) {
	initServicesDB(t)
	if _, err := db.DB.Exec("DROP TABLE security_crs_version"); err != nil {
		t.Fatal(err)
	}
	if _, err := readCurrentCRSVersion(); err == nil {
		t.Fatal("读失败的版本读取必须返回错误（不得回落 bundled 参与更新短路）")
	}
}

// 读版本行失败时更新必须 fail-visible——旧实现以 bundled 参与
// 「已是最新」短路，远端 tag 恰等于 bundled 时更新被静默跳过。
func TestCRSUpdateRun_versionReadFailureIsVisible(t *testing.T) {
	// Given 版本行不可读（表缺失）+ 远端 tag 恰等于镜像捆绑版本
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	if _, err := db.DB.Exec("DROP TABLE security_crs_version"); err != nil {
		t.Fatal(err)
	}
	m.fetchLatestTag = func(context.Context) (string, error) { return CRSBundledVersion, nil }
	m.downloadTarball = func(context.Context, string, string, downloadProgressFunc) error {
		return errors.New("下载不应发生")
	}

	// When
	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("读版本失败后运行未退出")
	}

	// Then 显式失败（fail-visible）而非「已是最新」
	snap := m.StatusSnapshot()
	if snap.Status != string(CRSStatusFailed) {
		t.Fatalf("终态=%q, want failed（读失败不得静默跳过）", snap.Status)
	}
	if !strings.Contains(snap.Message, "读取当前 CRS 版本失败") {
		t.Fatalf("message=%q, want 版本读取失败根因", snap.Message)
	}
}

// defer 注册序不变量：running 复位 defer 必须先注册（LIFO → 最后执行），
// 审计 defer 才能在 running 仍置位时读本轮终态快照。反向注册会让复位先跑，
// 两步之间 StartUpdate 可成功进入并写 checking，旧轮审计读到下一轮状态。
// （两个 defer 在终态相同的前提下运行期不可区分，故以源码注册序钉住。）
func TestCRSUpdateRun_runningResetDeferRegisteredBeforeAudit(t *testing.T) {
	fn := serviceFunctionFromFile(t, "crsupdate.go", "runWithContext")
	order := crsRunningAuditDeferOrder(fn)
	if len(order) != 2 || order[0] != "running-reset" || order[1] != "audit" {
		t.Fatalf("defer registrations=%v, want running-reset before audit (LIFO reset last)", order)
	}
}

// Given 版本行存在且指向已安装的上游版本；另一形态是行里的 version 为空。
// When 取日志口径的当前 CRS 版本（启动载入摘要行消费）。
// Then 返回行内版本；空版本回落镜像捆绑版本——日志摘要与安装判定必须同源，
// 否则载入摘要宣称的版本与引擎实际加载的 CRS 目录不一致。
func TestCurrentCRSVersionForLog_matchesVersionRow(t *testing.T) {
	initServicesDB(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	if got := CurrentCRSVersionForLog(); got != "v4.14.0" {
		t.Fatalf("CurrentCRSVersionForLog()=%q, want v4.14.0（须与版本行同源）", got)
	}
	seedCRSVersionRow(t, "", false)
	if got := CurrentCRSVersionForLog(); got != CRSBundledVersion {
		t.Fatalf("空版本 CurrentCRSVersionForLog()=%q, want bundled %q", got, CRSBundledVersion)
	}
}

// 版本表两族（CRS / IP2Region）的「排程槽未推进」记录器与 IsRunning 必须是
// 单一实现：曾各持一份逐字相同的代码（仅日志前缀不同），任一侧改动都会让
// 两族的调度契约（成功轮未推进槽=按失败返回、running 原子置位/复位）漂移。
func TestVersionTableSlotRecorder_singleSourceSemantics(t *testing.T) {
	var rec versionTableSlotRecorder
	if err := rec.get(); err != nil {
		t.Fatalf("初始原因=%v, want nil", err)
	}
	cause := errors.New("排程不可读")
	rec.set(cause, crsUpdateLogFamily)
	if err := rec.get(); !errors.Is(err, cause) {
		t.Fatalf("set 后读取=%v, want %v", err, cause)
	}
	// 每次运行起点清空：上一轮的读失败不得让本轮成功轮仍被判失败。
	rec.set(nil, crsUpdateLogFamily)
	if err := rec.get(); err != nil {
		t.Fatalf("清空后读取=%v, want nil", err)
	}

	var mu sync.Mutex
	running := false
	if versionTableTaskIsRunning(&mu, &running) {
		t.Fatal("running=false 时必须返回 false")
	}
	running = true
	if !versionTableTaskIsRunning(&mu, &running) {
		t.Fatal("running=true 时必须返回 true")
	}
}

// 两族管理器的 ScheduleSlotError 必须委托同一记录器（改动任一侧字段/锁口径
// 都会在此断言处暴露）。
func TestVersionTableSlotRecorder_bothFamiliesDelegate(t *testing.T) {
	crs := newTestCRSManager(t)
	ip := newTestIP2RegionManager(t)
	cause := errors.New("状态行写入失败")
	crs.setSlotAdvanceError(cause)
	ip.setSlotAdvanceError(cause)
	if err := crs.ScheduleSlotError(); !errors.Is(err, cause) {
		t.Fatalf("CRS ScheduleSlotError=%v, want %v", err, cause)
	}
	if err := ip.ScheduleSlotError(); !errors.Is(err, cause) {
		t.Fatalf("IP2Region ScheduleSlotError=%v, want %v", err, cause)
	}
}
