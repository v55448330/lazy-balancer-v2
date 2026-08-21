package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// TestNormalizeLegacySecurityPolicyEnums_slaveNormalizesLocally_whenSyncSecurityOff
// 验证 R54-N1：sync_security=0 时从节点收不到 security 段快照，本地遗留空串行
// 没有任何其他修复路径（Update 400 拒修、Create 归一、快照被门控），启动归一是
// 唯一修复者——必须本地归一，但从节点无集群版本权威，不得 bump。
func TestNormalizeLegacySecurityPolicyEnums_slaveNormalizesLocally_whenSyncSecurityOff(t *testing.T) {
	// Given 从节点 + sync_security=0（security 段被门控）+ 一条遗留空串行
	setupSecurityEnumTestDB(t)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0, sync_security=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	insertLegacyPolicyRow(t, "legacy-all", "", "", "")
	before := clusterVersion(t)

	// When 启动归一
	NormalizeLegacySecurityPolicyEnums(context.Background())

	// Then 本地归一到默认值（唯一修复路径），但集群版本不 bump
	var mode, ipACLMode, geoipMode string
	if err := db.DB.QueryRow("SELECT mode, ip_acl_mode, geoip_mode FROM security_policies WHERE name='legacy-all'").
		Scan(&mode, &ipACLMode, &geoipMode); err != nil {
		t.Fatal(err)
	}
	if mode != "off" || ipACLMode != "deny" || geoipMode != "deny" {
		t.Fatalf("slave with sync_security=0 must normalize locally: (%q,%q,%q), want (off,deny,deny)", mode, ipACLMode, geoipMode)
	}
	if v := clusterVersion(t); v != before {
		t.Fatalf("slave must not bump cluster_version: %d, want %d", v, before)
	}
}

// TestNormalizeLegacySecurityPolicyEnums_normalizesWhitespaceAndNullRows 验证
// R54-N6(a)：COALESCE+TRIM 加固口径——纯空格值行与 NULL 行同样被归一（R53 前
// 仅 ” 等值匹配覆盖不到这两类残留）。
func TestNormalizeLegacySecurityPolicyEnums_normalizesWhitespaceAndNullRows(t *testing.T) {
	// Given 主节点 + 一条纯空格值行 + 一条 NULL 值行
	setupSecurityEnumTestDB(t)
	insertLegacyPolicyRow(t, "spaces", " ", "   ", "  ")
	if _, err := db.DB.Exec("INSERT INTO security_policies (name, mode, ip_acl_mode, geoip_mode) VALUES ('nulls', NULL, NULL, NULL)"); err != nil {
		t.Fatal(err)
	}
	before := clusterVersion(t)

	// When 启动归一
	NormalizeLegacySecurityPolicyEnums(context.Background())

	// Then 两类行都归一到默认值，集群版本 +1
	rows, err := db.DB.Query("SELECT name, mode, ip_acl_mode, geoip_mode FROM security_policies ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string][3]string{}
	for rows.Next() {
		var name, mode, ipACLMode, geoipMode string
		if err := rows.Scan(&name, &mode, &ipACLMode, &geoipMode); err != nil {
			t.Fatal(err)
		}
		got[name] = [3]string{mode, ipACLMode, geoipMode}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := map[string][3]string{
		"spaces": {"off", "deny", "deny"},
		"nulls":  {"off", "deny", "deny"},
	}
	for name, w := range want {
		if got[name] != w {
			t.Fatalf("policy %s = %v, want %v", name, got[name], w)
		}
	}
	if v := clusterVersion(t); v != before+1 {
		t.Fatalf("cluster_version=%d, want %d (bumped exactly once)", v, before+1)
	}
}

// TestRefreshLatestAsync_recordsLastCheckedOnFailure 验证 R54-N4：后台上游版本
// 检查失败时同样推进 last_checked——持续故障期间 UI 的「上次检查时间」随之
// 推进，而不是停留在最后一次成功造成「已是最新 + checked long ago」的静默假象。
func TestRefreshLatestAsync_recordsLastCheckedOnFailure(t *testing.T) {
	// Given 主节点 + last_checked 为空的版本行 + 上游 fetch 恒失败
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	m.fetchLatestTag = func(context.Context) (string, error) {
		return "", errors.New("upstream 403")
	}

	// When 后台版本检查发起并失败
	m.RefreshLatestAsync()

	// Then last_checked 被推进（失败也是一次检查尝试）
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, _, _, _, lastChecked, _, _ := crsVersionRow(t)
		if lastChecked != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed background fetch must still advance last_checked")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRefreshLatestAsync_refiresAfterSuccessWindow 验证 R54-N6(c)：成功路径的
// 10 分钟缓存窗口过后，下一次调用重新发起 fetch 并刷新缓存版本。
func TestRefreshLatestAsync_refiresAfterSuccessWindow(t *testing.T) {
	// Given 首次后台检查已成功建立缓存
	m := newTestCRSManager(t)
	calls := make(chan struct{}, 4)
	m.fetchLatestTag = func(context.Context) (string, error) {
		calls <- struct{}{}
		return "v4.15.0", nil
	}
	refreshing := func() bool {
		m.latestMu.Lock()
		defer m.latestMu.Unlock()
		return m.latestRefreshing
	}
	m.RefreshLatestAsync()
	<-calls
	deadline := time.Now().Add(5 * time.Second)
	for refreshing() {
		if time.Now().After(deadline) {
			t.Fatal("first refresh did not settle")
		}
		time.Sleep(time.Millisecond)
	}

	// When 10 分钟窗口过后再次调用
	m.latestMu.Lock()
	m.latestFetchedAt = time.Now().Add(-11 * time.Minute)
	m.latestMu.Unlock()
	m.RefreshLatestAsync()

	// Then 重新发起 fetch，缓存版本可用
	select {
	case <-calls:
	case <-time.After(5 * time.Second):
		t.Fatal("success-path cache must re-fire a fetch after the 10min window")
	}
	if tag, known := m.LatestVersionCached(); !known || tag != "v4.15.0" {
		t.Fatalf("cached latest=(%q,%v), want (v4.15.0,true)", tag, known)
	}
}

// TestReconcileCRSState_versionOnlySnapshotWithUnhealthyLiveLeftInPlace 验证
// R54-N6(b)：VERSION-only 快照 + live 树也不健康（无版本标记、无完整 rules）
// 时 heal 保留现场语义——不从一个自身不健康的 live 树「重建」快照。
func TestReconcileCRSState_versionOnlySnapshotWithUnhealthyLiveLeftInPlace(t *testing.T) {
	// Given VERSION-only 快照 + live 树无版本标记且无 rules
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), "v4.15.0\n")

	// When 启动对账
	reconcileCRSStateFrom(liveDir, snapshotDir, "v4.15.0")

	// Then heal 跳过，VERSION-only 现场保留供诊断，不向快照伪造 rules 树
	if got := readCRSVersionMarker(snapshotDir); got != "v4.15.0" {
		t.Fatalf("snapshot marker=%q, want preserved v4.15.0", got)
	}
	if _, err := os.Stat(filepath.Join(snapshotDir, "rules")); !os.IsNotExist(err) {
		t.Fatal("heal must not fabricate a snapshot rules tree from an unhealthy live tree")
	}
}

// TestCRSUpdateRun_installFailureRestoresStockBaseline 验证 R54-N3：stock 基线
// 写入之后的任何失败（如重载失败）回滚时，crs-setup.stock.conf 一并恢复到
// 更新前版本——否则下次迁移的 diff 基线停留在新版本，两版之间上游改动过的
// 默认行会被误判为用户自定义而静默回退。
func TestCRSUpdateRun_installFailureRestoresStockBaseline(t *testing.T) {
	// Given live 树带旧 stock 基线，更新将在重载步骤失败
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# old setup")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.stock.conf"), "# old stock baseline")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
	})
	m.reloader = func() error { return errors.New("reload boom") }

	// When 安装失败触发回滚
	m.run("manual")

	// Then stock 基线恢复到更新前版本，备份被消费
	stock, err := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.stock.conf"))
	if err != nil || string(stock) != "# old stock baseline" {
		t.Fatalf("crs-setup.stock.conf=%q,%v, want restored pre-update baseline", stock, err)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "crs-setup.stock.conf.bak")); !os.IsNotExist(err) {
		t.Fatal("crs-setup.stock.conf.bak should be consumed by restore")
	}
	_, status, _, _, _, _, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
}

// TestCRSUpdateRun_successRemovesStockBackup 验证 R54-N3 成功路径：更新成功后
// stock 基线备份随其他备份一并清理，不残留到下次运行。
func TestCRSUpdateRun_successRemovesStockBackup(t *testing.T) {
	// Given live 树带旧 stock 基线，更新将成功
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# old setup")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.stock.conf"), "# old stock baseline")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
	})
	m.reloader = func() error { return nil }

	// When 更新成功
	m.run("manual")

	// Then 新 stock 基线落盘且无备份残留
	stock, err := os.ReadFile(filepath.Join(m.crsDir, "crs-setup.stock.conf"))
	if err != nil || string(stock) != "# new setup" {
		t.Fatalf("crs-setup.stock.conf=%q,%v, want new baseline", stock, err)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "crs-setup.stock.conf.bak")); !os.IsNotExist(err) {
		t.Fatal("crs-setup.stock.conf.bak should be removed after a successful update")
	}
}

// TestClusterService_BecomeSlave_stopsUpdateSchedulers 验证 R54-N5：节点降级
// 注册进另一集群时，CRS/IP2Region 自动更新调度器一并停止（与 Promote 侧
// SetMasterRole(true) 对称）——否则已越过 is_master 守卫的 tick 会在从节点
// 上继续执行更新，瞬时打破从节点只读不变量。
func TestClusterService_BecomeSlave_stopsUpdateSchedulers(t *testing.T) {
	// Given 主节点上运行中的 CRS/IP2Region 自动更新调度器
	service, _ := newClusterTestService(t)
	InitCRSUpdateManager(func() error { return nil })
	t.Cleanup(ResetCRSUpdateManagerForTest)
	InitIP2RegionUpdateManager(func() error { return nil })
	t.Cleanup(ResetIP2RegionUpdateManagerForTest)
	crsManager := GetCRSUpdateManager()
	ip2regionMgr := GetIP2RegionUpdateManager()
	crsManager.SetMasterRole(true)
	ip2regionMgr.SetMasterRole(true)
	crsSchedulerOn := func() bool {
		crsManager.schedulerMu.Lock()
		defer crsManager.schedulerMu.Unlock()
		return crsManager.schedulerStop != nil
	}
	ip2regionSchedulerOn := func() bool {
		ip2regionMgr.schedulerMu.Lock()
		defer ip2regionMgr.schedulerMu.Unlock()
		return ip2regionMgr.schedulerStop != nil
	}
	if !crsSchedulerOn() || !ip2regionSchedulerOn() {
		t.Fatal("given: schedulers must be running on the master")
	}

	// When 节点降级注册进另一集群
	if err := service.BecomeSlave(context.Background(), "https://master.example", models.ClusterRegistration{RegistrationID: 9, RegistrationSecret: "secret"}); err != nil {
		t.Fatalf("become slave: %v", err)
	}

	// Then 两个自动更新调度器都停止
	if crsSchedulerOn() {
		t.Fatal("CRS scheduler must stop when the node becomes a slave")
	}
	if ip2regionSchedulerOn() {
		t.Fatal("IP2Region scheduler must stop when the node becomes a slave")
	}
}

// TestCRSUpdateRun_slaveAbortsBeforeFetch 验证 R54-N5 的 run() 起点角色复查：
// demote 与调度器 tick 的竞态窗口（tick 已越过守卫、更新刚发出时节点被降级）
// 下，更新管线在从节点上启动必须立即终止——不发起 fetch、不写本地版本行。
func TestCRSUpdateRun_slaveAbortsBeforeFetch(t *testing.T) {
	// Given 从节点（demote 已提交）+ 一条版本行
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
	m.downloadTarball = func(context.Context, string, string, downloadProgressFunc) error {
		return errors.New("must not reach download on a slave")
	}

	// When 更新管线在从节点上启动
	m.run("auto")

	// Then 起点复查直接终止：不发起 fetch、不写版本行状态
	if fetchCalled {
		t.Fatal("slave node must abort the update pipeline before fetching")
	}
	_, status, _, _, _, _, _ := crsVersionRow(t)
	if status != "idle" {
		t.Fatalf("update_status=%q, want untouched (seed default idle) on slave abort", status)
	}
	m.mu.Lock()
	state := m.state
	m.mu.Unlock()
	if state.status != CRSStatusFailed {
		t.Fatalf("in-memory status=%q, want failed (aborted on slave)", state.status)
	}
}

// TestIP2RegionUpdateRun_slaveAbortsBeforeFetch 验证 R54-N5 对 IP2Region 更新
// 管线同样的 run() 起点角色复查。
func TestIP2RegionUpdateRun_slaveAbortsBeforeFetch(t *testing.T) {
	// Given 从节点（demote 已提交）+ 一条版本行
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

	// When 更新管线在从节点上启动
	m.run("auto")

	// Then 起点复查直接终止：不发起 fetch、不写版本行状态
	if fetchCalled {
		t.Fatal("slave node must abort the update pipeline before fetching")
	}
	_, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "idle" {
		t.Fatalf("update_status=%q, want untouched (seed default idle) on slave abort", status)
	}
	m.mu.Lock()
	state := m.state
	m.mu.Unlock()
	if state.status != IP2RegionStatusFailed {
		t.Fatalf("in-memory status=%q, want failed (aborted on slave)", state.status)
	}
}
