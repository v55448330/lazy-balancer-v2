package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// ---------------------------------------------------------------------------
// 回归钉
// ---------------------------------------------------------------------------

func TestSnapshot_buildIsolatesCorruptedJSONRows(t *testing.T) {
	// 主节点单行 JSON 损坏（条件/上游/白名单列）不得让整包快照 500：
	// 坏行显式隔离（跳过）+ 限频结构化告警（表/行 ID），健康行照常下发。
	cluster, database := newClusterTestService(t)
	mustExec := func(query string, args ...any) {
		t.Helper()
		if _, err := database.Exec(query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}
	// 自定义拦截规则：1=坏行，2=健康行
	mustExec(`INSERT INTO security_custom_rules (id,name,conditions) VALUES (1,'bad-rule','{not-json')`)
	mustExec(`INSERT INTO security_custom_rules (id,name,conditions) VALUES (2,'healthy-rule','[]')`)
	// 自定义路由：11=坏行（upstreams_json 畸形），12=健康行
	mustExec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_snapshot_probe','snapshot-probe','http','snapshot.example',80,1)`)
	mustExec(`INSERT INTO path_rules (id,rule_id,sort_order,match_type,path,upstreams_json) VALUES (11,'lb_snapshot_probe',0,'prefix','/bad','{not-json')`)
	mustExec(`INSERT INTO path_rules (id,rule_id,sort_order,match_type,path,upstreams_json) VALUES (12,'lb_snapshot_probe',1,'prefix','/ok','[]')`)
	// API Key：21=坏行（MCP 白名单畸形），22=健康行
	mustExec(`INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by,mcp_enabled,mcp_ip_whitelist) VALUES (21,'bad-key','h1','lb_bad',1,1,'{not-json')`)
	mustExec(`INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by,mcp_enabled,mcp_ip_whitelist) VALUES (22,'healthy-key','h2','lb_ok',1,1,'["10.0.0.0/8"]')`)

	isolated := make(chan string, 16)
	resetSnapshotRowIsolationThrottle()
	snapshotRowIsolationHook = func(table string, rowID any, _ error) {
		isolated <- fmt.Sprintf("%s:%v", table, rowID)
	}
	t.Cleanup(func() {
		snapshotRowIsolationHook = nil
		resetSnapshotRowIsolationThrottle()
	})

	snapshot, err := cluster.buildFullSnapshot(context.Background(), database)
	if err != nil {
		t.Fatalf("snapshot build failed on corrupted single rows: %v", err)
	}

	// 健康行照常发布，坏行被隔离。
	if len(snapshot.SecurityCustomRules) != 1 || snapshot.SecurityCustomRules[0].Name != "healthy-rule" {
		t.Fatalf("custom rules=%+v, want only healthy-rule", snapshot.SecurityCustomRules)
	}
	var pathIDs []int
	for _, rule := range snapshot.Rules {
		if rule.CaddyID != "lb_snapshot_probe" {
			continue
		}
		for _, pathRule := range rule.PathRules {
			pathIDs = append(pathIDs, pathRule.ID)
		}
	}
	if len(pathIDs) != 1 || pathIDs[0] != 12 {
		t.Fatalf("path rule ids=%v, want [12] (bad row isolated)", pathIDs)
	}
	var keyIDs []int
	for _, key := range snapshot.APIKeys {
		keyIDs = append(keyIDs, key.ID)
	}
	if len(keyIDs) != 1 || keyIDs[0] != 22 {
		t.Fatalf("api key ids=%v, want [22] (bad row isolated)", keyIDs)
	}

	// 告警必须点名表与行 ID（结构化），不得静默跳过。
	seen := map[string]bool{}
	for range 3 {
		select {
		case got := <-isolated:
			seen[got] = true
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for isolation warnings, seen=%v", seen)
		}
	}
	for _, want := range []string{"security_custom_rules:1", "path_rules:11", "api_keys:21"} {
		if !seen[want] {
			t.Fatalf("isolation warnings=%v, want %q", seen, want)
		}
	}
}

func TestSnapshotRowIsolationThrottle_evictsExpiredEntriesAndKeepsThrottle(t *testing.T) {
	// Given an expired key, a still-active key, and a new corrupted row.
	newClusterTestService(t)
	resetSnapshotRowIsolationThrottle()
	var warnings int
	snapshotRowIsolationHook = func(string, any, error) { warnings++ }
	t.Cleanup(func() {
		snapshotRowIsolationHook = nil
		resetSnapshotRowIsolationThrottle()
	})
	now := time.Now()
	snapshotRowIsolationMu.Lock()
	snapshotRowIsolationSeen["table:expired"] = now.Add(-snapshotRowIsolationWindow - time.Second)
	snapshotRowIsolationSeen["table:fresh"] = now
	snapshotRowIsolationMu.Unlock()

	// When a distinct row is isolated.
	warnCorruptedSnapshotRow("table", "new", errors.New("bad row"))

	// Then expired state is reclaimed without dropping active throttle state.
	snapshotRowIsolationMu.Lock()
	_, expiredExists := snapshotRowIsolationSeen["table:expired"]
	_, freshExists := snapshotRowIsolationSeen["table:fresh"]
	_, newExists := snapshotRowIsolationSeen["table:new"]
	snapshotRowIsolationMu.Unlock()
	if expiredExists || !freshExists || !newExists {
		t.Fatalf("throttle map expired=%v fresh=%v new=%v, want false/true/true", expiredExists, freshExists, newExists)
	}
	warnCorruptedSnapshotRow("table", "fresh", errors.New("bad row"))
	if warnings != 1 {
		t.Fatalf("warnings=%d, want only the new key to warn", warnings)
	}
}

// ---------------------------------------------------------------------------
// 回归钉
// ---------------------------------------------------------------------------

func TestSyncService_Pull_304_clears_waf_repull_state_after_manual_convergence(t *testing.T) {
	// 连续未收敛计数达阈值 + last_sync_error 已上表面后，运营方手工修复
	// CRS/ip2region 文件 → 下一轮 304 未检出漂移时必须清零计数并清空
	// WAF 专项文案（此前只在 apply 路径清零，手工修复后错误永驻）。
	_, database := newClusterTestService(t)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/branding" {
			response.WriteHeader(http.StatusOK)
			return
		}
		response.WriteHeader(http.StatusNotModified)
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='token', applied_version=9, last_sync_error=? WHERE id=1",
		master.URL, encodeSyncError(fmt.Sprintf("安全数据持续同步失败（已连续 %d 轮未收敛）", wafRepullMaxFailures), models.SyncErrorCodeTransportError)); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(master.URL))
	service.wafRepullFailures.Store(wafRepullMaxFailures)

	if _, err := service.Pull(context.Background()); err != nil {
		t.Fatalf("pull: %v", err)
	}

	if got := service.wafRepullFailures.Load(); got != 0 {
		t.Fatalf("wafRepullFailures=%d after 304 without drift, want 0", got)
	}
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if msg, _ := decodeSyncError(stored); msg != "" {
		t.Fatalf("last_sync_error=%q, want cleared after manual convergence", msg)
	}
}

// ---------------------------------------------------------------------------
// 回归钉
// ---------------------------------------------------------------------------

func TestSyncService_applySnapshot_brandingFailureMarksRetryAndClearsOnSuccess(t *testing.T) {
	cluster, database := newClusterTestService(t)
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	setNodeMasterRole(t, database, false) // applySnapshot 是纯从端路径，后置标记只在从端语境落库
	dataDir := t.TempDir()
	// 注入落盘失败：branding.json 位置被目录占用（os.WriteFile → EISDIR）。
	if err := os.Mkdir(filepath.Join(dataDir, "branding.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	service := NewSyncService(database, &config.Config{DataDir: dataDir, CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	if err := service.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply with branding write failure must stay committed-not-failed: %v", err)
	}
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if msg, _ := decodeSyncError(stored); !strings.HasPrefix(msg, syncBrandingFailureMarkerPrefix) {
		t.Fatalf("last_sync_error=%q, want %s retry marker", msg, syncBrandingFailureMarkerPrefix)
	}

	// 修复落盘条件后，下一轮（users 节被哈希跳过）仍必须重试并清除标记。
	if err := os.Remove(filepath.Join(dataDir, "branding.json")); err != nil {
		t.Fatal(err)
	}
	if err := service.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("retry apply: %v", err)
	}
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if msg, _ := decodeSyncError(stored); msg != "" {
		t.Fatalf("last_sync_error=%q, want cleared after branding retry success", msg)
	}
	content, err := os.ReadFile(filepath.Join(dataDir, "branding.json"))
	if err != nil || string(content) != emptyBrandingTemplate {
		t.Fatalf("branding.json content=%q err=%v, want default template", content, err)
	}
}

func TestSyncService_applySnapshot_brandingWithoutDataDirDegradesExplicitly(t *testing.T) {
	// dataDir 未配置=显式降级：不得静默跳过（留痕一次），也不得误写重试标记
	// （重试没有意义——没有任何路径可写）。
	cluster, database := newClusterTestService(t)
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	service := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	snapshotBrandingDegradeWarned.Store(false)

	if err := service.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply without data dir: %v", err)
	}
	if !snapshotBrandingDegradeWarned.Load() {
		t.Fatal("missing data dir must leave an explicit degradation trace")
	}
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if msg, _ := decodeSyncError(stored); strings.HasPrefix(msg, syncBrandingFailureMarkerPrefix) {
		t.Fatalf("last_sync_error=%q, degradation must not write a retry marker", msg)
	}
}

func TestSyncService_Pull_repulls_after_branding_failure_marker(t *testing.T) {
	cluster, database := newClusterTestService(t)
	snapshot := dbConsistentWafDriftFixture(t, cluster, 9, "token")
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	snapshot = signTestSnapshot(snapshot, "token")

	requestedVersions := make(chan string, 8)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/branding" {
			response.WriteHeader(http.StatusOK)
			return
		}
		version := request.URL.Query().Get("since_version")
		requestedVersions <- version
		if version == "0" {
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(models.APIResponse{Code: 0, Data: snapshot})
			return
		}
		response.WriteHeader(http.StatusNotModified)
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='token', applied_version=9, last_sync_error=? WHERE id=1",
		master.URL, encodeSyncError(syncBrandingFailureMarkerPrefix+": 品牌配置落盘失败", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dataDir, "branding.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	service := NewSyncService(database, &config.Config{DataDir: dataDir, CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// 失败仍在：304 → 全量重拉 → 品牌落盘再次失败 → 标记保留。
	if _, err := service.Pull(context.Background()); err != nil {
		t.Fatalf("pull with branding failure: %v", err)
	}
	if v := waitSyncTest(t, requestedVersions); v != "9" {
		t.Fatalf("first request since_version=%q, want 9", v)
	}
	if v := waitSyncTest(t, requestedVersions); v != "0" {
		t.Fatalf("second request since_version=%q, want 0 (branding retry repull)", v)
	}
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if msg, _ := decodeSyncError(stored); !strings.HasPrefix(msg, syncBrandingFailureMarkerPrefix) {
		t.Fatalf("last_sync_error=%q, want marker retained while branding write keeps failing", msg)
	}

	// 修复后：下一轮 304 仍触发重拉，落盘成功即清除标记。
	if err := os.Remove(filepath.Join(dataDir, "branding.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Pull(context.Background()); err != nil {
		t.Fatalf("pull after fix: %v", err)
	}
	if v := waitSyncTest(t, requestedVersions); v != "9" {
		t.Fatalf("third request since_version=%q, want 9", v)
	}
	if v := waitSyncTest(t, requestedVersions); v != "0" {
		t.Fatalf("fourth request since_version=%q, want 0 (retry until fixed)", v)
	}
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if msg, _ := decodeSyncError(stored); msg != "" {
		t.Fatalf("last_sync_error=%q, want cleared after branding write succeeded", msg)
	}
}

// 拉取准入必须重新打开，不能继承 DrainPulls 的停止态。
func TestClusterService_BecomeSlave_drainsOldMasterPullAndReopensAdmission(t *testing.T) {
	_, database := newClusterTestService(t)
	const token = "cluster-token"
	oldMaster := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/branding" {
			response.WriteHeader(http.StatusOK)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"data": signedTestSnapshot(8, token)})
	}))
	defer oldMaster.Close()
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddyServer.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0,master_url=?,cluster_token=? WHERE id=1", oldMaster.URL, token); err != nil {
		t.Fatal(err)
	}
	syncService := NewSyncService(database, &config.Config{DataDir: t.TempDir(), CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	applyEntered := make(chan struct{})
	releaseApply := make(chan struct{})
	syncService.beforeApplyWrite = func() {
		close(applyEntered)
		waitSyncBarrier(t, releaseApply)
	}
	pullDone := make(chan error, 1)
	go func() {
		_, err := syncService.Pull(context.Background())
		pullDone <- err
	}()
	waitSyncTest(t, applyEntered)
	cluster := NewClusterService(database, "")
	becomeDone := make(chan error, 1)
	go func() {
		becomeDone <- cluster.BecomeSlave(context.Background(), "http://new-master.example", models.ClusterRegistration{RegistrationID: 9, RegistrationSecret: "new-secret"})
	}()
	select {
	case err := <-becomeDone:
		close(releaseApply)
		<-pullDone
		t.Fatalf("master switch returned before old pull drained: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(releaseApply)
	if err := waitSyncTest(t, pullDone); err != nil {
		t.Fatalf("old pull: %v", err)
	}
	if err := waitSyncTest(t, becomeDone); err != nil {
		t.Fatalf("become slave: %v", err)
	}
	var masterURL string
	if err := database.QueryRow(`SELECT master_url FROM global_config WHERE id=1`).Scan(&masterURL); err != nil {
		t.Fatal(err)
	}
	if masterURL != "http://new-master.example" {
		t.Fatalf("master_url=%q", masterURL)
	}
	if _, err := syncService.Pull(context.Background()); errors.Is(err, errSyncPullStopped) {
		t.Fatal("new master pull admission remained stopped after registration")
	}
}

// 删除刚创建的注册记录。
func TestClusterService_BecomeSlave_detachesOnlyPreviousDifferentMaster(t *testing.T) {
	_, database := newClusterTestService(t)
	detached := make(chan string, 1)
	oldMaster := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		detached <- r.Header.Get("X-Cluster-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer oldMaster.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0,master_url=?,cluster_token='old-token' WHERE id=1", oldMaster.URL); err != nil {
		t.Fatal(err)
	}
	cluster := NewClusterService(database, "")
	if err := cluster.BecomeSlave(context.Background(), "http://new-master.example", models.ClusterRegistration{RegistrationID: 9, RegistrationSecret: "new-secret"}); err != nil {
		t.Fatal(err)
	}
	select {
	case token := <-detached:
		if token != "old-token" {
			t.Fatalf("detach token=%q", token)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("previous master did not receive detached report")
	}

	if _, err := database.Exec("UPDATE global_config SET master_url=?,cluster_token='old-token' WHERE id=1", oldMaster.URL); err != nil {
		t.Fatal(err)
	}
	if err := cluster.BecomeSlave(context.Background(), oldMaster.URL, models.ClusterRegistration{RegistrationID: 10, RegistrationSecret: "same-secret"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-detached:
		t.Fatal("same-master re-registration must not detach its new registration")
	case <-time.After(300 * time.Millisecond):
	}
}

// ---------------------------------------------------------------------------
// 回归钉
// ---------------------------------------------------------------------------

func TestClusterService_Promote_drainsPostAdmissionApply(t *testing.T) {
	// admission 已通过（apply 窗口内）的在途拉取也必须被 Promote 排干：
	// engine.StopLoop 只取消 daemon ctx，不等旧拉取落定。
	_, database := newClusterTestService(t)
	const token = "cluster-token"
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/branding" {
			response.WriteHeader(http.StatusOK)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"data": signedTestSnapshot(8, token)})
	}))
	defer master.Close()
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token=? WHERE id=1", master.URL, token); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}
	syncService := NewSyncService(database, &config.Config{DataDir: t.TempDir(), CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	applyEntered := make(chan struct{})
	releaseApply := make(chan struct{})
	syncService.beforeApplyWrite = func() {
		close(applyEntered)
		waitSyncBarrier(t, releaseApply)
	}
	cluster := NewClusterService(database, "")
	pullDone := make(chan error, 1)
	go func() {
		_, err := syncService.Pull(context.Background())
		pullDone <- err
	}()
	waitSyncTest(t, applyEntered)

	promoteDone := make(chan error, 1)
	go func() { promoteDone <- cluster.Promote(context.Background()) }()
	select {
	case err := <-promoteDone:
		t.Fatalf("promote returned while an admitted apply was still in flight: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	close(releaseApply)
	if err := waitSyncTest(t, pullDone); err != nil {
		t.Fatalf("in-flight pull: %v", err)
	}
	if err := waitSyncTest(t, promoteDone); err != nil {
		t.Fatalf("promote: %v", err)
	}
	var isMaster bool
	var appliedVersion int
	if err := database.QueryRow("SELECT is_master,applied_version FROM global_config WHERE id=1").Scan(&isMaster, &appliedVersion); err != nil {
		t.Fatalf("read promoted state: %v", err)
	}
	if !isMaster || appliedVersion != 0 {
		t.Fatalf("promoted state is_master=%v applied_version=%d, want master with reset version", isMaster, appliedVersion)
	}
	// 排干后必须拒绝新拉取：停机哨兵或「主节点不能从其他节点同步」都成立
	// （Promote 已翻转角色，两条拒绝路径任一命中即证明拉取未被准入）。
	if _, err := syncService.Pull(context.Background()); err == nil ||
		(!errors.Is(err, errSyncPullStopped) && !errors.Is(err, errSyncMasterNoPull)) {
		t.Fatalf("pull after promotion error=%v, want 排干/角色拒绝", err)
	}
}

func TestSyncService_applySnapshot_rechecksRoleInsideTransaction(t *testing.T) {
	// Pull 的 admission 前复核通过后角色被翻转（模拟 Promote 抢先提交）：
	// apply 事务内二次复核必须中止，绝不把从节点数据写回主节点库。
	cluster, database := newClusterTestService(t)
	snapshot := signedTestSnapshot(12, "token")
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	snapshot = signTestSnapshot(snapshot, "token")
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url='http://master.example', cluster_token='token', applied_version=5 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir(), CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	_ = cluster
	service.applyGuard = syncApplyGuard{MasterURL: "http://master.example", Token: "token"}
	// 复核之后（模拟）：角色已翻转为主节点。
	if _, err := database.Exec("UPDATE global_config SET is_master=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	err := service.applySnapshot(context.Background(), snapshot)
	if !errors.Is(err, errSyncApplyRoleChanged) {
		t.Fatalf("apply error=%v, want errSyncApplyRoleChanged", err)
	}
	var appliedVersion int
	if err := database.QueryRow("SELECT COALESCE(applied_version,0) FROM global_config WHERE id=1").Scan(&appliedVersion); err != nil {
		t.Fatal(err)
	}
	if appliedVersion != 5 {
		t.Fatalf("applied_version=%d, want 5 (aborted apply must not write)", appliedVersion)
	}
}

// ---------------------------------------------------------------------------
// 回归钉
// ---------------------------------------------------------------------------

func TestBecomeSlave_keepsUserStoppedClusterSyncWithManualEnableHint(t *testing.T) {
	_, database := newClusterTestService(t)
	probe := &roleLifecycleProbe{}
	te := wireClusterLifecycleEngineForTest(t, probe, false)
	waitForCond(t, 2*time.Second, func() bool { return probe.syncStarts.Load() == 1 })
	te.StopLoop("cluster-sync")
	waitForCond(t, 2*time.Second, func() bool {
		for _, meta := range te.DescribeAll() {
			if meta.ID == "cluster-sync" && !meta.Running {
				return true
			}
		}
		return false
	})
	probe.syncStarts.Store(0)
	logs := captureServiceLog(t)

	service := NewClusterService(database, "")
	if err := service.BecomeSlave(context.Background(), "https://master.example", models.ClusterRegistration{RegistrationID: 9, RegistrationSecret: "secret"}); err != nil {
		t.Fatalf("become slave: %v", err)
	}

	// 角色翻转不得复活用户停止态（task-engine 标准 v2.2 §5）：调度保持停止、
	// 同步生命周期零调用，且以 warn + 操作审计显式提示「切从后不会同步，
	// 请手动开启」（不静默脱管）；偏好表不回写 enabled=1。
	if meta, ok := te.Lookup("cluster-sync"); !ok || meta.LoopOn {
		t.Fatalf("cluster-sync loop_on=%v, want 保持用户停止态", meta.LoopOn)
	}
	assertCounterStable(t, &probe.syncStarts, 0, 100*time.Millisecond)
	if enabled, ok := loadTaskLoopPrefs()["cluster-sync"]; ok && enabled {
		t.Fatalf("cluster-sync preference=%v found=%v, want 保持关闭（不得回写启用）", enabled, ok)
	}
	if got := strings.Count(logs.String(), "切从后不会同步，请手动开启"); got != 1 {
		t.Fatalf("保持停止提示 warn=%d 条, want 1: %s", got, logs.String())
	}
	var audits int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='同步停止' AND detail LIKE '%切从后不会同步，请手动开启%'`).Scan(&audits); err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if audits != 1 {
		t.Fatalf("切从保持停止的显式审计=%d 行, want 1", audits)
	}
}

// ---------------------------------------------------------------------------
// 回归钉
// ---------------------------------------------------------------------------

func TestClusterService_RegisterNode_reportsOverwrittenApprovedNode(t *testing.T) {
	_, database := newClusterTestService(t)
	service := NewClusterService(database, "")
	now := time.Now()
	request := func(token, name string) models.ClusterRegisterRequest {
		return models.ClusterRegisterRequest{Token: token, Name: name, IPAddress: "10.0.0.5", Port: 9000}
	}
	firstToken, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.RegisterNode(context.Background(), request(firstToken, "first-name"), "10.0.0.5", now)
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if first.OverwrittenNodeID != 0 {
		t.Fatalf("first registration overwritten_node_id=%d, want 0", first.OverwrittenNodeID)
	}
	if err := service.ApproveNode(context.Background(), first.RegistrationID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE nodes SET name='original-name' WHERE id=?", first.RegistrationID); err != nil {
		t.Fatal(err)
	}

	secondToken, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.RegisterNode(context.Background(), request(secondToken, "second-name"), "10.0.0.5", now)
	if err != nil {
		t.Fatalf("duplicate registration: %v", err)
	}
	if second.RegistrationID != first.RegistrationID {
		t.Fatalf("duplicate registration id=%d, want same row %d", second.RegistrationID, first.RegistrationID)
	}
	if second.OverwrittenNodeID != first.RegistrationID || second.OverwrittenNodeName != "original-name" {
		t.Fatalf("overwritten node=%d/%q, want %d/original-name", second.OverwrittenNodeID, second.OverwrittenNodeName, first.RegistrationID)
	}
}

// ---------------------------------------------------------------------------
// 回归钉
// ---------------------------------------------------------------------------

func TestClusterService_GenerateLoginTicket_distinguishesOfflineFromMissing(t *testing.T) {
	_, database := newClusterTestService(t)
	service := NewClusterService(database, "")
	now := time.Now()
	hash := sha256.Sum256([]byte("lb_cluster_offline"))
	hexHash := hex.EncodeToString(hash[:])
	mustExec := func(query string, args ...any) {
		t.Helper()
		if _, err := database.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	// 7：已批准但从未上报（last_seen NULL）；8：已批准但凭据缺失；
	// 9：未批准且在线。
	mustExec(`INSERT INTO nodes (id,name,ip_address,port,is_approved,cluster_token_hash,last_seen) VALUES (7,'never-reported','10.0.0.7',8000,1,?,NULL)`, hexHash)
	mustExec(`INSERT INTO nodes (id,name,ip_address,port,is_approved,cluster_token_hash,last_seen) VALUES (8,'no-credential','10.0.0.8',8000,1,'',datetime('now'))`)
	mustExec(`INSERT INTO nodes (id,name,ip_address,port,is_approved,cluster_token_hash,last_seen) VALUES (9,'not-approved','10.0.0.9',8000,0,?,datetime('now'))`, hexHash)

	claims := func(nodeID int) models.ClusterLoginTicketClaims {
		return models.ClusterLoginTicketClaims{UserID: 1, Username: "admin", NodeID: nodeID}
	}
	if _, err := service.GenerateLoginTicket(context.Background(), claims(7), now); !errors.Is(err, ErrNodeOffline) {
		t.Fatalf("approved-never-reported error=%v, want ErrNodeOffline", err)
	}
	if _, err := service.GenerateLoginTicket(context.Background(), claims(8), now); !errors.Is(err, ErrNodeTokenPending) {
		t.Fatalf("missing-credential error=%v, want ErrNodeTokenPending（已批准但令牌待交付 ≠ 节点不存在）", err)
	}
	if _, err := service.GenerateLoginTicket(context.Background(), claims(9), now); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("not-approved error=%v, want ErrNodeNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// 回归钉
// ---------------------------------------------------------------------------

func TestClusterService_BecomeSlave_resetsLastSync(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET last_sync=datetime('now'), applied_version=7 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	service := NewClusterService(database, "")
	if err := service.BecomeSlave(context.Background(), "https://master.example", models.ClusterRegistration{RegistrationID: 9, RegistrationSecret: "secret"}); err != nil {
		t.Fatalf("become slave: %v", err)
	}
	var lastSync sql.NullTime
	var appliedVersion int
	if err := database.QueryRow("SELECT last_sync, COALESCE(applied_version,0) FROM global_config WHERE id=1").Scan(&lastSync, &appliedVersion); err != nil {
		t.Fatal(err)
	}
	if lastSync.Valid {
		t.Fatalf("last_sync=%v after demote, want NULL", lastSync.Time)
	}
	if appliedVersion != 0 {
		t.Fatalf("applied_version=%d after demote, want 0", appliedVersion)
	}
	status, err := service.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.LastSyncAt != "" {
		t.Fatalf("status last_sync_at=%q after demote, want empty", status.LastSyncAt)
	}
}

// 106-02 钉测缺口：clearWafRepullFailureMessage 的「标记段 + WAF 专项文案」
// 拆分分支是组合消息的唯一正确剥离点。缺了它（退化为整体清空）会把
// apply_ok_reload_failed 标记一并抹掉——而该标记是 304 补偿重拉的唯一触发器
// （「库=新版本、Caddy=旧运行配置」的自愈通道）。
// 既有用例只种纯 WAF 文案，且该场景下 Pull defer 的 recordSyncError(nil,nil)
// 也会清空，故删掉拆分分支仍绿。本用例种组合消息 + 已收敛的文件态记账，
// 断言标记段存活且 WAF 段被剥离。
func TestSyncService_Pull_304_keepsReloadMarkerWhenClearingWafRepullMessage(t *testing.T) {
	_, database := newClusterTestService(t)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/branding" {
			response.WriteHeader(http.StatusOK)
			return
		}
		response.WriteHeader(http.StatusNotModified)
	}))
	defer master.Close()

	combined := "apply_ok_reload_failed: caddy down | 同步失败（已连续 3 次）: " +
		fmt.Sprintf("安全数据持续同步失败（已连续 %d 轮未收敛）", wafRepullMaxFailures)
	// applied_waf_ref_hash=nullRef 基准 = 主节点无安全数据文件，wafFilesDrifted
	// 走豁免分支（false）→ 本轮视为已收敛，触发 WAF 专项文案清理。
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='token', applied_version=9, applied_waf_ref_hash=?, last_sync_error=? WHERE id=1",
		master.URL, wafFilesNullRefHash, encodeSyncError(combined, models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(master.URL))
	service.wafRepullFailures.Store(wafRepullMaxFailures)
	// 补偿重拉降频期（failures=6 → 非 backoffDue）：304+marker 时跳过全量重拉、
	// 直接走到 WAF 收敛清理——这是「标记段 + WAF 专项文案」组合消息唯一可达的
	// 清理点（无降频时会先被补偿重拉吃掉本轮）。
	service.reloadRepullFailures.Store(wafRepullMaxFailures + 1)

	if _, err := service.Pull(context.Background()); err != nil {
		t.Fatalf("pull: %v", err)
	}

	if got := service.wafRepullFailures.Load(); got != 0 {
		t.Fatalf("wafRepullFailures=%d after 304 without drift, want 0", got)
	}
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, _ := decodeSyncError(stored)
	if !strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) {
		t.Fatalf("last_sync_error=%q 必须保留 apply_ok_reload_failed 标记段（304 补偿唯一触发器）", msg)
	}
	if strings.Contains(msg, wafRepullFailureMessagePrefix) {
		t.Fatalf("last_sync_error=%q 必须剥离 WAF 专项文案（已收敛）", msg)
	}
	if !strings.Contains(msg, "caddy down") {
		t.Fatalf("last_sync_error=%q 必须保留标记段的失败原因", msg)
	}
}
