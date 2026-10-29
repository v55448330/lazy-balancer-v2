package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// clusterLifecycleFake 是 lifecycleRecorder 的布尔观测视图：生命周期回调在
// 引擎 daemon goroutine 上异步执行，「回调是否已发生」的断言必须经
// waitForCond + 布尔视图（内嵌计数 >0），不得读后即断。
type clusterLifecycleFake struct {
	lifecycleRecorder
}

func (f *clusterLifecycleFake) acmeStarted() bool { return f.acmeStarts.Load() > 0 }
func (f *clusterLifecycleFake) syncStarted() bool { return f.syncStarts.Load() > 0 }
func (f *clusterLifecycleFake) syncStopped() bool { return f.syncStops.Load() > 0 }

// v3SnapshotWithACMESection 将直调 applySnapshot 的夹具补齐为生产可达形态：
// 生产快照经 verifiedSnapshotIntegrity 闸门后必为当前 schema 且携带 ACME
// 区段；validateSnapshotACMEState 对缺区段统一硬拒（移除 v2 放行
// 死分支后，未设 SchemaVersion/ACME 的旧夹具会被拒）。
func v3SnapshotWithACMESection(snapshot models.ClusterSnapshot) models.ClusterSnapshot {
	snapshot.SchemaVersion = CurrentSnapshotSchema
	snapshot.ACME = &models.ClusterACMEState{
		CAProviders:        []models.CAProvider{},
		CertificateConfigs: []models.CertificateConfig{},
		DNSOwnership:       json.RawMessage(`{"version":1,"records":[]}`),
	}
	return snapshot
}

func newClusterTestService(t *testing.T) (*ClusterService, *sql.DB) {
	stubUpdateRetrySleep(t) // 任务内重试等待即时化（威胁库失败路径测试）
	database := setupIsolatedDB(t)
	service := NewClusterService(database, "")
	// 显式注销全局注册表条目：Cleanup 后注册先执行，早于夹具的 Close/还原。
	t.Cleanup(func() { unregisterClusterService(service) })
	return service, database
}

// replaceSnapshotDB 是 replaceSnapshotTx 的裸事务包装：只覆盖三节写入与
// 归一列，不含角色复核、Caddy 重载、提交后副作用（日志清理/爬虫快照/重载
// 判定）。用例用它时命名必须体现「事务层/往返」口径（TestReplaceSnapshotTx_*
// 或 TestClusterSnapshot_*RoundTrip），不得取名 TestApplySnapshot_* 冒充
// 端到端 apply 行为——后者只由 SyncService.applySnapshot 覆盖。
func replaceSnapshotDB(ctx context.Context, database *sql.DB, snapshot models.ClusterSnapshot) error {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := replaceSnapshotTx(ctx, tx, snapshot, &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}); err != nil {
		return err
	}
	return tx.Commit()
}

func TestClusterService_RegisterToken_regeneration_invalidates_previous_unused_token(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	first, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatalf("generate first token: %v", err)
	}

	// When：重新生成令牌（旧令牌仍未使用、未过期）
	second, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatalf("generate second token: %v", err)
	}

	// Then：旧令牌被作废，新令牌可用，令牌表仅剩新令牌
	req := models.ClusterRegisterRequest{Name: "slave-a", IPAddress: "10.0.0.2", Port: 8000}
	req.Token = first
	if _, err := service.RegisterNode(context.Background(), req, req.IPAddress, now); !errors.Is(err, ErrInvalidRegisterToken) {
		t.Fatalf("register with stale token error=%v, want invalid token", err)
	}
	req.Token = second
	if _, err := service.RegisterNode(context.Background(), req, req.IPAddress, now); err != nil {
		t.Fatalf("register with fresh token: %v", err)
	}
	var tokenCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM cluster_register_tokens").Scan(&tokenCount); err != nil {
		t.Fatalf("count register tokens: %v", err)
	}
	if tokenCount != 1 {
		t.Fatalf("register token count=%d, want 1 (stale unused token GC'd)", tokenCount)
	}
}

func TestClusterService_RegisterToken_is_one_time(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	req := models.ClusterRegisterRequest{Token: token, Name: "slave-a", IPAddress: "10.0.0.2", Port: 8000}

	// When
	_, err = service.RegisterNode(context.Background(), req, req.IPAddress, now)
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}
	_, secondErr := service.RegisterNode(context.Background(), req, req.IPAddress, now)

	// Then
	if !errors.Is(secondErr, ErrInvalidRegisterToken) {
		t.Fatalf("second registration error=%v, want ErrInvalidRegisterToken（已消费令牌）", secondErr)
	}
	var plaintextCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM cluster_register_tokens WHERE token_hash=?", token).Scan(&plaintextCount); err != nil {
		t.Fatalf("query plaintext token: %v", err)
	}
	if plaintextCount != 0 {
		t.Fatal("registration token was stored in plaintext")
	}
}

func TestClusterService_RegisterNodeStoresAndUpdatesAccessURL(t *testing.T) {
	service, database := newClusterTestService(t)
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token, Name: "slave-a", IPAddress: "172.18.0.2", Port: 8000, AccessURL: "http://172.18.0.2:8001",
	}, "172.18.0.2", now)
	if err != nil {
		t.Fatal(err)
	}
	var accessURL string
	if err := database.QueryRow("SELECT access_url FROM nodes WHERE id=?", registration.RegistrationID).Scan(&accessURL); err != nil {
		t.Fatal(err)
	}
	if accessURL != "http://172.18.0.2:8001" {
		t.Fatalf("access_url=%q", accessURL)
	}
	if err := service.UpdateNodeAccessURL(context.Background(), registration.RegistrationID, "https://node.example:8443"); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT access_url FROM nodes WHERE id=?", registration.RegistrationID).Scan(&accessURL); err != nil {
		t.Fatal(err)
	}
	if accessURL != "https://node.example:8443" {
		t.Fatalf("updated access_url=%q", accessURL)
	}
}

// 自述 access_url 的唯一防护（主机必须与注册来源地址一致）：该值随后被用作
// 登录/服务控制能力票据的投递地址，未校验时持有注册令牌的一方可把票据引向
// 第三方主机。缺测试会让这道防护在重构中静默消失。
func TestClusterService_RegisterNode_ignoresAccessURLFromForeignHost(t *testing.T) {
	service, database := newClusterTestService(t)
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	register := func(name, ipAddress, accessURL, sourceIP string, port int) models.ClusterRegistration {
		t.Helper()
		token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
		if err != nil {
			t.Fatalf("generate token: %v", err)
		}
		registration, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
			Token: token, Name: name, IPAddress: ipAddress, Port: port, AccessURL: accessURL,
		}, sourceIP, now)
		if err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
		return registration
	}
	storedAccessURL := func(registrationID int) string {
		t.Helper()
		var accessURL sql.NullString
		if err := database.QueryRow("SELECT access_url FROM nodes WHERE id=?", registrationID).Scan(&accessURL); err != nil {
			t.Fatalf("read access_url: %v", err)
		}
		return accessURL.String
	}

	// When：自述地址指向第三方主机。
	foreign := register("slave-foreign", "10.0.0.9", "http://10.9.9.9:8001", "10.0.0.9", 8000)

	// Then：显式标记忽略且不落库（不落库才是防护生效的证据）。
	if !foreign.AccessURLIgnored {
		t.Fatal("跨主机自述 access_url 必须标记忽略")
	}
	if stored := storedAccessURL(foreign.RegistrationID); stored != "" {
		t.Fatalf("access_url=%q, want 空（防护失效会把能力票据引向第三方主机）", stored)
	}

	// 对照：同主机自述地址照常落库（防止把防护写成「一律忽略」）。
	same := register("slave-same", "10.0.0.10", "https://10.0.0.10:8443", "10.0.0.10", 8001)
	if same.AccessURLIgnored {
		t.Fatal("同主机自述 access_url 不得标记忽略")
	}
	if stored := storedAccessURL(same.RegistrationID); stored != "https://10.0.0.10:8443" {
		t.Fatalf("access_url=%q, want 同主机地址落库", stored)
	}
}

func TestClusterAccessURLValidation(t *testing.T) {
	valid := []string{"", "http://node.example:8000", "https://[2001:db8::1]:8443"}
	invalid := []string{"ftp://node.example/file", "file:///tmp/socket", "http:node.example", "https://user:pass@node.example", "https://node.example?token=secret", "https://node.example#fragment"}
	for _, value := range valid {
		if err := models.ValidateClusterAccessURL(value); err != nil {
			t.Errorf("valid URL %q rejected: %v", value, err)
		}
	}
	for _, value := range invalid {
		if err := models.ValidateClusterAccessURL(value); !errors.Is(err, models.ErrInvalidClusterAccessURL) {
			t.Errorf("invalid URL %q error=%v", value, err)
		}
	}
}

func TestClusterService_RegisterToken_rejects_expired_token(t *testing.T) {
	// Given
	service, _ := newClusterTestService(t)
	issuedAt := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, issuedAt)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// When
	_, registerErr := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token, Name: "slave-a", IPAddress: "10.0.0.2", Port: 8000,
	}, "10.0.0.2", issuedAt.Add(31*time.Minute))

	// Then
	if !errors.Is(registerErr, ErrInvalidRegisterToken) {
		t.Fatalf("registration error=%v, want ErrInvalidRegisterToken（过期令牌）", registerErr)
	}
}

func TestClusterService_ApproveNode_redelivers_cluster_token_until_confirmed(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	registerToken, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	registration, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: registerToken, Name: "slave-a", IPAddress: "10.0.0.2", Port: 8000,
	}, "10.0.0.2", now)
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	var storedRegistrationSecret string
	if err := database.QueryRow("SELECT registration_secret FROM nodes WHERE id=?", registration.RegistrationID).Scan(&storedRegistrationSecret); err != nil {
		t.Fatalf("query registration secret: %v", err)
	}
	if storedRegistrationSecret == registration.RegistrationSecret {
		t.Fatal("registration secret was stored in plaintext on the master")
	}
	if storedRegistrationSecret != tokenHash(registration.RegistrationSecret) {
		t.Fatal("registration secret was not stored as its SHA-256 hash")
	}
	if err := service.ApproveNode(context.Background(), registration.RegistrationID, time.Now()); err != nil {
		t.Fatalf("approve node: %v", err)
	}

	// When
	first, err := service.RegistrationStatus(context.Background(), registration.RegistrationID, registration.RegistrationSecret, time.Now())
	if err != nil {
		t.Fatalf("first status: %v", err)
	}
	second, err := service.RegistrationStatus(context.Background(), registration.RegistrationID, registration.RegistrationSecret, time.Now())
	if err != nil {
		t.Fatalf("second status: %v", err)
	}

	// Then
	if first.Status != "approved" || first.ClusterToken == "" {
		t.Fatalf("first status = %#v, want approved with token", first)
	}
	if second.ClusterToken != first.ClusterToken {
		t.Fatalf("redelivered token=%q, want %q", second.ClusterToken, first.ClusterToken)
	}
	nodeID, err := AuthenticateClusterToken(context.Background(), database, first.ClusterToken)
	if err != nil || nodeID != registration.RegistrationID {
		t.Fatalf("issued token authentication node=%d err=%v", nodeID, err)
	}
	var plaintextCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM nodes WHERE cluster_token_hash=?", first.ClusterToken).Scan(&plaintextCount); err != nil {
		t.Fatalf("query plaintext cluster token: %v", err)
	}
	if plaintextCount != 0 {
		t.Fatal("cluster token was stored in plaintext")
	}
	if _, _, err := service.Snapshot(context.Background(), 0, "", first.ClusterToken); err != nil {
		t.Fatalf("authenticate snapshot: %v", err)
	}
	if _, err := service.RegistrationStatus(context.Background(), registration.RegistrationID, registration.RegistrationSecret, time.Now()); !errors.Is(err, ErrInvalidClusterAuth) {
		t.Fatalf("registration secret remained valid after authenticated snapshot delivery: %v", err)
	}
}

func TestClusterService_RegistrationStatus_rejects_expired_secret(t *testing.T) {
	service, database := newClusterTestService(t)
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	registerToken, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	registration, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: registerToken, Name: "slave-expired", IPAddress: "10.0.0.3", Port: 8000,
	}, "10.0.0.3", now)
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := service.ApproveNode(context.Background(), registration.RegistrationID, time.Now()); err != nil {
		t.Fatalf("approve node: %v", err)
	}
	if _, err := database.Exec("UPDATE nodes SET registration_secret_expires_at=datetime('now','-1 second') WHERE id=?", registration.RegistrationID); err != nil {
		t.Fatalf("expire registration secret: %v", err)
	}

	_, err = service.RegistrationStatus(context.Background(), registration.RegistrationID, registration.RegistrationSecret, time.Now())

	if !errors.Is(err, ErrInvalidClusterAuth) {
		t.Fatalf("expired registration status error=%v, want invalid auth", err)
	}
}

func TestClusterService_Snapshot_uses_version_and_fingerprint(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET cluster_version=7 WHERE id=1"); err != nil {
		t.Fatalf("set version: %v", err)
	}
	if _, err := database.Exec("INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('lb_fingerprint','fingerprint','http',8080)"); err != nil {
		t.Fatalf("seed fingerprint rule: %v", err)
	}
	if _, err := database.Exec("INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES ('lb_fingerprint',0,'prefix','/before/')"); err != nil {
		t.Fatalf("seed fingerprint path rule: %v", err)
	}
	initial, changed, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil || !changed {
		t.Fatalf("initial snapshot changed=%v err=%v", changed, err)
	}

	// When
	if _, err := database.Exec("UPDATE path_rules SET path='/after/' WHERE rule_id='lb_fingerprint'"); err != nil {
		t.Fatalf("change content without version bump: %v", err)
	}
	cached, cachedChanged, err := service.Snapshot(context.Background(), 7, initial.Fingerprint, "")
	if err != nil {
		t.Fatalf("cached snapshot: %v", err)
	}
	if err := BumpClusterVersion(context.Background(), database); err != nil {
		t.Fatalf("bump cluster version: %v", err)
	}
	invalidated, invalidatedChanged, err := service.Snapshot(context.Background(), 7, initial.Fingerprint, "")

	// Then
	if cachedChanged || cached.Fingerprint != initial.Fingerprint {
		t.Fatalf("unbumped content rebuilt snapshot changed=%v fingerprint=%q", cachedChanged, cached.Fingerprint)
	}
	if err != nil || !invalidatedChanged || invalidated.Fingerprint == initial.Fingerprint || invalidated.Version != 8 {
		t.Fatalf("invalidated snapshot=%#v changed=%v err=%v", invalidated, invalidatedChanged, err)
	}
}

func TestClusterService_Snapshot_signatures_verify_for_each_requesting_token(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET cluster_version=3 WHERE id=1"); err != nil {
		t.Fatalf("set version: %v", err)
	}

	// When
	first, _, err := service.Snapshot(context.Background(), 0, "", "token-a")
	if err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	second, _, err := service.Snapshot(context.Background(), 0, "", "token-b")
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}

	// Then
	if first.Fingerprint != second.Fingerprint || first.Signature == second.Signature {
		t.Fatalf("fingerprints/signatures first=%q/%q second=%q/%q", first.Fingerprint, first.Signature, second.Fingerprint, second.Signature)
	}
	if err := verifySnapshotIntegrity(first, "token-a", 0); err != nil {
		t.Fatalf("verify first snapshot: %v", err)
	}
	if err := verifySnapshotIntegrity(second, "token-b", 0); err != nil {
		t.Fatalf("verify second snapshot: %v", err)
	}
}

func TestClusterService_buildSnapshot_readsOnlyFromProvidedTransaction(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	tx, err := database.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("begin snapshot transaction: %v", err)
	}
	defer tx.Rollback()
	if err := database.Close(); err != nil {
		t.Fatalf("close database pool: %v", err)
	}

	// When
	snapshot, err := service.buildSnapshot(context.Background(), tx)

	// Then
	if err != nil {
		t.Fatalf("build snapshot from active transaction after pool close: %v", err)
	}
	if snapshot.Version != 0 {
		t.Fatalf("snapshot version=%d, want 0", snapshot.Version)
	}
}

func TestSyncService_finishRun_doesNotClearNewerRun(t *testing.T) {
	// Given
	service := &SyncService{generation: 2, cancel: func() {}}

	// When
	service.finishRun(1)

	// Then
	if service.cancel == nil {
		t.Fatal("stale run cleared the newer run cancellation handle")
	}
}

func TestSyncService_run_retries_transient_state_read_failure(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, false) // run 循环的同步状态写只属于从节点语境
	attempts := 0
	retryReached := make(chan struct{})
	service := &SyncService{db: database}
	service.loadRunState = func(context.Context) (bool, string, int, error) {
		attempts++
		if attempts == 1 {
			return false, "", 0, errors.New("temporary database failure")
		}
		return true, "", 60, nil
	}
	service.waitRunDelay = func(context.Context, time.Duration) bool {
		close(retryReached)
		return true
	}

	// When
	service.run(context.Background())

	// Then
	<-retryReached
	if attempts != 2 {
		t.Fatalf("sync state reads=%d, want retry then master exit", attempts)
	}
	var lastError string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&lastError); err != nil {
		t.Fatalf("read last sync error: %v", err)
	}
	if !strings.Contains(lastError, "temporary database failure") {
		t.Fatalf("last_sync_error=%q, want transient database failure", lastError)
	}
}

func TestSyncService_Stop_waits_for_run_before_Start_creates_next_generation(t *testing.T) {
	// Given
	firstStarted := make(chan struct{})
	firstCanceled := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan struct{})
	active := 0
	maxActive := 0
	var activeMu sync.Mutex
	runs := 0
	service := &SyncService{runFn: func(ctx context.Context) {
		activeMu.Lock()
		runs++
		run := runs
		active++
		if active > maxActive {
			maxActive = active
		}
		activeMu.Unlock()
		if run == 1 {
			close(firstStarted)
			<-ctx.Done()
			close(firstCanceled)
			<-releaseFirst
		} else {
			close(secondStarted)
		}
		activeMu.Lock()
		active--
		activeMu.Unlock()
	}}
	service.Start()
	<-firstStarted
	stopReturned := make(chan struct{})
	go func() {
		service.Stop()
		close(stopReturned)
	}()
	<-firstCanceled
	startReturned := make(chan struct{})
	go func() {
		service.Start()
		close(startReturned)
	}()

	// When
	close(releaseFirst)
	<-stopReturned
	<-startReturned
	<-secondStarted
	service.Stop()

	// Then
	activeMu.Lock()
	defer activeMu.Unlock()
	if maxActive != 1 || active != 0 {
		t.Fatalf("run concurrency max=%d active=%d, want max=1 active=0", maxActive, active)
	}
}

func TestRestoreSnapshotCerts_returns_delete_and_materialize_errors(t *testing.T) {
	// Given
	originalCertDir := certDir
	certDir = t.TempDir()
	t.Cleanup(func() { certDir = originalCertDir })
	previous := []models.ClusterCertificate{{RuleID: "invalid/rule", CertPEM: "cert", KeyPEM: "key"}}
	current := []models.ClusterCertificate{{RuleID: "other/invalid", CertPEM: "cert", KeyPEM: "key"}}

	// When
	err := restoreSnapshotCerts(previous, current)

	// Then
	if err == nil {
		t.Fatal("certificate restoration errors were discarded")
	}
	if !strings.Contains(err.Error(), "invalid/rule") || !strings.Contains(err.Error(), "other/invalid") {
		t.Fatalf("restore error=%q, want both delete and materialize failures", err)
	}
}

func TestComputeNodeStatus_marks_stale_approved_node_offline(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 18, 12, 10, 0, 0, time.UTC)
	lastSeen := now.Add(-181 * time.Second)

	// When
	status := ComputeNodeStatus(true, lastSeen, 60, now)

	// Then
	if status != "offline" {
		t.Fatalf("status = %q, want offline", status)
	}
}

// 巡检离线阈值 max(2×sync_interval,120s)
// （cluster_masterserving.go）与 UI 阈值 2×clamp(sync_interval)（ComputeNodeStatus/
// updateOverview）在 sync_interval∈[10,59] 分叉——interval=30 时巡检以 120s 判
// 在线、UI 以 60s 判离线，同一节点在告警与节点列表两口径打架。归一为同一函数
// nodeOfflineThreshold 后，两口径在分叉区间必须一致。
func TestNodeOfflineThreshold_unifiesInspectAndUIAtLowInterval(t *testing.T) {
	// Given sync_interval=30（分叉区间）+ 节点 90s 前上报（巡检阈值 120s 内、
	// 旧 UI 阈值 60s 外）
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	lastSeen := now.Add(-90 * time.Second)

	// When 取统一阈值并走 UI 判定
	threshold := nodeOfflineThreshold(30)
	status := ComputeNodeStatus(true, lastSeen, 30, now)

	// Then 阈值=max(2×30,120)=120s（与巡检同口径）；UI 90s<120s 判在线
	if threshold != 120*time.Second {
		t.Fatalf("nodeOfflineThreshold(30)=%v, want 120s（max(2×interval,120s)，与巡检同口径）", threshold)
	}
	if status != "online" {
		t.Fatalf("ComputeNodeStatus(interval=30, last_seen 90s 前)=%q, want online（巡检同刻判在线，两口径必须一致）", status)
	}
	// 脏值 clamp 保持口径：sync_interval=5 按 60s 计 → max(120,120)=120s
	if got := nodeOfflineThreshold(5); got != 120*time.Second {
		t.Fatalf("nodeOfflineThreshold(5)=%v, want 120s（脏值 clamp 60s 后与下限取大）", got)
	}
	// 大 interval 不被下限钳制：interval=300 → 600s
	if got := nodeOfflineThreshold(300); got != 600*time.Second {
		t.Fatalf("nodeOfflineThreshold(300)=%v, want 600s", got)
	}
}

func TestClusterService_Promote_resets_slave_state(t *testing.T) {
	// Given
	// Promote 成功路径会拉起自动备份调度器——测试结束即停,
	// 防止泄漏的 worker 跨用例 tick 全局 DB。
	_, database := newClusterTestService(t)
	lifecycle := &clusterLifecycleFake{}
	service := NewClusterService(database, "")
	wireClusterLifecycleEngineForTest(t, lifecycle, false)
	if _, err := database.Exec(`UPDATE global_config SET is_master=0, master_url='https://master', cluster_token='secret', cluster_version=4, applied_version=3, sync_fingerprint='fp-1', last_sync_error='{"code":"transport_error","message":"同步拉取失败"}', registration_confirm_failures=2 WHERE id=1`); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}
	installGlobalConfigVersionTrigger(t, database)

	// When
	if err := service.Promote(context.Background()); err != nil {
		t.Fatalf("promote: %v", err)
	}

	// Then
	var isMaster bool
	var masterURL, token string
	var version, appliedVersion, confirmFailures int
	var fingerprint, syncError string
	if err := database.QueryRow(`SELECT is_master, COALESCE(master_url,''), COALESCE(cluster_token,''), cluster_version, COALESCE(applied_version,0), COALESCE(sync_fingerprint,''), COALESCE(last_sync_error,''), COALESCE(registration_confirm_failures,0) FROM global_config WHERE id=1`).Scan(&isMaster, &masterURL, &token, &version, &appliedVersion, &fingerprint, &syncError, &confirmFailures); err != nil {
		t.Fatalf("read promoted state: %v", err)
	}
	if !isMaster || masterURL != "" || token != "" || version != 5 {
		t.Fatalf("promoted state master=%v url=%q token=%q version=%d", isMaster, masterURL, token, version)
	}
	if appliedVersion != 0 || fingerprint != "" || syncError != "" || confirmFailures != 0 {
		t.Fatalf("promote left slave residue: applied_version=%d fingerprint=%q sync_error=%q confirm_failures=%d", appliedVersion, fingerprint, syncError, confirmFailures)
	}
	waitForCond(t, 2*time.Second, func() bool { return lifecycle.syncStopped() && lifecycle.acmeStarted() })
}

func TestClusterService_Promote_removes_old_master_pin_and_audits(t *testing.T) {
	// Given
	// Promote 成功路径会拉起自动备份调度器——测试结束即停。
	_, database := newClusterTestService(t)
	service := NewClusterService(database, "")
	masterURL := "https://master.example:8443"
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='secret' WHERE id=1", masterURL); err != nil {
		t.Fatal(err)
	}
	pinPath, err := clusterPinPath("", database, "master.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(pinPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte("fingerprint\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// When
	if err := service.Promote(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Then
	if _, err := os.Stat(pinPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pin stat error=%v, want not exist", err)
	}
	var action, detail string
	if err := db.AuditDB.QueryRow("SELECT action,detail FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&action, &detail); err != nil {
		t.Fatal(err)
	}
	if action != "清理" || !strings.Contains(detail, masterURL) {
		t.Fatalf("audit action=%q detail=%q", action, detail)
	}
}

func TestClusterService_Promote_succeeds_when_pin_cleanup_fails_then_retries_on_snapshot(t *testing.T) {
	// Given
	// Promote 成功路径会拉起自动备份调度器——测试结束即停。
	service, database := newClusterTestService(t)
	masterURL := "https://master.example:8443"
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='secret' WHERE id=1", masterURL); err != nil {
		t.Fatal(err)
	}
	pinPath, err := clusterPinPath("", database, "master.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pinPath, 0700); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(pinPath, "blocker")
	if err := os.WriteFile(blocker, []byte("block removal"), 0600); err != nil {
		t.Fatal(err)
	}

	// When
	promoteErr := service.Promote(context.Background())
	_, residualErr := os.Stat(pinPath)
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	_, _, snapshotErr := service.Snapshot(context.Background(), 0, "", "")
	_, finalErr := os.Stat(pinPath)

	// Then
	if promoteErr != nil {
		t.Fatalf("promote returned pin cleanup failure: %v", promoteErr)
	}
	if residualErr != nil {
		t.Fatalf("failed cleanup did not leave retryable pin: %v", residualErr)
	}
	if snapshotErr != nil || !errors.Is(finalErr, os.ErrNotExist) {
		t.Fatalf("snapshot retry error=%v final pin stat=%v", snapshotErr, finalErr)
	}
}

func TestClusterService_Promote_restarts_sync_when_transaction_fails(t *testing.T) {
	_, database := newClusterTestService(t)
	lifecycle := &clusterLifecycleFake{}
	service := NewClusterService(database, "")
	wireClusterLifecycleEngineForTest(t, lifecycle, false)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}
	if _, err := database.Exec(`CREATE TRIGGER reject_promotion BEFORE UPDATE OF is_master ON global_config
		WHEN NEW.is_master=1 BEGIN SELECT RAISE(ABORT, 'reject promotion'); END`); err != nil {
		t.Fatalf("install promotion failure trigger: %v", err)
	}

	if err := service.Promote(context.Background()); err == nil {
		t.Fatal("promotion unexpectedly succeeded")
	}
	waitForCond(t, 2*time.Second, func() bool { return lifecycle.syncStopped() && lifecycle.syncStarted() })
	var isMaster bool
	if err := database.QueryRow("SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
		t.Fatalf("read role after failed promotion: %v", err)
	}
	if isMaster {
		t.Fatal("failed promotion committed master role")
	}
}

func TestReplaceSnapshotDB_replaces_resources_without_overwriting_role(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url='https://master', sync_interval=45 WHERE id=1"); err != nil {
		t.Fatalf("seed role fields: %v", err)
	}
	caddyConfig := "{}"
	snapshot := models.ClusterSnapshot{
		Version: 9,
		Rules: []models.LbRule{{
			CaddyID: "lb_snapshot1", Name: "snapshot", Protocol: "http", ListenPort: 8080,
			Strategy: "round_robin", Enabled: true, CustomRoutesEnabled: true,
			ProxyDialTimeout: 3, ProxyResponseHeaderTimeout: 4, ProxyReadTimeout: 5, ProxyWriteTimeout: 6, ProxyStreamTimeout: 7, ProxyFlushInterval: -1, ProxyStreamCloseDelay: 5,
			Upstreams: []models.Upstream{{ID: 11, Host: "127.0.0.1", Port: 9000, Weight: 1, Enabled: true, Protocol: "http"}},
			PathRules: []models.PathRule{{ID: 21, SortOrder: 2, MatchType: "prefix", Path: "/metrics/", Upstreams: nil}},
		}},
		Users:         []models.ClusterUser{{ID: 20, Username: "admin-master", PasswordHash: "hash", Role: "admin", IsEnabled: true}},
		APIKeys:       []models.ClusterAPIKey{{ID: 30, Name: "ci", KeyHash: "key-hash", KeyPrefix: "lb_sk_master", CreatedBy: 20, IsEnabled: true}},
		BasicSettings: models.ClusterBasicSettings{LogLevel: new("debug"), AccessLogJSON: new(true), Timezone: new("Asia/Shanghai"), SyncInterval: new(120), ProxyDialTimeout: new(8), ProxyResponseHeaderTimeout: new(9), ProxyReadTimeout: new(10), ProxyWriteTimeout: new(11), ProxyStreamTimeout: new(12), ProxyFlushInterval: new(0), ProxyStreamCloseDelay: new(3)},
		CaddyConfig:   &caddyConfig,
	}

	// When
	err := replaceSnapshotDB(context.Background(), database, snapshot)

	// Then
	if err != nil {
		t.Fatalf("replace snapshot: %v", err)
	}
	var rules, upstreams, paths, users, keys int
	if err := database.QueryRow(`SELECT (SELECT COUNT(*) FROM lb_rules), (SELECT COUNT(*) FROM upstreams), (SELECT COUNT(*) FROM path_rules), (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM api_keys)`).Scan(&rules, &upstreams, &paths, &users, &keys); err != nil {
		t.Fatalf("count replaced resources: %v", err)
	}
	if rules != 1 || upstreams != 1 || paths != 1 || users != 1 || keys != 1 {
		t.Fatalf("resource counts rules=%d upstreams=%d paths=%d users=%d keys=%d", rules, upstreams, paths, users, keys)
	}
	var isMaster bool
	var masterURL string
	var syncInterval int
	if err := database.QueryRow("SELECT is_master, master_url, sync_interval FROM global_config WHERE id=1").Scan(&isMaster, &masterURL, &syncInterval); err != nil {
		t.Fatalf("read preserved role: %v", err)
	}
	if isMaster || masterURL != "https://master" || syncInterval != 120 {
		t.Fatalf("role overwritten master=%v url=%q interval=%d", isMaster, masterURL, syncInterval)
	}
	var path string
	var ruleDialTimeout, globalDialTimeout int
	if err := database.QueryRow(`SELECT r.proxy_dial_timeout,p.path,g.proxy_dial_timeout FROM lb_rules r JOIN path_rules p ON p.rule_id=r.caddy_id JOIN global_config g ON g.id=1 WHERE r.caddy_id='lb_snapshot1'`).Scan(&ruleDialTimeout, &path, &globalDialTimeout); err != nil {
		t.Fatalf("read new snapshot fields: %v", err)
	}
	if ruleDialTimeout != 3 || path != "/metrics/" || globalDialTimeout != 8 {
		t.Fatalf("new snapshot fields rule_dial=%d path=%q global_dial=%d", ruleDialTimeout, path, globalDialTimeout)
	}
}

func TestReplaceSnapshotDB_clamps_invalid_jwt_expiry(t *testing.T) {
	_, database := newClusterTestService(t)
	for _, expiry := range []int{0, -1, 1441} {
		snapshot := models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{JWTExpireMinutes: new(expiry)}}
		if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
			t.Fatalf("replace snapshot with JWT expiry %d: %v", expiry, err)
		}
		var got int
		if err := database.QueryRow("SELECT jwt_expire_minutes FROM global_config WHERE id=1").Scan(&got); err != nil {
			t.Fatalf("read JWT expiry: %v", err)
		}
		if got != 20 {
			t.Fatalf("JWT expiry after snapshot value %d = %d, want 20", expiry, got)
		}
	}
}

func TestClusterSnapshot_syncs_password_version_and_changed_at(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,password_version,password_changed_at)
		VALUES (20,'admin-master','hash','admin',1,9,'2026-07-31 01:02:03')`); err != nil {
		t.Fatalf("seed user password timestamp: %v", err)
	}

	snapshot, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if len(snapshot.Users) != 1 || snapshot.Users[0].PasswordVersion != 9 || snapshot.Users[0].PasswordChangedAt == nil || *snapshot.Users[0].PasswordChangedAt != "2026-07-31T01:02:03.000Z" {
		t.Fatalf("snapshot password fields=%#v", snapshot.Users)
	}
	if _, err := database.Exec("DELETE FROM users"); err != nil {
		t.Fatalf("clear users: %v", err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}
	var restored string
	var restoredVersion int64
	if err := database.QueryRow("SELECT password_version,strftime('%Y-%m-%dT%H:%M:%fZ',password_changed_at) FROM users WHERE id=20").Scan(&restoredVersion, &restored); err != nil {
		t.Fatalf("read restored password timestamp: %v", err)
	}
	if restoredVersion != 9 || restored != "2026-07-31T01:02:03.000Z" {
		t.Fatalf("restored password_version=%d password_changed_at=%q", restoredVersion, restored)
	}
}

func TestClusterSnapshot_preservesUserTimesAndLegacyRuleID(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,created_at,last_login)
		VALUES (21,'time-user','hash','admin',1,'2026-07-01 01:02:03','2026-07-31 04:05:06')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id,caddy_id,name,protocol,listen_port) VALUES (4242,'lb_legacy_id','legacy id','http',8080)`); err != nil {
		t.Fatal(err)
	}

	// When
	snapshot, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(snapshot.Users[0])
	if err != nil {
		t.Fatal(err)
	}
	var decoded models.ClusterUser
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatal(err)
	}
	var createdAt, lastLogin string
	var legacyID int
	if err := database.QueryRow(`SELECT strftime('%Y-%m-%dT%H:%M:%fZ',u.created_at),strftime('%Y-%m-%dT%H:%M:%fZ',u.last_login),r.id FROM users u CROSS JOIN lb_rules r WHERE u.id=21 AND r.caddy_id='lb_legacy_id'`).Scan(&createdAt, &lastLogin, &legacyID); err != nil {
		t.Fatal(err)
	}

	// Then
	if len(snapshot.Users) != 1 || len(snapshot.Rules) != 1 {
		t.Fatalf("users=%d rules=%d", len(snapshot.Users), len(snapshot.Rules))
	}
	if !decoded.LastLogin.Valid || decoded.CreatedAt.IsZero() {
		t.Fatalf("decoded user times=%#v", decoded)
	}
	if snapshot.Rules[0].ID != 4242 || legacyID != 4242 {
		t.Fatalf("snapshot rule id=%d restored id=%d", snapshot.Rules[0].ID, legacyID)
	}
	if createdAt != "2026-07-01T01:02:03.000Z" || lastLogin != "2026-07-31T04:05:06.000Z" {
		t.Fatalf("restored created_at=%q last_login=%q", createdAt, lastLogin)
	}
}

func TestClusterSnapshotPreservesAPIKeyRestrictionsAndRuleTimestamps(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (20,'owner','hash','admin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by,is_enabled,mcp_enabled,read_only,mcp_ip_whitelist) VALUES (30,'restricted','hash','lb_key',20,1,1,1,'["192.0.2.0/24"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,created_at,updated_at) VALUES ('lb_times','times','http',8080,'2026-07-01 01:02:03','2026-07-02 04:05:06')`); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != CurrentSnapshotSchema || snapshot.MinReaderVersion != CurrentSnapshotSchema {
		t.Fatalf("snapshot schema=%d min_reader=%d", snapshot.SchemaVersion, snapshot.MinReaderVersion)
	}
	if len(snapshot.APIKeys) != 1 || !snapshot.APIKeys[0].MCPEnabled || !snapshot.APIKeys[0].ReadOnly || len(snapshot.APIKeys[0].MCPIPWhitelist) != 1 {
		t.Fatalf("snapshot API key=%#v", snapshot.APIKeys)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err := service.Promote(context.Background()); err != nil {
		t.Fatal(err)
	}
	var mcpEnabled, readOnly bool
	var whitelist, createdAt, updatedAt string
	if err := database.QueryRow(`SELECT k.mcp_enabled,k.read_only,k.mcp_ip_whitelist,strftime('%Y-%m-%d %H:%M:%S',r.created_at),strftime('%Y-%m-%d %H:%M:%S',r.updated_at) FROM api_keys k CROSS JOIN lb_rules r WHERE k.id=30 AND r.caddy_id='lb_times'`).Scan(&mcpEnabled, &readOnly, &whitelist, &createdAt, &updatedAt); err != nil {
		t.Fatal(err)
	}
	if !mcpEnabled || !readOnly || whitelist != `["192.0.2.0/24"]` || createdAt != "2026-07-01 01:02:03" || updatedAt != "2026-07-02 04:05:06" {
		t.Fatalf("restored key/times mcp=%v read_only=%v whitelist=%q created=%q updated=%q", mcpEnabled, readOnly, whitelist, createdAt, updatedAt)
	}
}

func TestSyncService_applySnapshot_inherits_version_for_promotion(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	if err := syncService.applySnapshot(context.Background(), v3SnapshotWithACMESection(models.ClusterSnapshot{Version: 100})); err != nil {
		t.Fatalf("apply version 100: %v", err)
	}

	if err := service.Promote(context.Background()); err != nil {
		t.Fatalf("promote slave: %v", err)
	}
	published, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("publish promoted snapshot: %v", err)
	}
	if published.Version < 100 {
		t.Fatalf("promoted snapshot version=%d, want >=100", published.Version)
	}
}

func TestSyncService_applySnapshot_keeps_committed_snapshot_when_caddy_rejects_config(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}
	if _, err := database.Exec("INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('local-admin','hash','admin',1)"); err != nil {
		t.Fatalf("seed local user: %v", err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusBadRequest)
		_, _ = response.Write([]byte("rejected"))
	}))
	defer caddyServer.Close()
	cfg := &config.Config{CaddyAdminURL: caddyServer.URL}
	syncService := NewSyncService(database, cfg, NewCaddyService(caddyServer.URL))
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{
		Version:       2,
		Users:         []models.ClusterUser{{ID: 99, Username: "incoming", PasswordHash: "hash", Role: "admin", IsEnabled: true}},
		BasicSettings: models.ClusterBasicSettings{LogLevel: new("info"), AccessLogJSON: new(true), Timezone: new("Asia/Shanghai")},
	})

	// When
	err := syncService.applySnapshot(context.Background(), snapshot)

	// Then: Caddy 重载发生在事务提交之后，拒绝仅记录日志与审计，不回滚快照
	if err != nil {
		t.Fatalf("snapshot apply returned error despite committed data: %v", err)
	}
	var incomingCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM users WHERE username='incoming'").Scan(&incomingCount); err != nil {
		t.Fatalf("read committed users: %v", err)
	}
	if incomingCount != 1 {
		t.Fatalf("committed incoming users=%d, want 1", incomingCount)
	}
	var reloadFailures int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='重载失败' AND resource='Caddy服务'").Scan(&reloadFailures); err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if reloadFailures != 1 {
		t.Fatalf("reload failure audit entries=%d, want 1", reloadFailures)
	}
}

func TestSyncService_applySnapshot_invalidates_cache_only_after_commit(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}
	reject := false
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		if reject {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	snapshotA := v3SnapshotWithACMESection(models.ClusterSnapshot{Version: 1, Users: []models.ClusterUser{{ID: 1, Username: "user-a", PasswordHash: "hash", Role: "admin", IsEnabled: true}}, BasicSettings: models.ClusterBasicSettings{LogLevel: new("info"), Timezone: new("Asia/Shanghai")}})
	if err := syncService.applySnapshot(context.Background(), snapshotA); err != nil {
		t.Fatalf("apply snapshot A: %v", err)
	}
	// 快照读取是主节点-only 契约（读路径 SQL 角色复核）：缓存检查前切主角色
	// （apply 直调路径的零值守卫不校验角色，语义不受影响）。
	if _, err := database.Exec("UPDATE global_config SET is_master=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	cachedA, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil || len(cachedA.Users) != 1 || cachedA.Users[0].Username != "user-a" {
		t.Fatalf("cache snapshot A=%#v err=%v", cachedA.Users, err)
	}

	snapshotB := v3SnapshotWithACMESection(models.ClusterSnapshot{Version: 2, Users: []models.ClusterUser{{ID: 2, Username: "user-b", PasswordHash: "hash", Role: "admin", IsEnabled: true}}, BasicSettings: snapshotA.BasicSettings})
	if err := syncService.applySnapshot(context.Background(), snapshotB); err != nil {
		t.Fatalf("apply snapshot B: %v", err)
	}
	cachedB, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil || len(cachedB.Users) != 1 || cachedB.Users[0].Username != "user-b" {
		t.Fatalf("cache snapshot B=%#v err=%v", cachedB.Users, err)
	}

	reject = true
	snapshotC := v3SnapshotWithACMESection(models.ClusterSnapshot{Version: 3, Users: []models.ClusterUser{{ID: 3, Username: "user-c", PasswordHash: "hash", Role: "admin", IsEnabled: true}}, BasicSettings: snapshotA.BasicSettings})
	// Caddy 拒绝不再回滚快照：提交照常发生，缓存随之失效并重建为 user-c。
	if err := syncService.applySnapshot(context.Background(), snapshotC); err != nil {
		t.Fatalf("snapshot C apply: %v", err)
	}
	afterReloadFailure, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil || len(afterReloadFailure.Users) != 1 || afterReloadFailure.Users[0].Username != "user-c" {
		t.Fatalf("cache after C=%#v err=%v", afterReloadFailure.Users, err)
	}
}

func TestSyncService_restart_callback_runs_when_synced_admin_TLS_changes(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0, admin_tls_enabled=0 WHERE id=1"); err != nil {
		t.Fatalf("seed slave mode: %v", err)
	}
	RecordRuntimeAdminTLS(AdminTLSConfig{Enabled: false, Mode: "selfsigned"})
	restarted := make(chan struct{}, 1)
	SetRestartRequiredHandler(func() { restarted <- struct{}{} })
	t.Cleanup(func() { SetRestartRequiredHandler(nil) })
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{Version: 2, BasicSettings: models.ClusterBasicSettings{
		LogLevel: new("info"), AccessLogJSON: new(true), Timezone: new("Asia/Shanghai"), AdminTLSEnabled: new(true), AdminTLSMode: new("selfsigned"),
	}})

	// When
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then
	select {
	case <-restarted:
	default:
		t.Fatal("restart callback was not invoked")
	}
}

func TestSyncService_pollRegistration_clears_temporary_secret_after_approval(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && request.URL.Path == "/api/v1/cluster/registration/confirm" {
			if request.Header.Get("X-Cluster-Token") != "lb_cluster_approved" {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			response.WriteHeader(http.StatusOK)
			return
		}
		if request.Header.Get("X-Registration-Secret") != "temporary-secret" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"code":0,"data":{"status":"approved","cluster_token":"lb_cluster_approved"}}`))
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, registration_id=7, registration_secret='temporary-secret', cluster_token='' WHERE id=1", master.URL); err != nil {
		t.Fatalf("seed pending registration: %v", err)
	}
	syncService := NewSyncService(database, &config.Config{}, NewCaddyService(master.URL))

	// When
	syncService.pollRegistration(context.Background())

	// Then
	var clusterToken, registrationSecret string
	if err := database.QueryRow("SELECT cluster_token, registration_secret FROM global_config WHERE id=1").Scan(&clusterToken, &registrationSecret); err != nil {
		t.Fatalf("read approved registration: %v", err)
	}
	if clusterToken != "lb_cluster_approved" || registrationSecret != "" {
		t.Fatalf("approved credentials token=%q temporary_secret=%q", clusterToken, registrationSecret)
	}
}

func TestSyncService_Report_sends_status_with_space_format_last_sync(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	var gotAuth string
	var gotBody []byte
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		gotAuth = request.Header.Get("X-Cluster-Token")
		if request.Body != nil {
			buf := make([]byte, 4096)
			n, _ := request.Body.Read(buf)
			gotBody = buf[:n]
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"code":0,"message":"ok"}`))
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='tok-1', applied_version=3, last_sync=datetime('now') WHERE id=1", master.URL); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}
	syncService := NewSyncService(database, &config.Config{}, NewCaddyService(master.URL))

	// When
	err := syncService.Report(context.Background())

	// Then
	if err != nil {
		t.Fatalf("report failed with space-format last_sync: %v", err)
	}
	if gotAuth != "tok-1" {
		t.Fatalf("cluster token header = %q", gotAuth)
	}
	if len(gotBody) == 0 || !strings.Contains(string(gotBody), `"applied_version":3`) {
		t.Fatalf("report payload = %q", string(gotBody))
	}
}

func TestClusterService_UpdateSettings_sync_interval_master_only(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	interval := 45
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}

	// When
	slaveErr := service.UpdateSettings(context.Background(), models.ClusterSettingsRequest{SyncInterval: &interval})

	// Then
	if slaveErr == nil {
		t.Fatal("slave updated sync_interval")
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1 WHERE id=1"); err != nil {
		t.Fatalf("restore master mode: %v", err)
	}
	if _, err := database.Exec("UPDATE global_config SET cluster_version=0 WHERE id=1"); err != nil {
		t.Fatalf("reset cluster version: %v", err)
	}
	installGlobalConfigVersionTrigger(t, database)

	// When
	masterErr := service.UpdateSettings(context.Background(), models.ClusterSettingsRequest{SyncInterval: &interval})

	// Then
	if masterErr != nil {
		t.Fatalf("master update settings: %v", masterErr)
	}
	var gotInterval, gotVersion int
	if err := database.QueryRow("SELECT sync_interval, cluster_version FROM global_config WHERE id=1").Scan(&gotInterval, &gotVersion); err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if gotInterval != 45 || gotVersion != 1 {
		t.Fatalf("interval=%d version=%d", gotInterval, gotVersion)
	}
}

func TestClusterService_UpdateSettings_rejects_role_change_before_update(t *testing.T) {
	service, database := newClusterTestService(t)
	checkedRole := make(chan struct{})
	continueUpdate := make(chan struct{})
	service.beforeUpdateSettings = func() {
		close(checkedRole)
		<-continueUpdate
	}
	interval := 45
	updateDone := make(chan error, 1)
	go func() {
		updateDone <- service.UpdateSettings(context.Background(), models.ClusterSettingsRequest{SyncInterval: &interval})
	}()
	<-checkedRole
	if err := service.BecomeSlave(context.Background(), "https://master", models.ClusterRegistration{}); err != nil {
		t.Fatalf("become slave: %v", err)
	}
	close(continueUpdate)
	if err := <-updateDone; err == nil {
		t.Fatal("settings update succeeded after role changed to slave")
	}
	var gotInterval int
	var isMaster bool
	if err := database.QueryRow("SELECT sync_interval,is_master FROM global_config WHERE id=1").Scan(&gotInterval, &isMaster); err != nil {
		t.Fatalf("read settings after role change: %v", err)
	}
	if isMaster || gotInterval == interval {
		t.Fatalf("role/settings after interleaving is_master=%v sync_interval=%d", isMaster, gotInterval)
	}
}

func installGlobalConfigVersionTrigger(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(`CREATE TRIGGER test_cluster_version_global_config_update
		AFTER UPDATE ON global_config
		WHEN OLD.cluster_version IS NEW.cluster_version AND NEW.is_master=1
		BEGIN UPDATE global_config SET cluster_version=cluster_version+1 WHERE id=1; END`); err != nil {
		t.Fatalf("install global config version trigger: %v", err)
	}
}

// 三分类合并(2026-09-19 用户裁定):全局配置并入系统数据节(恒同步不可
// 禁用)——BasicSettings/CaddyConfig 不再受任何开关裁剪,快照恒携带。
func TestClusterSnapshot_alwaysCarriesGlobalSettings(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.ExecContext(ctx, "UPDATE global_config SET access_log_json=1, access_log_format='{request}', caddy_log_level='warn' WHERE id=1"); err != nil {
		t.Fatalf("seed access log settings: %v", err)
	}
	tx, err := database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("begin snapshot tx: %v", err)
	}
	defer tx.Rollback()
	snapshot, err := service.buildSnapshot(ctx, tx)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}

	// Then：全局设置与 Caddy 配置恒携带(无开关裁剪路径)
	if snapshot.CaddyConfig == nil {
		t.Fatal("caddy config must always be carried (users section is always synced)")
	}
	if snapshot.BasicSettings.AccessLogJSON == nil || !*snapshot.BasicSettings.AccessLogJSON ||
		snapshot.BasicSettings.AccessLogFormat == nil || *snapshot.BasicSettings.AccessLogFormat != "{request}" ||
		snapshot.BasicSettings.CaddyLogLevel == nil || *snapshot.BasicSettings.CaddyLogLevel != "warn" {
		t.Fatalf("access log settings must always be carried: %#v", snapshot.BasicSettings)
	}
}

// 测试名/注释原以「Caddy 同步开关关闭」描述行为，
// 但三分类合并后已无 sync_caddy_config 开关（列已删，见下方
// TestClusterService_Status_removesLegacySyncCaddyConfig）。真实契约是：
// 快照未携带 caddy_config（=旧主端缺席）时跳过 Caddy 全局列，保留从端本地值。
func TestUpdateSnapshotSettings_preservesSlaveAccessLogSettingsWhenSnapshotOmitsCaddyConfig(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.ExecContext(ctx, "UPDATE global_config SET access_log_json=0, access_log_format='slave-format' WHERE id=1"); err != nil {
		t.Fatalf("seed slave access log settings: %v", err)
	}
	apply := func(t *testing.T, snapshot models.ClusterSnapshot) {
		t.Helper()
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin apply tx: %v", err)
		}
		defer tx.Rollback()
		if err := updateSnapshotSettings(ctx, tx, snapshot); err != nil {
			t.Fatalf("apply settings: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit apply tx: %v", err)
		}
	}
	readAccessLog := func(t *testing.T) (bool, string) {
		t.Helper()
		var jsonOut bool
		var format string
		if err := database.QueryRowContext(ctx, "SELECT access_log_json, access_log_format FROM global_config WHERE id=1").Scan(&jsonOut, &format); err != nil {
			t.Fatalf("read access log settings: %v", err)
		}
		return jsonOut, format
	}

	// When snapshot omits caddy_config（旧主端快照缺席；无开关语义）
	apply(t, models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{
		LogLevel: new("debug"), AccessLogJSON: new(true), AccessLogFormat: new("master-format"), JWTExpireMinutes: new(20),
	}})

	// Then slave-local access log settings survive, ungated settings applied
	gotJSON, gotFormat := readAccessLog(t)
	if gotJSON || gotFormat != "slave-format" {
		t.Fatalf("access log settings overwritten when snapshot omits caddy_config: json=%v format=%q", gotJSON, gotFormat)
	}
	var logLevel string
	if err := database.QueryRowContext(ctx, "SELECT log_level FROM global_config WHERE id=1").Scan(&logLevel); err != nil {
		t.Fatalf("read log level: %v", err)
	}
	if logLevel != "debug" {
		t.Fatalf("ungated log level not applied: %q", logLevel)
	}

	// When snapshot carries caddy_config
	caddyConfig := "{}"
	apply(t, models.ClusterSnapshot{CaddyConfig: &caddyConfig, BasicSettings: models.ClusterBasicSettings{
		AccessLogJSON: new(true), AccessLogFormat: new("master-format"), JWTExpireMinutes: new(20),
	}})
	gotJSON, gotFormat = readAccessLog(t)
	if !gotJSON || gotFormat != "master-format" {
		t.Fatalf("access log settings not applied when snapshot carries caddy_config: json=%v format=%q", gotJSON, gotFormat)
	}
}

// 旧主端 basic_settings 缺字段与显式零值不同。缺席字段必须
// 全部跳过写入，不能将本节点现有配置清成 Go 零值。
func TestUpdateSnapshotSettings_legacyAbsentFieldsPreserveEntireLocalRow(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.Exec(`UPDATE global_config SET
		log_level='warn',task_log_size_mb=77,audit_log_size_mb=78,runtime_log_size_mb=79,
		audit_retention_months=8,jwt_expire_minutes=777,timezone='UTC',acme_email='local@example.test',
		cert_expiry_days=44,cert_renewal_days=45,cert_renewal_attempts=6,default_ca_provider_id=88,
		sync_interval=321,
		admin_tls_enabled=1,admin_tls_mode='upload',admin_tls_cert='local-cert',admin_tls_key='local-key',
		mfa_write_guard=1,mfa_lockout_enabled=1,github_proxy_url='https://local.proxy',oidc_config='{"issuer":"local"}',
		branding_json='{"app_name":"local"}',caddy_config='{"apps":{}}',access_log_json=0,
		access_log_format='local-format',caddy_log_level='error',caddy_log_size_mb=66,
		request_body_max_size_mb=64,http_read_timeout=61,http_write_timeout=62,http_idle_timeout=63,
		upstream_keepalive_timeout=64,proxy_dial_timeout=65,proxy_response_header_timeout=66,
		proxy_read_timeout=67,proxy_write_timeout=68,proxy_stream_timeout=69,proxy_flush_interval=70,
		proxy_stream_close_delay=71,github_proxy_url='https://local.proxy',server_tokens_hidden=1,
		trusted_proxy_enabled=1,trusted_proxy_ranges='["192.0.2.1"]',trusted_proxy_range_refs='[7]',
		trusted_proxy_headers='["X-Local"]',trusted_proxy_strict=0
		WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	readRow := func() string {
		t.Helper()
		rows, err := database.Query(`SELECT * FROM global_config WHERE id=1`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		values := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if !rows.Next() {
			t.Fatal("global_config row missing")
		}
		if err := rows.Scan(dest...); err != nil {
			t.Fatal(err)
		}
		object := make(map[string]any, len(columns))
		for i, column := range columns {
			object[column] = values[i]
		}
		encoded, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	before := readRow()
	var snapshot models.ClusterSnapshot
	if err := json.Unmarshal([]byte(`{"basic_settings":{},"caddy_config":"{\"apps\":{}}"}`), &snapshot); err != nil {
		t.Fatal(err)
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := updateSnapshotSettings(ctx, tx, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if after := readRow(); after != before {
		t.Fatalf("legacy absent fields changed local global_config\nbefore=%s\nafter=%s", before, after)
	}
}

func TestClusterService_Status_omitsSyncCaddyConfig(t *testing.T) {
	// Given
	service, _ := newClusterTestService(t)

	// When
	status, err := service.Status(context.Background())
	if err != nil {
		t.Fatalf("status error: %v", err)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}

	// Then
	if strings.Contains(string(encoded), "sync_caddy_config") {
		t.Fatalf("status JSON still contains sync_caddy_config: %s", encoded)
	}
}

func TestClusterService_UpdateSettings_ignoresLegacySyncCaddyConfig(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.ExecContext(ctx, "UPDATE global_config SET is_master=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	// When legacy payload carries the removed switch, it must be ignored rather than error
	var req models.ClusterSettingsRequest
	if err := json.Unmarshal([]byte(`{"sync_caddy_config":false}`), &req); err != nil {
		t.Fatal(err)
	}
	if err := service.UpdateSettings(ctx, req); err != nil {
		t.Fatalf("update settings: %v", err)
	}

	// Then
	var columnCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='sync_caddy_config'").Scan(&columnCount); err != nil {
		t.Fatal(err)
	}
	if columnCount != 0 {
		t.Fatalf("sync_caddy_config column still exists")
	}
}

func TestClusterService_UpdateSettings_sync_interval_range_validation(t *testing.T) {
	// 发现1：sync_interval 落库前必须做范围校验，否则从节点 run 循环
	// waitDelay(0) 进入零间隔 Pull 风暴。
	service, database := newClusterTestService(t)
	ctx := context.Background()

	rejected := []int{0, -1, 9, 86401, 1000000}
	for _, value := range rejected {
		interval := value
		err := service.UpdateSettings(ctx, models.ClusterSettingsRequest{SyncInterval: &interval})
		if !errors.Is(err, ErrInvalidSyncInterval) {
			t.Fatalf("interval=%d: err=%v, want ErrInvalidSyncInterval", value, err)
		}
	}

	accepted := []int{10, 60, 86400}
	for _, value := range accepted {
		interval := value
		if err := service.UpdateSettings(ctx, models.ClusterSettingsRequest{SyncInterval: &interval}); err != nil {
			t.Fatalf("interval=%d: unexpected err %v", value, err)
		}
		var got int
		if err := database.QueryRow("SELECT sync_interval FROM global_config WHERE id=1").Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != value {
			t.Fatalf("interval=%d: persisted=%d", value, got)
		}
	}
}

func TestClusterService_Nodes_matchesOverviewOnlineCount_withDirtySyncInterval(t *testing.T) {
	// 存量脏值 sync_interval=5时，从节点
	// run loop 实际以 60s 上报；节点列表（ComputeNodeStatus）与总览在线数
	// （updateOverview）必须同口径按 60s 计（阈值 120s），否则同一节点在两页面
	// 判定打架，且上报窗口内的从节点被误判离线。
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET sync_interval=5 WHERE id=1`); err != nil {
		t.Fatalf("seed dirty sync_interval: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO nodes (id,name,mode,ip_address,is_approved,status,last_seen) VALUES
		(1,'recent','slave','10.0.0.1',1,'online',datetime('now','-30 seconds')),
		(2,'stale','slave','10.0.0.2',1,'online',datetime('now','-150 seconds'))`); err != nil {
		t.Fatalf("seed nodes: %v", err)
	}
	metrics := &MetricsService{}

	// When
	nodes, err := service.Nodes(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	metrics.updateOverview(parsedMetrics{})

	// Then：两条路径对每个节点的在线判定一致（30s<120s 在线，150s>120s 离线）
	statusByID := make(map[int]string, len(nodes))
	for _, node := range nodes {
		statusByID[node.ID] = node.Status
	}
	if statusByID[1] != "online" || statusByID[2] != "offline" {
		t.Fatalf("node statuses=%v, want 1=online 2=offline（sync_interval=5 应按 60s 计，阈值 120s）", statusByID)
	}
	wantOnline := 0
	for _, status := range statusByID {
		if status == "online" {
			wantOnline++
		}
	}
	if got := metrics.GetOverview().OnlineNodes; got != wantOnline {
		t.Fatalf("overview online=%d, want %d（与节点列表判定一致）", got, wantOnline)
	}
}

// 重新注册不携带 AccessURL(cluster_mode.go 恒空)时
// 必须保留管理员维护的存量,不静默清空。
func TestClusterService_ReRegisterPreservesAccessURL(t *testing.T) {
	service, database := newClusterTestService(t)
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token, Name: "slave-a", IPAddress: "172.18.0.2", Port: 8000, AccessURL: "http://127.0.0.1:8001",
	}, "172.18.0.2", now)
	if err != nil {
		t.Fatal(err)
	}
	// 管理员维护 access_url
	if err := service.UpdateNodeAccessURL(context.Background(), registration.RegistrationID, "https://node.example:8443"); err != nil {
		t.Fatal(err)
	}

	// When: 重新注册(同 IP+port,不携带 AccessURL——生产形态)
	token2, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token2, Name: "slave-a", IPAddress: "172.18.0.2", Port: 8000,
	}, "172.18.0.2", now); err != nil {
		t.Fatal(err)
	}

	// Then: access_url 保留
	var accessURL string
	if err := database.QueryRow("SELECT access_url FROM nodes WHERE id=?", registration.RegistrationID).Scan(&accessURL); err != nil {
		t.Fatal(err)
	}
	if accessURL != "https://node.example:8443" {
		t.Fatalf("access_url=%q after re-register, want preserved %q", accessURL, "https://node.example:8443")
	}
}

// ConfirmRegistration 清列必须与 Snapshot 旧协议交付
// 确认（cluster_snapshot.go:84）对齐——registration_secret_expires_at 一并
// 置 NULL，否则残留过期时间戳与已清空的 secret 长期分叉。
func TestConfirmRegistration_clearsSecretAndExpiry(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO nodes (name,mode,ip_address,cluster_token_hash,registration_secret,registration_secret_expires_at,is_approved,status)
		VALUES ('s1','slave','10.0.0.2',?, 'pending-secret', datetime('now','+30 minutes'),1,'online')`, tokenHash("slave-token")); err != nil {
		t.Fatal(err)
	}

	// When
	name, err := service.ConfirmRegistration(context.Background(), "slave-token")
	if err != nil {
		t.Fatal(err)
	}
	if name != "s1" {
		t.Fatalf("确认返回节点名=%q, want s1（审计归因依赖该值）", name)
	}

	// Then：secret 与过期时间戳双列均 NULL
	var secret, expires sql.NullString
	if err := database.QueryRow(`SELECT registration_secret, registration_secret_expires_at FROM nodes WHERE name='s1'`).Scan(&secret, &expires); err != nil {
		t.Fatal(err)
	}
	if secret.Valid || expires.Valid {
		t.Fatalf("registration_secret.Valid=%v expires_at.Valid=%v（值 %q/%q）, want 双列均 NULL", secret.Valid, expires.Valid, secret.String, expires.String)
	}
}

// nodes 不在 cluster_version 触发器清单——删除节点
// 必须与注册/改坐标同构地在同事务 bump，否则快照缓存（键含 cluster_version）
// 继续携带被删节点的站点项，直到下一次无关 bump。
func TestDeleteNodeBumpsClusterVersion(t *testing.T) {
	service, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-del")
	version := func() int {
		t.Helper()
		var v int
		if err := database.QueryRow(`SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1`).Scan(&v); err != nil {
			t.Fatalf("read cluster_version: %v", err)
		}
		return v
	}
	before := version()
	if err := service.DeleteNode(context.Background(), nodeID); err != nil {
		t.Fatalf("delete node: %v", err)
	}
	if after := version(); after != before+1 {
		t.Fatalf("cluster_version %d→%d，want +1（拓扑变更必须传播）", before, after)
	}
}

// 作废旧令牌与写入新令牌必须同成同败：分两语句无事务时，INSERT 失败会留下
// 「旧令牌已被 DELETE、新令牌未落库」的空窗——管理员拿到的仍是错误提示，
// 却已无任何可用令牌。
func TestGenerateRegisterToken_invalidationAndInsertAreAtomic(t *testing.T) {
	service, database := newClusterTestService(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	first, _, err := service.GenerateRegisterToken(ctx, 1, now)
	if err != nil {
		t.Fatalf("generate first token: %v", err)
	}
	if _, err := database.Exec(`CREATE TRIGGER reject_register_token_insert BEFORE INSERT ON cluster_register_tokens
		BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.GenerateRegisterToken(ctx, 1, now); err == nil {
		t.Fatal("注入的 INSERT 失败必须以错误上抛")
	}
	if _, err := database.Exec("DROP TRIGGER reject_register_token_insert"); err != nil {
		t.Fatal(err)
	}

	var tokenCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM cluster_register_tokens").Scan(&tokenCount); err != nil {
		t.Fatal(err)
	}
	if tokenCount != 1 {
		t.Fatalf("生成失败后令牌数=%d, want 1（作废必须随生成失败回滚）", tokenCount)
	}
	req := models.ClusterRegisterRequest{Token: first, Name: "slave-atomic", IPAddress: "10.0.0.2", Port: 8000}
	if _, err := service.RegisterNode(ctx, req, req.IPAddress, now); err != nil {
		t.Fatalf("旧令牌必须仍可用（作废被回滚）: %v", err)
	}
}

// 并发生成注册令牌后只允许留一枚有效令牌（作废+生成在同一事务内串行化）。
func TestGenerateRegisterToken_concurrentGenerationLeavesSingleValidToken(t *testing.T) {
	service, database := newClusterTestService(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	const workers = 16
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := service.GenerateRegisterToken(ctx, 1, now)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("并发生成令牌失败: %v", err)
		}
	}
	var valid int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cluster_register_tokens WHERE used_at IS NULL AND expires_at > ?`, now.UTC()).Scan(&valid); err != nil {
		t.Fatal(err)
	}
	if valid != 1 {
		t.Fatalf("并发生成后有效令牌数=%d, want 1（只允许最晚一次生成存活）", valid)
	}
}

// 审批同时推进注册密钥的 24h 到期窗口，必须与同域其他方法一样使用注入 now
// （真实时钟会让到期边界无法确定性断言）。
func TestApproveNode_expiryUsesInjectedNow(t *testing.T) {
	service, database := newClusterTestService(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	token, _, err := service.GenerateRegisterToken(ctx, 1, now)
	if err != nil {
		t.Fatalf("generate register token: %v", err)
	}
	registration, err := service.RegisterNode(ctx, models.ClusterRegisterRequest{
		Token: token, Name: "slave-expiry", IPAddress: "10.0.0.21", Port: 8000,
	}, "10.0.0.21", now)
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := service.ApproveNode(ctx, registration.RegistrationID, now); err != nil {
		t.Fatalf("approve node: %v", err)
	}
	var expiresAt sql.NullTime
	if err := database.QueryRow(`SELECT registration_secret_expires_at FROM nodes WHERE id=?`, registration.RegistrationID).Scan(&expiresAt); err != nil {
		t.Fatal(err)
	}
	want := now.Add(24 * time.Hour)
	if !expiresAt.Valid || !expiresAt.Time.UTC().Equal(want) {
		t.Fatalf("registration_secret_expires_at=%v, want 注入 now+24h=%v", expiresAt, want)
	}
	// 落库形态必须仍可被 SQLite datetime() 解析（cluster_auth 的注册密钥
	// 到期门用 datetime(...) 比较；解析失败会静默按过期拒绝）。
	var parsed sql.NullString
	if err := database.QueryRow(`SELECT datetime(registration_secret_expires_at) FROM nodes WHERE id=?`, registration.RegistrationID).Scan(&parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Valid {
		t.Fatalf("datetime(registration_secret_expires_at) 解析失败（值 %v）——认证门会静默拒绝注册密钥", expiresAt)
	}
}

// approved 分支的 confirm 失败必须在下一轮重试，且连续达到上限后真正终止注册
// 循环。此前在同一条 UPDATE 里先清 registration_secret：confirm 失败后下轮
// pollRegistration 因 secret=="" 早退，confirm 永不重试、计数至多 1，
// 「连续 5 次失败停止注册并提示人工介入」在 confirm 轴上不可达。
func TestSyncService_pollRegistration_retriesConfirmAndStopsAfterConsecutiveFailures(t *testing.T) {
	_, database := newClusterTestService(t)
	var confirmHits int
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && request.URL.Path == "/api/v1/cluster/registration/confirm" {
			confirmHits++
			// 凭证类拒绝（令牌无效）才推进终止轨道；5xx/409/403 属暂时性。
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		if request.Header.Get("X-Registration-Secret") != "temporary-secret" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"code":0,"data":{"status":"approved","cluster_token":"lb_cluster_approved"}}`))
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, registration_id=7, registration_secret='temporary-secret', cluster_token='', registration_confirm_failures=0 WHERE id=1", master.URL); err != nil {
		t.Fatalf("seed pending registration: %v", err)
	}
	syncService := NewSyncService(database, &config.Config{}, NewCaddyService(master.URL))

	// 首轮：令牌落库、confirm 失败、注册密钥必须保留（下一轮可重试）。
	syncService.pollRegistration(context.Background())
	var secret string
	var failures int
	if err := database.QueryRow("SELECT registration_secret, COALESCE(registration_confirm_failures,0) FROM global_config WHERE id=1").Scan(&secret, &failures); err != nil {
		t.Fatalf("read registration state: %v", err)
	}
	if secret != "temporary-secret" {
		t.Fatalf("confirm 失败后 registration_secret=%q, want 保留（否则 confirm 永不重试）", secret)
	}
	if failures != 1 {
		t.Fatalf("registration_confirm_failures=%d, want 1", failures)
	}

	// 第二轮：仍会重新查询状态并发起 confirm（重试可达）。
	syncService.pollRegistration(context.Background())
	if confirmHits != 2 {
		t.Fatalf("confirm attempts=%d after two polls, want 2（confirm 轴重试不可达）", confirmHits)
	}

	// 补足到上限：第 5 次失败触发终止轨道（清注册态并落终止文案）。
	for range registrationConfirmMaxFailures - 2 {
		syncService.pollRegistration(context.Background())
	}
	if confirmHits != registrationConfirmMaxFailures {
		t.Fatalf("confirm attempts=%d, want %d", confirmHits, registrationConfirmMaxFailures)
	}
	var registrationID sql.NullInt64
	var secretAfter, clusterToken, lastSyncError string
	if err := database.QueryRow("SELECT registration_id, COALESCE(registration_secret,''), COALESCE(cluster_token,''), COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&registrationID, &secretAfter, &clusterToken, &lastSyncError); err != nil {
		t.Fatalf("read terminal state: %v", err)
	}
	if secretAfter != "" || registrationID.Valid || clusterToken != "" {
		t.Fatalf("终止轨道未清注册态: secret=%q registration_id=%v token=%q", secretAfter, registrationID, clusterToken)
	}
	if !strings.Contains(lastSyncError, "连续失败") {
		t.Fatalf("last_sync_error=%q, want 携带连续失败终止文案", lastSyncError)
	}

	// 注册循环已退出：后续轮询不再发 confirm。
	syncService.pollRegistration(context.Background())
	if confirmHits != registrationConfirmMaxFailures {
		t.Fatalf("终止后仍在重试 confirm: attempts=%d", confirmHits)
	}
}

// 生产 run 循环中「令牌已落库、confirm 未成功」的轮次必须重试 confirm：
// run 此前只在 cluster_token 为空时进注册轮询，approved 分支落库令牌后永不再
// 轮询 → confirm 的「连续 5 次终止」与「稍后自动重试」文案都不可达，本地明文
// registration_secret 无限期滞留。本用例走 run 循环（非直调 pollRegistration），
// 断言连续轮次都在重试 confirm。
func TestSyncService_run_retriesPendingRegistrationConfirmAfterTokenStored(t *testing.T) {
	_, database := newClusterTestService(t)
	var confirmHits int
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/cluster/register/7/status":
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"code":0,"data":{"status":"approved","cluster_token":"lb_cluster_approved"}}`))
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/cluster/registration/confirm":
			confirmHits++
			// 5xx 属暂时性：可重试、不清注册态（409 导入窗口同族）。
			response.WriteHeader(http.StatusInternalServerError)
		case request.URL.Path == "/api/v1/cluster/sync/snapshot":
			response.WriteHeader(http.StatusNotModified)
		default:
			response.WriteHeader(http.StatusOK)
		}
	}))
	defer master.Close()
	seedApprovedRegistration(t, database, master.URL)
	syncService := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	rounds := 0
	syncService.waitRunDelay = func(context.Context, time.Duration) bool {
		rounds++
		return rounds < 3
	}

	syncService.run(context.Background())

	// 3 个周期：首轮状态轮询 + confirm，随后两轮令牌已在库、仍须重试 confirm。
	if confirmHits != 3 {
		t.Fatalf("confirm attempts=%d over 3 run cycles, want 3（令牌落库后 confirm 重试不可达）", confirmHits)
	}
	var failures int
	var secret, stored string
	if err := database.QueryRow("SELECT COALESCE(registration_confirm_failures,0), COALESCE(registration_secret,''), COALESCE(cluster_token,'') FROM global_config WHERE id=1").Scan(&failures, &secret, &stored); err != nil {
		t.Fatalf("read registration state: %v", err)
	}
	// 5xx 属暂时性：只重试、不清注册态、不推进 5 连败终止计数（终止计数只服务
	// 凭证类拒绝）。
	if failures != 0 {
		t.Fatalf("registration_confirm_failures=%d, want 0（暂时性失败不得推进终止轨道）", failures)
	}
	if secret != "temporary-secret" {
		t.Fatalf("registration_secret=%q, want 保留（暂时性失败不得清注册态）", secret)
	}
	if stored != "lb_cluster_approved" {
		t.Fatalf("cluster_token=%q, want 已落库令牌保留", stored)
	}
}

// seedApprovedRegistration 建立「主节点已审批、本地待 confirm」的注册态；
// confirm 端点响应由各用例自建 mux 决定。
func seedApprovedRegistration(t *testing.T, database *sql.DB, masterURL string) {
	t.Helper()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, registration_id=7, registration_secret='temporary-secret', cluster_token='', registration_confirm_failures=0 WHERE id=1", masterURL); err != nil {
		t.Fatalf("seed pending registration: %v", err)
	}
}

// 暂时性 confirm 失败（409 导入窗口 / 403 目标降级 / 5xx 主节点故障）必须
// 可重试且不清任何注册态：confirm 只是冗余交付确认，令牌在审批时刻即有效。
func TestPollRegistration_transientConfirmFailuresKeepRegistrationState(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{name: "import_window_409", status: http.StatusConflict},
		{name: "demoted_403", status: http.StatusForbidden},
		{name: "master_error_500", status: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, database := newClusterTestService(t)
			var confirmHits int
			master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Method == http.MethodPost && request.URL.Path == "/api/v1/cluster/registration/confirm" {
					confirmHits++
					response.WriteHeader(tc.status)
					return
				}
				response.Header().Set("Content-Type", "application/json")
				_, _ = response.Write([]byte(`{"code":0,"data":{"status":"approved","cluster_token":"lb_cluster_approved"}}`))
			}))
			defer master.Close()
			seedApprovedRegistration(t, database, master.URL)
			syncService := NewSyncService(database, &config.Config{}, NewCaddyService(master.URL))

			for range registrationConfirmMaxFailures * 2 {
				syncService.pollRegistration(context.Background())
			}
			if confirmHits < registrationConfirmMaxFailures*2 {
				t.Fatalf("confirm attempts=%d, want 持续重试（不得提前终止）", confirmHits)
			}

			var registrationID sql.NullInt64
			var secret, clusterToken, lastSyncError string
			var failures int
			if err := database.QueryRow("SELECT registration_id, COALESCE(registration_secret,''), COALESCE(cluster_token,''), COALESCE(last_sync_error,''), COALESCE(registration_confirm_failures,0) FROM global_config WHERE id=1").Scan(&registrationID, &secret, &clusterToken, &lastSyncError, &failures); err != nil {
				t.Fatalf("read registration state: %v", err)
			}
			if !registrationID.Valid || secret != "temporary-secret" || clusterToken != "lb_cluster_approved" {
				t.Fatalf("暂时性失败清除了注册态: id=%v secret=%q token=%q", registrationID, secret, clusterToken)
			}
			if failures != 0 {
				t.Fatalf("registration_confirm_failures=%d, want 0（暂时性失败不得计入终止轨道）", failures)
			}
			msg, _ := decodeSyncError(lastSyncError)
			if !strings.Contains(msg, "稍后自动重试") {
				t.Fatalf("last_sync_error=%q, want 可重试文案", msg)
			}
		})
	}
}

// 网络错误同样不得推进终止轨道或清除注册态。
func TestPollRegistration_networkFailureKeepsRegistrationState(t *testing.T) {
	_, database := newClusterTestService(t)
	var confirmHits int
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && request.URL.Path == "/api/v1/cluster/registration/confirm" {
			confirmHits++
			// ErrAbortHandler 直接断连（客户端观测到网络错误，而非 HTTP 状态）。
			panic(http.ErrAbortHandler)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"code":0,"data":{"status":"approved","cluster_token":"lb_cluster_approved"}}`))
	}))
	defer master.Close()
	seedApprovedRegistration(t, database, master.URL)
	syncService := NewSyncService(database, &config.Config{}, NewCaddyService(master.URL))

	for range registrationConfirmMaxFailures * 2 {
		syncService.pollRegistration(context.Background())
	}
	if confirmHits < registrationConfirmMaxFailures*2 {
		t.Fatalf("confirm attempts=%d, want 持续重试（不得提前终止）", confirmHits)
	}
	var registrationID sql.NullInt64
	var secret, clusterToken string
	if err := database.QueryRow("SELECT registration_id, COALESCE(registration_secret,''), COALESCE(cluster_token,'') FROM global_config WHERE id=1").Scan(&registrationID, &secret, &clusterToken); err != nil {
		t.Fatalf("read registration state: %v", err)
	}
	if !registrationID.Valid || secret != "temporary-secret" || clusterToken != "lb_cluster_approved" {
		t.Fatalf("网络失败清除了注册态: id=%v secret=%q token=%q", registrationID, secret, clusterToken)
	}
}
