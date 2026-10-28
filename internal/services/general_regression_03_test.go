package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
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
	"lazy-balancer-v2/internal/taskengine"
)

func assertPullAdmissionOpen(t *testing.T, sync *SyncService) {
	t.Helper()
	if err := sync.beginPull(); err != nil {
		t.Fatalf("pull admission still closed: %v", err)
	}
	sync.pullWG.Done()
}

// BecomeSlave 排干成功后 UPDATE 失败必须重开拉取准入——否则
// 「已是从节点换主」不换代，旧 daemon 后续每轮 Pull 恒 errSyncPullStopped
// 且该哨兵不落库 → 永久静默脱同步。
func TestBecomeSlave_reopensPullAdmissionWhenTopologyWriteFails(t *testing.T) {
	service, database := newClusterTestService(t)
	sync := NewSyncService(database, nil, nil)
	if err := sync.DrainPulls(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if _, err := database.Exec(`CREATE TRIGGER fail_demote BEFORE UPDATE ON global_config
		WHEN NEW.is_master=0 BEGIN SELECT RAISE(ABORT,'disk full'); END`); err != nil {
		t.Fatal(err)
	}

	err := service.BecomeSlave(context.Background(), "https://master.example", models.ClusterRegistration{RegistrationID: 3, RegistrationSecret: "secret"})
	if err == nil {
		t.Fatal("BecomeSlave unexpectedly succeeded with failing UPDATE trigger")
	}
	assertPullAdmissionOpen(t, sync)
}

// Promote 失败路径（排干成功 + 提交失败）必须重开准入——原实现
// 依赖「失败后重启 cluster-sync → startLocked 重开」的隐式链，当用户此前关闭
// 调度或引擎缺失时准入永久关闭，从节点「立即同步」被静默拒绝。
func TestPromote_reopensPullAdmissionOnCommitFailure(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	sync := NewSyncService(database, nil, nil)
	if _, err := database.Exec(`CREATE TRIGGER fail_promote BEFORE UPDATE ON global_config
		WHEN NEW.is_master=1 BEGIN SELECT RAISE(ABORT,'disk full'); END`); err != nil {
		t.Fatal(err)
	}

	if err := service.Promote(context.Background()); err == nil {
		t.Fatal("Promote unexpectedly succeeded with failing UPDATE trigger")
	}
	assertPullAdmissionOpen(t, sync)
}

// /Promote 复位 last_sync（与 BecomeSlave 对称）并显式
// 失效快照缓存（角色翻转后不得继续以旧缓存供快照）。
func TestPromote_clearsLastSyncAndSnapshotCache(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0, last_sync=datetime('now'), applied_version=5 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	clusterSnapshotCaches.Store(database, &clusterSnapshotCache{})
	t.Cleanup(func() { clusterSnapshotCaches.Delete(database) })

	if err := service.Promote(context.Background()); err != nil {
		t.Fatalf("promote: %v", err)
	}
	var lastSync sql.NullTime
	var appliedVersion int
	if err := database.QueryRow("SELECT last_sync, COALESCE(applied_version,0) FROM global_config WHERE id=1").Scan(&lastSync, &appliedVersion); err != nil {
		t.Fatal(err)
	}
	if lastSync.Valid {
		t.Fatalf("last_sync=%v after promote, want NULL", lastSync.Time)
	}
	if appliedVersion != 0 {
		t.Fatalf("applied_version=%d after promote, want 0", appliedVersion)
	}
	if _, ok := clusterSnapshotCaches.Load(database); ok {
		t.Fatal("snapshot cache still present after role flip to master")
	}
}

// /BecomeSlave 同样失效快照缓存并清空内存 TOFU pin 缓存
// （与 Promote handler 的 ForgetClusterPins 收尾对称）。
func TestBecomeSlave_invalidatesSnapshotCacheAndPins(t *testing.T) {
	service, database := newClusterTestService(t)
	sync := NewSyncService(database, nil, nil)
	sync.pinMu.Lock()
	sync.verifiedPins["/tmp/master.pin"] = "fingerprint"
	sync.pinMu.Unlock()
	clusterSnapshotCaches.Store(database, &clusterSnapshotCache{})
	t.Cleanup(func() { clusterSnapshotCaches.Delete(database) })

	if err := service.BecomeSlave(context.Background(), "https://new-master.example", models.ClusterRegistration{RegistrationID: 4, RegistrationSecret: "secret"}); err != nil {
		t.Fatalf("become slave: %v", err)
	}
	if _, ok := clusterSnapshotCaches.Load(database); ok {
		t.Fatal("snapshot cache still present after role flip to slave")
	}
	sync.pinMu.Lock()
	remaining := len(sync.verifiedPins)
	sync.pinMu.Unlock()
	if remaining != 0 {
		t.Fatalf("verified pin cache entries=%d after master switch, want 0", remaining)
	}
}

// Wake 早于 waitDelay 注册（周期中途到达）不得丢失——原实现
// close 后替换通道，下一次等待拿到新通道，唤醒被吞，最长延迟一个 interval。
func TestSyncService_wakeBeforeWaitIsNotLost(t *testing.T) {
	s := &SyncService{}
	s.Wake() // 模拟 Pull/Report 期间到达的唤醒
	done := make(chan bool, 1)
	go func() { done <- s.defaultWaitDelay(context.Background(), time.Hour) }()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("defaultWaitDelay returned false for pending wake")
		}
	case <-time.After(time.Second):
		t.Fatal("wake requested before wait was lost")
	}
}

func TestApplyConfig_sameBytesSinksRenderDegradation(t *testing.T) {
	newClusterTestService(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		t.Errorf("unexpected request %s %s (same-byte path must not POST /load)", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Cleanup(func() { setLastRenderDegradation("") })

	s := NewCaddyService(srv.URL)
	degraded := "受信代理设置读取失败：按未启用渲染"
	err := s.applyConfigLockedOpt(map[string]interface{}{caddyConfigDegradationKey: degraded}, false, false)
	if !IsSameConfig(err) {
		t.Fatalf("err=%v, want errSameConfig", err)
	}
	if got := LastRenderDegradation(); got != degraded {
		t.Fatalf("degradation=%q after same-byte apply, want %q", got, degraded)
	}

	// 降级解除后的干净渲染若同样同字节，必须清空残留状态（否则
	// recordCaddyApplyResult(nil) 会把旧降级重新持久化）。
	err = s.applyConfigLockedOpt(map[string]interface{}{}, false, false)
	if !IsSameConfig(err) {
		t.Fatalf("err=%v, want errSameConfig on clean render", err)
	}
	if got := LastRenderDegradation(); got != "" {
		t.Fatalf("degradation=%q after clean same-byte apply, want empty", got)
	}
}

// 超限运行配置不是可参与同字节比较的合法短配置，必须返回明确的超限错误。
func TestReadAdminConfigBody_rejectsOversize(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(&spaceFillReader{remaining: caddyAdminConfigMaxBytes + 1}),
	}
	if _, err := ReadAdminConfigBody(resp); !errors.Is(err, errCaddyAdminConfigTooLarge) {
		t.Fatalf("err=%v, want errCaddyAdminConfigTooLarge", err)
	}
}

// 证书任务日志的文件名组件必须与 housekeeping 反解使用同一规则 ID 口径。
func TestCertJobLogLockKeyMatchesHousekeepingKey(t *testing.T) {
	ruleID := "lb.dot.rule"
	component := certJobLogFileComponent(ruleID)
	// 本用例只比较键口径，acquire 登记的两份引用不在此释放——直接按 key 删除
	// 会绕过引用协议（表内删除不等于引用归零），因此整表重置还原。
	t.Cleanup(func() { certJobLogWriteLocks = refCountedLockTable{} })

	writeLock := lockCertJobLog(ruleID)
	parsed, ok := certJobLogRuleIDFromName("certjob-" + component + ".log.1")
	if !ok {
		t.Fatal("housekeeping could not parse cert job log name")
	}
	if lockCertJobLog(parsed) != writeLock {
		t.Fatalf("write lock key=%q vs housekeeping key=%q use different mutexes", ruleID, parsed)
	}
}

// 节点异常必须重置连续正常窗口，恢复后重新累计，不能立即补发心跳。
func TestMasterServingRound_anomalyResetsHeartbeatWindow(t *testing.T) {
	newServingTestEnv(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET cluster_version=3 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	nodeID := seedServingNode(t, "edge-r", servingBase.Add(-10*time.Second).UTC().Format("2006-01-02 15:04:05"), 3, 3600)
	w := newServingWatch()
	ctx := context.Background()
	round := func(i int) {
		masterSyncServingRound(ctx, servingBase.Add(time.Duration(i)*masterSyncInspectInterval), w)
	}
	for i := range 30 {
		round(i)
	}
	// 一轮异常（离线）
	if _, err := db.DB.Exec(`UPDATE nodes SET last_seen=NULL WHERE id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
	round(30)
	// 恢复后跑 59 轮（未满 60）：不得有心跳
	for i := 31; i < 90; i++ {
		ts := servingBase.Add(time.Duration(i) * masterSyncInspectInterval).UTC().Format("2006-01-02 15:04:05")
		if _, err := db.DB.Exec(`UPDATE nodes SET last_seen=? WHERE id=?`, ts, nodeID); err != nil {
			t.Fatal(err)
		}
		round(i)
	}
	if count := countHeartbeatLines(readClusterSyncLog(t)); count != 0 {
		t.Fatalf("heartbeat emitted %d time(s) with only 59 clean rounds after anomaly, want 0", count)
	}
	ts := servingBase.Add(90 * masterSyncInspectInterval).UTC().Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`UPDATE nodes SET last_seen=? WHERE id=?`, ts, nodeID); err != nil {
		t.Fatal(err)
	}
	round(90)
	if count := countHeartbeatLines(readClusterSyncLog(t)); count != 1 {
		t.Fatalf("heartbeat count=%d after 60 clean rounds, want 1", count)
	}
}

func countHeartbeatLines(logBody string) int {
	count := 0
	for _, line := range servingLines(logBody) {
		if strings.Contains(line, "服务面正常") {
			count++
		}
	}
	return count
}

func TestCertificateService_StopWithoutStartReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service := &CertificateService{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	finished := make(chan struct{})
	go func() {
		service.Stop()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("Stop blocked forever before Start")
	}
}

// 队列活动态由守护派生——初始化即停止；未启动时
// 入队必须是无迁移的 no-op（从节点/用户停调度后重启不得留下半启动子系统）。
func TestCAQueueManager_inactiveUntilDaemonStarts(t *testing.T) {
	newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(nil)
	t.Cleanup(ResetCAQueueManagerForTest)
	qm := GetCAQueueManager()
	if qm.IsActive() {
		t.Fatal("queue active before cert-issuance daemon Start")
	}
	transitioned := false
	if _, changed, err := qm.EnqueueIfActive(1, 42, "lb_x", "x.example.test", func() (int, bool, error) {
		transitioned = true
		return 42, true, nil
	}); err != nil || changed || transitioned {
		t.Fatalf("inactive enqueue: changed=%v transitioned=%v err=%v, want no-op", changed, transitioned, err)
	}
	qm.Start()
	if !qm.IsActive() {
		t.Fatal("queue inactive after Start")
	}
	qm.Stop()
	if qm.IsActive() {
		t.Fatal("queue active after Stop")
	}
}

// 部署尝试封顶后保留可部署态（慢速重试），不得落 failed 终态把
// 材料/磁盘分叉变成无自动通道的搁浅。
func TestDeploymentFailed_atCapKeepsDeployableState(t *testing.T) {
	_, database := newClusterTestService(t)
	taskengine.SetLogDir(t.TempDir())
	if _, err := database.Exec(`INSERT INTO cert_jobs (id, rule_id, domain, status, deployment_attempts)
		VALUES (7, 'lb_deploy', 'deploy.example.test', 'downloaded', ?)`, maxCertificateDeploymentAttempts-1); err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(90 * 24 * time.Hour).UTC()
	material := issuedCertificate{
		ruleID:            "lb_deploy",
		certPEM:           "CERT-PEM",
		keyPEM:            "KEY-PEM",
		notAfter:          notAfter,
		providerID:        1,
		deploymentAttempt: maxCertificateDeploymentAttempts - 1,
	}
	if err := (&CertIssuer{}).deploymentFailed(7, material, "磁盘写失败", errors.New("disk full")); err == nil {
		t.Fatal("deploymentFailed must return an error")
	}
	var status, message string
	var attempts int
	var availableAfter sql.NullTime
	if err := database.QueryRow(`SELECT status, COALESCE(message,''), COALESCE(deployment_attempts,0), deployment_available_after
		FROM cert_jobs WHERE id=7`).Scan(&status, &message, &attempts, &availableAfter); err != nil {
		t.Fatal(err)
	}
	if status != "downloaded" {
		t.Fatalf("status=%q after capped deployment failure, want downloaded (material retained, slow retry)", status)
	}
	if attempts != maxCertificateDeploymentAttempts {
		t.Fatalf("deployment_attempts=%d, want %d", attempts, maxCertificateDeploymentAttempts)
	}
	if !availableAfter.Valid || time.Until(availableAfter.Time) < 20*time.Minute {
		t.Fatalf("deployment_available_after=%v, want slow retry (~30m) window", availableAfter)
	}
	if !strings.Contains(message, "慢速重试") {
		t.Fatalf("message=%q, want slow-retry disclosure", message)
	}
}

// 读侧补上界钳制（写侧 0-CertRenewalDaysMax / 1-10，导入 0-CertRenewalDaysMax / 1-10）
// ——带外直写大值不得造成续签风暴/超限重试。
func TestCertRenewalConfigReadSideClampsUpperBounds(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET cert_renewal_days=365, cert_renewal_attempts=100 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got := GetCertRenewalDays(); got != 30 {
		t.Fatalf("GetCertRenewalDays()=%d for out-of-range 365, want fallback 30", got)
	}
	if got := getCertRenewalAttempts(); got != 5 {
		t.Fatalf("getCertRenewalAttempts()=%d for out-of-range 100, want fallback 5", got)
	}
}

// 手动证书到期巡检只扫启用规则（禁用规则不进入任何 TLS 策略，
// 不得产生 CRITICAL 假告警）。
func TestCheckManualCertExpiration_skipsDisabledRules(t *testing.T) {
	_, database := newClusterTestService(t)
	certPEM, _ := expiredShapeCertAndKey(t, "manual-disabled.test", time.Now().Add(-time.Hour))
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert)
		VALUES ('lb_manual_disabled','manual-disabled','manual-disabled.test','http',8080,0,1,'manual',?)`, certPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=30 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	resetCertificateServiceForTest(t)
	var buf strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	NewCertificateService().checkManualCertExpiration()

	if strings.Contains(buf.String(), "CRITICAL") || strings.Contains(buf.String(), "expired") {
		t.Fatalf("log=%q, want no expiry alerts for disabled rule", buf.String())
	}
}

// 主节点快照全量替换——否则本地 acme_dns 规则的 acme_config_id 悬空或绑到
// 主端同 id 的错误 DNS 账号。
func TestReplaceSnapshotTx_rulesDisabledKeepsACMETables(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.ExecContext(ctx, `
		INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (5,'local-ca','letsencrypt','https://local.example/directory',1);
		INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES (5,'local-dns','dnspod','{"token":"local"}',1);
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,acme_config_id) VALUES ('lb_local_acme','local-acme','local.example.test','http',8080,1,1,'acme_dns',5)`); err != nil {
		t.Fatal(err)
	}
	snapshot := models.ClusterSnapshot{
		Version: 11,
		ACME: &models.ClusterACMEState{
			CAProviders:        []models.CAProvider{{ID: 9, Name: "master-ca", Provider: "letsencrypt", DirectoryURL: "https://master.example/directory", Enabled: true}},
			CertificateConfigs: []models.CertificateConfig{{ID: 9, Name: "master-dns", DNSProvider: "dnspod", Enabled: true}},
		},
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	sk := &sectionSkips{disabled: map[string]bool{"rules": true}, unchanged: map[string]bool{}}
	if err := replaceSnapshotTx(ctx, tx, snapshot, sk); err != nil {
		t.Fatalf("replaceSnapshotTx: %v", err)
	}
	var localProviders, masterProviders, localConfigs, masterConfigs int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM ca_providers WHERE id=5").Scan(&localProviders); err != nil {
		t.Fatalf("query local ca_providers: %v", err)
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM ca_providers WHERE id=9").Scan(&masterProviders); err != nil {
		t.Fatalf("query master ca_providers: %v", err)
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificate_configs WHERE id=5").Scan(&localConfigs); err != nil {
		t.Fatalf("query local certificate_configs: %v", err)
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM certificate_configs WHERE id=9").Scan(&masterConfigs); err != nil {
		t.Fatalf("query master certificate_configs: %v", err)
	}
	if localProviders != 1 || localConfigs != 1 {
		t.Fatalf("rules disabled: local ca_providers=%d certificate_configs=%d, want preserved", localProviders, localConfigs)
	}
	if masterProviders != 0 || masterConfigs != 0 {
		t.Fatalf("rules disabled: master ca_providers=%d certificate_configs=%d inserted, want skipped", masterProviders, masterConfigs)
	}
}

func TestApplySnapshot_rulesDisabledPreservesLocalDNSOwnership(t *testing.T) {
	_, database := newClusterTestService(t)
	dataDir := t.TempDir()
	localOwnership := `{"version":1,"records":[{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com","value":"local","record_id":"local-1"}]}`
	masterOwnership := `{"version":1,"records":[{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com","value":"master","record_id":"master-1"}]}`
	ownershipPath := filepath.Join(dataDir, "acme_dns_ownership.json")
	if err := os.WriteFile(ownershipPath, []byte(localOwnership), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{}`))
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{DataDir: dataDir, CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{
		Version: 10,
		MasterSyncSwitches: &models.ClusterSyncSwitchesPayload{
			Users: true, Rules: false, Security: true,
		},
	})
	snapshot.ACME.DNSOwnership = json.RawMessage(masterOwnership)
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)

	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}
	got, err := os.ReadFile(ownershipPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != localOwnership {
		t.Fatalf("ownership=%s, want local ownership preserved when rules sync disabled", got)
	}
}

// （证伪 + 加固钉）：预检失败必须落「CA 提供商测试失败」精确归因。
// 报告声称 from=creating_account 恒不命中，但 logger.Log("creating_account")
// 已先行迁移状态；本测钉住最终 message（failJob 形态对 logger 迁移失败亦稳健）。
func TestIssue_precheckFailureKeepsProviderAttribution(t *testing.T) {
	_, database := newClusterTestService(t)
	taskengine.SetLogDir(t.TempDir())
	if _, err := database.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,acme_config_id)
		VALUES ('lb_precheck','precheck','precheck.example.test','http',8080,1,1,'acme_dns',0);
		INSERT INTO cert_jobs (id,rule_id,domain,status) VALUES (11,'lb_precheck','precheck.example.test','queued')`); err != nil {
		t.Fatal(err)
	}
	err := NewCertIssuer(nil).Issue(context.Background(), 11, "lb_precheck", "precheck.example.test", models.CAProvider{ID: 999, Name: "missing", Provider: "letsencrypt"})
	if err == nil {
		t.Fatal("expected precheck failure for missing CA provider")
	}
	var status, message string
	if err := database.QueryRow("SELECT status, COALESCE(message,'') FROM cert_jobs WHERE id=11").Scan(&status, &message); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("status=%q after precheck failure, want failed", status)
	}
	if !strings.Contains(message, "CA 提供商测试失败") {
		t.Fatalf("message=%q, want provider-test attribution", message)
	}
}

// 续期扫描在队列暂停时不得静默跳过——摘要行已宣称「检测到 N 个
// 任务」，未入队必须留痕（在途守卫形态仍静默）。
func TestRenewalScan_logsWhenQueueInactive(t *testing.T) {
	_, database := newClusterTestService(t)
	taskengine.SetLogDir(t.TempDir())
	if _, err := database.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_renew','renew','renew.example.test','http',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (id,rule_id,domain,status,expires_at)
		VALUES (12,'lb_renew','renew.example.test','issued',datetime('now','+1 day'))`); err != nil {
		t.Fatal(err)
	}
	ResetCAQueueManagerForTest()
	InitCAQueueManager(nil)
	t.Cleanup(ResetCAQueueManagerForTest)
	resetCertificateServiceForTest(t)
	var buf strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	NewCertificateService().renewExpiringCertificates(context.Background())

	if !strings.Contains(buf.String(), "CA 队列已暂停") {
		t.Fatalf("log=%q, want inactive-queue skip disclosure", buf.String())
	}
	var status string
	if err := database.QueryRow("SELECT status FROM cert_jobs WHERE id=12").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "issued" {
		t.Fatalf("status=%q, want issued (no enqueue while queue inactive)", status)
	}
}

func TestIPListTempFileName_forms(t *testing.T) {
	for _, name := range []string{"u-deny-123.tmp", "u-deny-lb_x-987.tmp", "p12-acl-55.tmp", "p12-acl-deadbeef1234-55.tmp", "tp-42.tmp"} {
		if !ipListTempFileName.MatchString(name) {
			t.Fatalf("投影临时文件 %q 应命中 GC regex", name)
		}
	}
	for _, name := range []string{"ops-notes.tmp", "ops-deadbeef1234-55.tmp", "backup-deadbeef1234.tmp", "u-deny-123.txt"} {
		if ipListTempFileName.MatchString(name) {
			t.Fatalf("非投影临时文件 %q 不应命中 GC regex（用户文件不碰）", name)
		}
	}
}

// 角色读取单源语义——主/从/读失败（读失败返回错误，由调用方决定
// fail-open/closed；nil 库返回错误而非 panic）。
func TestRoleOf_masterSlaveAndReadFailure(t *testing.T) {
	_, database := newClusterTestService(t)
	if role, err := RoleOf(context.Background(), database); err != nil || !role {
		t.Fatalf("RoleOf master: role=%v err=%v", role, err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if role, err := RoleOf(context.Background(), database); err != nil || role {
		t.Fatalf("RoleOf slave: role=%v err=%v", role, err)
	}
	if _, err := database.Exec("DELETE FROM global_config WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if role, err := RoleOf(context.Background(), database); err == nil || role {
		t.Fatalf("RoleOf missing row: role=%v err=%v, want error + false", role, err)
	}
	if _, err := RoleOf(context.Background(), nil); err == nil {
		t.Fatal("RoleOf(nil db) must return error")
	}
}
