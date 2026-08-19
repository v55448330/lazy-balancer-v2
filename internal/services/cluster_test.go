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

type clusterLifecycleFake struct {
	acmeStarted bool
	syncStarted bool
	syncStopped bool
}

func (f *clusterLifecycleFake) StartACME() { f.acmeStarted = true }
func (f *clusterLifecycleFake) StopACME()  {}
func (f *clusterLifecycleFake) StartSync() { f.syncStarted = true }
func (f *clusterLifecycleFake) StopSync()  { f.syncStopped = true }

func newClusterTestService(t *testing.T) (*ClusterService, *sql.DB) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	database := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	return NewClusterService(database, nil), database
}

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
	if _, err := service.RegisterNode(context.Background(), req, now); !errors.Is(err, ErrInvalidRegisterToken) {
		t.Fatalf("register with stale token error=%v, want invalid token", err)
	}
	req.Token = second
	if _, err := service.RegisterNode(context.Background(), req, now); err != nil {
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
	_, err = service.RegisterNode(context.Background(), req, now)
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}
	_, secondErr := service.RegisterNode(context.Background(), req, now)

	// Then
	if secondErr == nil {
		t.Fatal("second registration succeeded with a consumed token")
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
		Token: token, Name: "slave-a", IPAddress: "172.18.0.2", Port: 8000, AccessURL: "http://127.0.0.1:8001",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	var accessURL string
	if err := database.QueryRow("SELECT access_url FROM nodes WHERE id=?", registration.RegistrationID).Scan(&accessURL); err != nil {
		t.Fatal(err)
	}
	if accessURL != "http://127.0.0.1:8001" {
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
	}, issuedAt.Add(31*time.Minute))

	// Then
	if registerErr == nil {
		t.Fatal("registration succeeded with an expired token")
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
	}, now)
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
	if err := service.ApproveNode(context.Background(), registration.RegistrationID); err != nil {
		t.Fatalf("approve node: %v", err)
	}

	// When
	first, err := service.RegistrationStatus(context.Background(), registration.RegistrationID, registration.RegistrationSecret)
	if err != nil {
		t.Fatalf("first status: %v", err)
	}
	second, err := service.RegistrationStatus(context.Background(), registration.RegistrationID, registration.RegistrationSecret)
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
	if _, err := service.RegistrationStatus(context.Background(), registration.RegistrationID, registration.RegistrationSecret); !errors.Is(err, ErrInvalidClusterAuth) {
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
	}, now)
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := service.ApproveNode(context.Background(), registration.RegistrationID); err != nil {
		t.Fatalf("approve node: %v", err)
	}
	if _, err := database.Exec("UPDATE nodes SET registration_secret_expires_at=datetime('now','-1 second') WHERE id=?", registration.RegistrationID); err != nil {
		t.Fatalf("expire registration secret: %v", err)
	}

	_, err = service.RegistrationStatus(context.Background(), registration.RegistrationID, registration.RegistrationSecret)

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

func TestClusterService_Promote_resets_slave_state(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	lifecycle := &clusterLifecycleFake{}
	service := NewClusterService(database, lifecycle)
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
	if !lifecycle.syncStopped || !lifecycle.acmeStarted {
		t.Fatalf("lifecycle syncStopped=%v acmeStarted=%v", lifecycle.syncStopped, lifecycle.acmeStarted)
	}
}

func TestClusterService_Promote_removes_old_master_pin_and_audits(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	service := NewClusterService(database, nil)
	masterURL := "https://master.example:8443"
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='secret' WHERE id=1", masterURL); err != nil {
		t.Fatal(err)
	}
	pinPath, err := clusterPinPathForDatabase(database, "master.example:8443")
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
	if action != "清理证书指纹" || !strings.Contains(detail, masterURL) {
		t.Fatalf("audit action=%q detail=%q", action, detail)
	}
}

func TestClusterService_Promote_succeeds_when_pin_cleanup_fails_then_retries_on_snapshot(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	masterURL := "https://master.example:8443"
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='secret' WHERE id=1", masterURL); err != nil {
		t.Fatal(err)
	}
	pinPath, err := clusterPinPathForDatabase(database, "master.example:8443")
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
	service := NewClusterService(database, lifecycle)
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
	if !lifecycle.syncStopped || !lifecycle.syncStarted {
		t.Fatalf("lifecycle syncStopped=%v syncStarted=%v", lifecycle.syncStopped, lifecycle.syncStarted)
	}
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
		BasicSettings: models.ClusterBasicSettings{LogLevel: "debug", AccessLogJSON: true, Timezone: "Asia/Shanghai", SyncInterval: 120, ProxyDialTimeout: 8, ProxyResponseHeaderTimeout: 9, ProxyReadTimeout: 10, ProxyWriteTimeout: 11, ProxyStreamTimeout: 12, ProxyFlushInterval: 0, ProxyStreamCloseDelay: 3},
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
		snapshot := models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{JWTExpireMinutes: expiry}}
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
	if err := syncService.applySnapshot(context.Background(), models.ClusterSnapshot{Version: 100}); err != nil {
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
	snapshot := models.ClusterSnapshot{
		Version:       2,
		Users:         []models.ClusterUser{{ID: 99, Username: "incoming", PasswordHash: "hash", Role: "admin", IsEnabled: true}},
		BasicSettings: models.ClusterBasicSettings{LogLevel: "info", AccessLogJSON: true, Timezone: "Asia/Shanghai"},
	}

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
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='重载失败' AND resource='Caddy配置'").Scan(&reloadFailures); err != nil {
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
	snapshotA := models.ClusterSnapshot{Version: 1, Users: []models.ClusterUser{{ID: 1, Username: "user-a", PasswordHash: "hash", Role: "admin", IsEnabled: true}}, BasicSettings: models.ClusterBasicSettings{LogLevel: "info", Timezone: "Asia/Shanghai"}}
	if err := syncService.applySnapshot(context.Background(), snapshotA); err != nil {
		t.Fatalf("apply snapshot A: %v", err)
	}
	cachedA, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil || len(cachedA.Users) != 1 || cachedA.Users[0].Username != "user-a" {
		t.Fatalf("cache snapshot A=%#v err=%v", cachedA.Users, err)
	}

	snapshotB := models.ClusterSnapshot{Version: 2, Users: []models.ClusterUser{{ID: 2, Username: "user-b", PasswordHash: "hash", Role: "admin", IsEnabled: true}}, BasicSettings: snapshotA.BasicSettings}
	if err := syncService.applySnapshot(context.Background(), snapshotB); err != nil {
		t.Fatalf("apply snapshot B: %v", err)
	}
	cachedB, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil || len(cachedB.Users) != 1 || cachedB.Users[0].Username != "user-b" {
		t.Fatalf("cache snapshot B=%#v err=%v", cachedB.Users, err)
	}

	reject = true
	snapshotC := models.ClusterSnapshot{Version: 3, Users: []models.ClusterUser{{ID: 3, Username: "user-c", PasswordHash: "hash", Role: "admin", IsEnabled: true}}, BasicSettings: snapshotA.BasicSettings}
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
	snapshot := models.ClusterSnapshot{Version: 2, BasicSettings: models.ClusterBasicSettings{
		LogLevel: "info", AccessLogJSON: true, Timezone: "Asia/Shanghai", AdminTLSEnabled: true, AdminTLSMode: "selfsigned",
	}}

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

func TestClusterSnapshot_accessLogSettingsFollowGlobalConfigGate(t *testing.T) {
	// Given
	service, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.ExecContext(ctx, "UPDATE global_config SET access_log_json=1, access_log_format='{request}' WHERE id=1"); err != nil {
		t.Fatalf("seed access log settings: %v", err)
	}
	build := func(t *testing.T) models.ClusterSnapshot {
		t.Helper()
		tx, err := database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatalf("begin snapshot tx: %v", err)
		}
		defer tx.Rollback()
		snapshot, err := service.buildSnapshot(ctx, tx)
		if err != nil {
			t.Fatalf("build snapshot: %v", err)
		}
		return snapshot
	}

	// When sync off
	if _, err := database.ExecContext(ctx, "UPDATE global_config SET sync_global_config=0 WHERE id=1"); err != nil {
		t.Fatalf("disable caddy sync: %v", err)
	}
	off := build(t)

	// Then caddy-gated fields stay at zero values
	if off.CaddyConfig != nil {
		t.Fatal("caddy config present with sync off")
	}
	if off.BasicSettings.AccessLogJSON || off.BasicSettings.AccessLogFormat != "" || off.BasicSettings.CaddyLogLevel != "" {
		t.Fatalf("access log settings leaked with sync off: %#v", off.BasicSettings)
	}

	// When sync on
	if _, err := database.ExecContext(ctx, "UPDATE global_config SET sync_global_config=1 WHERE id=1"); err != nil {
		t.Fatalf("enable caddy sync: %v", err)
	}
	on := build(t)
	if on.CaddyConfig == nil {
		t.Fatal("caddy config missing with sync on")
	}
	if !on.BasicSettings.AccessLogJSON || on.BasicSettings.AccessLogFormat != "{request}" {
		t.Fatalf("access log settings missing with sync on: %#v", on.BasicSettings)
	}
}

func TestUpdateSnapshotSettings_preservesSlaveAccessLogSettingsWhenCaddySyncOff(t *testing.T) {
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

	// When snapshot carries no caddy config (sync off)
	apply(t, models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{
		LogLevel: "debug", AccessLogJSON: true, AccessLogFormat: "master-format", JWTExpireMinutes: 20,
	}})

	// Then slave-local access log settings survive, ungated settings applied
	gotJSON, gotFormat := readAccessLog(t)
	if gotJSON || gotFormat != "slave-format" {
		t.Fatalf("access log settings overwritten without caddy sync: json=%v format=%q", gotJSON, gotFormat)
	}
	var logLevel string
	if err := database.QueryRowContext(ctx, "SELECT log_level FROM global_config WHERE id=1").Scan(&logLevel); err != nil {
		t.Fatalf("read log level: %v", err)
	}
	if logLevel != "debug" {
		t.Fatalf("ungated log level not applied: %q", logLevel)
	}

	// When snapshot carries caddy config (sync on)
	caddyConfig := "{}"
	apply(t, models.ClusterSnapshot{CaddyConfig: &caddyConfig, BasicSettings: models.ClusterBasicSettings{
		AccessLogJSON: true, AccessLogFormat: "master-format", JWTExpireMinutes: 20,
	}})
	gotJSON, gotFormat = readAccessLog(t)
	if !gotJSON || gotFormat != "master-format" {
		t.Fatalf("access log settings not applied with caddy sync: json=%v format=%q", gotJSON, gotFormat)
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
	// R42 发现1：sync_interval 落库前必须做范围校验，否则从节点 run 循环
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
