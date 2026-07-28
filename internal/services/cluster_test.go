package services

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

type clusterLifecycleFake struct {
	acmeStarted bool
	syncStopped bool
}

func (f *clusterLifecycleFake) StartACME() { f.acmeStarted = true }
func (f *clusterLifecycleFake) StopACME()  {}
func (f *clusterLifecycleFake) StartSync() {}
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

func TestClusterService_ApproveNode_returns_cluster_token_once(t *testing.T) {
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
	if second.ClusterToken != "" {
		t.Fatal("cluster token was disclosed more than once")
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
	if _, err := database.Exec(`UPDATE global_config SET is_master=0, master_url='https://master', cluster_token='secret', cluster_version=4 WHERE id=1`); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}

	// When
	if err := service.Promote(context.Background()); err != nil {
		t.Fatalf("promote: %v", err)
	}

	// Then
	var isMaster bool
	var masterURL, token string
	var version int
	if err := database.QueryRow("SELECT is_master, COALESCE(master_url,''), COALESCE(cluster_token,''), cluster_version FROM global_config WHERE id=1").Scan(&isMaster, &masterURL, &token, &version); err != nil {
		t.Fatalf("read promoted state: %v", err)
	}
	if !isMaster || masterURL != "" || token != "" || version != 5 {
		t.Fatalf("promoted state master=%v url=%q token=%q version=%d", isMaster, masterURL, token, version)
	}
	if !lifecycle.syncStopped || !lifecycle.acmeStarted {
		t.Fatalf("lifecycle syncStopped=%v acmeStarted=%v", lifecycle.syncStopped, lifecycle.acmeStarted)
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
			Strategy: "round_robin", Enabled: true, IPACLMode: "allow", IPACLList: []string{"192.0.2.0/24"}, CustomRoutesEnabled: true,
			ProxyDialTimeout: 3, ProxyResponseHeaderTimeout: 4, ProxyReadTimeout: 5, ProxyWriteTimeout: 6, ProxyStreamTimeout: 7,
			Upstreams: []models.Upstream{{ID: 11, Host: "127.0.0.1", Port: 9000, Weight: 1, Enabled: true, Protocol: "http"}},
			PathRules: []models.PathRule{{ID: 21, SortOrder: 2, MatchType: "prefix", Path: "/metrics/", Upstreams: nil}},
		}},
		Users:         []models.ClusterUser{{ID: 20, Username: "admin-master", PasswordHash: "hash", Role: "admin", IsEnabled: true}},
		APIKeys:       []models.ClusterAPIKey{{ID: 30, Name: "ci", KeyHash: "key-hash", KeyPrefix: "lb_sk_master", CreatedBy: 20, IsEnabled: true}},
		BasicSettings: models.ClusterBasicSettings{LogLevel: "debug", AccessLogJSON: true, Timezone: "Asia/Shanghai", SyncInterval: 120, ProxyDialTimeout: 8, ProxyResponseHeaderTimeout: 9, ProxyReadTimeout: 10, ProxyWriteTimeout: 11, ProxyStreamTimeout: 12},
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
	var ipACLMode, ipACLList, path string
	var ruleDialTimeout, globalDialTimeout int
	if err := database.QueryRow(`SELECT r.ip_acl_mode,r.ip_acl_list,r.proxy_dial_timeout,p.path,g.proxy_dial_timeout FROM lb_rules r JOIN path_rules p ON p.rule_id=r.caddy_id JOIN global_config g ON g.id=1 WHERE r.caddy_id='lb_snapshot1'`).Scan(&ipACLMode, &ipACLList, &ruleDialTimeout, &path, &globalDialTimeout); err != nil {
		t.Fatalf("read new snapshot fields: %v", err)
	}
	if ipACLMode != "allow" || ipACLList != `["192.0.2.0/24"]` || ruleDialTimeout != 3 || path != "/metrics/" || globalDialTimeout != 8 {
		t.Fatalf("new snapshot fields mode=%q list=%q rule_dial=%d path=%q global_dial=%d", ipACLMode, ipACLList, ruleDialTimeout, path, globalDialTimeout)
	}
}

func TestSyncService_applySnapshot_rolls_back_when_caddy_rejects_config(t *testing.T) {
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
	var oldUsername string
	if err := database.QueryRow("SELECT username FROM users ORDER BY id LIMIT 1").Scan(&oldUsername); err != nil {
		t.Fatalf("read old user: %v", err)
	}

	// When
	err := syncService.applySnapshot(context.Background(), snapshot)

	// Then
	if err == nil {
		t.Fatal("snapshot apply succeeded despite Caddy rejection")
	}
	var oldCount, incomingCount int
	if err := database.QueryRow("SELECT SUM(username=?), SUM(username='incoming') FROM users", oldUsername).Scan(&oldCount, &incomingCount); err != nil {
		t.Fatalf("read rollback users: %v", err)
	}
	if oldCount != 1 || incomingCount != 0 {
		t.Fatalf("rollback users old=%d incoming=%d", oldCount, incomingCount)
	}
}

func TestSyncService_pollRegistration_clears_temporary_secret_after_approval(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
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
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
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
	if gotInterval != 45 || gotVersion == 0 {
		t.Fatalf("interval=%d version=%d", gotInterval, gotVersion)
	}
}
