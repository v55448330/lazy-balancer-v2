package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func TestVerifySnapshotConsistency_allows_zero_upstream_rule_with_warning(t *testing.T) {
	// Given：主节点存在启用但零上游的规则（历史/导入残留的数据漂移）
	snapshot := models.ClusterSnapshot{
		Rules: []models.LbRule{
			{CaddyID: "lb_drift", Enabled: true},
			{CaddyID: "lb_healthy", Enabled: true, Upstreams: []models.Upstream{{Host: "127.0.0.1", Port: 8080}}},
			{CaddyID: "lb_disabled", Enabled: false},
		},
	}

	// When
	err := verifySnapshotConsistency(snapshot)

	// Then：不再拒绝快照，生成端会跳过该规则并告警
	if err != nil {
		t.Fatalf("zero-upstream snapshot rejected: %v", err)
	}
}

type syncDrainLifecycle struct {
	sync        *SyncService
	stopEntered chan struct{}
}

func (l *syncDrainLifecycle) StartACME() {}
func (l *syncDrainLifecycle) StopACME()  {}
func (l *syncDrainLifecycle) StartSync() { l.sync.Start() }
func (l *syncDrainLifecycle) StopSync() {
	close(l.stopEntered)
	l.sync.Stop()
}

func waitSyncTest[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for synchronization point")
		var zero T
		return zero
	}
}

func waitSyncBarrier(ch <-chan struct{}) {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
	}
}

func TestSyncService_RegisterWithMaster_acceptsHTTP(t *testing.T) {
	// HTTP 现在是允许的（建议但非必选 HTTPS）：对不可达地址返回传输错误而非协议拒绝。
	service := &SyncService{client: &http.Client{Timeout: 500 * time.Millisecond}}
	_, err := service.RegisterWithMaster(context.Background(), "http://127.0.0.1:1", models.ClusterRegisterRequest{})
	if err == nil || strings.Contains(err.Error(), "必须使用 HTTPS") {
		t.Fatalf("registration error=%v, want transport failure not HTTPS rejection", err)
	}
}

func TestSyncService_do_rejectsCertificateFingerprintMismatchBeforeSendingToken(t *testing.T) {
	dataDir := t.TempDir()
	receivedTokens := make(chan string, 2)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		receivedTokens <- request.Header.Get("X-Cluster-Token")
		response.WriteHeader(http.StatusOK)
	}))
	defer master.Close()
	service := NewSyncService(nil, &config.Config{DataDir: dataDir}, nil)
	req, err := http.NewRequest(http.MethodGet, master.URL+"/api/v1/cluster/sync/snapshot", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Cluster-Token", "secret-token")
	response, err := service.do(req)
	if err != nil {
		t.Fatalf("first TOFU request: %v", err)
	}
	response.Body.Close()
	if token := waitSyncTest(t, receivedTokens); token != "secret-token" {
		t.Fatalf("first request token=%q, want secret-token", token)
	}
	pinPath, err := service.clusterPinPath(req.URL.Host)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte(strings.Repeat("0", sha256.Size*2)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	retry, err := http.NewRequest(http.MethodGet, master.URL+"/api/v1/cluster/sync/snapshot", nil)
	if err != nil {
		t.Fatal(err)
	}
	retry.Header.Set("X-Cluster-Token", "secret-token")
	if _, err := service.do(retry); err == nil || !strings.Contains(err.Error(), "指纹不匹配") {
		t.Fatalf("mismatched certificate error=%v", err)
	}
	select {
	case token := <-receivedTokens:
		t.Fatalf("fingerprint-mismatched request sent token %q", token)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSyncService_do_doesNotFollowHTTPRedirectOrForwardCredentials(t *testing.T) {
	received := make(chan http.Header, 1)
	plaintext := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		received <- request.Header.Clone()
		response.WriteHeader(http.StatusOK)
	}))
	defer plaintext.Close()
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, plaintext.URL, http.StatusFound)
	}))
	defer master.Close()

	service := NewSyncService(nil, &config.Config{DataDir: t.TempDir()}, nil)
	req, err := http.NewRequest(http.MethodGet, master.URL+"/api/v1/cluster/sync/snapshot", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Cluster-Token", "cluster-secret")
	req.Header.Set("X-Registration-Secret", "registration-secret")
	response, err := service.do(req)
	if err != nil {
		t.Fatalf("redirect request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("status=%d, want %d", response.StatusCode, http.StatusFound)
	}
	select {
	case header := <-received:
		t.Fatalf("plaintext redirect was followed with cluster_token=%q registration_secret=%q", header.Get("X-Cluster-Token"), header.Get("X-Registration-Secret"))
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSyncService_clusterPinPath_normalizesDefaultHTTPSPort(t *testing.T) {
	service := NewSyncService(nil, &config.Config{DataDir: t.TempDir()}, nil)
	implicit, err := service.clusterPinPath("MASTER.example")
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := service.clusterPinPath("master.example:443")
	if err != nil {
		t.Fatal(err)
	}
	if implicit != explicit {
		t.Fatalf("implicit pin path %q differs from explicit path %q", implicit, explicit)
	}
}

func TestVerifyOrStoreClusterPin_rejectsWidePermissions(t *testing.T) {
	const fingerprint = "fingerprint"
	t.Run("directory", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "cluster_ca_pins")
		if err := os.Mkdir(directory, 0755); err != nil {
			t.Fatal(err)
		}
		if err := verifyOrStoreClusterPin(filepath.Join(directory, "pin"), fingerprint); err == nil || !strings.Contains(err.Error(), "目录权限过宽") {
			t.Fatalf("error=%v, want wide directory permission rejection", err)
		}
	})
	t.Run("file", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "cluster_ca_pins")
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "pin")
		if err := os.WriteFile(path, []byte(fingerprint+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := verifyOrStoreClusterPin(path, fingerprint); err == nil || !strings.Contains(err.Error(), "文件权限过宽") {
			t.Fatalf("error=%v, want wide file permission rejection", err)
		}
	})
}

func TestStoreClusterPin_writeFailureLeavesNoPartialDestination(t *testing.T) {
	// Given
	directory := filepath.Join(t.TempDir(), "cluster_ca_pins")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "pin")
	writeFailure := errors.New("injected write failure")

	// When
	err := storeClusterPin(path, "first", func(*os.File) error { return writeFailure })
	retryErr := verifyOrStoreClusterPin(path, "second")

	// Then
	if !errors.Is(err, writeFailure) || retryErr != nil {
		t.Fatalf("write error=%v retry error=%v", err, retryErr)
	}
	stored, readErr := os.ReadFile(path)
	if readErr != nil || strings.TrimSpace(string(stored)) != "second" {
		t.Fatalf("stored=%q read error=%v", stored, readErr)
	}
}

func TestSyncService_Pull_persistsEveryFailure(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url='', cluster_token='' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	// When
	_, pullErr := service.Pull(context.Background())

	// Then
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if pullErr == nil || !strings.Contains(stored, pullErr.Error()) {
		t.Fatalf("pull error=%v stored=%q", pullErr, stored)
	}
}

func TestSyncService_Pull_persistsFailureAfterParentContextCanceled(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// When
	_, pullErr := service.Pull(ctx)
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}

	// Then
	if pullErr == nil || !strings.Contains(stored, pullErr.Error()) {
		t.Fatalf("pull error=%v stored=%q", pullErr, stored)
	}
}

func TestSyncService_Pull_clearsLastSyncErrorOnNotModified(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNotModified)
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='token', applied_version=7, last_sync_error='stale failure' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	// When
	result, pullErr := service.Pull(context.Background())
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}

	// Then
	if pullErr != nil || result.Changed || result.AppliedVersion != 7 || stored != "" {
		t.Fatalf("result=%#v error=%v last_sync_error=%q", result, pullErr, stored)
	}
}

func TestDecodeSyncError_preservesLegacyPlainText(t *testing.T) {
	// Given
	const legacy = "同步拉取失败: legacy failure"

	// When
	message, code := decodeSyncError(legacy)

	// Then
	if message != legacy || code != "" {
		t.Fatalf("message=%q code=%q", message, code)
	}
}

func TestSyncService_Pull_persistsResultWhileHoldingPullMutex(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url='', cluster_token='' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	serialized := false
	service.beforeRecordSyncStatus = func() {
		if service.pullMu.TryLock() {
			service.pullMu.Unlock()
			return
		}
		serialized = true
	}

	// When
	_, pullErr := service.Pull(context.Background())

	// Then
	if pullErr == nil || !serialized {
		t.Fatalf("pull error=%v serialized=%v", pullErr, serialized)
	}
}

func TestSyncService_do_repeatedRequestsDoNotContinuouslyIncreaseGoroutines(t *testing.T) {
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer master.Close()
	service := NewSyncService(nil, &config.Config{DataDir: t.TempDir()}, nil)

	request := func() {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, master.URL+"/api/v1/cluster/sync/snapshot", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := service.do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			t.Fatalf("drain response: %v", err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatalf("close response: %v", err)
		}
	}

	request()
	baseline := runtime.NumGoroutine()
	for range 60 {
		request()
	}
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	if increase := runtime.NumGoroutine() - baseline; increase > 15 {
		t.Fatalf("goroutines increased by %d after repeated requests", increase)
	}
}

func TestSyncService_Pull_applies_old_response_after_new_snapshot_applied(t *testing.T) {
	_, database := newClusterTestService(t)
	const token = "cluster-token"
	oldRequestEntered := make(chan struct{})
	releaseOldResponse := make(chan struct{})
	requestNumber := make(chan int, 2)
	var requests atomic.Int32
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/branding" {
			response.WriteHeader(http.StatusOK)
			return
		}
		number := int(requests.Add(1))
		requestNumber <- number
		version := 2
		if number == 1 {
			version = 1
			close(oldRequestEntered)
			waitSyncBarrier(releaseOldResponse)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"data": signedTestSnapshot(version, token)})
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token=? WHERE id=1", master.URL, token); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}
	dataDir := t.TempDir()
	oldPull := NewSyncService(database, &config.Config{CaddyAdminURL: caddy.URL, DataDir: dataDir}, NewCaddyService(caddy.URL))
	newPull := NewSyncService(database, &config.Config{CaddyAdminURL: caddy.URL, DataDir: dataDir}, NewCaddyService(caddy.URL))
	oldDone := make(chan error, 1)
	go func() {
		_, err := oldPull.Pull(context.Background())
		oldDone <- err
	}()
	waitSyncTest(t, oldRequestEntered)
	newDone := make(chan error, 1)
	go func() {
		_, err := newPull.Pull(context.Background())
		newDone <- err
	}()
	if got := waitSyncTest(t, requestNumber); got != 1 {
		t.Fatalf("first request number=%d", got)
	}
	if got := waitSyncTest(t, requestNumber); got != 2 {
		t.Fatalf("second request number=%d", got)
	}
	if err := waitSyncTest(t, newDone); err != nil {
		t.Fatalf("apply newer snapshot: %v", err)
	}
	close(releaseOldResponse)

	if err := waitSyncTest(t, oldDone); err != nil {
		t.Fatalf("late older snapshot rejected: %v", err)
	}
	var appliedVersion int
	if err := database.QueryRow("SELECT applied_version FROM global_config WHERE id=1").Scan(&appliedVersion); err != nil {
		t.Fatalf("read applied version: %v", err)
	}
	if appliedVersion != 1 {
		t.Fatalf("applied version=%d, want 1（从节点跟随主节点版本回退）", appliedVersion)
	}
}

func TestVerifySnapshotIntegrity_acceptsSameAppliedVersion(t *testing.T) {
	const token = "cluster-token"
	snapshot := signedTestSnapshot(7, token)
	if err := verifySnapshotIntegrity(snapshot, token, 7); err != nil {
		t.Fatalf("same snapshot version rejected: %v", err)
	}
}

func TestVerifySnapshotIntegrity_acceptsMasterVersionRegressionWithWarning(t *testing.T) {
	// Given
	const token = "cluster-token"
	snapshot := signedTestSnapshot(3, token)
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)

	// When
	err := verifySnapshotIntegrity(snapshot, token, 7)

	// Then
	if err != nil {
		t.Fatalf("regressed master version rejected: %v", err)
	}
	if !strings.Contains(logs.String(), "检测到主节点配置版本回退") {
		t.Fatalf("missing regression warning, logs=%q", logs.String())
	}
}

func TestVerifySnapshotIntegrity_classifiesAuthenticHigherMinReaderVersion(t *testing.T) {
	// Given
	const token = "cluster-token"
	snapshot := signTestSnapshot(models.ClusterSnapshot{
		Version: 1, SchemaVersion: CurrentSnapshotSchema, MinReaderVersion: CurrentSnapshotSchema + 1,
	}, token)

	// When
	err := verifySnapshotIntegrity(snapshot, token, 0)

	// Then
	var schemaTooNew *SnapshotSchemaTooNewError
	if !errors.As(err, &schemaTooNew) {
		t.Fatalf("authentic higher min-reader error=%v", err)
	}
	if got := syncErrorCode(err); got != models.SyncErrorCodeSchemaTooNew {
		t.Fatalf("sync error code=%q, want %q", got, models.SyncErrorCodeSchemaTooNew)
	}
}

func TestVerifySnapshotIntegrity_rejectsForgedHigherMinReaderVersionAsSignatureInvalid(t *testing.T) {
	// Given：伪造快照携带超高 min_reader_version 但签名无效，永不进入 schema_too_new 终止路径
	snapshot := models.ClusterSnapshot{
		Version:          1,
		SchemaVersion:    CurrentSnapshotSchema,
		MinReaderVersion: CurrentSnapshotSchema + 1,
		Fingerprint:      strings.Repeat("0", sha256.Size*2),
		Signature:        strings.Repeat("0", sha256.Size*2),
		CanonicalPayload: json.RawMessage(`{"version":1,"schema_version":3,"min_reader_version":4}`),
	}

	// When
	err := verifySnapshotIntegrity(snapshot, "cluster-token", 0)

	// Then
	var schemaTooNew *SnapshotSchemaTooNewError
	if err == nil || errors.As(err, &schemaTooNew) || !strings.Contains(err.Error(), "签名校验失败") {
		t.Fatalf("forged higher min-reader error=%v", err)
	}
}

func TestVerifySnapshotIntegrity_rejectsUnsignedHigherMinReaderVersionAsSignatureInvalid(t *testing.T) {
	// Given：未签名快照携带超高 min_reader_version，同样不得进入 schema_too_new 终止路径
	snapshot := models.ClusterSnapshot{
		Version: 1, SchemaVersion: CurrentSnapshotSchema, MinReaderVersion: CurrentSnapshotSchema + 1,
	}

	// When
	err := verifySnapshotIntegrity(snapshot, "cluster-token", 0)

	// Then
	var schemaTooNew *SnapshotSchemaTooNewError
	if err == nil || errors.As(err, &schemaTooNew) || !strings.Contains(err.Error(), "缺少签名") {
		t.Fatalf("unsigned higher min-reader error=%v", err)
	}
}

func TestVerifySnapshotIntegrity_rejects_tamperedACMECredentials(t *testing.T) {
	// Given
	const token = "cluster-token"
	snapshot := models.ClusterSnapshot{
		Version: 3, SchemaVersion: CurrentSnapshotSchema, MinReaderVersion: CurrentSnapshotSchema,
		ACME: &models.ClusterACMEState{CAProviders: []models.CAProvider{{ID: 7, Credentials: `{"eab_kid":"kid","eab_hmac_key":"secret"}`}}},
	}
	snapshot = signTestSnapshot(snapshot, token)

	// When
	snapshot.CanonicalPayload = bytes.Replace(snapshot.CanonicalPayload, []byte("secret"), []byte("tampered"), 1)
	err := verifySnapshotIntegrity(snapshot, token, 0)

	// Then
	if err == nil || !strings.Contains(err.Error(), "签名校验失败") {
		t.Fatalf("tampered ACME credentials error=%v", err)
	}
}

func TestVerifySnapshotIntegrity_rejectsForgedHigherSchemaAsSignatureInvalid(t *testing.T) {
	// Given
	snapshot := models.ClusterSnapshot{
		Version:          1,
		SchemaVersion:    CurrentSnapshotSchema + 1,
		MinReaderVersion: CurrentSnapshotSchema,
		Fingerprint:      strings.Repeat("0", sha256.Size*2),
		Signature:        strings.Repeat("0", sha256.Size*2),
		CanonicalPayload: json.RawMessage(`{"version":1,"schema_version":4,"min_reader_version":3}`),
	}

	// When
	err := verifySnapshotIntegrity(snapshot, "cluster-token", 0)

	// Then
	var schemaTooNew *SnapshotSchemaTooNewError
	if err == nil || errors.As(err, &schemaTooNew) || !strings.Contains(err.Error(), "签名校验失败") {
		t.Fatalf("forged higher-schema error=%v", err)
	}
}

func TestVerifySnapshotIntegrity_classifiesAuthenticatedHigherSchema(t *testing.T) {
	// Given
	const token = "cluster-token"
	snapshot := signTestSnapshot(models.ClusterSnapshot{
		Version: 1, SchemaVersion: CurrentSnapshotSchema + 1, MinReaderVersion: CurrentSnapshotSchema,
	}, token)

	// When
	err := verifySnapshotIntegrity(snapshot, token, 0)

	// Then
	var schemaTooNew *SnapshotSchemaTooNewError
	if !errors.As(err, &schemaTooNew) {
		t.Fatalf("authenticated higher-schema error=%v", err)
	}
}

func TestSyncService_run_stopsAfterReportingHigherMasterSchema(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	var snapshotRequests atomic.Int32
	reported := make(chan models.ClusterReport, 1)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/cluster/sync/snapshot":
			snapshotRequests.Add(1)
			_ = json.NewEncoder(response).Encode(map[string]any{"data": signTestSnapshot(models.ClusterSnapshot{
				Version: 1, SchemaVersion: CurrentSnapshotSchema + 1, MinReaderVersion: CurrentSnapshotSchema,
			}, "cluster-token")})
		case "/api/v1/cluster/nodes/report":
			var report models.ClusterReport
			_ = json.NewDecoder(request.Body).Decode(&report)
			reported <- report
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token', sync_interval=5 WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))
	waits := 0
	service.waitRunDelay = func(context.Context, time.Duration) bool {
		waits++
		return false
	}

	// When
	service.run(context.Background())
	report := waitSyncTest(t, reported)
	insert, err := database.Exec(`INSERT INTO nodes (name,ip_address,is_approved,status) VALUES ('slave-a','127.0.0.1',1,'online')`)
	if err != nil {
		t.Fatal(err)
	}
	nodeID, err := insert.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	cluster := NewClusterService(database, nil)
	if err := cluster.ReportNode(context.Background(), int(nodeID), report, time.Now()); err != nil {
		t.Fatal(err)
	}
	nodes, err := cluster.Nodes(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Then
	want := fmt.Sprintf("主节点快照版本 v%d 超出本节点支持范围 v%d，请升级从节点", CurrentSnapshotSchema+1, CurrentSnapshotSchema)
	if snapshotRequests.Load() != 1 || waits != 0 || !strings.Contains(report.LastSyncError, want) || report.SyncErrorCode != models.SyncErrorCodeSchemaTooNew || report.ServiceStatus != "degraded" || len(nodes) != 1 || nodes[0].Health == nil || nodes[0].Health.SyncErrorCode != models.SyncErrorCodeSchemaTooNew {
		t.Fatalf("requests=%d waits=%d report=%#v nodes=%#v", snapshotRequests.Load(), waits, report, nodes)
	}
}

func TestSyncService_run_haltsOnAuthenticHigherMinReaderVersion(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	var snapshotRequests atomic.Int32
	reported := make(chan models.ClusterReport, 1)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/cluster/sync/snapshot":
			snapshotRequests.Add(1)
			_ = json.NewEncoder(response).Encode(map[string]any{"data": signTestSnapshot(models.ClusterSnapshot{
				Version: 1, SchemaVersion: CurrentSnapshotSchema, MinReaderVersion: CurrentSnapshotSchema + 1,
			}, "cluster-token")})
		case "/api/v1/cluster/nodes/report":
			var report models.ClusterReport
			_ = json.NewDecoder(request.Body).Decode(&report)
			reported <- report
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token', sync_interval=5 WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))
	waits := 0
	service.waitRunDelay = func(context.Context, time.Duration) bool {
		waits++
		return false
	}

	// When
	service.run(context.Background())
	report := waitSyncTest(t, reported)

	// Then
	want := fmt.Sprintf("主节点快照版本 v%d 超出本节点支持范围 v%d，请升级从节点", CurrentSnapshotSchema+1, CurrentSnapshotSchema)
	if snapshotRequests.Load() != 1 || waits != 0 || !strings.Contains(report.LastSyncError, want) || report.SyncErrorCode != models.SyncErrorCodeSchemaTooNew || syncLifecycleState(service.state.Load()) != syncStateHalted {
		t.Fatalf("requests=%d waits=%d state=%d report=%#v", snapshotRequests.Load(), waits, service.state.Load(), report)
	}
}

func TestSyncService_manualPullResumesHaltedWorker(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	const token = "cluster-token"
	var version atomic.Int32
	version.Store(-1)
	reported := make(chan models.ClusterReport, 4)
	snapshotRequested := make(chan int, 4)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/cluster/sync/snapshot":
			current := int(version.Load())
			snapshotRequested <- current
			if current < 0 {
				_ = json.NewEncoder(response).Encode(map[string]any{"data": signTestSnapshot(models.ClusterSnapshot{
					Version: 1, SchemaVersion: CurrentSnapshotSchema + 1, MinReaderVersion: CurrentSnapshotSchema,
				}, token)})
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"data": signedTestSnapshot(current, token)})
		case "/api/v1/cluster/nodes/report":
			var report models.ClusterReport
			_ = json.NewDecoder(request.Body).Decode(&report)
			reported <- report
		default:
			response.WriteHeader(http.StatusOK)
		}
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token=?, sync_interval=60 WHERE id=1", master.URL, token); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))
	service.Start()
	t.Cleanup(service.Stop)
	waitSyncTest(t, reported)
	version.Store(1)

	// When
	manual, pullErr := service.Pull(context.Background())
	version.Store(2)
	service.Resume()
	resumedVersion := waitSyncTest(t, snapshotRequested)
	for resumedVersion != 2 {
		resumedVersion = waitSyncTest(t, snapshotRequested)
	}

	// Then
	if pullErr != nil || !manual.Changed {
		t.Fatalf("manual result=%#v error=%v", manual, pullErr)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		var applied int
		if err := database.QueryRow("SELECT applied_version FROM global_config WHERE id=1").Scan(&applied); err != nil {
			t.Fatal(err)
		}
		if applied == 2 {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("resumed worker did not apply the next master version")
}

func TestSyncService_Pull_manualSuccessClearsHigherSchemaTerminalError(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	const token = "cluster-token"
	higherSchema := atomic.Bool{}
	higherSchema.Store(true)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		if higherSchema.Load() {
			_ = json.NewEncoder(response).Encode(map[string]any{"data": models.ClusterSnapshot{SchemaVersion: CurrentSnapshotSchema + 1}})
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"data": signedTestSnapshot(1, token)})
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token=? WHERE id=1", master.URL, token); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))
	if _, err := service.Pull(context.Background()); err == nil {
		t.Fatal("higher schema pull unexpectedly succeeded")
	}
	higherSchema.Store(false)

	// When
	result, err := service.Pull(context.Background())
	var stored string
	if queryErr := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); queryErr != nil {
		t.Fatal(queryErr)
	}

	// Then
	if err != nil || !result.Changed || stored != "" {
		t.Fatalf("result=%#v error=%v last_sync_error=%q", result, err, stored)
	}
}

func TestClusterSnapshot_decode_ignores_unknownACMEFields(t *testing.T) {
	// Given
	payload := []byte(`{"version":2,"acme":{"ca_providers":[{"id":7,"name":"provider"}],"future_field":{"enabled":true}},"future_root":"ignored"}`)

	// When
	var snapshot models.ClusterSnapshot
	err := json.Unmarshal(payload, &snapshot)

	// Then
	if err != nil || snapshot.ACME == nil || len(snapshot.ACME.CAProviders) != 1 || snapshot.ACME.CAProviders[0].ID != 7 {
		t.Fatalf("decoded snapshot=%#v error=%v", snapshot, err)
	}
}

func TestSyncService_Pull_rejectsSchemaV1SnapshotWithoutWritingDatabase(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	const token = "cluster-token"
	v1 := models.ClusterSnapshot{
		Version:       1,
		SchemaVersion: 1,
		Users:         []models.ClusterUser{{ID: 99, Username: "v1-user", PasswordHash: "hash", Role: "admin", IsEnabled: true}},
	}
	v1 = signTestSnapshot(v1, token)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"data": v1})
	}))
	defer master.Close()
	if _, err := database.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (10,'local-user','hash','admin',1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token=? WHERE id=1", master.URL, token); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	// When
	_, pullErr := service.Pull(context.Background())
	var username string
	if err := database.QueryRow("SELECT username FROM users WHERE id=10").Scan(&username); err != nil {
		t.Fatal(err)
	}

	// Then
	// Round 35 S-11: 移除 v1/v2 legacy 回退后，v1 快照因缺少 canonical_payload
	// 在签名校验阶段被拒绝。验证关键不变量：拒绝发生 + 本地数据未被覆盖。
	if pullErr == nil || username != "local-user" {
		t.Fatalf("pull error=%v local username=%q", pullErr, username)
	}
}

func TestSyncService_Promote_drains_blocked_manual_pull_without_applying(t *testing.T) {
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
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token=? WHERE id=1", master.URL, token); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}
	syncService := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(master.URL))
	beforeApply := make(chan struct{})
	releaseApply := make(chan struct{})
	syncService.beforeApplySnapshot = func() {
		close(beforeApply)
		waitSyncBarrier(releaseApply)
	}
	lifecycle := &syncDrainLifecycle{sync: syncService, stopEntered: make(chan struct{})}
	cluster := NewClusterService(database, lifecycle)
	pullDone := make(chan error, 1)
	go func() {
		_, err := syncService.Pull(context.Background())
		pullDone <- err
	}()
	waitSyncTest(t, beforeApply)
	promoteDone := make(chan error, 1)
	go func() { promoteDone <- cluster.Promote(context.Background()) }()
	waitSyncTest(t, lifecycle.stopEntered)
	select {
	case err := <-promoteDone:
		t.Fatalf("promote returned before active pull drained: %v", err)
	default:
	}

	close(releaseApply)
	if err := waitSyncTest(t, pullDone); err == nil {
		t.Fatal("pull applied snapshot after promotion")
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
		t.Fatalf("promoted state is_master=%v applied_version=%d", isMaster, appliedVersion)
	}
	if _, err := syncService.Pull(context.Background()); err == nil {
		t.Fatal("new pull was accepted after sync stopped")
	}
}

func TestSyncService_Stop_returns_when_run_is_waiting_before_pull_admission(t *testing.T) {
	beforeAdmission := make(chan struct{})
	releaseAdmission := make(chan struct{})
	admissionStopped := make(chan struct{})
	service := &SyncService{}
	service.beforeBeginPull = func() {
		close(beforeAdmission)
		waitSyncBarrier(releaseAdmission)
	}
	service.afterStopAdmission = func() { close(admissionStopped) }
	service.runFn = func(ctx context.Context) {
		_, _ = service.Pull(ctx)
	}

	service.Start()
	waitSyncTest(t, beforeAdmission)
	stopped := make(chan struct{})
	go func() {
		service.Stop()
		close(stopped)
	}()
	waitSyncTest(t, admissionStopped)
	close(releaseAdmission)
	waitSyncTest(t, stopped)
}

func signedTestSnapshot(version int, token string) models.ClusterSnapshot {
	snapshot := models.ClusterSnapshot{
		Version: version, SchemaVersion: CurrentSnapshotSchema, MinReaderVersion: CurrentSnapshotSchema,
		ACME: &models.ClusterACMEState{CAProviders: []models.CAProvider{}, CertificateConfigs: []models.CertificateConfig{}, DNSOwnership: json.RawMessage(`{"version":1,"records":[]}`)},
	}
	return signTestSnapshot(snapshot, token)
}

func signTestSnapshot(snapshot models.ClusterSnapshot, token string) models.ClusterSnapshot {
	canonical := snapshot
	canonical.Fingerprint = ""
	canonical.Signature = ""
	canonical.CanonicalPayload = nil
	content, err := json.Marshal(canonical)
	if err != nil {
		panic(err)
	}
	if snapshot.SchemaVersion >= 3 {
		hash := sha256.Sum256(content)
		snapshot.Fingerprint = hex.EncodeToString(hash[:])
		snapshot.CanonicalPayload = content
	}
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(content)
	snapshot.Signature = hex.EncodeToString(mac.Sum(nil))
	return snapshot
}

func TestSyncService_Pull_refetchesFullSnapshotOnLocalDrift(t *testing.T) {
	// Given：主节点对增量请求回 304；从节点记录的 rules 哈希与主节点一致
	// 但本地 lb_rules 为空（数据丢失）——304 后必须以 since_version=0 重拉
	// 全量快照并强制重放，而不是被「配置无变化」永久掩盖。
	_, database := newClusterTestService(t)
	snapshot := signedTestSnapshot(9, "token")
	snapshot.Rules = []models.LbRule{{
		CaddyID: "lb_drift", Name: "drift", Protocol: "http", Domain: "drift.example.com",
		ListenPort: 80, Enabled: true,
	}}
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	snapshot = signTestSnapshot(snapshot, "token")

	requestedVersions := make(chan string, 2)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requestedVersions <- request.URL.Query().Get("since_version")
		if request.URL.Query().Get("since_version") == "0" {
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(models.APIResponse{Code: 0, Data: snapshot})
			return
		}
		response.WriteHeader(http.StatusNotModified)
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='token', applied_version=9 WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cluster_applied_sections (section, hash, applied_version) VALUES ('rules', ?, 9)`,
		snapshot.SectionHashes["rules"]); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir(), CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When
	result, pullErr := service.Pull(context.Background())

	// Then
	if pullErr != nil {
		t.Fatalf("pull: %v", pullErr)
	}
	if !result.Changed || result.AppliedVersion != 9 {
		t.Fatalf("result=%#v, want changed full-snapshot apply", result)
	}
	if v := waitSyncTest(t, requestedVersions); v != "9" {
		t.Fatalf("first request since_version=%q, want 9", v)
	}
	if v := waitSyncTest(t, requestedVersions); v != "0" {
		t.Fatalf("second request since_version=%q, want 0 (drift re-pull)", v)
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_drift'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("drift 未自愈: lb_rules 行数=%d, want 1", count)
	}
}

func TestSyncService_Pull_refetchesFullSnapshotOnWafFileDrift(t *testing.T) {
	// N-01 端到端：apply 期安全数据拉取/落盘失败仅记日志不返回错误
	// （cluster_apply.go），记录哈希已提交但本地文件未收敛；主节点无新变更
	// → 下轮 304。304 分支的 WAF 兜底必须比对 cluster_applied_sections 的
	// waf_files 节哈希与本地文件态，不一致则 since_version=0 全量重拉并
	// 重新拉取安全数据，直至收敛。
	_, database := newClusterTestService(t)

	// 主节点文件树：快照引用与文件包的真实来源。
	masterTree := t.TempDir()
	os.MkdirAll(filepath.Join(masterTree, "crs", "rules"), 0755)
	os.WriteFile(filepath.Join(masterTree, "crs", "rules", "a.conf"), []byte("SecRule X 1"), 0644)
	os.WriteFile(filepath.Join(masterTree, "crs", "VERSION"), []byte("v4.28.0"), 0644)
	masterXdb := filepath.Join(masterTree, "ip2region.xdb")
	os.WriteFile(masterXdb, []byte("master-xdb-bytes"), 0644)

	oldLive, oldXdb := crsLiveDir, ip2regionLivePath
	crsLiveDir, ip2regionLivePath = filepath.Join(masterTree, "crs"), masterXdb
	ref := BuildWafFileRef()
	bundle := BuildWafFileBundle()
	// 模拟 apply 期失败后的从节点：本地文件树为空（从未收敛）。
	slaveTree := t.TempDir()
	crsLiveDir, ip2regionLivePath = filepath.Join(slaveTree, "crs"), filepath.Join(slaveTree, "ip2region.xdb")
	defer func() { crsLiveDir, ip2regionLivePath = oldLive, oldXdb }()
	os.MkdirAll(crsLiveDir, 0755)
	if ref == nil || bundle == nil {
		t.Fatal("master ref/bundle must build")
	}

	snapshot := signedTestSnapshot(9, "token")
	snapshot.WafFiles = ref
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	snapshot = signTestSnapshot(snapshot, "token")

	requestedVersions := make(chan string, 2)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/cluster/sync/waf-files" {
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{"data": bundle})
			return
		}
		requestedVersions <- request.URL.Query().Get("since_version")
		if request.URL.Query().Get("since_version") == "0" {
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(models.APIResponse{Code: 0, Data: snapshot})
			return
		}
		response.WriteHeader(http.StatusNotModified)
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='token', applied_version=9 WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	seedAppliedSection(t, database, "waf_files", snapshot.SectionHashes["waf_files"])
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddyServer.Close()
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir(), CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When
	result, pullErr := service.Pull(context.Background())

	// Then
	if pullErr != nil {
		t.Fatalf("pull: %v", pullErr)
	}
	if !result.Changed || result.AppliedVersion != 9 {
		t.Fatalf("result=%#v, want changed full-snapshot apply", result)
	}
	if v := waitSyncTest(t, requestedVersions); v != "9" {
		t.Fatalf("first request since_version=%q, want 9", v)
	}
	if v := waitSyncTest(t, requestedVersions); v != "0" {
		t.Fatalf("second request since_version=%q, want 0 (WAF drift re-pull)", v)
	}
	if got, err := os.ReadFile(filepath.Join(crsLiveDir, "rules", "a.conf")); err != nil || string(got) != "SecRule X 1" {
		t.Fatalf("CRS not converged: content=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(ip2regionLivePath); err != nil || string(got) != "master-xdb-bytes" {
		t.Fatalf("xdb not converged: content=%q err=%v", got, err)
	}
}

func TestSyncService_driftedSections_bypassesStaleSnapshotCache(t *testing.T) {
	// I-1 回归：本地规则在同步之外被删改但不递增 cluster_version，快照缓存
	// 键（version/所有权/开关）不变 → 命中缓存会返回陈旧快照掩盖漂移。
	// driftedSections 必须绕过缓存、直接重建本地快照才能检测到漂移。
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_a','a','http','a.example',80,1)`); err != nil {
		t.Fatal(err)
	}
	// 预热快照缓存：记录与主节点一致的 rules 已应用哈希。
	cluster := NewClusterService(database, nil)
	snap, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	seedAppliedSection(t, database, "rules", snap.SectionHashes["rules"])

	// 稳态下本地规则被删（不 bump cluster_version）。
	if _, err := database.Exec(`DELETE FROM lb_rules WHERE caddy_id='lb_a'`); err != nil {
		t.Fatal(err)
	}

	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	if drifted := service.driftedSections(context.Background()); drifted != "rules" {
		t.Fatalf("drifted=%q, want rules（缓存命中掩盖了漂移）", drifted)
	}
}

func TestSyncService_driftedSections_skipsDisabledSwitch(t *testing.T) {
	// I-2 回归：曾同步过的节随后开关关闭 + 本地改动，若漂移检测不看开关会
	// 每轮都报告漂移并全量重拉，而 apply 又跳过该节 → 永久死循环。
	_, database := newClusterTestService(t)
	seedAppliedSection(t, database, "users", "stale-applied-hash")
	if _, err := database.Exec("UPDATE global_config SET sync_users=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'local','h','admin',1)`); err != nil {
		t.Fatal(err)
	}

	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	if drifted := service.driftedSections(context.Background()); drifted != "" {
		t.Fatalf("drifted=%q, want \"\"（开关关闭的节不得触发重拉循环）", drifted)
	}

	// 开关重新打开且本地数据缺失 → 仍应检测漂移。
	if _, err := database.Exec("UPDATE global_config SET sync_users=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	cluster := NewClusterService(database, nil)
	snap, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	seedAppliedSection(t, database, "users", snap.SectionHashes["users"])
	if _, err := database.Exec(`DELETE FROM users`); err != nil {
		t.Fatal(err)
	}
	if drifted := service.driftedSections(context.Background()); drifted != "users" {
		t.Fatalf("drifted=%q, want users（开关打开且数据缺失应检测）", drifted)
	}
}
