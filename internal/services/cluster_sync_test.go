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

type blockingRoundTripper struct {
	entered chan struct{}
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

func (r blockingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	close(r.entered)
	select {
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case <-time.After(time.Second):
		return nil, context.DeadlineExceeded
	}
}

func TestSyncService_RegisterWithMaster_rejectsHTTP(t *testing.T) {
	service := &SyncService{client: &http.Client{Timeout: time.Second}}
	_, err := service.RegisterWithMaster(context.Background(), "http://master.example", models.ClusterRegisterRequest{})
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("registration error=%v, want HTTPS rejection", err)
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

func TestSyncService_Pull_rejects_old_response_after_new_snapshot_applied(t *testing.T) {
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

	if err := waitSyncTest(t, oldDone); err == nil {
		t.Fatal("late older snapshot was accepted")
	}
	var appliedVersion int
	if err := database.QueryRow("SELECT applied_version FROM global_config WHERE id=1").Scan(&appliedVersion); err != nil {
		t.Fatalf("read applied version: %v", err)
	}
	if appliedVersion != 2 {
		t.Fatalf("applied version=%d, want 2", appliedVersion)
	}
}

func TestVerifySnapshotIntegrityRejectsSameAppliedVersion(t *testing.T) {
	const token = "cluster-token"
	snapshot := signedTestSnapshot(7, token)
	if err := verifySnapshotIntegrity(snapshot, token, 7); err == nil {
		t.Fatal("same snapshot version was accepted")
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
	if pullErr == nil || !strings.Contains(pullErr.Error(), "主节点") || username != "local-user" {
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
