package services

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func TestSyncService_Pull_masterUnauthorizedIsTerminalFailure(t *testing.T) {
	// Given：主节点对本节点的快照拉取持续返回 401 且带本服务错误码
	// （clusterTokenAuth 的凭据拒绝形态）
	_, database := newClusterTestService(t)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("X-LB-Error-Code", ClusterTokenInvalidErrorCode)
		response.WriteHeader(http.StatusUnauthorized)
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	// When
	_, pullErr := service.Pull(context.Background())
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	message, code := decodeSyncError(stored)

	// Then：返回终止类错误并持久化明确的原因与错误码
	if !errors.Is(pullErr, errSyncTokenRevoked) {
		t.Fatalf("pull error=%v, want token-revoked terminal failure", pullErr)
	}
	if !strings.Contains(message, "集群令牌已被主节点撤销") {
		t.Fatalf("stored message=%q, want revocation guidance", message)
	}
	if code != models.SyncErrorCodeValidationFailed {
		t.Fatalf("stored code=%q, want %q", code, models.SyncErrorCodeValidationFailed)
	}
}

func TestSyncService_Pull_bareForbiddenIsRetryableProxyRejection(t *testing.T) {
	// Given：前置代理/网关对快照端点返回裸 403（无 master_required 码）
	_, database := newClusterTestService(t)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusForbidden)
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	// When
	_, pullErr := service.Pull(context.Background())
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	message, code := decodeSyncError(stored)

	// Then：非终止（不得据此判定令牌撤销），文案区分「代理拒绝」
	if errors.Is(pullErr, errSyncTokenRevoked) {
		t.Fatalf("pull error=%v, want non-terminal retryable failure", pullErr)
	}
	if !strings.Contains(message, "非令牌撤销") {
		t.Fatalf("stored message=%q, want proxy-rejection wording", message)
	}
	if code != models.SyncErrorCodeTransportError {
		t.Fatalf("stored code=%q, want %q", code, models.SyncErrorCodeTransportError)
	}
}

func TestSyncService_run_haltsAndSkipsReportOnMasterUnauthorized(t *testing.T) {
	// Given：主节点撤销本节点令牌后，快照端点返回 401
	_, database := newClusterTestService(t)
	var snapshotRequests, reportRequests atomic.Int32
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/cluster/sync/snapshot":
			snapshotRequests.Add(1)
			response.Header().Set("X-LB-Error-Code", ClusterTokenInvalidErrorCode)
			response.WriteHeader(http.StatusUnauthorized)
		case "/api/v1/cluster/nodes/report":
			reportRequests.Add(1)
			response.WriteHeader(http.StatusOK)
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
	service.waitRunDelay = func(context.Context, time.Duration) bool { return false }

	// When
	service.run(context.Background())
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}

	// Then：同步循环 halted（不再无限重拉）、跳过状态上报、错误已落库
	if snapshotRequests.Load() != 1 {
		t.Fatalf("snapshot requests=%d, want 1（halt 后不得继续重试）", snapshotRequests.Load())
	}
	if reportRequests.Load() != 0 {
		t.Fatalf("report requests=%d, want 0（令牌被撤销后跳过上报）", reportRequests.Load())
	}
	if syncLifecycleState(service.state.Load()) != syncStateHalted {
		t.Fatalf("state=%d, want halted", service.state.Load())
	}
	if !strings.Contains(stored, "集群令牌已被主节点撤销") {
		t.Fatalf("stored last_sync_error=%q, want revocation message", stored)
	}
}

func TestClusterService_BecomeSlave_resetsRegistrationConfirmFailures(t *testing.T) {
	// Given：此前注册确认连续失败，残留计数非零
	service, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET registration_confirm_failures=3, last_sync_error='旧错误', applied_version=7 WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	// When：重新走从节点注册流程
	if err := service.BecomeSlave(context.Background(), "https://master.example", models.ClusterRegistration{RegistrationID: 9, RegistrationSecret: "secret"}); err != nil {
		t.Fatalf("become slave: %v", err)
	}
	var failures int
	var lastSyncError string
	var appliedVersion int
	if err := database.QueryRow("SELECT COALESCE(registration_confirm_failures,0), COALESCE(last_sync_error,''), COALESCE(applied_version,0) FROM global_config WHERE id=1").Scan(&failures, &lastSyncError, &appliedVersion); err != nil {
		t.Fatal(err)
	}

	// Then：注册确认失败计数与同步残留被一并清零（与提升路径对称）
	if failures != 0 || lastSyncError != "" || appliedVersion != 0 {
		t.Fatalf("failures=%d last_sync_error=%q applied_version=%d, want 0/\"\"/0", failures, lastSyncError, appliedVersion)
	}
}

// 前置代理/身份网关返回的裸 401 不代表令牌撤销：必须可重试（与裸 403 同口径），
// 否则从节点在主节点可用、令牌有效的情况下永久停同步，且文案误导管理员重新注册。
func TestSyncService_Pull_bareUnauthorizedIsRetryableProxyRejection(t *testing.T) {
	// Given：快照端点被前置代理以 401 拒绝（无本服务错误码、无本服务文案）
	_, database := newClusterTestService(t)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte(`<html>gateway login</html>`))
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	// When
	_, pullErr := service.Pull(context.Background())
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	message, code := decodeSyncError(stored)

	// Then：非终止、可重试，文案区分「非令牌撤销」
	if errors.Is(pullErr, errSyncTokenRevoked) {
		t.Fatalf("pull error=%v, want non-terminal retryable failure（代理 401 不是令牌撤销）", pullErr)
	}
	if !strings.Contains(message, "非令牌撤销") {
		t.Fatalf("stored message=%q, want proxy-401 wording", message)
	}
	if code != models.SyncErrorCodeTransportError {
		t.Fatalf("stored code=%q, want %q", code, models.SyncErrorCodeTransportError)
	}
}

// 旧主节点兼容形态：401 无错误码、但 body 是本服务「集群凭证无效」文案 → 仍终止。
func TestSyncService_Pull_unauthorizedWithLegacyBodyIsTerminal(t *testing.T) {
	_, database := newClusterTestService(t)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte(`{"code":401,"message":"集群凭证无效"}`))
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	_, pullErr := service.Pull(context.Background())
	if !errors.Is(pullErr, errSyncTokenRevoked) {
		t.Fatalf("pull error=%v, want token-revoked（无错误码但文案可识别）", pullErr)
	}
}

// 裸 401（代理鉴权）不得把同步循环置为 halted：本轮照常上报并按下轮重试。
func TestSyncService_run_keepsRetryingOnProxyUnauthorized(t *testing.T) {
	_, database := newClusterTestService(t)
	var snapshotRequests, reportRequests atomic.Int32
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/cluster/sync/snapshot":
			snapshotRequests.Add(1)
			response.WriteHeader(http.StatusUnauthorized)
		case "/api/v1/cluster/nodes/report":
			reportRequests.Add(1)
			response.WriteHeader(http.StatusOK)
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
	service.waitRunDelay = func(context.Context, time.Duration) bool { return false }

	service.run(context.Background())

	if snapshotRequests.Load() != 1 {
		t.Fatalf("snapshot requests=%d, want 1", snapshotRequests.Load())
	}
	if reportRequests.Load() != 1 {
		t.Fatalf("report requests=%d, want 1（可重试类失败仍照常上报）", reportRequests.Load())
	}
	if syncLifecycleState(service.state.Load()) == syncStateHalted {
		t.Fatal("代理 401 不得把同步循环置为 halted（会永久停同步等人工介入）")
	}
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "集群令牌已被主节点撤销") {
		t.Fatalf("last_sync_error=%q, want 非令牌撤销 文案", stored)
	}
}
