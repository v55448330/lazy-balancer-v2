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
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func TestSyncService_Pull_masterUnauthorizedIsTerminalFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"unauthorized", http.StatusUnauthorized},
		{"forbidden", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given：主节点对本节点的快照拉取持续返回 401/403（令牌已被撤销）
			_, database := newClusterTestService(t)
			master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(tc.status)
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
		})
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

func TestSyncService_Report_httpFailureAuditsOnChangeOnly(t *testing.T) {
	// Given：主节点上报端点先持续 403，再恢复，再 403
	_, database := newClusterTestService(t)
	var mode atomic.Int32 // 0=403, 1=200
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		if mode.Load() == 1 {
			response.WriteHeader(http.StatusOK)
			return
		}
		response.WriteHeader(http.StatusForbidden)
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))
	auditCount := func() int {
		t.Helper()
		var count int
		if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='上报失败'").Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}

	// When：同一 403 失败连续上报两次
	firstErr := service.Report(context.Background())
	secondErr := service.Report(context.Background())
	afterRepeated := auditCount()

	// Then：错误如实返回，审计只记一次（节流生效）
	if firstErr == nil || secondErr == nil || !strings.Contains(firstErr.Error(), "403") {
		t.Fatalf("report errors=%v/%v, want HTTP 403 failures", firstErr, secondErr)
	}
	if afterRepeated != 1 {
		t.Fatalf("audit rows after repeated failure=%d, want 1（同一错误只记一次）", afterRepeated)
	}

	// When：上报恢复后再次失败
	mode.Store(1)
	if err := service.Report(context.Background()); err != nil {
		t.Fatalf("recovered report: %v", err)
	}
	mode.Store(0)
	if err := service.Report(context.Background()); err == nil {
		t.Fatal("re-failed report unexpectedly succeeded")
	}

	// Then：恢复后的新失败重新留痕
	if got := auditCount(); got != 2 {
		t.Fatalf("audit rows after recovery-then-failure=%d, want 2（恢复后重记）", got)
	}
}
