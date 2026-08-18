package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// R32-1：run 循环 loadState 瞬时失败（SQLITE_BUSY 等）不得覆盖 apply_ok_reload_failed
// 标记——标记是 304 全量重拉补偿的唯一触发器。失败周期组合保留标记；loadState 恢复后
// 304 分支必须触发 since_version=0 全量重拉补偿。
func TestSyncService_run_loadStateTransientFailure_preservesReloadMarker_then304Repull(t *testing.T) {
	// Given：重载失败标记已存在；主节点对 since_version=7 回 304、对 since_version=0
	// 返回 v9 全量快照
	_, database := newClusterTestService(t)
	snapshot := signedTestSnapshot(9, "token")
	requestedVersions := make(chan string, 2)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/cluster/sync/snapshot":
			since := request.URL.Query().Get("since_version")
			requestedVersions <- since
			if since == "0" {
				response.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(response).Encode(models.APIResponse{Code: 0, Data: snapshot})
				return
			}
			response.WriteHeader(http.StatusNotModified)
		case "/api/v1/cluster/nodes/report":
			response.WriteHeader(http.StatusOK)
		default:
			response.WriteHeader(http.StatusOK)
		}
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='token', applied_version=7, last_sync_error=? WHERE id=1",
		master.URL, encodeSyncError("apply_ok_reload_failed: caddy down", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))

	// loadState 第 1 次调用注入瞬时失败，之后恢复正常读取
	loadStateCalls := 0
	service.loadRunState = func(ctx context.Context) (bool, string, int, error) {
		loadStateCalls++
		if loadStateCalls == 1 {
			return false, "", 0, errors.New("SQLITE_BUSY: database is locked")
		}
		var isMaster bool
		var token string
		var interval int
		err := database.QueryRowContext(ctx, "SELECT is_master, COALESCE(cluster_token,''), COALESCE(sync_interval,60) FROM global_config WHERE id=1").Scan(&isMaster, &token, &interval)
		return isMaster, token, interval, err
	}
	// 第 1 次 waitDelay 时机在失败落库之后：捕获标记组合结果；第 2 次返回 false 退出
	var captured string
	waitCalls := 0
	service.waitRunDelay = func(_ context.Context, _ time.Duration) bool {
		waitCalls++
		if waitCalls == 1 {
			_ = database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&captured)
		}
		return waitCalls < 2
	}

	// When：失败 1 个周期后 loadState 恢复
	service.run(context.Background())

	// Then：失败周期保留标记并组合「读取同步状态失败」消息 + 计数 1
	msg, code := decodeSyncError(captured)
	if !strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) {
		t.Fatalf("captured message=%q, want reload failure marker preserved", msg)
	}
	if !strings.Contains(msg, "读取同步状态失败: SQLITE_BUSY: database is locked") {
		t.Fatalf("captured message=%q, want load-state failure combined", msg)
	}
	if !strings.Contains(msg, syncFailureCountPrefix+"1"+syncFailureCountSuffix) {
		t.Fatalf("captured message=%q, want failure count 1", msg)
	}
	if code != models.SyncErrorCodeTransportError {
		t.Fatalf("captured code=%q, want transport_error", code)
	}

	// Then：loadState 恢复后 304 分支检测到标记 → since_version=0 全量重拉补偿生效
	if v := waitSyncTest(t, requestedVersions); v != "7" {
		t.Fatalf("first request since_version=%q, want 7", v)
	}
	if v := waitSyncTest(t, requestedVersions); v != "0" {
		t.Fatalf("second request since_version=%q, want 0 (304 compensation despite transient loadState failure)", v)
	}
	var appliedVersion int
	if err := database.QueryRow("SELECT applied_version FROM global_config WHERE id=1").Scan(&appliedVersion); err != nil {
		t.Fatal(err)
	}
	if appliedVersion != 9 {
		t.Fatalf("applied_version=%d, want 9（补偿重拉已应用）", appliedVersion)
	}
	if loadStateCalls != 2 {
		t.Fatalf("loadState calls=%d, want 2", loadStateCalls)
	}
}

// R32-2：快照完整性失败（签名无效）同一错误单周期只落库一次——Pull defer 覆盖
// err != nil 路径，显式调用已删除，run 循环在 pullErr 非空时不再重复写。
func TestSyncService_run_integrityFailure_writesLastSyncErrorOnce(t *testing.T) {
	// Given：重载失败标记已存在（终止类错误应覆盖它）；主节点返回伪造签名的快照
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET last_sync_error=? WHERE id=1",
		encodeSyncError("apply_ok_reload_failed: caddy down", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatal(err)
	}
	tampered := signedTestSnapshot(9, "wrong-token")
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/cluster/sync/snapshot":
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(models.APIResponse{Code: 0, Data: tampered})
		case "/api/v1/cluster/nodes/report":
			response.WriteHeader(http.StatusOK)
		default:
			response.WriteHeader(http.StatusOK)
		}
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='token', applied_version=0 WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	// 触发器统计 last_sync_error 的 UPDATE 次数（标记种子写入发生在建触发器之前，不计入）
	if _, err := database.Exec("CREATE TABLE IF NOT EXISTS sync_error_write_tally (n INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("CREATE TRIGGER IF NOT EXISTS trg_sync_error_write_tally AFTER UPDATE OF last_sync_error ON global_config BEGIN INSERT INTO sync_error_write_tally (n) VALUES (1); END"); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))
	service.waitRunDelay = func(context.Context, time.Duration) bool { return false }

	// When：单个周期内 Pull 遭遇完整性失败
	service.run(context.Background())

	// Then：last_sync_error 内容正确且只写一次（终止类覆盖标记）
	var writeCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM sync_error_write_tally").Scan(&writeCount); err != nil {
		t.Fatal(err)
	}
	if writeCount != 1 {
		t.Fatalf("last_sync_error writes=%d, want exactly 1", writeCount)
	}
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, code := decodeSyncError(stored)
	if strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) || !strings.Contains(msg, "签名校验失败") {
		t.Fatalf("stored message=%q, want terminal signature error overwriting marker", msg)
	}
	if code != models.SyncErrorCodeSignatureInvalid {
		t.Fatalf("stored code=%q, want signature_invalid", code)
	}
}

// R32-3：pollRegistration 的传输类失败同样走共享 helper——不覆盖重载失败标记。
// 仅异常清 token 场景（注册中）可达，但标记保护语义必须与其余路径一致。
func TestSyncService_run_pollRegistration_transportFailure_preservesReloadMarker(t *testing.T) {
	// Given：重载失败标记已存在；节点处于注册中（token 为空），主节点返回 500
	_, database := newClusterTestService(t)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusInternalServerError)
		_, _ = response.Write([]byte("boom"))
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='', registration_id=1, registration_secret='reg-secret', last_sync_error=? WHERE id=1",
		master.URL, encodeSyncError("apply_ok_reload_failed: caddy down", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	var captured string
	service.waitRunDelay = func(_ context.Context, _ time.Duration) bool {
		_ = database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&captured)
		return false
	}

	// When：注册轮询周期遭遇主节点 5xx
	service.run(context.Background())

	// Then：标记保留，传输错误组合追加
	msg, code := decodeSyncError(captured)
	if !strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) {
		t.Fatalf("captured message=%q, want reload failure marker preserved", msg)
	}
	if !strings.Contains(msg, "查询注册状态失败（主节点返回 500）") {
		t.Fatalf("captured message=%q, want registration poll failure combined", msg)
	}
	if code != models.SyncErrorCodeTransportError {
		t.Fatalf("captured code=%q, want transport_error", code)
	}
}
