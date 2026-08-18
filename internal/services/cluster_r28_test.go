package services

import (
	"context"
	"encoding/json"
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

// R28 A-M2：快照提交成功但 Caddy 重载失败时，必须留下可识别、可重试的
// 状态（apply_ok_reload_failed 标记写入 last_sync_error），否则主节点
// 版本未变 → 后续同步一律 304 → 陈旧运行配置被永久掩盖且状态页仍显示 ok。
func TestSyncService_applySnapshot_reloadFailure_marks_apply_ok_reload_failed(t *testing.T) {
	// Given：快照可正常提交，但 Caddy admin 对 /load 一律返回 500
	cluster, database := newClusterTestService(t)
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusInternalServerError)
		_, _ = response.Write([]byte("caddy boom"))
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When
	applyErr := syncService.applySnapshot(context.Background(), snapshot)

	// Then：applySnapshot 按设计返回 nil（重载失败不回滚已提交快照），
	// last_sync_error 已落库携带标记（UI 与主节点 Report 通道可见）；
	// 快照事务本身已提交（applied_version 已推进）。
	if applyErr != nil {
		t.Fatalf("apply error=%v, want nil（重载失败不回滚已提交快照）", applyErr)
	}
	var appliedVersion int
	var lastSyncError string
	if err := database.QueryRow("SELECT COALESCE(applied_version,0), COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&appliedVersion, &lastSyncError); err != nil {
		t.Fatal(err)
	}
	if appliedVersion != snapshot.Version {
		t.Fatalf("applied_version=%d, want %d（快照必须已提交）", appliedVersion, snapshot.Version)
	}
	if !strings.Contains(lastSyncError, "apply_ok_reload_failed") {
		t.Fatalf("last_sync_error=%q, want apply_ok_reload_failed marker", lastSyncError)
	}
}

func TestSyncService_applySnapshot_success_clears_reload_failure_marker(t *testing.T) {
	// Given：上一轮重载失败留下了标记；本轮 Caddy 恢复正常（200）
	cluster, database := newClusterTestService(t)
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET last_sync_error=?", encodeSyncError("apply_ok_reload_failed: previous failure", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When
	err = syncService.applySnapshot(context.Background(), snapshot)

	// Then：应用成功返回 nil，标记随成功路径清空
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	var lastSyncError string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&lastSyncError); err != nil {
		t.Fatal(err)
	}
	if lastSyncError != "" {
		t.Fatalf("last_sync_error=%q, want cleared after successful reload", lastSyncError)
	}
}

func TestSyncService_Pull_repulls_full_snapshot_after_reload_failure_marker(t *testing.T) {
	// Given：主节点对增量请求回 304；从节点 last_sync_error 携带重载失败
	// 标记且本地数据无漂移——304 分支必须识别标记并以 since_version=0
	// 全量重拉，让 apply 重试重载，而不是被「配置无变化」永久掩盖。
	_, database := newClusterTestService(t)
	snapshot := signedTestSnapshot(9, "token")
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
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='token', applied_version=9, last_sync_error=? WHERE id=1",
		master.URL, encodeSyncError("apply_ok_reload_failed: caddy down", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir(), CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When
	result, pullErr := service.Pull(context.Background())

	// Then：先按增量请求（9），再因标记全量重拉（0）；重载成功后标记清空
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
		t.Fatalf("second request since_version=%q, want 0 (reload-failure re-pull)", v)
	}
	var lastSyncError string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&lastSyncError); err != nil {
		t.Fatal(err)
	}
	if lastSyncError != "" {
		t.Fatalf("last_sync_error=%q, want cleared after successful retry", lastSyncError)
	}
}

// R29 HIGH-1：apply 成功但 Caddy 重载失败时，标记必须在同一 Pull 周期内
// 存活（defer 清空不得吞掉本周期写入的标记）；下一周期 304 时必须以
// since_version=0 全量重拉补偿重试。
func TestSyncService_Pull_reload_failure_marker_survives_defer_and_triggers_repull(t *testing.T) {
	// Given：从节点 applied_version=9；主节点首个增量请求回快照、之后回 304；
	// Caddy admin 对 /load 一律 500（重载失败）
	_, database := newClusterTestService(t)
	snapshot := signedTestSnapshot(9, "token")
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	snapshot = signTestSnapshot(snapshot, "token")

	requestedVersions := make(chan string, 4)
	var snapshotServed atomic.Int32
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		version := request.URL.Query().Get("since_version")
		requestedVersions <- version
		if version == "0" || snapshotServed.Add(1) == 1 {
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
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusInternalServerError)
	}))
	defer caddyServer.Close()
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir(), CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When：第一轮 Pull —— 主节点回快照，apply 提交但重载失败
	result, pullErr := service.Pull(context.Background())
	if pullErr != nil {
		t.Fatalf("first pull: %v", pullErr)
	}
	if !result.Changed || result.AppliedVersion != 9 {
		t.Fatalf("first result=%#v, want changed apply of version 9", result)
	}
	if v := waitSyncTest(t, requestedVersions); v != "9" {
		t.Fatalf("first request since_version=%q, want 9", v)
	}

	// Then：标记存活过 defer（成功路径不得清空本周期写入的标记）
	var lastSyncError string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&lastSyncError); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastSyncError, "apply_ok_reload_failed") {
		t.Fatalf("first pull last_sync_error=%q, want apply_ok_reload_failed marker", lastSyncError)
	}

	// When：第二轮 Pull —— 增量请求被回 304，标记必须触发 since_version=0 全量重拉
	result, pullErr = service.Pull(context.Background())
	if pullErr != nil {
		t.Fatalf("second pull: %v", pullErr)
	}
	if v := waitSyncTest(t, requestedVersions); v != "9" {
		t.Fatalf("second first request since_version=%q, want 9", v)
	}
	if v := waitSyncTest(t, requestedVersions); v != "0" {
		t.Fatalf("second re-pull since_version=%q, want 0 (reload-failure marker)", v)
	}
	if !result.Changed || result.AppliedVersion != 9 {
		t.Fatalf("second result=%#v, want changed re-apply", result)
	}

	// Then：重载仍失败，标记继续存活（下周期继续补偿）
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&lastSyncError); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastSyncError, "apply_ok_reload_failed") {
		t.Fatalf("second pull last_sync_error=%q, want marker still present", lastSyncError)
	}
}

// R28 A-LOW-2：上报被拒时 200 字节截断可能落在多字节 UTF-8 字符中间，
// 错误信息尾部不得残留半个字符的乱码字节。
func TestSyncService_Report_rejection_body_trims_partial_utf8_tail(t *testing.T) {
	// Given：主节点 403 正文为 300 字节的纯中文
	_, database := newClusterTestService(t)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte(strings.Repeat("中", 100)))
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))

	// When
	err := service.Report(context.Background())

	// Then：正文摘要回退到合法 UTF-8 边界（66 个完整字符 = 198 字节）
	if err == nil {
		t.Fatal("report unexpectedly succeeded")
	}
	want := "body=" + strings.Repeat("中", 66)
	if !strings.HasSuffix(err.Error(), want) {
		t.Fatalf("report error=%q, want suffix %q", err.Error(), want)
	}
	if strings.Contains(err.Error(), "\uFFFD") {
		t.Fatalf("report error=%q contains replacement rune", err.Error())
	}
}

// R30 F1：run 循环周期末的 recordSyncError(nil,nil) 不得清掉本周期 Pull
// 落库的 apply_ok_reload_failed 标记——R29 只修了 Pull defer，run 层第二处
// 清空点让 304 分支的自愈补偿在生产中从未触发。测试必须走真实 run() 循环。
func TestSyncService_run_reloadFailureMarker_survivesCycleEndAndTriggersRepull(t *testing.T) {
	// Given：从节点 applied_version=9；主节点首次快照请求回快照、之后回 304
	//（since_version=0 时始终回快照）；上报端点 200；Caddy 重载一律 500
	_, database := newClusterTestService(t)
	snapshot := signedTestSnapshot(9, "token")
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	snapshot = signTestSnapshot(snapshot, "token")

	requestedVersions := make(chan string, 4)
	var snapshotServed atomic.Bool
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/cluster/nodes/report" {
			response.WriteHeader(http.StatusOK)
			return
		}
		version := request.URL.Query().Get("since_version")
		requestedVersions <- version
		if version == "0" || !snapshotServed.Swap(true) {
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
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusInternalServerError)
	}))
	defer caddyServer.Close()
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir(), CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	// 只跑一个周期就退出循环：Pull → Report → 周期末 recordSyncError 清空点
	service.waitRunDelay = func(context.Context, time.Duration) bool { return false }

	// When：真实 run() 循环执行一个完整周期（apply 成功、重载失败、上报成功）
	service.run(context.Background())

	// Then：周期末清空点未吞掉标记
	var lastSyncError string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&lastSyncError); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastSyncError, "apply_ok_reload_failed") {
		t.Fatalf("after run cycle last_sync_error=%q, want apply_ok_reload_failed marker to survive cycle end", lastSyncError)
	}

	// When：下一周期 Pull —— 增量请求被回 304，标记必须触发 since_version=0 全量重拉
	result, pullErr := service.Pull(context.Background())
	if pullErr != nil {
		t.Fatalf("second-cycle pull: %v", pullErr)
	}
	if v := waitSyncTest(t, requestedVersions); v != "9" {
		t.Fatalf("run cycle request since_version=%q, want 9", v)
	}
	if v := waitSyncTest(t, requestedVersions); v != "9" {
		t.Fatalf("second cycle first request since_version=%q, want 9", v)
	}
	if v := waitSyncTest(t, requestedVersions); v != "0" {
		t.Fatalf("second cycle re-pull since_version=%q, want 0 (reload-failure marker)", v)
	}

	// Then：全量重拉完成补偿重试，重载仍失败，标记继续存活
	if !result.Changed || result.AppliedVersion != 9 {
		t.Fatalf("result=%#v, want changed re-apply of version 9", result)
	}
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&lastSyncError); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastSyncError, "apply_ok_reload_failed") {
		t.Fatalf("after repull last_sync_error=%q, want marker still present", lastSyncError)
	}
}

// R30 F2：传输层错误不得覆盖 apply_ok_reload_failed 标记（标记是全量重拉补偿的
// 唯一触发器）；组合消息保留前缀保证 304 分支 HasPrefix 检测仍命中。终止类错误
// 允许覆盖。recordSyncError(nil,nil) 对标记同样保留（与 run 循环跳过同口径兜底）。
func TestSyncService_recordSyncError_preservesReloadFailureMarkerOnTransportError(t *testing.T) {
	// Given：last_sync_error 携带重载失败标记；本轮拉取遇到传输层错误
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET last_sync_error=?", encodeSyncError("apply_ok_reload_failed: caddy down", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService("http://127.0.0.1:1"))
	transportErr := newSyncFailure(models.SyncErrorCodeTransportError, errors.New("连接主节点失败: 网络不可达"))

	// When：记录传输层错误
	service.recordSyncError(context.Background(), transportErr, nil)

	// Then：组合消息保留标记前缀并附上传输错误详情
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, code := decodeSyncError(stored)
	if !strings.HasPrefix(msg, "apply_ok_reload_failed") || !strings.Contains(msg, "同步拉取失败") || code != models.SyncErrorCodeTransportError {
		t.Fatalf("stored=%q msg=%q code=%q, want composed marker+transport error", stored, msg, code)
	}

	// When：recordSyncError(nil,nil)（周期末成功路径的兜底调用）
	service.recordSyncError(context.Background(), nil, nil)

	// Then：标记仍存活
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, _ = decodeSyncError(stored)
	if !strings.HasPrefix(msg, "apply_ok_reload_failed") {
		t.Fatalf("after empty record last_sync_error=%q, want marker preserved", stored)
	}

	// When：终止类错误（令牌撤销）
	service.recordSyncError(context.Background(), newSyncFailure(models.SyncErrorCodeValidationFailed, errSyncTokenRevoked), nil)

	// Then：允许覆盖标记
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, _ = decodeSyncError(stored)
	if strings.HasPrefix(msg, "apply_ok_reload_failed") || !strings.Contains(msg, "同步拉取失败") {
		t.Fatalf("after terminal error last_sync_error=%q, want overwritten", stored)
	}
}

func TestTruncateValidUTF8Tail(t *testing.T) {
	// Given：67 个三字节字符共 201 字节，截到 200 字节必落在字符中间
	multibyte := []byte(strings.Repeat("中", 67))
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{name: "empty", input: nil, want: ""},
		{name: "ascii unchanged", input: []byte("plain ascii"), want: "plain ascii"},
		{name: "valid multibyte unchanged", input: []byte("中文ok"), want: "中文ok"},
		{name: "mid-character cut trims to boundary", input: multibyte[:200], want: strings.Repeat("中", 66)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When
			got := string(truncateValidUTF8Tail(test.input))
			// Then
			if got != test.want {
				t.Fatalf("truncateValidUTF8Tail()=%q, want %q", got, test.want)
			}
		})
	}
}
