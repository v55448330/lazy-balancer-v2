package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// R33 F-2：主节点 5xx 响应体（此前 ≤4096B）嵌入错误消息会击穿 R31 的 512B
// 有界设计，并经 Report 随 60s 周期持续膨胀主节点库。修复后 body 截断至
// 200B 并回退到合法 UTF-8 边界，last_sync_error 必须始终 < 512B 且无乱码。
func TestSyncService_run_fiveHundredHugeBody_lastSyncErrorBounded(t *testing.T) {
	// Given：主节点快照端点返回 500；body 402B（199 个 'A' + 3B 中文字符被
	// 字节截断 + 200 个 'B'），超过 200B 截断线且切断多字节字符尾部
	_, database := newClusterTestService(t)
	master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/cluster/sync/snapshot":
			response.WriteHeader(http.StatusInternalServerError)
			_, _ = response.Write([]byte(strings.Repeat("A", 199) + "中" + strings.Repeat("B", 200)))
		default:
			response.WriteHeader(http.StatusOK)
		}
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))
	service.waitRunDelay = func(context.Context, time.Duration) bool { return false }

	// When：单个周期内 Pull 遭遇 5xx
	service.run(context.Background())

	// Then：last_sync_error 有界（<512B）、UTF-8 合法、body 截断生效
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) >= 512 {
		t.Fatalf("last_sync_error=%d bytes, want bounded under 512", len(stored))
	}
	if !utf8.ValidString(stored) {
		t.Fatalf("last_sync_error is not valid UTF-8: %q", stored)
	}
	msg, code := decodeSyncError(stored)
	if !strings.Contains(msg, "主节点快照请求失败(500)") {
		t.Fatalf("message=%q, want 5xx failure message", msg)
	}
	if code != models.SyncErrorCodeTransportError {
		t.Fatalf("code=%q, want transport_error", code)
	}
	if strings.Contains(msg, "B") {
		t.Fatalf("message=%q contains post-truncation body bytes, want body truncated at 200B", msg)
	}
	if strings.Contains(msg, "中") {
		t.Fatalf("message=%q contains truncated multi-byte char tail, want valid UTF-8 boundary rollback", msg)
	}
}

// R33 F-1：bumpRegistrationConfirmFailure 的终止类写点改经 combineOrReplaceSyncError
// 落库（语义与直写等价：ValidationFailed 属终止类，helper 直接覆盖重载失败标记），
// 闭合「所有写点经 helper」不变式。达到上限后停止自动重试并清理注册状态。
func TestSyncService_bumpRegistrationConfirmFailure_terminalWriteViaHelper(t *testing.T) {
	// Given：已连续失败 4 次（本次为第 5 次触发上限）；重载失败标记已存在
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET registration_confirm_failures=4, cluster_token='approved-token', last_sync_error=? WHERE id=1",
		encodeSyncError("apply_ok_reload_failed: caddy down", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	// When：第 5 次 confirm 失败
	service.bumpRegistrationConfirmFailure(context.Background(), "approved-token", "confirm 端点返回 500")

	// Then：终止类错误经 helper 覆盖标记（与直写语义等价），注册状态清理
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	msg, code := decodeSyncError(stored)
	if strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) {
		t.Fatalf("message=%q, want terminal failure overwriting reload marker", msg)
	}
	if !strings.Contains(msg, "集群注册确认连续失败 5 次") {
		t.Fatalf("message=%q, want confirm failure threshold message", msg)
	}
	if code != models.SyncErrorCodeValidationFailed {
		t.Fatalf("code=%q, want validation_failed", code)
	}
	var failures int
	var regSecret, clusterToken string
	if err := database.QueryRow("SELECT COALESCE(registration_confirm_failures,0), COALESCE(registration_secret,''), COALESCE(cluster_token,'') FROM global_config WHERE id=1").Scan(&failures, &regSecret, &clusterToken); err != nil {
		t.Fatal(err)
	}
	if failures != 0 {
		t.Fatalf("registration_confirm_failures=%d, want reset 0", failures)
	}
	if regSecret != "" {
		t.Fatalf("registration_secret=%q, want cleared", regSecret)
	}
	if clusterToken != "" {
		t.Fatalf("cluster_token=%q, want cleared", clusterToken)
	}
}

func TestWafBundleSyncDetail_reportsPerComponentOutcome(t *testing.T) {
	bundle := &WafFileBundle{CRSVersion: "v4.28.0", IP2RegionTag: "v3.17.0"}
	tests := []struct {
		name                   string
		crsChanged, xdbChanged bool
		want                   string
	}{
		{"both updated", true, true, "CRS 规则已更新至 v4.28.0；IP2Region数据库已更新至 v3.17.0"},
		{"only crs updated", true, false, "CRS 规则已更新至 v4.28.0；IP2Region数据库已是最新"},
		{"only xdb updated", false, true, "CRS 规则已是最新；IP2Region数据库已更新至 v3.17.0"},
		{"version missing falls back to bare update", true, false, "CRS 规则已更新；IP2Region数据库已是最新"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bundle
			if tt.name == "version missing falls back to bare update" {
				b = &WafFileBundle{}
			}
			if got := wafBundleSyncDetail(b, tt.crsChanged, tt.xdbChanged); got != tt.want {
				t.Fatalf("detail=%q, want %q", got, tt.want)
			}
		})
	}
}
