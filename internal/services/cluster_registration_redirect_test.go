package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"lazy-balancer-v2/internal/config"
)

// 注册链路（状态轮询 / 确认）与注册请求本身必须同口径：3xx 是**失败**
// 而不是成功。两者此前只拦 >=400，302/307 落进成功分支——确认路径据此
// 复位失败计数并清空 registration_secret（与「确认成功才清密钥」的契约相反），
// 状态轮询把重定向页当 JSON 解析后静默轮询。
//
// 主节点启用 HTTPS 后残留 3xx 说明主节点地址形态需人工修正；处置口径与
// RegisterWithMaster 一致：按可重试失败上报可行动文案、**不清任何注册态**，
// 修正地址后下一次 200 正常走完成链路。

const registrationRedirectLocation = "https://master.example.invalid/admin"

// seedPendingRegistration 置为「已注册待确认」的从节点状态（密钥未消费）。
func seedPendingRegistration(t *testing.T, masterURL, token string) *SyncService {
	t.Helper()
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET is_master=0, master_url=?, registration_id=7,
		registration_secret='pending-secret', cluster_token=?, registration_confirm_failures=0 WHERE id=1`,
		masterURL, token); err != nil {
		t.Fatalf("seed pending registration: %v", err)
	}
	return NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
}

func readRegistrationState(t *testing.T, service *SyncService) (secret, token, syncErrorMessage string) {
	t.Helper()
	var stored string
	if err := service.db.QueryRow(`SELECT COALESCE(registration_secret,''), COALESCE(cluster_token,''), COALESCE(last_sync_error,'') FROM global_config WHERE id=1`).
		Scan(&secret, &token, &stored); err != nil {
		t.Fatalf("read registration state: %v", err)
	}
	syncErrorMessage, _ = decodeSyncError(stored)
	return secret, token, syncErrorMessage
}

func TestSyncService_redeemRegistrationConfirm_redirectIsFailureAndKeepsSecret(t *testing.T) {
	var redirecting atomic.Bool
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/cluster/registration/confirm" {
			http.NotFound(response, request)
			return
		}
		if redirecting.Load() {
			response.Header().Set("Location", registrationRedirectLocation)
			response.WriteHeader(http.StatusFound)
			return
		}
		response.WriteHeader(http.StatusOK)
	}))
	defer master.Close()
	service := seedPendingRegistration(t, master.URL, "lb_cluster_token")

	// When：confirm 端点返回 302（跨主机重定向，不被同主机升级重放消费）
	redirecting.Store(true)
	service.redeemRegistrationConfirm(context.Background(), master.URL, "lb_cluster_token")

	// Then：3xx 不得按成功处理——注册密钥保留、错误可观测
	secret, token, syncErrorMessage := readRegistrationState(t, service)
	if secret != "pending-secret" {
		t.Fatalf("confirm 3xx 后 registration_secret=%q, want 保留（3xx 不是确认成功）", secret)
	}
	if token != "lb_cluster_token" {
		t.Fatalf("confirm 3xx 后 cluster_token=%q, want 不变", token)
	}
	if !strings.Contains(syncErrorMessage, "重定向") {
		t.Fatalf("last_sync_error=%q, want 携带重定向可行动文案", syncErrorMessage)
	}

	// When：地址形态修正后 confirm 返回 200
	redirecting.Store(false)
	service.redeemRegistrationConfirm(context.Background(), master.URL, "lb_cluster_token")

	// Then：正常链路不回归——确认成功即清空本地注册密钥
	if secret, _, _ = readRegistrationState(t, service); secret != "" {
		t.Fatalf("confirm 成功后 registration_secret=%q, want 清空", secret)
	}
}

func TestSyncService_redeemRegistrationConfirm_307IsFailureToo(t *testing.T) {
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Location", registrationRedirectLocation)
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer master.Close()
	service := seedPendingRegistration(t, master.URL, "lb_cluster_token")

	service.redeemRegistrationConfirm(context.Background(), master.URL, "lb_cluster_token")

	secret, _, syncErrorMessage := readRegistrationState(t, service)
	if secret != "pending-secret" {
		t.Fatalf("confirm 307 后 registration_secret=%q, want 保留", secret)
	}
	if !strings.Contains(syncErrorMessage, "307") {
		t.Fatalf("last_sync_error=%q, want 携带 HTTP 307", syncErrorMessage)
	}
}

func TestSyncService_pollRegistration_redirectKeepsPendingRegistration(t *testing.T) {
	var redirecting atomic.Bool
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/api/v1/cluster/register/7/status":
			if redirecting.Load() {
				response.Header().Set("Location", registrationRedirectLocation)
				response.WriteHeader(http.StatusFound)
				return
			}
			if request.Header.Get("X-Registration-Secret") != "pending-secret" {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"code":0,"data":{"status":"approved","cluster_token":"lb_cluster_token"}}`))
		case request.URL.Path == "/api/v1/cluster/registration/confirm":
			response.WriteHeader(http.StatusOK)
		default:
			http.NotFound(response, request)
		}
	}))
	defer master.Close()
	service := seedPendingRegistration(t, master.URL, "")

	// When：状态查询返回 302
	redirecting.Store(true)
	service.pollRegistration(context.Background())

	// Then：3xx 不得落进「approved 令牌入账 + confirm + 清密钥」成功链
	secret, token, syncErrorMessage := readRegistrationState(t, service)
	if secret != "pending-secret" {
		t.Fatalf("轮询 3xx 后 registration_secret=%q, want 保留", secret)
	}
	if token != "" {
		t.Fatalf("轮询 3xx 后 cluster_token=%q, want 空（重定向页不是审批响应）", token)
	}
	if !strings.Contains(syncErrorMessage, "重定向") {
		t.Fatalf("last_sync_error=%q, want 携带重定向可行动文案", syncErrorMessage)
	}

	// When：地址修正后状态查询返回 200 approved
	redirecting.Store(false)
	service.pollRegistration(context.Background())

	// Then：正常链路不回归——令牌入账、确认成功、密钥清空
	secret, token, _ = readRegistrationState(t, service)
	if token != "lb_cluster_token" {
		t.Fatalf("approved 后 cluster_token=%q, want lb_cluster_token", token)
	}
	if secret != "" {
		t.Fatalf("approved 后 registration_secret=%q, want 清空", secret)
	}
}
