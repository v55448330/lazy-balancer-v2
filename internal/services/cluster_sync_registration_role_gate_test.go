package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/config"
)

// 注册/确认簿记（cluster_token/registration_secret/registration_id/
// registration_confirm_failures）只能在从节点语境落库。Promote 提交会一次性
// 清空这些列，但从端 daemon 的 Stop 取消是异步的，已进入执行的写语句可能在
// 提交后落库——没有角色谓词就会把旧主凭据与明文注册密钥写回新主节点，而全仓
// 没有第二处清空点（只剩降级/导入）。

func TestSyncService_registrationBookkeeping_roleGate(t *testing.T) {
	_, database := newClusterTestService(t)
	var confirmHits int
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/status"):
			_, _ = response.Write([]byte(`{"data":{"status":"approved","cluster_token":"new-token"}}`))
		case strings.HasSuffix(request.URL.Path, "/registration/confirm"):
			confirmHits++
			_, _ = response.Write([]byte(`{"message":"ok"}`))
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer master.Close()
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	// seed 模拟「升主/降级提交前已存在注册态」的翻转窗口：从端写入仍在途。
	seed := func(isMaster int) {
		t.Helper()
		if _, err := database.Exec(`UPDATE global_config SET is_master=?, master_url=?, registration_id=7,
			registration_secret='leftover-secret', cluster_token='', registration_confirm_failures=4 WHERE id=1`, isMaster, master.URL); err != nil {
			t.Fatalf("seed registration bookkeeping: %v", err)
		}
	}
	read := func() (int, string, string) {
		t.Helper()
		var failures int
		var secret, token string
		if err := database.QueryRow(`SELECT COALESCE(registration_confirm_failures,0),
			COALESCE(registration_secret,''), COALESCE(cluster_token,'') FROM global_config WHERE id=1`).Scan(&failures, &secret, &token); err != nil {
			t.Fatalf("read registration bookkeeping: %v", err)
		}
		return failures, secret, token
	}

	// Given：节点已升主（Promote 清空注册列），但在途的从端轮询晚到
	seed(1)

	// When：状态轮询拿到 approved 令牌
	service.pollRegistration(context.Background())

	// Then：主节点不得被写回旧主令牌，也不得继续确认流程
	if failures, secret, token := read(); failures != 4 || secret != "leftover-secret" || token != "" {
		t.Fatalf("master bookkeeping=(failures=%d secret=%q token=%q), want unchanged seed", failures, secret, token)
	}
	if confirmHits != 0 {
		t.Fatalf("master confirm requests=%d, want 0（令牌未落库即不得确认）", confirmHits)
	}

	// When：在途的 confirm 成功/失败回写晚到
	service.redeemRegistrationConfirm(context.Background(), master.URL, "old-token")
	service.bumpRegistrationConfirmFailure(context.Background(), "confirm 端点返回 500")
	service.resetRegistrationConfirmFailure(context.Background())

	// Then：注册密钥、失败计数与令牌均不得被旧从端改写
	if failures, secret, token := read(); failures != 4 || secret != "leftover-secret" || token != "" {
		t.Fatalf("master bookkeeping after confirm callbacks=(failures=%d secret=%q token=%q), want unchanged seed", failures, secret, token)
	}

	// When：节点降级为从节点后同一条链路执行
	seed(0)
	confirmHits = 0
	service.pollRegistration(context.Background())

	// Then：从端语义不回归——令牌落库、确认成功清密钥、失败计数复位
	failures, secret, token := read()
	if token != "new-token" {
		t.Fatalf("slave cluster_token=%q, want new-token", token)
	}
	if secret != "" {
		t.Fatalf("slave registration_secret=%q, want cleared after confirm", secret)
	}
	if failures != 0 {
		t.Fatalf("slave registration_confirm_failures=%d, want reset 0", failures)
	}
	if confirmHits != 1 {
		t.Fatalf("slave confirm requests=%d, want 1", confirmHits)
	}
}

func TestSyncService_bumpRegistrationConfirmFailure_slaveStillCounts(t *testing.T) {
	// 反向断言：角色谓词不得让从端的 5 连败终止轨道失效。
	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, false)
	if _, err := database.Exec(`UPDATE global_config SET registration_confirm_failures=4,
		cluster_token='approved-token', registration_secret='pending-secret' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	service.bumpRegistrationConfirmFailure(context.Background(), "confirm 端点返回 401")

	var failures int
	var secret, token string
	if err := database.QueryRow(`SELECT COALESCE(registration_confirm_failures,0),
		COALESCE(registration_secret,''), COALESCE(cluster_token,'') FROM global_config WHERE id=1`).Scan(&failures, &secret, &token); err != nil {
		t.Fatal(err)
	}
	if failures != 0 || secret != "" || token != "" {
		t.Fatalf("slave terminal track=(failures=%d secret=%q token=%q), want cleared", failures, secret, token)
	}
}
