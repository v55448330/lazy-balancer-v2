package services

// 注册确认/状态轮询的 5 连败终止轨道必须把同步循环置 Halted（与令牌撤销
// 同口径）：只清注册态不置 Halted 时，run 循环按未注册态 10s 空转，任务监控
// 呈现 running 而节点状态已是「终止」——两个观测面分叉。Halted 后任务面
// 经 clusterSyncStatusMirror 投射 failed，恢复通道=重新注册（BecomeSlave
// 的 Resume）/提升为主节点，与终止文案指引一致。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/taskengine"
)

// Given 从节点已注册（master_url+registration_id+secret），主节点对状态
// 轮询恒 401（凭证类拒绝）。
// When run 循环连续 5 轮轮询失败推进终止轨道。
// Then IsHalted=true、注册态清空、任务面状态镜像=failed；循环退出不再空转。
func TestSyncService_registrationTerminalTrackHaltsLifecycle(t *testing.T) {
	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, false)
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer master.Close()
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	if _, err := database.Exec(`UPDATE global_config SET master_url=?, registration_id=7, registration_secret='secret', cluster_token='' WHERE id=1`, master.URL); err != nil {
		t.Fatal(err)
	}
	// 等待即时化：终止轨道的判定不依赖真实 10s 节拍。
	service.waitRunDelay = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }

	previous := TaskEngine()
	engine := taskengine.NewEngine(taskengine.Options{StartPaused: true})
	SetTaskEngineForTest(engine)
	SetSyncLifecycleHaltedProbe(service.IsHalted)
	t.Cleanup(func() {
		service.Stop()
		SetTaskEngineForTest(previous)
		SetSyncLifecycleHaltedProbe(nil)
		engine.Stop()
	})
	engine.SetRole(false)

	service.Start()
	deadline := time.Now().Add(5 * time.Second)
	for !service.IsHalted() {
		if time.Now().After(deadline) {
			t.Fatal("5 连败终止轨道未把同步循环置 Halted（任务面 running 与节点终止态分叉）")
		}
		time.Sleep(5 * time.Millisecond)
	}
	var secret, token string
	if err := database.QueryRow(`SELECT COALESCE(registration_secret,''), COALESCE(cluster_token,'') FROM global_config WHERE id=1`).Scan(&secret, &token); err != nil {
		t.Fatal(err)
	}
	if secret != "" || token != "" {
		t.Fatalf("终止后注册态未清空: secret=%q token=%q", secret, token)
	}
	if got := clusterSyncStatusMirror(); got != string(TaskStatusFailed) {
		t.Fatalf("终止后任务面状态=%q, want failed（Halted 投射）", got)
	}
}

// Given 从节点 confirm 连续失败 4 次（未达上限）。
// When 第 5 次失败。
// Then 未达上限不得提前 Halted；达上限即 Halted（终止轨道与令牌撤销同口径）。
func TestSyncService_bumpRegistrationConfirmFailure_haltsOnlyAtLimit(t *testing.T) {
	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, false)
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	for i := 1; i < registrationConfirmMaxFailures; i++ {
		service.bumpRegistrationConfirmFailure(context.Background(), "confirm 端点返回 401")
		if service.IsHalted() {
			t.Fatalf("第 %d 次失败（未达上限）不得 Halted", i)
		}
	}
	service.bumpRegistrationConfirmFailure(context.Background(), "confirm 端点返回 401")
	if !service.IsHalted() {
		t.Fatal("达到 5 连败上限必须 Halted（与令牌撤销终止同口径）")
	}
}
