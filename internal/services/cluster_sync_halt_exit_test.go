package services

// 注册终止轨道置 Halted 后 run 循环必须退出（与 Pull 终止轨道同构）：
// Halted 而 run 仍存活时 cancel/done 不清空，Resume 的 <-done 前提永不成立
// ——重新注册（BecomeSlave→Resume）死锁，只能重启进程。本组钉测走真实
// goroutine 形态（Start 启动、真实等待、Resume 真实复活），不手工 Store
// Halted、不用恒真 waitRunDelay 绕过终止形态。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
)

// Given 从节点已注册（master_url+registration_id+secret），主节点对状态
// 轮询恒 401。
// When run 循环连续 5 轮轮询失败推进终止轨道（真实节拍）。
// Then Halted 且 run goroutine 退出（cancel/done 清空、状态轮询不再增长），
// Resume 不阻塞并拉起新循环进入注册轮询。
func TestSyncService_registrationHaltExitsRunLoopAndResumeUnblocks(t *testing.T) {
	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, false)
	var statusHits atomic.Int32
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusHits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer master.Close()
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	t.Cleanup(service.Stop)
	if _, err := database.Exec(`UPDATE global_config SET master_url=?, registration_id=7, registration_secret='secret', cluster_token='' WHERE id=1`, master.URL); err != nil {
		t.Fatal(err)
	}

	// When：真实节拍推进 5 连败终止轨道（轮询分支 delay=10s，测试即时化等待）。
	service.waitRunDelay = func(ctx context.Context, _ time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Millisecond):
			return true
		}
	}
	service.Start()
	deadline := time.Now().Add(5 * time.Second)
	for !service.IsHalted() {
		if time.Now().After(deadline) {
			t.Fatal("5 连败终止轨道未置 Halted")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Then：Halted ⇒ run 退出（finishRun 清 cancel/done）。
	deadline = time.Now().Add(3 * time.Second)
	for {
		service.mu.Lock()
		exited := service.cancel == nil && service.done == nil
		service.mu.Unlock()
		if exited {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("置 Halted 后 run 未退出：cancel/done 未清空，Resume 的 <-done 前提不成立（重新注册死锁）")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// run 已退出：状态轮询不得再增长（无 10s 空转）。
	hitsAtExit := statusHits.Load()
	time.Sleep(50 * time.Millisecond)
	if got := statusHits.Load(); got != hitsAtExit {
		t.Fatalf("Halted 后状态轮询仍在增长 %d→%d（run 未真正退出）", hitsAtExit, got)
	}

	// Then：重新注册（终止轨道已清注册态，BecomeSlave 会重新落 master_url/
	// secret）后 Resume 不阻塞并拉起新循环进入注册轮询——真实恢复通道。
	if _, err := database.Exec(`UPDATE global_config SET master_url=?, registration_id=7, registration_secret='secret', cluster_token='' WHERE id=1`, master.URL); err != nil {
		t.Fatal(err)
	}
	resumed := make(chan struct{})
	go func() {
		service.Resume()
		close(resumed)
	}()
	select {
	case <-resumed:
	case <-time.After(3 * time.Second):
		t.Fatal("Halted 后 Resume 阻塞（<-done 等待未退出的 run）")
	}
	deadline = time.Now().Add(3 * time.Second)
	for statusHits.Load() <= hitsAtExit {
		if time.Now().After(deadline) {
			t.Fatal("Resume 后新循环未重新进入注册轮询")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Given 从节点令牌已落库、注册确认尚未成功（残留态），主节点对 confirm
// 恒 401。
// When retryPendingRegistrationConfirm 轨道连续 5 轮失败推进终止。
// Then 与状态轮询轨道同构：Halted 且 run 退出，Resume 不阻塞。
func TestSyncService_confirmRetryHaltExitsRunLoopAndResumeUnblocks(t *testing.T) {
	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, false)
	var confirmHits atomic.Int32
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		confirmHits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer master.Close()
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	t.Cleanup(service.Stop)
	if _, err := database.Exec(`UPDATE global_config SET master_url=?, registration_id=7, registration_secret='secret', cluster_token='stale-token' WHERE id=1`, master.URL); err != nil {
		t.Fatal(err)
	}
	service.waitRunDelay = func(ctx context.Context, _ time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Millisecond):
			return true
		}
	}
	service.Start()
	deadline := time.Now().Add(5 * time.Second)
	for !service.IsHalted() {
		if time.Now().After(deadline) {
			t.Fatal("confirm 重试 5 连败未置 Halted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		service.mu.Lock()
		exited := service.cancel == nil && service.done == nil
		service.mu.Unlock()
		if exited {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("confirm 终止轨道置 Halted 后 run 未退出（Resume 死锁形态）")
		}
		time.Sleep(5 * time.Millisecond)
	}
	resumed := make(chan struct{})
	go func() {
		service.Resume()
		close(resumed)
	}()
	select {
	case <-resumed:
	case <-time.After(3 * time.Second):
		t.Fatal("confirm 终止后 Resume 阻塞")
	}
}
