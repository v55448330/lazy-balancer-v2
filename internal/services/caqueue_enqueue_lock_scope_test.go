package services

import (
	"context"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// EnqueueIfActive 的全局锁不得跨越 provider 解析与失败归因：m.mu 是队列全局锁，
// IsJobActive/CancelJob/HasRunningJobForRule（删除/禁用规则的 HTTP 快路径与
// 删除排空）都会被它阻塞。旧实现用 defer m.mu.Unlock() 把 transition 闭包、
// loadCAProvider（多次查询）、跟随默认归一与 failJob（退避窗口读 + 状态写 +
// 任务日志文件 IO + 操作审计写）整段包进临界区——CA 故障或 SQLITE_BUSY 重试时
// 这些快路径出现秒级卡顿。
func TestCAQueueManager_EnqueueIfActive_doesNotHoldGlobalLockAcrossProviderResolve(t *testing.T) {
	newClusterTestService(t)
	const providerDelay = 500 * time.Millisecond
	manager, jobID := newStubbedQueueManager(t)

	var once sync.Once
	entered := make(chan struct{})
	manager.beforeProviderEnqueue = func() {
		once.Do(func() { close(entered) })
		time.Sleep(providerDelay)
	}

	enqueueDone := make(chan error, 1)
	go func() {
		_, _, err := manager.EnqueueIfActive(1, jobID, "lb_queue_lock_scope", "lock-scope.example.com",
			func() (int, bool, error) { return jobID, true, nil })
		enqueueDone <- err
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("provider 解析前的测试缝未在 5s 内进入")
	}

	// When：解析仍在进行（500ms），另一 goroutine 走全局锁快路径
	start := time.Now()
	manager.IsJobActive(jobID + 1)
	elapsed := time.Since(start)

	// Then：快路径必须立即返回——持锁做 provider IO 时这里会等到 ≥500ms。
	if elapsed > 100*time.Millisecond {
		t.Fatalf("IsJobActive 耗时 %s（>100ms），EnqueueIfActive 仍持全局锁做 provider 解析", elapsed)
	}
	if err := <-enqueueDone; err != nil {
		t.Fatalf("enqueue err=%v, want nil", err)
	}
}

// 预留必须在入队落定后立即释放（否则该 jobID 永久视为在途，重试/恢复全部 409）。
func TestCAQueueManager_EnqueueIfActive_releasesReservation(t *testing.T) {
	newClusterTestService(t)
	manager, jobID := newStubbedQueueManager(t)

	if _, changed, err := manager.EnqueueIfActive(1, jobID, "lb_queue_lock_scope", "lock-scope.example.com",
		func() (int, bool, error) { return jobID, true, nil }); err != nil || !changed {
		t.Fatalf("enqueue changed=%v err=%v, want true/nil", changed, err)
	}
	manager.mu.Lock()
	_, reserved := manager.reservedJobs[jobID]
	manager.mu.Unlock()
	if reserved {
		t.Fatal("入队完成后仍在途预留未释放")
	}
}

// provider 解析失败（已定局业务失败）同样必须释放预留：否则 failJob 落定的
// failed 行会永久占住在途保护，手动重试恒 409。
func TestCAQueueManager_EnqueueIfActive_releasesReservationOnProviderFailure(t *testing.T) {
	newClusterTestService(t)
	manager, _ := newStubbedQueueManager(t)
	// 「存在但已禁用」的显式选择：loadCAProvider 对已删除 ID 会回退到首个启用
	// 提供商（历史延续），只有已禁用才是显性失败，因此这里造一个禁用行。
	providerResult, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES ('disabled-ca','letsencrypt','https://invalid.example/directory','{}',1,0,0)`)
	if err != nil {
		t.Fatalf("seed disabled provider: %v", err)
	}
	disabledID64, err := providerResult.LastInsertId()
	if err != nil {
		t.Fatalf("read provider id: %v", err)
	}
	disabledID := int(disabledID64)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,ca_provider_id)
		VALUES ('lb_queue_lock_missing','lb_queue_lock_missing','missing.example.com','http',8080,1,1,'acme_dns',?)`, disabledID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES ('lb_queue_lock_missing','missing.example.com','queued',?)`, disabledID)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	failJobID64, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	failJobID := int(failJobID64)

	_, changed, enqueueErr := manager.EnqueueIfActive(disabledID, failJobID, "lb_queue_lock_missing", "missing.example.com",
		func() (int, bool, error) { return failJobID, true, nil })
	if enqueueErr == nil {
		t.Fatal("provider 不存在时必须返回错误")
	}
	if !changed {
		t.Fatal("changed=false, want true（状态迁移已发生）")
	}
	manager.mu.Lock()
	_, reserved := manager.reservedJobs[failJobID]
	manager.mu.Unlock()
	if reserved {
		t.Fatal("provider 解析失败路径未释放在途预留")
	}
}

// newStubbedQueueManager 直构一个不启动 loop、执行体为 no-op 的队列管理器：
// 本组用例只关心锁范围，不得真实发起 ACME 流程。
func newStubbedQueueManager(t *testing.T) (*CAQueueManager, int) {
	t.Helper()
	provider := models.CAProvider{ID: 1, Name: "stub", Provider: ProviderLetsEncrypt, Enabled: true, MaxConcurrent: 1}
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	queue := newCAQueue(provider, func() error { return nil }, t.TempDir())
	queue.executeFn = func(context.Context, queueItem, models.CAProvider) error { return nil }
	manager.queues[provider.ID] = queue
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES ('lb_queue_lock_scope','lock-scope.example.com','queued',1)`)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID64, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	return manager, int(jobID64)
}
