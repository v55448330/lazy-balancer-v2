package services

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// —— B1a：CA 队列自建泵退役（task-engine 标准 v2.2 违规项 #1）——
// 派发泵由 cert-issuance daemon 的 RunTicker 承载：Manager.DispatchOnce(ctx)
// 遍历全部 provider 队列执行一轮派发；入队经 Manager.Wake() 唤醒守护；
// Manager.StatusSnapshot() 提供只读投影。队列不再持有 stopCh/wakeCh/loopDone
// 自建泵（go q.loop() 已删除）。

func TestCAQueueManager_DispatchOnce_dispatchesPendingAcrossQueues(t *testing.T) {
	useCertSweepTickTestEnv(t)
	seedCAProviderBounds(t, 21, 2, 0)
	seedCAProviderBounds(t, 22, 2, 0)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id)
		VALUES (77,'lb_dispatch_a','dispatch-a.example.com','queued',21),
		       (78,'lb_dispatch_b','dispatch-b.example.com','queued',22)`); err != nil {
		t.Fatalf("seed dispatch jobs: %v", err)
	}

	m := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	startedA := make(chan struct{})
	startedB := make(chan struct{})
	m.mu.Lock()
	m.enqueueResolvedLocked(models.CAProvider{ID: 21, Name: "p21", Provider: "letsencrypt", MaxConcurrent: 2}, 77, "lb_dispatch_a", "dispatch-a.example.com")
	m.enqueueResolvedLocked(models.CAProvider{ID: 22, Name: "p22", Provider: "letsencrypt", MaxConcurrent: 2}, 78, "lb_dispatch_b", "dispatch-b.example.com")
	m.mu.Unlock()
	m.queues[21].executeFn = func(context.Context, queueItem, models.CAProvider) error { close(startedA); return nil }
	m.queues[22].executeFn = func(context.Context, queueItem, models.CAProvider) error { close(startedB); return nil }

	// 单轮 DispatchOnce 必须遍历全部 provider 队列各派发一次（自建泵退役后
	// 的唯一派发入口）。执行体经 go execute 异步启动：有界等待启动信号。
	m.DispatchOnce(context.Background())
	waitStarted := func(ch <-chan struct{}, provider string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("DispatchOnce 未派发 provider %s 的 pending 任务", provider)
		}
	}
	waitStarted(startedA, "21")
	waitStarted(startedB, "22")
}

func TestCAQueueManager_DispatchOnce_skipsAfterContextCancel(t *testing.T) {
	useCertSweepTickTestEnv(t)
	seedCAProviderBounds(t, 23, 2, 0)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id)
		VALUES (79,'lb_dispatch_c','dispatch-c.example.com','queued',23)`); err != nil {
		t.Fatalf("seed dispatch job: %v", err)
	}

	m := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	var executed atomic.Int32
	m.mu.Lock()
	m.enqueueResolvedLocked(models.CAProvider{ID: 23, Name: "p23", Provider: "letsencrypt", MaxConcurrent: 2}, 79, "lb_dispatch_c", "dispatch-c.example.com")
	m.mu.Unlock()
	m.queues[23].executeFn = func(context.Context, queueItem, models.CAProvider) error { executed.Add(1); return nil }

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.DispatchOnce(ctx)
	if got := executed.Load(); got != 0 {
		t.Fatalf("ctx 已取消仍派发 %d 次, want 0（停泵后不得新起签发执行）", got)
	}
}

func TestCAQueueManager_Wake_signalsDaemonChannelAndCoalesces(t *testing.T) {
	ResetCAQueueManagerForTest()
	InitCAQueueManager(nil)
	t.Cleanup(ResetCAQueueManagerForTest)
	m := GetCAQueueManager()

	select {
	case <-m.WakeCh():
		t.Fatal("初始唤醒通道不得有信号")
	default:
	}
	m.Wake()
	select {
	case <-m.WakeCh():
	default:
		t.Fatal("Wake 未向守护唤醒通道投递")
	}
	// 合并：缓冲 1，二次投递不阻塞也不堆积。
	m.Wake()
	m.Wake()
	select {
	case <-m.WakeCh():
	default:
		t.Fatal("合并后的待消费唤醒缺失")
	}
	select {
	case <-m.WakeCh():
		t.Fatal("唤醒应合并为单一信号，不得堆积")
	default:
	}
}

func TestCAQueue_enqueue_wakesDispatchDaemon(t *testing.T) {
	// 入队不再操作队列自建通道（已删），改为经 Manager.Wake() 唤醒守护派发。
	ResetCAQueueManagerForTest()
	InitCAQueueManager(nil)
	t.Cleanup(ResetCAQueueManagerForTest)
	m := GetCAQueueManager()

	m.mu.Lock()
	m.enqueueResolvedLocked(models.CAProvider{ID: 5, MaxConcurrent: 1}, 42, "lb_wake", "example.com")
	m.mu.Unlock()

	select {
	case <-m.WakeCh():
	default:
		t.Fatal("入队未唤醒派发守护")
	}
}

func TestCAQueueManager_StatusSnapshot_projectsCounts(t *testing.T) {
	m := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	q := newCAQueue(models.CAProvider{ID: 9, Name: "p9", Provider: "letsencrypt"}, nil)
	q.manager = m
	q.pending = []queueItem{{jobID: 1}, {jobID: 2}}
	q.running = 1
	m.mu.Lock()
	m.queues[9] = q
	m.mu.Unlock()

	snap := m.StatusSnapshot()
	if !snap.Active {
		t.Fatal("Active=false, want true（manager 活动态必须投影）")
	}
	if snap.Pending != 2 || snap.Running != 1 {
		t.Fatalf("totals pending=%d running=%d, want 2/1", snap.Pending, snap.Running)
	}
	if len(snap.Providers) != 1 {
		t.Fatalf("providers=%d, want 1", len(snap.Providers))
	}
	p := snap.Providers[0]
	if p.ProviderID != 9 || p.ProviderName != "p9" || p.Pending != 2 || p.Running != 1 {
		t.Fatalf("provider projection=%+v, want id=9 name=p9 pending=2 running=1", p)
	}

	// 只读：投影不得改写队列内存态。
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) != 2 || q.running != 1 {
		t.Fatalf("snapshot mutated queue state: pending=%d running=%d", len(q.pending), q.running)
	}
}

// 守护停泵等待：RunTicker 退出后由 stopCertIssuanceLifecycle 链等待在途执行
// 完成——q.wait 只等 executions（自建泵 loopDone 已删），有界返回。
func TestCAQueueManager_stopWaitsOnlyExecutions(t *testing.T) {
	oldTimeout := caQueueDrainTimeout
	caQueueDrainTimeout = 500 * time.Millisecond
	t.Cleanup(func() { caQueueDrainTimeout = oldTimeout })

	finished := make(chan struct{})
	queue := newCAQueue(models.CAProvider{ID: 1, MaxConcurrent: 1}, nil)
	queue.executions.Add(1)
	go func() {
		defer queue.executions.Done()
		close(finished)
	}()
	manager := &CAQueueManager{queues: map[int]*caQueue{1: queue}, active: true}
	queues := manager.stopQueuesLocked()
	if len(queues) != 1 {
		t.Fatalf("stopped queues=%d, want 1", len(queues))
	}
	// 无 loopDone 可等：q.wait 只剩在途执行的有界等待。
	if !queue.wait(time.Now().Add(caQueueDrainTimeout)) {
		t.Fatal("queue.wait timed out, want bounded return after execution exit")
	}
	select {
	case <-finished:
	default:
		t.Fatal("wait returned before execution finished")
	}
}
