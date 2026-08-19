package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// CAQueueManager schedules ACME issuance jobs per CA provider.
type CAQueueManager struct {
	mu                  sync.Mutex
	queues              map[int]*caQueue
	retiredQueues       []retiredCAQueue
	zombieJobs          map[int]struct{}
	reloader            func() error
	active              bool
	blockedRules        map[string]map[RuleBlockToken]struct{}
	nextBlockToken      RuleBlockToken
	compensationCtx     context.Context
	compensationCancel  context.CancelFunc
	compensationWG      sync.WaitGroup
	compensationBackoff func(int) time.Duration
	compensationTimeout time.Duration
	compensationDrain   func(context.Context, string) error
	compensationRestore func(context.Context, CertJobsSnapshot) error
	compensationRequeue func(context.Context, CertJobsSnapshot, *CAQueueManager) error
	dataDir             string
	beforeEnqueue       func()
	beforeActiveEnqueue func()
}

type RuleBlockToken uint64

// retiredCAQueue 登记 PauseAndDrain 超时退役的队列。retiredAt 供惰性摘除兜底
// （R45 发现3）：滞行执行越过 caExecutionTimeout+10min 宽松余量仍未退出只可能是
// 僵尸（执行上限 ctx 早已触发），超时摘除并记日志；摘除时在途 jobID 迁入
// zombieJobs 维持在途保护直到执行退出（R46 A-F2），R44-2 双执行防护不回退。
type retiredCAQueue struct {
	queue     *caQueue
	retiredAt time.Time
}

type RuleDeletionCompensation struct {
	RuleID   string
	Token    RuleBlockToken
	Snapshot CertJobsSnapshot
	Drain    func(context.Context) error
}

var (
	caQueueManager     *CAQueueManager
	caQueueManagerOnce sync.Once
)

// caExecutionTimeout 必须覆盖签发器内部最坏耗时预算
// （注册 30s + DNS 传播 5m + 验证 10m + 订单就绪 3m + 订单有效 5m ≈ 23.5m）
const caExecutionTimeout = 30 * time.Minute

// caQueueDrainTimeout 上限 PauseAndDrain 等待队列执行退出；issuer 异常不响应
// ctx 取消时等待永不返回，进程 Stop 会被永久挂起（R43 A-2，与 CancelJob 30s 同口径）。
// var 而非 const：测试需要缩短超时以覆盖超时路径，生产代码不得改写。
var caQueueDrainTimeout = 30 * time.Second

// InitCAQueueManager initializes the singleton queue manager with the given
// Caddy reloader. It must be called once during application startup before
// GetCAQueueManager is used.
func InitCAQueueManager(reloader func() error, dataDir ...string) {
	caQueueManagerOnce.Do(func() {
		var accountDataDir string
		if len(dataDir) > 0 {
			accountDataDir = dataDir[0]
		}
		compensationCtx, compensationCancel := context.WithCancel(context.Background())
		caQueueManager = &CAQueueManager{
			queues:             make(map[int]*caQueue),
			blockedRules:       make(map[string]map[RuleBlockToken]struct{}),
			reloader:           reloader,
			active:             true,
			dataDir:            accountDataDir,
			compensationCtx:    compensationCtx,
			compensationCancel: compensationCancel,
		}
	})
}

// GetCAQueueManager returns the singleton queue manager. InitCAQueueManager
// must have been called first.
func GetCAQueueManager() *CAQueueManager {
	return caQueueManager
}

// ResetCAQueueManagerForTest 停止并清空单例，仅供测试隔离使用
func ResetCAQueueManagerForTest() {
	if caQueueManager != nil {
		caQueueManager.Stop()
	}
	caQueueManager = nil
	caQueueManagerOnce = sync.Once{}
}

// CancelJob aborts an in-flight issuance for the given job across all
// provider queues; deletion handlers call this before removing the row so a
// worker cannot keep issuing and deploying after the job is gone.
func (m *CAQueueManager) CancelJob(jobID int) {
	cancelCertificateDeploymentRetry(jobID)
	m.mu.Lock()
	var done []<-chan struct{}
	var cancels []context.CancelFunc
	for _, q := range m.queues {
		q.mu.Lock()
		pending := q.pending[:0]
		for _, item := range q.pending {
			if item.jobID == jobID {
				delete(q.active, jobID)
				continue
			}
			pending = append(pending, item)
		}
		q.pending = pending
		cancel, ok := q.cancels[jobID]
		if ok {
			cancels = append(cancels, cancel)
		}
		if executionDone := q.executionDone[jobID]; executionDone != nil {
			done = append(done, executionDone)
		}
		q.mu.Unlock()
	}
	m.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	// 在途执行退出等待必须有界：issuer 执行若不响应 ctx 取消（如 DNS 传播轮询
	// 异常路径），HTTP 调用方（DeleteCertJob 等）会被永久挂起（R36 C-1）。
	for _, executionDone := range done {
		select {
		case <-executionDone:
		case <-time.After(30 * time.Second):
			Logf("warn", "取消证书任务 %d：等待在途执行退出超时（30s），继续后续流程", jobID)
		}
	}
}

func (m *CAQueueManager) CancelJobsForRule(ctx context.Context, ruleID string) error {
	deploymentDone := signalCancelCertificateDeploymentRetriesForRule(ruleID)
	m.mu.Lock()
	var done []<-chan struct{}
	var cancels []context.CancelFunc
	for _, q := range m.queues {
		q.mu.Lock()
		pending := q.pending[:0]
		for _, item := range q.pending {
			if item.ruleID == ruleID {
				delete(q.active, item.jobID)
				continue
			}
			pending = append(pending, item)
		}
		q.pending = pending
		for jobID, runningRuleID := range q.runningRules {
			if runningRuleID == ruleID {
				if cancel := q.cancels[jobID]; cancel != nil {
					cancels = append(cancels, cancel)
				}
				if executionDone := q.executionDone[jobID]; executionDone != nil {
					done = append(done, executionDone)
				}
			}
		}
		q.mu.Unlock()
	}
	m.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	done = append(done, deploymentDone...)
	// 在途执行退出等待除 ctx 外还需 30s 上限：客户端不断连时 ctx.Done 不触发，
	// issuer 异常不响应取消会把 DeleteRule 等 HTTP 调用方永久挂起（R43 A-2，
	// 与 CancelJob 的 30s 模式同款）。
	for _, executionDone := range done {
		select {
		case <-executionDone:
		case <-ctx.Done():
			return fmt.Errorf("等待规则 %s 的证书任务退出: %w", ruleID, ctx.Err())
		case <-time.After(30 * time.Second):
			Logf("warn", "取消规则 %s 证书任务：等待在途执行退出超时（30s），继续后续流程", ruleID)
		}
	}
	return nil
}

// BlockJobsForRule prevents new queue admission until its token is released.
func (m *CAQueueManager) BlockJobsForRule(ruleID string) RuleBlockToken {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.blockedRules == nil {
		m.blockedRules = make(map[string]map[RuleBlockToken]struct{})
	}
	m.nextBlockToken++
	token := m.nextBlockToken
	if m.blockedRules[ruleID] == nil {
		m.blockedRules[ruleID] = make(map[RuleBlockToken]struct{})
	}
	m.blockedRules[ruleID][token] = struct{}{}
	return token
}

// UnblockJobsForRule releases only the barrier created by the matching token.
func (m *CAQueueManager) UnblockJobsForRule(ruleID string, tokens ...RuleBlockToken) {
	if len(tokens) != 1 {
		return
	}
	m.mu.Lock()
	barriers := m.blockedRules[ruleID]
	delete(barriers, tokens[0])
	lastBarrierReleased := false
	if len(barriers) == 0 {
		delete(m.blockedRules, ruleID)
		lastBarrierReleased = true
	}
	m.mu.Unlock()
	if lastBarrierReleased {
		// 规则解锁后补扫一次部署重试（R31 M5）：阻塞期间被
		// scheduleCertificateDeploymentRetry 丢弃的 'downloaded' 任务（窗口已过）
		// 需重新调度，否则滞停到下次 Resume/Start。走全局函数通道，且必须先释放
		// 队列锁——补扫回调会再次查询 isRuleBlocked（重入本锁）。
		rescanDroppedCertificateDeploymentRetries()
	}
}

func (m *CAQueueManager) IsRuleBlocked(ruleID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.blockedRules[ruleID]) != 0
}

func (m *CAQueueManager) isRuleBlocked(ruleID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.blockedRules[ruleID]) != 0
}

func (m *CAQueueManager) StartRuleDeletionCompensation(compensation RuleDeletionCompensation) error {
	m.mu.Lock()
	if m.compensationCtx == nil || m.compensationCtx.Err() != nil {
		m.mu.Unlock()
		return errors.New("certificate queue manager is stopped")
	}
	ctx := m.compensationCtx
	m.compensationWG.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.compensationWG.Done()
		for attempt := 1; ; attempt++ {
			timeout := m.compensationTimeout
			if timeout <= 0 {
				timeout = 2 * time.Minute
			}
			attemptCtx, cancel := context.WithTimeout(ctx, timeout)
			err := m.compensateRuleDeletion(attemptCtx, compensation)
			cancel()
			if err == nil {
				return
			}
			if ctx.Err() != nil {
				return
			}
			Logf("error", "CRITICAL: DeleteRule certificate compensation failed for caddy_id=%s attempt=%d: %v", compensation.RuleID, attempt, err)
			delay := ruleDeletionCompensationBackoff(attempt)
			if m.compensationBackoff != nil {
				delay = m.compensationBackoff(attempt)
			}
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return
			}
		}
	}()
	return nil
}

func (m *CAQueueManager) compensateRuleDeletion(ctx context.Context, compensation RuleDeletionCompensation) error {
	var drainErr error
	if compensation.Drain != nil {
		drainErr = compensation.Drain(ctx)
	} else if m.compensationDrain != nil {
		drainErr = m.compensationDrain(ctx, compensation.RuleID)
	} else {
		drainErr = m.CancelJobsForRule(ctx, compensation.RuleID)
	}
	if drainErr != nil {
		return drainErr
	}
	restore := m.compensationRestore
	if restore == nil {
		restore = restoreCertJobsForRule
	}
	if err := restore(ctx, compensation.Snapshot); err != nil {
		return err
	}
	requeue := m.compensationRequeue
	if requeue == nil {
		requeue = requeueCertJobsSnapshot
	}
	if err := requeue(ctx, compensation.Snapshot, m); err != nil {
		return err
	}
	m.UnblockJobsForRule(compensation.RuleID, compensation.Token)
	return nil
}

func ruleDeletionCompensationBackoff(attempt int) time.Duration {
	delay := time.Minute
	for i := 1; i < attempt && delay < 10*time.Minute; i++ {
		delay *= 2
	}
	if delay > 10*time.Minute {
		return 10 * time.Minute
	}
	return delay
}

// PauseAndDrain prevents new work, cancels every queue, and waits for all
// workers to exit before returning.
func (m *CAQueueManager) PauseAndDrain() {
	// 先暂停部署重试 timer 再停队列：若先置 active=false，部署 timer 回调
	// 可能恰好越过 timersPaused 检查开始重载，破坏暂停屏障语义。
	pauseCertificateDeploymentRetries()
	m.mu.Lock()
	m.active = false
	queues := m.stopQueuesLocked()
	m.mu.Unlock()

	for _, q := range queues {
		q.wait()
	}
	// q.wait 超时返回时滞行执行（issuer 不响应 ctx 取消）可能仍未退出：旧队列已被
	// stopQueuesLocked 整体摘出 m.queues，Resume 的 stranded 扫描经 IsJobActive 只查
	// 新 map 会漏判在途 job，导致同 jobID 双执行（R44-2）。把仍带在途执行的旧队列
	// 登记到 retiredQueues 供 IsJobActive 合并检查；执行退出后其 active 清空，
	// 由 IsJobActive 惰性摘除，无需回调（避免与 m.mu→q.mu 锁序冲突）。
	var retired []*caQueue
	for _, q := range queues {
		q.mu.Lock()
		stillRunning := len(q.active) > 0
		q.mu.Unlock()
		if stillRunning {
			retired = append(retired, q)
		}
	}
	if len(retired) > 0 {
		m.mu.Lock()
		now := time.Now()
		for _, q := range retired {
			m.retiredQueues = append(m.retiredQueues, retiredCAQueue{queue: q, retiredAt: now})
		}
		m.mu.Unlock()
	}
}

func (m *CAQueueManager) stopQueuesLocked() []*caQueue {
	queues := make([]*caQueue, 0, len(m.queues))
	for _, q := range m.queues {
		q.mu.Lock()
		for _, item := range q.pending {
			delete(q.active, item.jobID)
		}
		q.pending = nil
		q.mu.Unlock()
		q.stop()
		queues = append(queues, q)
	}
	m.queues = make(map[int]*caQueue)
	return queues
}

func (m *CAQueueManager) Resume() {
	m.mu.Lock()
	m.active = true
	m.mu.Unlock()
	resumeCertificateDeploymentRetries()
	m.requeueLifecycleStrandedJobs()
}

// requeueLifecycleStrandedJobs 重入队因队列生命周期切换而滞留的任务：停止队列会把
// 在途签发置回 'queued'（requeueCanceledJob），恢复后这些行不会自行回到调度器，
// 只能靠重启或快照替换；Resume 时补一次显式重入队（EnqueueIfActive 幂等）。
func (m *CAQueueManager) requeueLifecycleStrandedJobs() {
	m.requeueStrandedJobs(`j.status='queued' OR j.status LIKE 'creating\_%' ESCAPE '\'`,
		"节点生命周期切换后恢复排队", "CA queue resume")
}

// requeueStrandedQueuedJobs 是周期巡检入口（R45 发现1）：滞行执行退出后任务停在
// 'queued' 而队列中无此任务，Resume 之外的周期巡检原先均不覆盖纯 'queued'，任务
// 会滞停至下次角色翻转/重启。CertificateService 的 30s waitingCA ticker 顺带调用
// 本函数，把滞停窗口收敛到 30s。只扫 'queued'：'waiting_ca' 有独立冷却语义，由
// requeueWaitingCAJobs 负责，此处不碰。
func (m *CAQueueManager) requeueStrandedQueuedJobs() {
	m.requeueStrandedJobs(`j.status='queued'`, "周期巡检发现队列外滞留，重新排队", "CA queue periodic scan")
}

// requeueStrandedJobs 是 Resume 与周期巡检共用的滞留任务重入队实现：按 whereClause
// 扫描任务，逐个经 IsJobActive（在途/滞行任务防双执行，R44-2）与
// certJobRuleApplicable（孤儿交周期 sweep 禁用）守卫后，以归一化转换 +
// EnqueueIfActive 重排队。
func (m *CAQueueManager) requeueStrandedJobs(whereClause, message, logPrefix string) {
	if db.DB == nil {
		return
	}
	rows, err := db.DB.Query(`
		SELECT j.id, COALESCE(j.rule_id,''), COALESCE(j.domain,''), j.status, COALESCE(j.ca_provider_id,0),
		       COALESCE(r.domain,''),
		       CASE WHEN r.caddy_id IS NOT NULL AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' THEN 1 ELSE 0 END
		FROM cert_jobs j
		LEFT JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE ` + whereClause)
	if err != nil {
		log.Printf("%s: stranded job scan failed: %v", logPrefix, err)
		return
	}
	type strandedJob struct {
		id, providerID int
		ruleID, domain string
		status         string
		ruleDomain     string
		ruleBound      bool
	}
	var jobs []strandedJob
	for rows.Next() {
		var job strandedJob
		if err := rows.Scan(&job.id, &job.ruleID, &job.domain, &job.status, &job.providerID, &job.ruleDomain, &job.ruleBound); err != nil {
			continue
		}
		jobs = append(jobs, job)
	}
	// 先关闭读迭代器再写库：SQLite 连接池上行迭代未结束时写入会触发 SQLITE_BUSY。
	if err := rows.Close(); err != nil {
		log.Printf("%s: close rows failed: %v", logPrefix, err)
		return
	}
	for _, job := range jobs {
		if m.IsJobActive(job.id) {
			// 防御（R31 M4）：任务正被队列执行时不得扫描重入队——把在途任务
			// 的 DB 状态置回 'queued' 会让执行结束后的状态转换失败并误标 failed。
			// 当前生产调用点（PauseAndDrain 之后）不会触发，测试直接调用 Resume
			// 时依赖此守卫。
			continue
		}
		if !certJobRuleApplicable(job.ruleBound, job.ruleDomain, job.domain) {
			// 孤儿任务交给周期 sweep 禁用，此处不重复处理
			continue
		}
		// 状态已 'queued' 的任务也走一次归一化转换（'queued'→'queued' 幂等），
		// 让 EnqueueIfActive 以 changed=true 真正入队；并发改过状态的行由
		// transitionJob 的 WHERE status IN (...) 守卫跳过。
		_, _, err := m.EnqueueIfActive(job.providerID, job.id, job.ruleID, job.domain, func() (int, bool, error) {
			err := transitionJob(db.DB, job.id, []string{job.status}, "queued", map[string]any{"message": message})
			if errors.Is(err, ErrJobTransitionConflict) {
				return job.id, false, nil
			}
			return job.id, err == nil, err
		})
		if err != nil {
			log.Printf("%s: requeue stranded job %d failed: %v", logPrefix, job.id, err)
		}
	}
}

// IsJobActive reports whether the job is currently queued or running.
func (m *CAQueueManager) IsJobActive(jobID int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	// age-out 摘除后迁入 zombieJobs 的 jobID 仍视为在途（R46 A-F2）：保护持续到
	// 滞行执行退出（releaseZombieJob），无 executionDone 信号的永久保留。
	if _, zombie := m.zombieJobs[jobID]; zombie {
		return true
	}
	for _, queue := range m.queues {
		queue.mu.Lock()
		_, active := queue.active[jobID]
		queue.mu.Unlock()
		if active {
			return true
		}
	}
	// 合并检查 PauseAndDrain 超时后退役的队列（R44-2）：滞行执行退出前
	// jobID 仍视为在途，阻止 Resume stranded 扫描重复入队；已全部退出的
	// 退役队列在此惰性摘除。
	active := false
	kept := m.retiredQueues[:0]
	for _, entry := range m.retiredQueues {
		queue := entry.queue
		queue.mu.Lock()
		_, jobActive := queue.active[jobID]
		remaining := len(queue.active)
		agedOut := remaining > 0 && time.Since(entry.retiredAt) > caExecutionTimeout+10*time.Minute
		var stranded map[int]chan struct{}
		if agedOut {
			stranded = make(map[int]chan struct{}, remaining)
			for strandedJobID := range queue.active {
				stranded[strandedJobID] = queue.executionDone[strandedJobID]
			}
		}
		queue.mu.Unlock()
		if jobActive {
			active = true
		}
		if remaining == 0 {
			continue
		}
		if agedOut {
			// 越过执行上限+10min 余量仍未退出的滞行执行只可能是僵尸（R45 发现3），
			// 摘除条目避免硬挂+高频角色翻转下 retiredQueues 理论无界增长；但在途
			// jobID 不得随条目遗忘——迁入 zombieJobs 维持双执行防护（R46 A-F2）。
			m.migrateZombieJobsLocked(stranded)
			Logf("warn", "CA 队列退役条目超过 %s 仍有 %d 个在途任务未退出，摘除并迁入僵尸保护", caExecutionTimeout+10*time.Minute, remaining)
			continue
		}
		kept = append(kept, entry)
	}
	m.retiredQueues = kept
	return active
}

// migrateZombieJobsLocked 把 age-out 摘除的退役队列在途 jobID 迁入 zombieJobs
// （R46 A-F2，R45 发现3 回归修复）：R44-2 的语义是 jobID 在滞行执行退出前永久
// 视为在途；直接摘除会让 IsJobActive 返回 false，重开同 jobID 双执行窗口
// （RetryCertJob/CreateOrRequeueCertJob/Resume 扫描均依赖此守卫）。带
// executionDone 信号的 jobID 挂 goroutine 等待执行退出后解除保护；无信号的
// （理论不可达：退役队列 active 均为在途执行）永久保留并记日志——僵尸事件本身
// 罕见，宁可永久保护也不放双执行。
func (m *CAQueueManager) migrateZombieJobsLocked(stranded map[int]chan struct{}) {
	if m.zombieJobs == nil {
		m.zombieJobs = make(map[int]struct{}, len(stranded))
	}
	for jobID, done := range stranded {
		if _, exists := m.zombieJobs[jobID]; exists {
			continue
		}
		m.zombieJobs[jobID] = struct{}{}
		if done == nil {
			Logf("warn", "CA 队列僵尸任务 %d 无 executionDone 信号，永久保留在途保护", jobID)
			continue
		}
		go m.releaseZombieJob(jobID, done)
	}
}

// releaseZombieJob 在滞行执行退出（executionDone 关闭，caQueue.execute 退出时
// 统一 close）后解除 jobID 的僵尸保护。
func (m *CAQueueManager) releaseZombieJob(jobID int, done <-chan struct{}) {
	<-done
	m.mu.Lock()
	delete(m.zombieJobs, jobID)
	m.mu.Unlock()
}

// Enqueue adds or re-enqueues a cert job.
func (m *CAQueueManager) Enqueue(providerID int, jobID int, ruleID, domains string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return errors.New("证书签发队列已暂停或未启动")
	}
	if len(m.blockedRules[ruleID]) != 0 {
		return fmt.Errorf("certificate queue admission blocked for rule %s", ruleID)
	}
	return m.enqueueLocked(providerID, jobID, ruleID, domains)
}

func (m *CAQueueManager) EnqueueIfActive(providerID int, jobID int, ruleID, domains string, transition func() (int, bool, error)) (int, bool, error) {
	if m.beforeActiveEnqueue != nil {
		m.beforeActiveEnqueue()
	}
	// 在途检查必须先于 transition/入队（R45 发现2）：滞行执行悬挂（PauseAndDrain
	// 超时后登记在 retiredQueues）期间，手动重试/规则重建若放行会同 jobID 双执行，
	// 且滞行退出时 requeueCanceledJob 会把已签发状态打回 'queued'。命中按阻塞同语义
	// 返回 changed=false，调用方走 !changed 分支（409）而非 500。
	// 既有调用方无回归：waiting_ca/滞留扫描的任务执行已退出不在 active；
	// requeueLifecycleStrandedJobs 已前置检查，此处为幂等二道闸。
	if m.IsJobActive(jobID) {
		return jobID, false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return jobID, false, nil
	}
	if len(m.blockedRules[ruleID]) != 0 {
		// 规则删除屏障期按冲突语义处理：返回 changed=false 让 handler 走 !changed
		// 分支回 409，而不是把暂时性屏障当成 500 服务器错误（R43 A-4）。
		return jobID, false, nil
	}
	jobID, changed, err := transition()
	if err != nil || !changed {
		return jobID, changed, err
	}
	return jobID, true, m.enqueueLocked(providerID, jobID, ruleID, domains)
}

func (m *CAQueueManager) enqueueLocked(providerID int, jobID int, ruleID, domains string) error {
	provider, err := loadCAProvider(providerID)
	if err != nil {
		failJob(jobID, fmt.Sprintf("CA Provider 不可用: %v", err))
		return err
	}
	log.Printf("CA queue Enqueue job=%d providerID=%d resolved=%s (%s)", jobID, providerID, provider.Name, provider.Provider)

	// Persist the resolved provider ID so renewals use the same provider unless
	// the admin intentionally changes the default and triggers a new job.
	if providerID != provider.ID {
		if _, err := db.DB.Exec("UPDATE cert_jobs SET ca_provider_id=? WHERE id=?", provider.ID, jobID); err != nil {
			log.Printf("CA queue: failed to update resolved provider for job %d: %v", jobID, err)
		}
	}

	q, ok := m.queues[provider.ID]
	if !ok {
		q = newCAQueue(provider, m.reloader, m.dataDir)
		m.queues[provider.ID] = q
		go q.loop()
	} else {
		// 队列缓存的 provider 快照可能早于用户修改的凭证/配置，每次入队刷新
		q.mu.Lock()
		q.provider = provider
		q.mu.Unlock()
	}
	if m.beforeEnqueue != nil {
		m.beforeEnqueue()
	}
	q.enqueue(queueItem{
		jobID:   jobID,
		ruleID:  ruleID,
		domains: domains,
	})
	return nil
}

func (m *CAQueueManager) enqueueCompensation(providerID int, jobID int, ruleID, domains string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return errors.New("certificate queue manager is stopped")
	}
	if len(m.blockedRules[ruleID]) == 0 {
		return fmt.Errorf("certificate compensation lease missing for rule %s", ruleID)
	}
	return m.enqueueLocked(providerID, jobID, ruleID, domains)
}

func (m *CAQueueManager) Start() {
	m.mu.Lock()
	if m.compensationCtx == nil || m.compensationCtx.Err() != nil {
		m.compensationCtx, m.compensationCancel = context.WithCancel(context.Background())
	}
	m.active = true
	m.mu.Unlock()
	resumeCertificateDeploymentRetries()
}

func (m *CAQueueManager) Stop() {
	m.mu.Lock()
	if m.compensationCancel != nil {
		m.compensationCancel()
	}
	m.mu.Unlock()
	m.compensationWG.Wait()
	m.PauseAndDrain()
}

type queueItem struct {
	jobID   int
	ruleID  string
	domains string
}

type caQueue struct {
	provider      models.CAProvider
	pending       []queueItem
	running       int
	active        map[int]struct{} // jobIDs currently pending or running
	cancels       map[int]context.CancelFunc
	executionDone map[int]chan struct{}
	runningRules  map[int]string
	lastOrder     time.Time
	reloader      func() error
	mu            sync.Mutex
	stopCh        chan struct{}
	wakeCh        chan struct{}
	ctx           context.Context
	cancel        context.CancelFunc
	loopDone      chan struct{}
	executions    sync.WaitGroup
	stopping      bool
	executeFn     func(context.Context, queueItem, models.CAProvider) error
}

type queueExecution struct {
	item     queueItem
	provider models.CAProvider
	ctx      context.Context
	cancel   context.CancelFunc
}

func newCAQueue(provider models.CAProvider, reloader func() error, dataDir ...string) *caQueue {
	if provider.MaxConcurrent <= 0 {
		provider.MaxConcurrent = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	q := &caQueue{
		provider:      provider,
		reloader:      reloader,
		active:        make(map[int]struct{}),
		cancels:       make(map[int]context.CancelFunc),
		executionDone: make(map[int]chan struct{}),
		runningRules:  make(map[int]string),
		stopCh:        make(chan struct{}),
		wakeCh:        make(chan struct{}, 1),
		loopDone:      make(chan struct{}),
		ctx:           ctx,
		cancel:        cancel,
	}
	q.executeFn = func(ctx context.Context, item queueItem, provider models.CAProvider) error {
		return NewCertIssuer(q.reloader, dataDir...).Issue(ctx, item.jobID, item.ruleID, item.domains, provider)
	}
	return q
}

func (q *caQueue) enqueue(item queueItem) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.active[item.jobID]; ok {
		return
	}
	q.pending = append(q.pending, item)
	q.active[item.jobID] = struct{}{}
	select {
	case q.wakeCh <- struct{}{}:
	default:
	}
}

func (q *caQueue) loop() {
	defer close(q.loopDone)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-q.stopCh:
			return
		case <-q.wakeCh:
			q.tick()
		case <-ticker.C:
			q.tick()
		}
	}
}

func (q *caQueue) tick() {
	q.mu.Lock()
	if q.stopping {
		q.mu.Unlock()
		return
	}
	if len(q.pending) == 0 {
		q.mu.Unlock()
		return
	}

	providerID := q.provider.ID
	provider, err := loadCAProvider(providerID)
	if err != nil || provider.ID != providerID {
		pending := q.pending
		q.pending = nil
		for _, item := range pending {
			delete(q.active, item.jobID)
		}
		q.mu.Unlock()
		message := fmt.Sprintf("CA Provider 不可用：配置已禁用或删除（ID %d）", providerID)
		for _, item := range pending {
			failJob(item.jobID, message)
		}
		return
	}
	if provider.MaxConcurrent <= 0 {
		provider.MaxConcurrent = 1
	}
	q.provider = provider
	if q.running >= provider.MaxConcurrent {
		q.mu.Unlock()
		return
	}
	interval := time.Duration(provider.MinIntervalMS) * time.Millisecond
	if time.Since(q.lastOrder) < interval {
		q.mu.Unlock()
		return
	}

	execution, ok := q.prepareExecutionLocked(q.ctx)
	if !ok {
		q.mu.Unlock()
		return
	}
	q.lastOrder = time.Now()
	q.mu.Unlock()

	go q.execute(execution)
}

func (q *caQueue) prepareExecutionLocked(parent context.Context) (queueExecution, bool) {
	if len(q.pending) == 0 {
		return queueExecution{}, false
	}
	item := q.pending[0]
	q.pending = q.pending[1:]
	q.running++
	q.executions.Add(1)
	ctx, cancel := context.WithTimeout(parent, caExecutionTimeout)
	q.cancels[item.jobID] = cancel
	done := make(chan struct{})
	q.executionDone[item.jobID] = done
	q.runningRules[item.jobID] = item.ruleID
	return queueExecution{item: item, provider: q.provider, ctx: ctx, cancel: cancel}, true
}

func (q *caQueue) execute(execution queueExecution) {
	item := execution.item
	defer q.executions.Done()
	defer execution.cancel()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("CA queue panic for job %d: %v", item.jobID, r)
			failJob(item.jobID, fmt.Sprintf("调度器异常: %v", r))
		}
		q.mu.Lock()
		q.running--
		delete(q.active, item.jobID)
		delete(q.cancels, item.jobID)
		close(q.executionDone[item.jobID])
		delete(q.executionDone, item.jobID)
		delete(q.runningRules, item.jobID)
		q.mu.Unlock()
	}()

	if err := execution.ctx.Err(); err != nil {
		q.handleExecutionCancellation(execution)
		return
	}

	// If the rule/job was deleted while the item was queued, skip it silently.
	if !jobExists(item.jobID) {
		log.Printf("CA queue: job %d no longer exists, skipping", item.jobID)
		return
	}

	if err := q.executeFn(execution.ctx, item, execution.provider); err != nil {
		log.Printf("CA queue execution failed for job %d rule %s: %v", item.jobID, item.ruleID, err)
		if execution.ctx.Err() != nil {
			q.handleExecutionCancellation(execution)
			return
		}
		handleQueueExecutionError(item.jobID, err)
	}
}

func (q *caQueue) handleExecutionCancellation(execution queueExecution) {
	if q.ctx.Err() != nil {
		requeueCanceledJob(execution.item.jobID)
		return
	}
	if errors.Is(execution.ctx.Err(), context.DeadlineExceeded) {
		failJob(execution.item.jobID, "证书签发执行超时")
	}
}

func (q *caQueue) stop() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.stopping {
		return
	}
	q.stopping = true
	q.cancel()
	close(q.stopCh)
}

func (q *caQueue) wait() {
	<-q.loopDone
	// executions.Wait 必须套 30s 上限：issuer 异常不响应 ctx 取消时 Wait 永不返回，
	// PauseAndDrain/进程 Stop 会被永久挂起（R43 A-2，与 CancelJob 同口径）。
	done := make(chan struct{})
	go func() {
		q.executions.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(caQueueDrainTimeout):
		Logf("warn", "CA 队列暂停：等待在途执行退出超时（%s），继续关闭流程", caQueueDrainTimeout)
	}
}

func requeueCanceledJob(jobID int) {
	if err := transitionJob(db.DB, jobID, jobStatusesExceptDisabled, "queued", map[string]any{"message": "节点生命周期切换，等待恢复签发"}); err != nil && !errors.Is(err, ErrJobTransitionConflict) {
		log.Printf("CA queue: failed to requeue canceled job %d: %v", jobID, err)
	}
}

func handleQueueExecutionError(jobID int, err error) {
	var deploymentErr *certificateDeploymentError
	if errors.As(err, &deploymentErr) {
		return
	}
	var rateLimitErr *CAProviderRateLimitError
	if errors.As(err, &rateLimitErr) {
		markJobWaitingCA(jobID, rateLimitErr.RetryAfter)
		return
	}
	failJob(jobID, fmt.Sprintf("CA 签发失败: %v", err))
}

// jobExists returns true if a cert_jobs row with the given id still exists.
func jobExists(jobID int) bool {
	var exists bool
	err := db.DB.QueryRow("SELECT 1 FROM cert_jobs WHERE id=?", jobID).Scan(&exists)
	return err == nil
}

func loadCAProvider(id int) (models.CAProvider, error) {
	var p models.CAProvider
	if id == 0 {
		// Use system default.
		var err error
		id, err = GetDefaultCAProvider()
		if err != nil {
			log.Printf("CA queue: failed to load default CA provider: %v", err)
			id = 0
		}
	}

	err := scanCAProvider(db.DB.QueryRow("SELECT "+caProviderColumns+" FROM ca_providers WHERE id=? AND enabled=1", id), &p)
	if err != nil {
		// If the requested/default provider is disabled or missing, fall back to the first enabled provider.
		var fallbackID int
		if fallbackErr := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&fallbackID); fallbackErr == nil {
			id = fallbackID
			err = scanCAProvider(db.DB.QueryRow("SELECT "+caProviderColumns+" FROM ca_providers WHERE id=? AND enabled=1", id), &p)
		}
	}
	if err != nil {
		return p, fmt.Errorf("load CA provider %d: %w", id, err)
	}
	return p, nil
}

// ResolveCAProviderID resolves provider zero using the same default selection as queue admission.
func ResolveCAProviderID(id int) (int, error) {
	if id != 0 {
		return id, nil
	}
	provider, err := loadCAProvider(id)
	if err != nil {
		return 0, err
	}
	return provider.ID, nil
}

func markJobWaitingCA(jobID int, retryAfter time.Duration) {
	maxAttempts := GetCertRenewalAttempts()

	var attempts int
	if err := db.DB.QueryRow("SELECT COALESCE(renewal_attempts,0) FROM cert_jobs WHERE id=?", jobID).Scan(&attempts); err != nil {
		log.Printf("CA queue: failed to read attempts for job %d: %v", jobID, err)
	}
	attempts++

	cooling := computeBackoff(attempts, retryAfter)
	available := time.Now().Add(cooling).UTC()
	loc := time.FixedZone("CST", 8*3600)
	display := available.In(loc)

	if attempts >= maxAttempts {
		message := fmt.Sprintf("CA 频率限制，已达到最大重试次数 %d", maxAttempts)
		err := transitionJob(db.DB, jobID, nonTerminalJobStatuses, "failed", map[string]any{
			"message":            message,
			"renewal_attempts":   attempts,
			"ca_available_after": nil,
			"last_error_code":    nil,
		})
		if err != nil && !errors.Is(err, ErrJobTransitionConflict) {
			log.Printf("CA queue: failed to mark job %d as failed at max attempts: %v", jobID, err)
			return
		}
		if err == nil {
			WriteCertJobLog(jobID, "ERROR", "failed", message)
			RecordAuditLog("system", "签发失败", "证书任务", FormatAuditDetail(AuditJobPart(jobID), AuditResultPart("max_attempts")), "")
		}
		return
	}

	err := transitionJob(db.DB, jobID, nonTerminalJobStatuses, "waiting_ca", map[string]any{
		"message":            "等待 CA 频率限制冷却",
		"ca_available_after": available.UTC().Format("2006-01-02 15:04:05"),
		"last_error_code":    "429",
		"renewal_attempts":   attempts,
	})
	if err != nil && !errors.Is(err, ErrJobTransitionConflict) {
		log.Printf("CA queue: failed to mark job %d as waiting_ca: %v", jobID, err)
		return
	}
	if err == nil {
		WriteCertJobLog(jobID, "WARN", "waiting_ca", fmt.Sprintf("CA 频率限制，第 %d 次，将在 %s 后重试", attempts, display.Format("2006-01-02 15:04:05 -07:00")))
		RecordAuditLog("system", "签发限流", "证书任务", FormatAuditDetail(AuditJobPart(jobID), fmt.Sprintf("第 %d 次限流", attempts), fmt.Sprintf("恢复时间：%s", display.Format("2006-01-02 15:04:05"))), "")
	}
}

// maxRenewalAttemptsMessage 在续签失败累计达到上限时追加终态说明，
// 与 429 路径（markJobWaitingCA）的「已达到最大重试次数」口径一致；
// 幂等：已含标记的 message 不再重复追加。
func maxRenewalAttemptsMessage(message string, maxAttempts int) string {
	const marker = "已达到最大重试次数"
	if strings.Contains(message, marker) {
		return message
	}
	return fmt.Sprintf("%s（%s %d，停止自动重试，可手动重试）", message, marker, maxAttempts)
}

func failJob(jobID int, message string) {
	if attempts := currentRenewalAttempts(jobID); attempts+1 >= GetCertRenewalAttempts() {
		message = maxRenewalAttemptsMessage(message, GetCertRenewalAttempts())
	}
	message = truncateJobMessage(message)
	err := transitionJob(db.DB, jobID, nonTerminalJobStatuses, "failed", map[string]any{
		"message":          message,
		"renewal_attempts": jobSQLExpression("COALESCE(renewal_attempts,0)+1"),
	})
	recordFailedJobTransition(jobID, message, err)
}

func failJobFromStatus(jobID int, expectedStatus, message string) {
	if attempts := currentRenewalAttempts(jobID); attempts+1 >= GetCertRenewalAttempts() {
		message = maxRenewalAttemptsMessage(message, GetCertRenewalAttempts())
	}
	message = truncateJobMessage(message)
	err := transitionJob(db.DB, jobID, []string{expectedStatus}, "failed", map[string]any{
		"message":          message,
		"renewal_attempts": jobSQLExpression("COALESCE(renewal_attempts,0)+1"),
	})
	recordFailedJobTransition(jobID, message, err)
}

// currentRenewalAttempts 读取任务当前续签失败次数（读取失败按 0 处理，
// 宁可漏标也不阻塞失败路径本身）。
func currentRenewalAttempts(jobID int) int {
	var attempts int
	if err := db.DB.QueryRow("SELECT COALESCE(renewal_attempts,0) FROM cert_jobs WHERE id=?", jobID).Scan(&attempts); err != nil {
		return 0
	}
	return attempts
}

func recordFailedJobTransition(jobID int, message string, err error) {
	if err != nil && !errors.Is(err, ErrJobTransitionConflict) {
		log.Printf("CA queue: failed to mark job %d as failed: %v", jobID, err)
		return
	}
	if err != nil {
		return
	}
	WriteCertJobLog(jobID, "ERROR", "failed", message)
	RecordAuditLog("system", "签发失败", "证书任务", FormatAuditDetail(AuditJobPart(jobID), AuditResultPart("failed")), "")
}
