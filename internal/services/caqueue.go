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
	for _, executionDone := range done {
		select {
		case <-executionDone:
		case <-ctx.Done():
			return fmt.Errorf("等待规则 %s 的证书任务退出: %w", ruleID, ctx.Err())
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
	if db.DB == nil {
		return
	}
	rows, err := db.DB.Query(`
		SELECT j.id, COALESCE(j.rule_id,''), COALESCE(j.domain,''), j.status, COALESCE(j.ca_provider_id,0),
		       COALESCE(r.domain,''),
		       CASE WHEN r.caddy_id IS NOT NULL AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' THEN 1 ELSE 0 END
		FROM cert_jobs j
		LEFT JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.status='queued' OR j.status LIKE 'creating\_%' ESCAPE '\'
	`)
	if err != nil {
		log.Printf("CA queue resume: stranded job scan failed: %v", err)
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
		log.Printf("CA queue resume: close rows failed: %v", err)
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
			err := transitionJob(db.DB, job.id, []string{job.status}, "queued", map[string]any{"message": "节点生命周期切换后恢复排队"})
			if errors.Is(err, ErrJobTransitionConflict) {
				return job.id, false, nil
			}
			return job.id, err == nil, err
		})
		if err != nil {
			log.Printf("CA queue resume: requeue stranded job %d failed: %v", job.id, err)
		}
	}
}

// IsJobActive reports whether the job is currently queued or running.
func (m *CAQueueManager) IsJobActive(jobID int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, queue := range m.queues {
		queue.mu.Lock()
		_, active := queue.active[jobID]
		queue.mu.Unlock()
		if active {
			return true
		}
	}
	return false
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return jobID, false, nil
	}
	if len(m.blockedRules[ruleID]) != 0 {
		return jobID, false, fmt.Errorf("certificate queue admission blocked for rule %s", ruleID)
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
	q.executions.Wait()
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
			RecordAuditLog("system", "签发失败", "证书签发任务", FormatAuditDetail(AuditJobPart(jobID), AuditResultPart("max_attempts")), "")
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
		RecordAuditLog("system", "CA限流", "证书签发任务", FormatAuditDetail(AuditJobPart(jobID), fmt.Sprintf("第 %d 次限流", attempts), fmt.Sprintf("恢复时间：%s", display.Format("2006-01-02 15:04:05"))), "")
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
	RecordAuditLog("system", "签发失败", "证书签发任务", FormatAuditDetail(AuditJobPart(jobID), AuditResultPart("failed")), "")
}
