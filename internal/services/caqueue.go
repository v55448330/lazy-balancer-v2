package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// CAQueueManager schedules ACME issuance jobs per CA provider.
type CAQueueManager struct {
	mu            sync.Mutex
	queues        map[int]*caQueue
	retiredQueues []retiredCAQueue
	zombieJobs    map[int]zombieJob
	// reservedJobs 是「已通过在途/活跃/规则屏障判定、正在锁外完成状态迁移与
	// provider 解析」的 jobID 预留集合。在途判定放锁外执行期间它必须仍算在途，
	// 否则并发 Retry/规则重建会看到 isJobActiveLocked=false 而二次入队。
	reservedJobs                  map[int]struct{}
	reloader                      func() error
	active                        bool
	blockedRules                  map[string]map[RuleBlockToken]struct{}
	nextBlockToken                RuleBlockToken
	compensationCtx               context.Context
	compensationCancel            context.CancelFunc
	compensationWG                sync.WaitGroup
	compensationBackoff           func(int) time.Duration
	compensationTimeout           time.Duration
	compensationDrain             func(context.Context, string) error
	compensationRestore           func(context.Context, CertJobsSnapshot) error
	compensationRequeue           func(context.Context, CertJobsSnapshot, *CAQueueManager) error
	dataDir                       string
	beforeEnqueue                 func()
	beforeActiveEnqueue           func()
	beforeProviderUnavailableFail func()
	// beforeProviderEnqueue 是 provider 解析前的测试缝（生产恒 nil）：用于在
	// 「已预留、尚未解析 provider」的窗口内注入延迟，验证解析不再持全局锁。
	beforeProviderEnqueue func()
}

type RuleBlockToken uint64

// retiredCAQueue 登记 PauseAndDrain 超时退役的队列。retiredAt 供惰性摘除兜底
// 滞行执行越过 caExecutionTimeoutMax+10min 宽松余量仍未退出只可能是
// 僵尸（执行上限 ctx 早已触发），超时摘除并记日志；摘除时在途 jobID 迁入
// zombieJobs 维持在途保护直到执行退出，双执行防护不回退。
type retiredCAQueue struct {
	queue     *caQueue
	retiredAt time.Time
}

// zombieJob retains the rule and completion signal after an aged-out retired
// queue is forgotten, so rule-scoped drains keep the same execution barrier.
type zombieJob struct {
	ruleID string
	done   <-chan struct{}
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

// caProviderConfigVersion 是 CA provider 配置版本号：UpdateCAProvider
// 提交后递增，队列 tick 发现版本与本地快照不一致时先重载 provider 再评估闸门。
// 修复「缓存闸门先于 loadCAProvider」的滞后：积压窗口内把 max_concurrent 抬高
// 或把 min_interval 下调，旧实现会一直用缓存值放行/拦截到 running 归零或间隔
// 到期。原子读写避免 q.mu→m.mu 反向锁序（锁序恒为 m.mu→q.mu）。
var caProviderConfigVersion atomic.Uint64

// caExecutionTimeout 是单域名签发的执行预算。预算必须严格
// 大于单域各分段预算之和，否则最坏路径被外层 ctx 抢先取消，错误归因从分段错误
// （「wait authorization 超时」「finalize 超时」）退化为泛化「证书签发执行超时」
// 并白烧一次 renewal_attempts。分段之和 = 注册 30s + DNS 传播 5m + 递归逐域
// 2m + 验证 10m + 订单就绪 3m + finalize 10m + 订单有效 5m = 35.5m，故基数取
// 40m（原 30m 小于该和，且注释算式漏计三段，属预算口径漂移）。分段预算仍是
// 主要快速失败机制，外层预算只作兜底。
const caExecutionTimeout = 40 * time.Minute

// caExecutionTimeoutMax 是按域名数缩放后的执行预算封顶：多域名签发的
// DNS 传播 + 递归逐域 + 验证按域名数串行叠加（每域最坏
// 增量 ≈17min——传播 5m + 递归 2m + 验证 10m），固定基数会把合法慢签发
// 误判为执行超时并白烧重试次数；每域 +15min 的缩放预算贴近该和。
// 封顶 60min：2 域 55m，3 域即 70m→封顶（超出部分按快速失败立场截断，
// 与 retiredCAQueue 惰性摘除的 age-out 余量耦合，不动）。
const caExecutionTimeoutMax = 60 * time.Minute

// caExecutionTimeoutFor 按授权域名数缩放执行预算：单域名 40min，每增加
// 一个域名追加 15min（原 10min 对每域最坏 ≈17min 单边
// 低估，慢签发白烧重试次数），封顶 60min。
func caExecutionTimeoutFor(domains string) time.Duration {
	count := 0
	for _, domain := range strings.Split(domains, ",") {
		if strings.TrimSpace(domain) != "" {
			count++
		}
	}
	if count < 1 {
		count = 1
	}
	timeout := caExecutionTimeout + time.Duration(count-1)*15*time.Minute
	if timeout > caExecutionTimeoutMax {
		return caExecutionTimeoutMax
	}
	return timeout
}

// caQueueDrainTimeout 上限 PauseAndDrain 等待队列执行退出；issuer 异常不响应
// ctx 取消时等待永不返回，进程 Stop 会被永久挂起（与 CancelJob 30s 同口径）。
// var 而非 const：测试需要缩短超时以覆盖超时路径，生产代码不得改写。
var caQueueDrainTimeout = 30 * time.Second

// InitCAQueueManager initializes the singleton queue manager with the given
// Caddy reloader. It must be called once during application startup before
// GetCAQueueManager is used. 可选 dataDir 为 ACME 账户密钥数据目录（审计
// 留空时签发链路创建账户密钥会直接报错——密钥路径退化为 CWD 相对路径
// 曾在测试环境堆积数千个私钥，生产必须传 cfg.DataDir）。
// reloader 契约：经 executeFn/retryCertificateDeployment 进入
// certissuer 部署临界区后才被调用，彼时已持 CaddyOpLock——必须传 InLock
// 变体（GenerateAndApplyConfigForceInLock），传自取锁变体即重入死锁。
func InitCAQueueManager(reloader func() error, dataDir ...string) {
	caQueueManagerOnce.Do(func() {
		var accountDataDir string
		if len(dataDir) > 0 {
			accountDataDir = dataDir[0]
		}
		compensationCtx, compensationCancel := context.WithCancel(context.Background())
		caQueueManager = &CAQueueManager{
			queues: make(map[int]*caQueue),
			// 活动态由 cert-issuance 守护生命周期派生，初始化即为
			// 停止。唯一激活点=StartACME 的 Start()（daemon Run 经
			// StartACME/StopACME 挂钩）；从节点启动、用户停止证书签发后重启
			// 等「守护从未启动」形态不得留下可签发却无证书服务（部署重试/
			// 启动恢复/补扫全为 nil）的半启动子系统，也避免运行期停止（409）
			// 与重启后停止（仍可签发）的语义反转。
			active:             false,
			blockedRules:       make(map[string]map[RuleBlockToken]struct{}),
			reloader:           reloader,
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

// caCancelWaitTimeout 是取消/删除路径等待在途执行退出的整体上限
// 逐 job 串行 30s 会让多任务挂起时 HTTP 调用方最坏等 N×30s。var 而非 const：
// 测试注入缩短时限以覆盖超时路径，生产代码不得改写。
var caCancelWaitTimeout = 30 * time.Second

// collectCancellationLocked 收集匹配任务的取消函数与在途执行完成信号，供
// CancelJob（按任务）与 CancelJobsForRule（按规则）共用同一扫描口径
// （此前按规则入口扫 m.queues + retiredQueues + zombieJobs，按任务
// 入口只扫 m.queues，契约不对称且退役/僵尸形态靠 ctx 已取消「碰巧安全」）。
// 调用方须持有 m.mu（锁序恒为 m.mu→q.mu）；返回的 cancel 必须在解锁后调用。
// pending 命中项从队列摘除并清 active（执行中任务不由这里摘 active，仍由
// execute 退出路径维护）。僵尸任务即使 done 为 nil 也必须加入等待集合——
// nil 表示永久僵尸，等待方只能由 ctx/共享 deadline 失败退出。
func (m *CAQueueManager) collectCancellationLocked(matches func(jobID int, ruleID string) bool) ([]context.CancelFunc, []<-chan struct{}) {
	var cancels []context.CancelFunc
	var done []<-chan struct{}
	collectQueue := func(q *caQueue) {
		q.mu.Lock()
		defer q.mu.Unlock()
		for jobID, cancel := range q.cancels {
			if !matches(jobID, q.runningRules[jobID]) {
				continue
			}
			if cancel != nil {
				cancels = append(cancels, cancel)
			}
		}
		for jobID, executionDone := range q.executionDone {
			if !matches(jobID, q.runningRules[jobID]) {
				continue
			}
			if executionDone != nil {
				done = append(done, executionDone)
			}
		}
	}
	for _, q := range m.queues {
		q.mu.Lock()
		pending := q.pending[:0]
		for _, item := range q.pending {
			if matches(item.jobID, item.ruleID) {
				delete(q.active, item.jobID)
				continue
			}
			pending = append(pending, item)
		}
		q.pending = pending
		q.mu.Unlock()
		collectQueue(q)
	}
	for _, entry := range m.retiredQueues {
		collectQueue(entry.queue)
	}
	for jobID, zombie := range m.zombieJobs {
		if matches(jobID, zombie.ruleID) {
			done = append(done, zombie.done)
		}
	}
	return cancels, done
}

// CancelJob aborts an in-flight issuance for the given job across all
// provider queues; deletion handlers call this before removing the row so a
// worker cannot keep issuing and deploying after the job is gone.
func (m *CAQueueManager) CancelJob(jobID int) {
	cancelCertificateDeploymentRetry(jobID)
	m.mu.Lock()
	cancels, done := m.collectCancellationLocked(func(id int, _ string) bool { return id == jobID })
	m.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	// 在途执行退出等待必须有界：issuer 执行若不响应 ctx 取消（如 DNS 传播轮询
	// 异常路径），HTTP 调用方（DeleteCertJob 等）会被永久挂起。
	// 所有 done 共享一个截止时间，不做逐 job 串行等待。
	deadline := time.After(caCancelWaitTimeout)
	for _, executionDone := range done {
		select {
		case <-executionDone:
		case <-deadline:
			Logf("warn", "取消证书任务 %d：等待在途执行退出超时（%s），继续后续流程", jobID, caCancelWaitTimeout)
			return
		}
	}
}

func (m *CAQueueManager) CancelJobsForRule(ctx context.Context, ruleID string) error {
	deploymentDone := signalCancelCertificateDeploymentRetriesForRule(ruleID)
	m.mu.Lock()
	cancels, done := m.collectCancellationLocked(func(_ int, runningRuleID string) bool { return runningRuleID == ruleID })
	m.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	done = append(done, deploymentDone...)
	// 在途执行退出等待除 ctx 外还需有界上限：客户端不断连时 ctx.Done 不触发，
	// issuer 异常不响应取消会把 DeleteRule 等 HTTP 调用方永久挂起。
	// 所有 done 共享一个截止时间——逐 job 串行 30s 在规则多任务
	// 挂起时最坏 N×30s。
	deadline := time.After(caCancelWaitTimeout)
	for _, executionDone := range done {
		select {
		case <-executionDone:
		case <-ctx.Done():
			return fmt.Errorf("等待规则 %s 的证书任务退出: %w", ruleID, ctx.Err())
		case <-deadline:
			Logf("warn", "取消规则 %s 证书任务：等待在途执行退出超时（%s），中止本轮删除并由补偿链重试", ruleID, caCancelWaitTimeout)
			return fmt.Errorf("等待规则 %s 的证书任务退出: %w", ruleID, context.DeadlineExceeded)
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
// 单参形态由编译器保证恰好一个 token——变参 + len!=1 静默 no-op 曾
// 让误传 0/2 个 token 的调用方永久持有租约（该规则证书操作长期 409）且无日志。
func (m *CAQueueManager) UnblockJobsForRule(ruleID string, token RuleBlockToken) {
	m.mu.Lock()
	barriers := m.blockedRules[ruleID]
	delete(barriers, token)
	lastBarrierReleased := false
	if len(barriers) == 0 {
		delete(m.blockedRules, ruleID)
		lastBarrierReleased = true
	}
	m.mu.Unlock()
	if lastBarrierReleased {
		// 规则解锁后补扫一次部署重试：阻塞期间被
		// scheduleCertificateDeploymentRetry 丢弃的 'downloaded' 任务（窗口已过）
		// 需重新调度，否则滞停到下次 Resume/Start。走全局函数通道，且必须先释放
		// 队列锁——补扫回调会再次查询 IsRuleBlocked（重入本锁）。
		rescanDroppedCertificateDeploymentRetries()
	}
}

func (m *CAQueueManager) IsRuleBlocked(ruleID string) bool {
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
			Logf("error", "问题: DeleteRule certificate compensation failed for caddy_id=%s attempt=%d: %v", compensation.RuleID, attempt, err)
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
	// 规则存在性前置检查：补偿退避窗口内规则可能已被另一路径删除
	// （管理员重试 DeleteRule、配置导入整树替换）。规则不存在时没有可恢复对象，
	// 直接按成功收尾释放租约——restore/requeue 内部的存在性检查为第二道防线，
	// 此处短路可避免无谓的 DELETE+INSERT 事务。
	ruleExists, err := ruleExistsForCertCompensation(ctx, compensation.RuleID)
	if err != nil {
		return err
	}
	if ruleExists {
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
// workers to exit before returning. The returned flag reports whether every
// queue fully drained within caQueueDrainTimeout: false means an
// execution that ignores ctx cancellation is still running (and was registered
// in retiredQueues). Callers requiring a quiescent queue state (e.g. config
// import) must reject/retry rather than proceed on false.
func (m *CAQueueManager) PauseAndDrain() bool {
	// 先暂停部署重试 timer 再停队列：若先置 active=false，部署 timer 回调
	// 可能恰好越过 timersPaused 检查开始重载，破坏暂停屏障语义。
	pauseCertificateDeploymentRetries()
	m.mu.Lock()
	m.active = false
	queues := m.stopQueuesLocked()
	// 本次 stopQueuesLocked 摘出的队列只是「本轮」的
	// 全集——前一次 PauseAndDrain 超时退役的队列（retiredQueues）与已迁入
	// zombieJobs 的滞行执行不在其中。第二次调用若不并入它们，会在旧签发执行
	// 仍存活时返回 drained=true，配置导入据此放行整树替换（同 jobID 写入与
	// 导入快照竞争）。这里先快照既有在途集合。
	priorRetired := append([]retiredCAQueue(nil), m.retiredQueues...)
	priorZombies := len(m.zombieJobs)
	m.mu.Unlock()

	drained := true
	// 截止时间在所有队列间**共享**（与 CancelJobsForRule、部署回调暂停同构）：
	// 逐队列各自等 caQueueDrainTimeout 会让 N 个 provider 的最坏等待变成
	// N×30s，而配置导入在取 caddyOpMu 之前调用本函数，该窗口内全部配置写
	// 请求排队。共享截止下总等待预算恒为一个 caQueueDrainTimeout。
	drainDeadline := time.Now().Add(caQueueDrainTimeout)
	for _, q := range queues {
		if !q.wait(drainDeadline) {
			drained = false
		}
	}
	// 既有退役队列的在途执行仍存活 → 未排空。
	for _, entry := range priorRetired {
		entry.queue.mu.Lock()
		stillRunning := len(entry.queue.active) > 0
		entry.queue.mu.Unlock()
		if stillRunning {
			drained = false
		}
	}
	if priorZombies > 0 {
		// zombieJobs 是「退役队列后仍视为在途」的保护区，只在执行退出时
		// 惰性清除；非空即代表仍有未知在途签发。
		drained = false
	}
	// q.wait 超时返回时滞行执行（issuer 不响应 ctx 取消）可能仍未退出：旧队列已被
	// stopQueuesLocked 整体摘出 m.queues，Resume 的 stranded 扫描经 IsJobActive 只查
	// 新 map 会漏判在途 job，导致同 jobID 双执行。把仍带在途执行的旧队列
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
		drained = false
		m.mu.Lock()
		now := time.Now()
		for _, q := range retired {
			m.retiredQueues = append(m.retiredQueues, retiredCAQueue{queue: q, retiredAt: now})
		}
		m.mu.Unlock()
	}
	return drained
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

// IsActive 返回队列是否允许执行签发任务（只读活动态，供导入恢复保留）。
func (m *CAQueueManager) IsActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

// 配置导入窗口的证书队列屏障（粘性）：导入以 PauseAndDrain 建立隔离，但
// 常驻 cert-issuance 的 Run 在异常退出有界重拉/角色对账 SetRole(true) 时会
// 再走 StartACME→CAQueueManager.Start（置 active + 恢复部署重试），把已排空
// 的队列重新打开并与导入事务并发写库。hold 期间 Start/Resume 被延迟为
// 「待恢复意图」，只在 EndConfigImportHold 真正打开；depth 支持嵌套会话。
var configImportHold struct {
	sync.Mutex
	depth        int
	pendingStart bool
}

// BeginConfigImportHold 进入导入屏障（在 PauseAndDrain 之前调用——覆盖
// 「排空完成到会话建立」的窗口）。
func BeginConfigImportHold() {
	configImportHold.Lock()
	configImportHold.depth++
	configImportHold.Unlock()
}

// EndConfigImportHold 退出导入屏障；最后一层退出时兑现被延迟的启动意图
// （CA 队列 + 证书生命周期）。读取意图与取走意图必须在同一次临界区内完成：
// 登记侧（startUnlessConfigImportHold / startCertIssuanceLifecycle）在判定
// 屏障活跃之后才登记，若本函数先解锁再消费，迟到的登记会落在「屏障已退出」
// 之后而永不被任何组件兑现（CA 队列保持 inactive、签发 worker 不启动，且
// 角色一致时不会重启 loop，本代进程内没有第二条恢复通道）。
func EndConfigImportHold() {
	configImportHold.Lock()
	if configImportHold.depth > 0 {
		configImportHold.depth--
	}
	release := configImportHold.depth == 0
	pending := release && configImportHold.pendingStart
	certPending := release && certIssuanceStartDeferred.CompareAndSwap(true, false)
	if release {
		configImportHold.pendingStart = false
	}
	configImportHold.Unlock()
	if !release {
		return
	}
	if pending {
		if manager := GetCAQueueManager(); manager != nil {
			manager.startIgnoringHold()
		}
	}
	if certPending {
		startCertIssuanceLifecycleIgnoringHold()
	}
}

// configImportHoldActive 当前是否处于导入屏障窗口。
func configImportHoldActive() bool {
	configImportHold.Lock()
	defer configImportHold.Unlock()
	return configImportHold.depth > 0
}

// configImportHoldDeferHook 仅测试注入（生产恒 nil）：在「判定屏障活跃」与
// 「登记延迟启动意图」之间执行，让用例把屏障退出精准插进这个窗口。窗口内的
// 退出正是旧实现丢意图的形态（两次独立加锁：End 可在中间读完意图并退出）。
var configImportHoldDeferHook func()

// startUnlessConfigImportHold 按导入屏障语义决定本次启动能否立即执行：
// true=屏障不在场（调用方直接启动），false=已登记延迟意图（由
// EndConfigImportHold 兑现）。登记后立即在屏障锁内复核一次——屏障若在判定与
// 登记之间退出（EndConfigImportHold 已读完意图），本代自行取走意图并返回
// true。这条自愈路径是「意图永不丢」的保证，不得删。
func startUnlessConfigImportHold() bool {
	if !configImportHoldActive() {
		return true
	}
	if configImportHoldDeferHook != nil {
		configImportHoldDeferHook()
	}
	deferCAQueueStartLocked()
	// 复核（屏障锁内）：屏障若已在判定与登记之间退出，本代自行取走意图。
	return takeDeferredCAQueueStartIfReleased()
}

// takeDeferredCAQueueStartIfReleased 在屏障锁内复核并取走延迟的队列启动意图：
// 屏障仍活跃则留给 EndConfigImportHold（返回 false），已退出则取走并返回 true。
func takeDeferredCAQueueStartIfReleased() bool {
	configImportHold.Lock()
	defer configImportHold.Unlock()
	if configImportHold.depth > 0 {
		return false
	}
	taken := configImportHold.pendingStart
	configImportHold.pendingStart = false
	return taken
}

// takeDeferredCertIssuanceStartIfReleased 与队列版同语义：屏障已退出则取走
// 证书生命周期的延迟启动意图（调用方自行启动），否则留给
// EndConfigImportHold 兑现。
func takeDeferredCertIssuanceStartIfReleased() bool {
	configImportHold.Lock()
	defer configImportHold.Unlock()
	if configImportHold.depth > 0 {
		return false
	}
	return certIssuanceStartDeferred.CompareAndSwap(true, false)
}

// deferCAQueueStartLocked 记录被屏障延迟的启动意图（调用方不持 hold 锁）。
func deferCAQueueStartLocked() {
	configImportHold.Lock()
	configImportHold.pendingStart = true
	configImportHold.Unlock()
}

func (m *CAQueueManager) Resume() {
	if !startUnlessConfigImportHold() {
		return
	}
	m.resumeIgnoringHold()
}

// resumeIgnoringHold 恢复活动态并重扫滞留任务（跳过导入屏障判定）。
func (m *CAQueueManager) resumeIgnoringHold() {
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
	if _, err := m.requeueStrandedJobs(`j.status='queued' OR j.status LIKE 'creating\_%' ESCAPE '\'`,
		"节点生命周期切换后恢复排队", "CA queue resume"); err != nil {
		// Resume 无 task_runs 承载失败态：读失败必须至少留 error 级痕迹，
		// 否则恢复窗口内的扫描失败完全静默（下次 Resume/30s 补扫重试）。
		Logf("error", "CA queue resume: stranded job requeue failed: %v", err)
	}
}

// requeueStrandedQueuedJobs 是周期巡检入口：滞行执行退出后任务停在
// 'queued' 而队列中无此任务，Resume 之外的周期巡检原先均不覆盖纯 'queued'，任务
// 会滞停至下次角色翻转/重启。CertificateService 的 30s waitingCA ticker 顺带调用
// 本函数，把滞停窗口收敛到 30s。只扫 'queued'：'waiting_ca' 有独立冷却语义，由
// requeueWaitingCAJobs 负责，此处不碰。返回（本轮实际重入队的任务数, error）
// ——动作计数供 30s 补扫摘要，读失败上抛使补扫轮记失败终态（此前读失败只打
// 应用日志，任务监控全绿而滞留任务永不重入队）。
func (m *CAQueueManager) requeueStrandedQueuedJobs(gates ...func() error) (int, error) {
	return m.requeueStrandedJobs(`j.status='queued'`, "周期巡检发现队列外滞留，重新排队", "CA queue periodic scan", gates...)
}

// requeueStrandedJobs 是 Resume 与周期巡检共用的滞留任务重入队实现：按 whereClause
// 扫描任务，逐个经 IsJobActive（在途/滞行任务防双执行）与
// certJobRuleApplicable（孤儿交周期 sweep 禁用）守卫后，以归一化转换 +
// EnqueueIfActive 重排队。周期巡检传入的 gate 在每个任务的实际写点前复核。
// 返回本轮实际重入队的任务数。
func (m *CAQueueManager) requeueStrandedJobs(whereClause, message, logPrefix string, gates ...func() error) (requeued int, err error) {
	if db.DB == nil {
		return 0, nil
	}
	rows, err := db.DB.Query(`
		SELECT j.id, COALESCE(j.rule_id,''), COALESCE(j.domain,''), j.status, COALESCE(j.ca_provider_id,0),
		       COALESCE(r.domain,''),
		       CASE WHEN r.caddy_id IS NOT NULL AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' THEN 1 ELSE 0 END
		FROM cert_jobs j
		LEFT JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE ` + whereClause)
	if err != nil {
		Logf("error", "%s: stranded job scan failed: %v", logPrefix, err)
		return 0, fmt.Errorf("扫描滞留证书任务: %w", err)
	}
	type strandedJob struct {
		id, providerID int
		ruleID, domain string
		status         string
		ruleDomain     string
		ruleBound      bool
	}
	var jobs []strandedJob
	scanFailures := 0
	for rows.Next() {
		var job strandedJob
		if err := rows.Scan(&job.id, &job.ruleID, &job.domain, &job.status, &job.providerID, &job.ruleDomain, &job.ruleBound); err != nil {
			// Scan 失败留痕（曾静默 continue——列类型
			// 漂移等系统性失败每次巡检零处理且零信号）。
			Logf("warn", "%s: stranded job scan row failed, skipped: %v", logPrefix, err)
			scanFailures++
			continue
		}
		jobs = append(jobs, job)
	}
	defer func() {
		if scanFailures > 0 {
			err = errors.Join(err, fmt.Errorf("滞留证书任务扫描有 %d 行读取失败（结果不可信）", scanFailures))
		}
	}()
	// 迭代错误检查（曾只查 Close——迭代中途出错会把部分任务集
	// 当全量处理；放弃本轮，下一轮 30s 巡检重试全量）。
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		Logf("error", "%s: stranded job iteration failed: %v", logPrefix, err)
		return requeued, fmt.Errorf("遍历滞留证书任务: %w", err)
	}
	// 先关闭读迭代器再写库：SQLite 连接池上行迭代未结束时写入会触发 SQLITE_BUSY。
	if err := rows.Close(); err != nil {
		Logf("error", "%s: close rows failed: %v", logPrefix, err)
		return requeued, fmt.Errorf("关闭滞留证书任务结果集: %w", err)
	}
	var actionErr error
	for _, job := range jobs {
		if m.IsJobActive(job.id) {
			// 防御：任务正被队列执行时不得扫描重入队——把在途任务
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
		// transitionJob 的 WHERE status IN (...) 守卫跳过。写门放在 transition
		// 闭包首行，使入队准入之后、数据库迁移之前仍有一次逐项角色/取消复核。
		var gateErr error
		_, changed, err := m.EnqueueIfActive(job.providerID, job.id, job.ruleID, job.domain, func() (int, bool, error) {
			if gateErr = runCertWaitingCAWriteGate(gates); gateErr != nil {
				return job.id, false, gateErr
			}
			err := transitionJob(db.DB, job.id, []string{job.status}, "queued", map[string]any{"message": message})
			if errors.Is(err, ErrJobTransitionConflict) {
				return job.id, false, nil
			}
			return job.id, err == nil, err
		})
		if gateErr != nil {
			return requeued, gateErr
		}
		if err != nil {
			actionErr = errors.Join(actionErr, fmt.Errorf("重排滞留任务 %d（规则 %s）: %w", job.id, job.ruleID, err))
			Logf("error", "%s: requeue stranded job %d failed: %v", logPrefix, job.id, err)
			continue
		}
		if changed {
			requeued++
		}
	}
	return requeued, errors.Join(err, actionErr)
}

// HasRunningJobForRule 报告该规则当前是否有 worker 正在执行证书任务。
// 只看 runningRules（执行中内存态）而非 DB 状态：queued 取消是瞬时的、
// waiting_ca 冷却可长达 1-3 小时，均不应拦截删除/禁用；慢路径的根源仅是
// 「worker 正在跑网络分段」。调用方（DeleteRule/DisableRule 预检）将其作为
// UX 快路径，检查与操作间的 TOCTOU 窗口（恰好派发）落入既有的有界等待+
// 中止保护，正确性不变。
func (m *CAQueueManager) HasRunningJobForRule(ruleID string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, queue := range m.queues {
		queue.mu.Lock()
		for _, runningRuleID := range queue.runningRules {
			if runningRuleID == ruleID {
				queue.mu.Unlock()
				return true
			}
		}
		queue.mu.Unlock()
	}
	for _, entry := range m.retiredQueues {
		queue := entry.queue
		queue.mu.Lock()
		for _, runningRuleID := range queue.runningRules {
			if runningRuleID == ruleID {
				queue.mu.Unlock()
				return true
			}
		}
		queue.mu.Unlock()
	}
	for _, zombie := range m.zombieJobs {
		if zombie.ruleID == ruleID {
			return true
		}
	}
	return false
}

// MarkJobRunningForTest 在队列表记一个「执行中」条目供 handler 层预检测试
// 使用（生产代码禁止调用）。与 ResetCAQueueManagerForTest 同族的测试缝：
// 自足登记 active+runningRules，模拟 execute() 的登记形态。
func (m *CAQueueManager) MarkJobRunningForTest(ruleID string, jobID int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.queues) == 0 {
		// 队列惰建（Enqueue 时按 provider 创建）；测试缝自建一个零值 provider
		// 队列以承载标记，Stop（ResetCAQueueManagerForTest）会正常收走其 loop。
		q := newCAQueue(models.CAProvider{}, m.reloader, m.dataDir)
		q.manager = m
		m.queues[q.provider.ID] = q
		go q.loop()
	}
	for _, queue := range m.queues {
		queue.mu.Lock()
		queue.active[jobID] = struct{}{}
		queue.runningRules[jobID] = ruleID
		queue.running++
		queue.mu.Unlock()
		return
	}
}

// MarkRetiredJobRunningForTest registers a straggler in the same retired-queue
// shape produced by PauseAndDrain timeout. Production code must not call it.
func (m *CAQueueManager) MarkRetiredJobRunningForTest(ruleID string, jobID int) chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	queue := newCAQueue(models.CAProvider{}, m.reloader, m.dataDir)
	queue.manager = m
	done := make(chan struct{})
	queue.active[jobID] = struct{}{}
	queue.runningRules[jobID] = ruleID
	queue.executionDone[jobID] = done
	queue.cancels[jobID] = func() {}
	queue.running++
	m.retiredQueues = append(m.retiredQueues, retiredCAQueue{queue: queue, retiredAt: time.Now()})
	return done
}

// IsJobActive reports whether the job is currently queued or running.
func (m *CAQueueManager) IsJobActive(jobID int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.isJobActiveLocked(jobID)
}

// isJobActiveLocked 在途判定本体（调用方必须持 m.mu）——EnqueueIfActive
// 在锁内复用本函数，使「在途判定 → 状态迁移 → 入队」同一临界区
// 锁外判定与锁内入队之间存在窗口，并发补扫/手动重试可同 jobID 双入队）。
func (m *CAQueueManager) isJobActiveLocked(jobID int) bool {
	// age-out 摘除后迁入 zombieJobs 的 jobID 仍视为在途：保护持续到
	// 滞行执行退出（releaseZombieJob），无 executionDone 信号的永久保留。
	if _, zombie := m.zombieJobs[jobID]; zombie {
		return true
	}
	// 正在锁外完成迁移/解析的预留同样算在途：判定与入队不再同临界区后，
	// 预留是「已受理但尚未落进队列」的唯一在途证据。
	if _, reserved := m.reservedJobs[jobID]; reserved {
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
	// 合并检查 PauseAndDrain 超时后退役的队列：滞行执行退出前
	// jobID 仍视为在途，阻止 Resume stranded 扫描重复入队；已全部退出的
	// 退役队列在此惰性摘除。
	active := false
	kept := m.retiredQueues[:0]
	for _, entry := range m.retiredQueues {
		queue := entry.queue
		queue.mu.Lock()
		_, jobActive := queue.active[jobID]
		remaining := len(queue.active)
		agedOut := remaining > 0 && time.Since(entry.retiredAt) > caExecutionTimeoutMax+10*time.Minute
		var stranded map[int]zombieJob
		if agedOut {
			stranded = make(map[int]zombieJob, remaining)
			for strandedJobID := range queue.active {
				stranded[strandedJobID] = zombieJob{ruleID: queue.runningRules[strandedJobID], done: queue.executionDone[strandedJobID]}
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
			// 越过执行上限+10min 余量仍未退出的滞行执行只可能是僵尸，
			// 摘除条目避免硬挂+高频角色翻转下 retiredQueues 理论无界增长；但在途
			// jobID 不得随条目遗忘——迁入 zombieJobs 维持双执行防护。
			m.migrateZombieJobsLocked(stranded)
			Logf("warn", "CA 队列退役条目超过 %s 仍有 %d 个在途任务未退出，摘除并迁入僵尸保护", caExecutionTimeoutMax+10*time.Minute, remaining)
			continue
		}
		kept = append(kept, entry)
	}
	m.retiredQueues = kept
	return active
}

// migrateZombieJobsLocked 把 age-out 摘除的退役队列在途 jobID 迁入 zombieJobs
// 语义是 jobID 在滞行执行退出前永久
// 视为在途；直接摘除会让 IsJobActive 返回 false，重开同 jobID 双执行窗口
// （RetryCertJob/CreateOrRequeueCertJob/Resume 扫描均依赖此守卫）。带
// executionDone 信号的 jobID 挂 goroutine 等待执行退出后解除保护；无信号的
// （理论不可达：退役队列 active 均为在途执行）永久保留并记日志——僵尸事件本身
// 罕见，宁可永久保护也不放双执行。
func (m *CAQueueManager) migrateZombieJobsLocked(stranded map[int]zombieJob) {
	if m.zombieJobs == nil {
		m.zombieJobs = make(map[int]zombieJob, len(stranded))
	}
	for jobID, zombie := range stranded {
		if _, exists := m.zombieJobs[jobID]; exists {
			continue
		}
		m.zombieJobs[jobID] = zombie
		if zombie.done == nil {
			Logf("warn", "CA 队列僵尸任务 %d 无 executionDone 信号，永久保留在途保护", jobID)
			continue
		}
		go m.releaseZombieJob(jobID, zombie.done)
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

// EnqueueForTest 是测试夹具（名字即「生产禁止调用」）：生产入队一律走
// EnqueueIfActive（在途守卫 + 状态迁移）或内部 enqueueLocked。注意本夹具
// **不做** isJobActiveLocked 在途守卫（测试需要重复入队同一 jobID 构造场景），
// 因此更不能被生产路径复用。
func (m *CAQueueManager) EnqueueForTest(providerID int, jobID int, ruleID, domains string) error {
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
	// 在途检查在 m.mu 内先于 transition/入队
	// 滞行执行悬挂（PauseAndDrain
	// 超时后登记在 retiredQueues）期间，手动重试/规则重建若放行会同 jobID 双执行，
	// 且滞行退出时 requeueCanceledJob 会把已签发状态打回 'queued'。命中按阻塞同语义
	// 返回 changed=false，调用方走 !changed 分支（409）而非 500。
	// 既有调用方无回归：waiting_ca/滞留扫描的任务执行已退出不在 active；
	// requeueLifecycleStrandedJobs 已前置检查，此处为幂等二道闸。
	// 全局锁只覆盖「在途判定 → 活跃/屏障判定 → 预留」：provider 解析（≥3 次
	// DB 往返）、失败归因（failJob：退避窗口读 + 状态写 + 任务日志文件 IO +
	// 操作审计写）与状态迁移闭包全部移到锁外。m.mu 是队列全局锁，持它做这些
	// IO 会阻塞 IsJobActive/CancelJob/HasRunningJobForRule——删除/禁用规则的
	// HTTP 快路径在 CA 故障或 SQLITE_BUSY 重试时出现秒级卡顿。
	// 不变量仍成立：预留集合让「判定 → 迁移 → 入队」在并发视角下原子
	// （isJobActiveLocked 把预留算在途）。
	m.mu.Lock()
	if m.isJobActiveLocked(jobID) {
		m.mu.Unlock()
		return jobID, false, nil
	}
	if !m.enqueueAdmissibleLocked(ruleID) {
		// 暂停（配置导入/停止）与规则删除屏障期间按冲突语义处理：返回
		// changed=false 让 handler 走 !changed 分支回 409，而不是把暂时性
		// 状态当成 500 服务器错误。
		m.mu.Unlock()
		return jobID, false, nil
	}
	m.reserveJobLocked(jobID)
	m.mu.Unlock()
	defer m.releaseJobReservation(jobID)

	jobID, changed, err := transition()
	if err != nil || !changed {
		return jobID, changed, err
	}
	provider, err := m.resolveEnqueueProvider(providerID, jobID, ruleID)
	if err != nil {
		return jobID, true, err
	}
	m.mu.Lock()
	if !m.enqueueAdmissibleLocked(ruleID) {
		// 锁外窗口内已暂停（配置导入/停止的 PauseAndDrain 已完成排空）或规则
		// 已被 BlockJobsForRule 建屏障：收尾不得再新建队列/pending 项——新队列
		// 及其 loop 不在排空快照内，会让「已排空」的判定与静默边界失效。
		// 已迁移的 queued 行留给 Resume/滞留扫描接管；返回 changed=false 让
		// 调用方按当前 inactive/受阻状态归因（409），不当作服务器错误。
		m.mu.Unlock()
		return jobID, false, nil
	}
	m.enqueueResolvedLocked(provider, jobID, ruleID, domains)
	m.mu.Unlock()
	return jobID, true, nil
}

// enqueueAdmissibleLocked 是锁外解析后的收尾准入复核（调用方持 m.mu）：判据
// 与首段准入检查同一实现（active + 规则屏障），避免两处判据漂移。
func (m *CAQueueManager) enqueueAdmissibleLocked(ruleID string) bool {
	return m.active && len(m.blockedRules[ruleID]) == 0
}

// reserveJobLocked 登记在途预留（调用方持 m.mu）。
func (m *CAQueueManager) reserveJobLocked(jobID int) {
	if m.reservedJobs == nil {
		m.reservedJobs = make(map[int]struct{})
	}
	m.reservedJobs[jobID] = struct{}{}
}

// releaseJobReservation 释放在途预留（入队落定或失败退出后调用）。
func (m *CAQueueManager) releaseJobReservation(jobID int) {
	m.mu.Lock()
	delete(m.reservedJobs, jobID)
	m.mu.Unlock()
}

// errCAProviderUnavailable 标记入队时 CA provider 解析失败（被禁用/删除且无
// enabled 回退）。该失败是已定局的业务状态而非瞬时错误：enqueueLocked 已同步
// failJob（任务置 failed + job 日志 + 审计，即现有 job-status/audit 通道）。
// 补偿重排队据此把此类错误按「该任务已定局」跳过而不上抛重试
// 上抛会让 StartRuleDeletionCompensation 退避循环永久重试——每轮 restore 复活
// failed 行再重新失败——且规则租约 blockedRules 永不释放，该规则证书操作持续 409）。
// 例外：只差部署的任务（certJobDeploymentOnly）不 failJob——部署链不
// 解析 provider，标 failed 会断开唯一自动恢复通道。
var errCAProviderUnavailable = errors.New("CA Provider 不可用")

// certJobDeploymentOnly 报告任务是否「材料已落库、只差部署」：部署生命周期
// （downloaded/cleanup_dns/cleanup_warning，即 JobLifecycleDownloaded）且
// cert_pem/key_pem 均非空。这类任务的自动恢复通道是部署重试（直接读库材料），
// 与 CA provider 可用性无关。读失败按普通签发任务处理（返回 false）——宁可
// 维持既有 failJob 语义，也不因一次读故障把签发任务永久留在非终态。
func certJobDeploymentOnly(jobID int) bool {
	status, hasMaterial, found, err := loadCertJobDeploymentState(jobID)
	if err != nil || !found {
		return false
	}
	return JobLifecycle(status) == JobLifecycleDownloaded && hasMaterial
}

// errCAQueueInactive 标记补偿重排队时队列未激活/已暂停。任务按分支语义保留：
// 签发/重签任务为标准 'queued'（Resume/周期巡检 stranded 扫描接管）；材料快速
// 路径任务保持 'downloaded' 且部署窗口已推到当前时刻（部署补扫接管）——两者
// 都不得上抛重试，否则租约永久不释放。
var errCAQueueInactive = errors.New("certificate queue manager is inactive")

// ruleFollowsDefaultCAProvider 报告规则当前是否「跟随默认 CA」（lb_rules.
// ca_provider_id=0）。规则行缺失（并发删除）按 false 处理——没有可对齐的选择，
// 保持调用方传入 id 的既有语义；读失败同样保守返回 false 并留 warn（不猜测）。
func ruleFollowsDefaultCAProvider(ruleID string) bool {
	if db.DB == nil || ruleID == "" {
		return false
	}
	var ruleCA int
	if err := db.DB.QueryRow("SELECT COALESCE(ca_provider_id,0) FROM lb_rules WHERE caddy_id=?", ruleID).Scan(&ruleCA); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			Logf("warn", "CA queue: 读取规则 %s 的 CA 提供商选择失败，按任务行传入口径解析: %v", ruleID, err)
		}
		return false
	}
	return ruleCA == 0
}

// enqueueLocked 是测试夹具/EnqueueForTest 使用的「解析 + 入队」组合（调用方已
// 持 m.mu）：生产路径已把解析拆到锁外（见 EnqueueIfActive），此处仅为测试
// 缝保持原形态——它不在生产调用链上。
func (m *CAQueueManager) enqueueLocked(providerID int, jobID int, ruleID, domains string) error {
	provider, err := m.resolveEnqueueProvider(providerID, jobID, ruleID)
	if err != nil {
		return err
	}
	m.enqueueResolvedLocked(provider, jobID, ruleID, domains)
	return nil
}

// resolveEnqueueProvider 解析入队要用的 CA provider，并完成「跟随默认」归一与
// 解析失败的业务归因（failJob / 只差部署降级）。**不得在持 m.mu 时调用**：
// 本函数含多次 DB 往返、任务日志文件 IO 与操作审计写，持全局锁会让
// IsJobActive/CancelJob/HasRunningJobForRule 等快路径一起排队。
func (m *CAQueueManager) resolveEnqueueProvider(providerID int, jobID int, ruleID string) (models.CAProvider, error) {
	if m.beforeProviderEnqueue != nil {
		m.beforeProviderEnqueue()
	}
	provider, err := loadCAProvider(providerID)
	// 「跟随默认 CA」语义收敛：规则选择为 0 时，任务行固化的旧默认 id 只是
	// 「当时的偏好」——它仍可用时保持固化（续期稳定性，不因默认切换改写在途
	// 任务）；一旦不可用（被禁用/删除），必须回落到**当前默认**而不是命中
	// 「显式选择但已禁用」硬错误（自动续签链终止而 UI 仍显示「跟随默认」）。
	// 回落成功即把任务行归一到 0：后续入队按当前默认解析，固化快照不再复活。
	if err != nil && providerID != 0 && ruleFollowsDefaultCAProvider(ruleID) {
		Logf("warn", "CA queue: 跟随默认规则的固化 provider %d 不可用（%v），按当前默认重新解析 job=%d", providerID, err, jobID)
		providerID = 0
		provider, err = loadCAProvider(providerID)
		if err == nil {
			if _, updateErr := db.DB.Exec("UPDATE cert_jobs SET ca_provider_id=0 WHERE id=? AND ca_provider_id<>0", jobID); updateErr != nil {
				Logf("error", "CA queue: failed to normalize follow-default provider for job %d: %v", jobID, updateErr)
			}
		}
	}
	if err != nil {
		// 只差部署的任务（部署生命周期 + 材料已落库）不依赖 CA provider
		// ——部署重试链 retryCertificateDeployment 直接读库材料写文件 + reload。
		// 把它标 failed 会摘掉唯一的自动恢复通道（部署补扫只收 downloaded/cleanup_*），
		// 因此保持可部署态并让 deployment_available_after 的补扫接管；provider
		// 恢复前不触发重签。签发生命周期（queued/creating_*/waiting_ca 等）仍按
		// 已定局的业务失败 failJob。
		if certJobDeploymentOnly(jobID) {
			Logf("warn", "CA queue: job %d 只差部署，CA Provider 不可用（%v）——保持待部署，由部署补扫接管", jobID, err)
			return models.CAProvider{}, fmt.Errorf("%w: %w", errCAProviderUnavailable, err)
		}
		failJob(jobID, fmt.Sprintf("CA Provider 不可用: %v", err))
		return models.CAProvider{}, fmt.Errorf("%w: %w", errCAProviderUnavailable, err)
	}
	Logf("info", "CA queue Enqueue job=%d providerID=%d resolved=%s (%s)", jobID, providerID, provider.Name, provider.Provider)

	// 只固化「显式选择」的解析结果：跟随默认（providerID=0）不得落库——落库会把
	// 当时默认的快照变成任务身份，后续默认切换/禁用不再作用于该任务（语义分叉，
	// 见函数入口的归一）。显式 id 的已删除回退仍按历史延续固化。
	if providerID != 0 && providerID != provider.ID {
		if _, err := db.DB.Exec("UPDATE cert_jobs SET ca_provider_id=? WHERE id=?", provider.ID, jobID); err != nil {
			Logf("error", "CA queue: failed to update resolved provider for job %d: %v", jobID, err)
		}
	}
	return provider, nil
}

// enqueueResolvedLocked 把已解析 provider 的任务放进对应队列（调用方持 m.mu，
// 本函数只做内存表操作 + 测试钩子）。
func (m *CAQueueManager) enqueueResolvedLocked(provider models.CAProvider, jobID int, ruleID, domains string) {
	q, ok := m.queues[provider.ID]
	if !ok {
		q = newCAQueue(provider, m.reloader, m.dataDir)
		q.manager = m
		m.queues[provider.ID] = q
		go q.loop()
	} else {
		// 队列缓存的 provider 快照可能早于用户修改的凭证/配置，每次入队刷新
		q.mu.Lock()
		q.provider = provider
		q.providerVersion = caProviderConfigVersion.Load()
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
}

func (m *CAQueueManager) enqueueCompensation(providerID int, jobID int, ruleID, domains string) error {
	// 在途检查必须先于入队：补偿退避循环在角色翻转退役旧队列后
	// 重跑时，drain（CancelJobsForRule）只扫 m.queues，看不到 retiredQueues/
	// zombieJobs 中的滞行执行，会误判"已全部退出"并放行补偿重入队——不经
	// IsJobActive 守卫即二次入队同 jobID → 双执行。命中时跳过（非错误），
	// 与 requeueStrandedJobs（:453）/ EnqueueIfActive（:592）同语义。
	if m.IsJobActive(jobID) {
		Logf("warn", "CA queue compensation enqueue skipped: job %d still active", jobID)
		return nil
	}
	// 与 EnqueueIfActive 同口径：全局锁只覆盖「活跃/租约判定 + 在途预留」，
	// provider 解析与失败归因在锁外完成（补偿退避重试与删除/禁用规则的快路径
	// 并发，持锁做 provider IO 会拖慢后者）。
	m.mu.Lock()
	if err := m.compensationAdmissionLocked(ruleID); err != nil {
		m.mu.Unlock()
		return err
	}
	m.reserveJobLocked(jobID)
	m.mu.Unlock()
	defer m.releaseJobReservation(jobID)

	provider, resolveErr := m.resolveEnqueueProvider(providerID, jobID, ruleID)
	if resolveErr != nil {
		return resolveErr
	}
	m.mu.Lock()
	if err := m.compensationAdmissionLocked(ruleID); err != nil {
		// 锁外窗口内被暂停/租约已释放（导入排空、停止或补偿已完成）：收尾
		// 不得再建队列——新队列不在排空快照内，会让导入的「已排空」判定失效。
		// 暂停/租约缺失都不上抛重试（补偿退避循环会把租约释放当成瞬时故障）。
		m.mu.Unlock()
		return err
	}
	m.enqueueResolvedLocked(provider, jobID, ruleID, domains)
	m.mu.Unlock()
	return nil
}

// compensationAdmissionLocked 是补偿重排队的准入判据（调用方持 m.mu）：首段
// 检查与锁外解析后的收尾复核共用同一实现，避免两处判据漂移。
func (m *CAQueueManager) compensationAdmissionLocked(ruleID string) error {
	if !m.active {
		return errCAQueueInactive
	}
	if len(m.blockedRules[ruleID]) == 0 {
		return fmt.Errorf("certificate compensation lease missing for rule %s", ruleID)
	}
	return nil
}

func (m *CAQueueManager) Start() {
	// 导入窗口：只登记意图，不得打开队列（否则 StartACME 的部署重试恢复会与
	// 导入事务并发写证书/库）。EndConfigImportHold 兑现，窗口内退出的交错由
	// startUnlessConfigImportHold 的自愈复核兜底。
	if !startUnlessConfigImportHold() {
		return
	}
	m.startIgnoringHold()
}

// startIgnoringHold 实际启动（跳过导入屏障判定；EndConfigImportHold 兑现
// 延迟意图与正常路径共用）。
func (m *CAQueueManager) startIgnoringHold() {
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
	// 补偿 goroutine 已全部退出（WG.Wait 之后），其持有的 blockedRules 租约再无
	// 释放者，必须统一回收：否则角色翻转/重启恢复后，复用同 caddy_id
	// 的规则会被残留屏障永久拦截（EnqueueIfActive 命中 blocked → 证书静默停发）。
	// PauseAndDrain 不得清理租约：它不弃置补偿（配置导入路径持 caddyOpMu 调用时
	// 补偿可能仍在退避中），清租约会让在途补偿的 enqueueCompensation 永久失败。
	m.releaseAllRuleBlocks()
	m.PauseAndDrain()
	// 显式停止作废导入窗口内登记的延迟启动意图：停止是用户/生命周期意图，
	// 导入结束不得把它兑现成启动。
	configImportHold.Lock()
	configImportHold.pendingStart = false
	configImportHold.Unlock()
}

// releaseAllRuleBlocks 回收全部规则删除屏障租约。锁序与 UnblockJobsForRule 一致：
// m.mu 临界区内重置 map，解锁后再补扫部署重试（回调经 IsRuleBlocked 重入本锁）。
func (m *CAQueueManager) releaseAllRuleBlocks() {
	m.mu.Lock()
	hadBlocks := len(m.blockedRules) > 0
	m.blockedRules = make(map[string]map[RuleBlockToken]struct{})
	m.mu.Unlock()
	if hadBlocks {
		rescanDroppedCertificateDeploymentRetries()
	}
}

type queueItem struct {
	jobID   int
	ruleID  string
	domains string
}

type caQueue struct {
	manager         *CAQueueManager
	provider        models.CAProvider
	providerVersion uint64 // 最近一次加载 provider 时的 caProviderConfigVersion 快照
	pending         []queueItem
	running         int
	active          map[int]struct{} // jobIDs currently pending or running
	cancels         map[int]context.CancelFunc
	executionDone   map[int]chan struct{}
	runningRules    map[int]string
	lastOrder       time.Time
	reloader        func() error
	mu              sync.Mutex
	stopCh          chan struct{}
	wakeCh          chan struct{}
	ctx             context.Context
	cancel          context.CancelFunc
	loopDone        chan struct{}
	executions      sync.WaitGroup
	stopping        bool
	executeFn       func(context.Context, queueItem, models.CAProvider) error
}

type queueExecution struct {
	item     queueItem
	provider models.CAProvider
	ctx      context.Context
	cancel   context.CancelFunc
}

// normalizeCAProviderSnapshot 是队列 provider 快照的归一唯一出口。闸门直接用
// 缓存快照判定（q.running >= q.provider.MaxConcurrent / lastOrder + MinInterval），
// 未归一的 0 值会让该 CA 的派发闸门永久关闭（running=0 >= 0 恒真），而
// enqueueLocked 复用队列时会同步 providerVersion——版本一致使 tick/refresh 的
// 重载分支也不再纠偏，故复用入口必须同样过本归一。
// 归一对落库/审计比对（NormalizeCAProvider*）与队列快照共用同一对函数，
// 队列侧不得另写钳制。
func normalizeCAProviderSnapshot(provider models.CAProvider) models.CAProvider {
	provider.MaxConcurrent = NormalizeCAProviderMaxConcurrent(provider.MaxConcurrent)
	provider.MinIntervalMS = NormalizeCAProviderMinIntervalMS(provider.MinIntervalMS)
	return provider
}

func newCAQueue(provider models.CAProvider, reloader func() error, dataDir ...string) *caQueue {
	provider = normalizeCAProviderSnapshot(provider)
	ctx, cancel := context.WithCancel(context.Background())
	q := &caQueue{
		provider:        provider,
		providerVersion: caProviderConfigVersion.Load(),
		reloader:        reloader,
		active:          make(map[int]struct{}),
		cancels:         make(map[int]context.CancelFunc),
		executionDone:   make(map[int]chan struct{}),
		runningRules:    make(map[int]string),
		stopCh:          make(chan struct{}),
		wakeCh:          make(chan struct{}, 1),
		loopDone:        make(chan struct{}),
		ctx:             ctx,
		cancel:          cancel,
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

	// 并发/间隔闸门只用缓存 provider（newCAQueue 与每次成功加载后均已归一化）
	// 与内存态即可判定，必须先于 loadCAProvider：积压窗口内每 100ms tick 都打
	// 1-2 次 provider 查询（~10 次/秒）。代价是闸门关闭期间对
	// provider 失效的发现推迟到下一次真实派发窗口，由 drain 路径统一收口。
	//
	// UpdateCAProvider 提交后递增 caProviderConfigVersion——
	// 版本不一致即先重载快照再评估闸门，max_concurrent 抬高/min_interval 下调
	// 在积压窗口内下一个 tick 生效；版本一致时不额外查库，查询收敛不回退。
	if q.providerVersion != caProviderConfigVersion.Load() {
		if !q.refreshProviderLocked() {
			return // 已解锁并处置 pending（provider 被禁用/删除）
		}
	}
	if q.running >= q.provider.MaxConcurrent {
		q.mu.Unlock()
		return
	}
	if time.Since(q.lastOrder) < time.Duration(q.provider.MinIntervalMS)*time.Millisecond {
		q.mu.Unlock()
		return
	}

	providerID := q.provider.ID
	// 仅真实派发窗口查一次库（闸门已在上方用缓存快照判定，空队列/限流/并发满
	// 都不查库）。此处不能移到锁外：派发与 pending 处置必须在同一临界区内完成，
	// 移出后需以 CAS 复核 provider 版本与 running 计数，收益（单查询/次派发）
	// 不抵并发不变量风险。
	provider, err := loadCAProvider(providerID)
	if err != nil || provider.ID != providerID {
		pending := q.pending
		q.pending = nil
		for _, item := range pending {
			delete(q.active, item.jobID)
		}
		q.mu.Unlock()
		message := fmt.Sprintf("CA Provider 不可用：配置已禁用或删除（ID %d）", providerID)
		q.manager.failPendingProviderUnavailable(pending, message)
		return
	}
	// loadCAProvider 已在唯一出口归一 max_concurrent/min_interval_ms，此处不再
	// 重复钳制（重复钳制会让「归一」出现第二份实现而漂移）。
	q.provider = provider
	q.providerVersion = caProviderConfigVersion.Load()
	// 加载到的新配置可能收紧，按新值复核（纯内存比较）：派发决策始终按最新
	// provider 配置评估，不弱于原先"每次 tick 先加载再评估"的语义。
	if q.running >= provider.MaxConcurrent {
		q.mu.Unlock()
		return
	}
	if time.Since(q.lastOrder) < time.Duration(provider.MinIntervalMS)*time.Millisecond {
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

// refreshProviderLocked 在 provider 配置版本变化时（调用方持 q.mu）重载快照并按
// 新值刷新本地版本快照。provider 被禁用/删除时排空 pending、删 active 占位并
// 解锁后逐个 failJob，返回 false（调用方须直接 return，锁已释放）。
func (q *caQueue) refreshProviderLocked() bool {
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
		q.manager.failPendingProviderUnavailable(pending, message)
		return false
	}
	// 归一已在 loadCAProvider 唯一出口完成（见 normalizeCAProviderSnapshot）。
	q.provider = provider
	q.providerVersion = caProviderConfigVersion.Load()
	return true
}

// failPendingProviderUnavailable 在队列解锁后逐个处置因 provider 失效而排空的
// pending 项。旧队列排空与新尝试入队可能交错，因此全局在途复核、queued 行复核
// 与旧尝试 failJob 必须在同一 m.mu 临界区内完成，并与 EnqueueIfActive 的
// 「在途判定→状态迁移→入队」串行：若另一 provider（含退役队列/zombie）已经
// 接管则跳过；若接管在复核后到达，则旧失败先落定，新尝试随后从 failed 重新入队。
func (m *CAQueueManager) failPendingProviderUnavailable(items []queueItem, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, item := range items {
		if m.isJobActiveLocked(item.jobID) {
			Logf("warn", "CA queue: provider-unavailable fail skipped for job %d: re-enqueued by concurrent path", item.jobID)
			continue
		}
		if !queuedJobStillExists(item.jobID) {
			Logf("warn", "CA queue: provider-unavailable fail skipped for job %d: job deleted or no longer queued", item.jobID)
			continue
		}
		if m.beforeProviderUnavailableFail != nil {
			m.beforeProviderUnavailableFail()
		}
		failJob(item.jobID, message)
	}
}

// queuedJobStillExists 报告 pending 队列项对应的任务行仍存在且仍保持入队时
// 预期的 'queued' 状态（所有重签发入队路径落库态均为 'queued'；例外是补偿重排队
// 保留/归一化为 'downloaded' 的证书材料任务——含 cleanup_* 转入，——
// 其重部署走 Issue 快速路径、不依赖 CA，被跳过后由部署补扫/重启恢复接管部署）。
func queuedJobStillExists(jobID int) bool {
	var queued int
	err := db.DB.QueryRow("SELECT status='queued' FROM cert_jobs WHERE id=?", jobID).Scan(&queued)
	return err == nil && queued == 1
}

func (q *caQueue) prepareExecutionLocked(parent context.Context) (queueExecution, bool) {
	if len(q.pending) == 0 {
		return queueExecution{}, false
	}
	item := q.pending[0]
	q.pending = q.pending[1:]
	q.running++
	q.executions.Add(1)
	ctx, cancel := context.WithTimeout(parent, caExecutionTimeoutFor(item.domains))
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
			Logf("error", "CA queue panic for job %d: %v", item.jobID, r)
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
		Logf("warn", "CA queue: job %d no longer exists, skipping", item.jobID)
		return
	}

	if err := q.executeFn(execution.ctx, item, execution.provider); err != nil {
		Logf("error", "CA queue execution failed for job %d rule %s: %v", item.jobID, item.ruleID, err)
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
		handleExecutionTimeout(execution.item.jobID)
		return
	}
	// 手动取消（CancelJob/删除任务）而非队列整体停用：执行已响应 ctx 退出，
	// 但不得把行留在 creating_* 等非终态；按取消终态收敛。drain 走上面的
	// q.ctx 分支 requeue，不进入这里。
	if execution.ctx.Err() != nil {
		failJob(execution.item.jobID, "证书任务已取消")
	}
}

// handleExecutionTimeout 归类执行超时（DeadlineExceeded）的终态
// 同族未收敛点）：证书材料先于部署落库（Issue 的 downloaded 中间态），
// 若超时发生在材料已落库之后，无条件 failJob 会把任务打成终态 failed——此时
// 续期扫描（新证书不在窗口）、首发失败重试（有 expires_at）、部署补扫（只收
// downloaded/cleanup_*）、启动恢复（终态跳过）、对账（只重建 issued/downloaded）
// 全部不可达，新证书材料搁浅且 HTTPS 规则无 TLS。材料在身的部署生命周期任务
// 保持可部署态并立即重排部署（30s 补扫/Resume 同口径接管）；无材料的失败维持
// failJob 语义。
func handleExecutionTimeout(jobID int) {
	const message = "执行超时：证书材料已落库，等待重新部署"
	if deferDeploymentForMaterialBearingJob(jobID, "execution_timeout", message) {
		return
	}
	failJobTransition(jobID, nonTerminalJobStatuses, "证书签发执行超时")
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

func (q *caQueue) wait(deadline time.Time) bool {
	<-q.loopDone
	// executions.Wait 必须套上限：issuer 异常不响应 ctx 取消时 Wait 永不返回，
	// PauseAndDrain/进程 Stop 会被永久挂起（与 CancelJob 同口径）。上限由
	// 调用方以共享截止时间传入——多队列串行等待不得各自重新计时。
	done := make(chan struct{})
	go func() {
		q.executions.Wait()
		close(done)
	}()
	remaining := time.Until(deadline)
	if remaining < 0 {
		remaining = 0
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		Logf("warn", "CA 队列暂停：等待在途执行退出超时（共享截止），继续关闭流程")
		return false
	}
}

func requeueCanceledJob(jobID int) {
	// 部署生命周期全集（downloaded/cleanup_dns/cleanup_warning，即
	// JobLifecycleDownloaded）且证书材料已落库的任务停在部署窗口——转 'queued'
	// 会丢弃已签发证书并触发整轮重签（Issue 快速路径只认 issued/downloaded，
	// cleanup_* 只被部署补扫接管）。保持原状态并把重试窗口推到 now：Resume 的
	// rescanDroppedDeploymentRetries 与 30s 周期补扫同口径覆盖（30s 补扫对
	// cleanup_* 不要求窗口到期，对 downloaded 按剩余 delay 重排）。
	// 判据用 JobLifecycle 而非裸 status=='downloaded'——cleanup_* 同属
	// 「材料已落库、只差部署」，漏收敛会把它们打回 queued 重签烧 CA 配额。
	if liveStatus, hasMaterial, found, err := loadCertJobDeploymentState(jobID); err == nil && found {
		if JobLifecycle(liveStatus) == JobLifecycleDownloaded && hasMaterial {
			// 窗口 + message + updated_at 同写由单源保证（PushCertJobDeploymentWindow）。
			if _, err := PushCertJobDeploymentWindow(db.DB, jobID, CertJobDeploymentWindowPush{
				Message:   "节点生命周期切换，等待恢复部署",
				Where:     "status=?",
				WhereArgs: []any{liveStatus},
			}); err != nil {
				Logf("error", "CA queue: failed to defer deployment retry for canceled job %d: %v", jobID, err)
			}
			return
		}
	}
	// from 集合收紧为 nonTerminalJobStatuses（不含终态 issued/failed）。可达性证据=本文件
	// 的并发部署回调形态：在途执行已把行推进到 'downloaded' 后被生命周期取消
	//（q.ctx 取消）与并发部署回调（30s 补扫/部署 timer）交错——回调 CAS 胜者
	// 已提交 'issued'（或在途执行在 failJob 落 'failed' 后 ctx 才被取消），
	// 本函数随后读到终态行。原实现会把终态无条件拉回 'queued'：issued→整轮
	// 重签（烧 CA 配额）、failed→终态不复活契约被绕过（导入/对账均以终态为
	// 不可复活边界）。'disabled' 本就排除，'downloaded' 由上分支保留部署语义。
	if err := transitionJob(db.DB, jobID, nonTerminalJobStatuses, "queued", map[string]any{"message": "节点生命周期切换，等待恢复签发"}); err != nil && !errors.Is(err, ErrJobTransitionConflict) {
		Logf("error", "CA queue: failed to requeue canceled job %d: %v", jobID, err)
	}
}

func handleQueueExecutionError(jobID int, err error) {
	var roleErr *certificateRoleError
	if errors.As(err, &roleErr) {
		// 主从翻转/角色读取瞬时失败不是 CA 签发失败：复用生命周期取消的
		// queued/部署保留语义，renewal_attempts 不增加，恢复后自动接续。
		requeueCanceledJob(jobID)
		return
	}
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
	explicitID := id
	if id == 0 {
		// Use system default.
		var err error
		id, err = GetDefaultCAProvider()
		if err != nil {
			Logf("error", "CA queue: failed to load default CA provider: %v", err)
			id = 0
		}
	}

	err := scanCAProvider(db.DB.QueryRow("SELECT "+caProviderColumns+" FROM ca_providers WHERE id=? AND enabled=1", id), &p)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return p, fmt.Errorf("load CA provider %d: %w", id, err)
	}
	if err == nil {
		// 归一必须在唯一加载出口完成：所有缓存快照写入点（newCAQueue /
		// enqueueLocked / tick / refreshProviderLocked）都从这里取 provider。
		return normalizeCAProviderSnapshot(p), nil
	}
	// 显式选择的提供商「存在但已禁用」时不得静默改派——回退会
	// 把任务签到另一 CA（消耗其配额）并持久化改写 cert_jobs.ca_provider_id，
	// 规则 UI 仍显示原提供商，仅有一条 resolved= 应用日志。改为显性失败（经
	// enqueueLocked 落 failed + job 日志/审计）。「已删除」仍保留回退：历史/
	// 导入任务的提供商行被清理后，续签链按首个启用提供商延续（用户裁定方案 A）。
	if explicitID != 0 {
		var enabled bool
		var name string
		stateErr := db.DB.QueryRow("SELECT COALESCE(enabled,0), COALESCE(name,'') FROM ca_providers WHERE id=?", explicitID).Scan(&enabled, &name)
		switch {
		case stateErr == nil && !enabled:
			return p, fmt.Errorf("CA 提供商 %d（%s）已禁用：显式选择不会静默改派，请先启用该提供商或修改规则选择", explicitID, name)
		case stateErr == nil:
			// enabled=1 而首查落空=两次查询之间状态被并发改写（或行被重建），
			// 不能当「已禁用」定局，也不能回退——返回可重试错误。
			return p, fmt.Errorf("CA 提供商 %d 状态在解析期间发生变化，请重试", explicitID)
		case !errors.Is(stateErr, sql.ErrNoRows):
			return p, fmt.Errorf("load CA provider %d: %w", explicitID, stateErr)
		}
	}
	// If the requested/default provider is disabled or missing, fall back to the first enabled provider.
	var fallbackID int
	if fallbackErr := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&fallbackID); fallbackErr == nil {
		if explicitID != 0 {
			// 已删除的显式 ID 回退是历史延续，但不得完全无声：点名原 ID 与
			// 实际使用的提供商，便于运维判断是否该清理旧任务。
			Logf("warn", "CA queue: 显式 CA 提供商 %d 已不存在，回退到提供商 %d（历史任务延续，后续签发将持久化该 ID）", explicitID, fallbackID)
		} else {
			// 「跟随默认」的 providerID=0 不可用（默认被删除/被导入写成禁用 ID）
			// 时静默改派到首个启用 provider：任务仍在消耗另一个 CA 的配额，而
			// 规则页仍显示「跟随默认」。回退本身保留（硬失败会让全局签发停摆），
			// 但必须留一条可归因的 warn。
			Logf("warn", "CA queue: 默认 CA 提供商不可用，回退到提供商 %d（规则仍显示「跟随默认」，请修复默认 CA 配置）", fallbackID)
		}
		id = fallbackID
		err = scanCAProvider(db.DB.QueryRow("SELECT "+caProviderColumns+" FROM ca_providers WHERE id=? AND enabled=1", id), &p)
	}
	if err != nil {
		return p, fmt.Errorf("load CA provider %d: %w", id, err)
	}
	return normalizeCAProviderSnapshot(p), nil
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
	maxAttempts := getCertRenewalAttempts()

	var attempts int
	if err := db.DB.QueryRow("SELECT COALESCE(renewal_attempts,0) FROM cert_jobs WHERE id=?", jobID).Scan(&attempts); err != nil {
		Logf("error", "CA queue: failed to read attempts for job %d: %v", jobID, err)
	}
	attempts++

	cooling := computeBackoff(attempts, retryAfter)
	// 库内写规范 UTC（available），日志/审计展示跟随部署时区
	//（global_config.timezone，tz.go 周期刷新）——旧硬编码 UTC+8 在配置
	// 非 Asia/Shanghai 的部署里展示时间漂移。
	available := time.Now().Add(cooling).UTC()
	display := available.In(CurrentLocation())

	if attempts >= maxAttempts {
		message := fmt.Sprintf("CA 频率限制，已达到最大重试次数 %d", maxAttempts)
		err := transitionJob(db.DB, jobID, nonTerminalJobStatuses, "failed", map[string]any{
			"message":            message,
			"renewal_attempts":   attempts,
			"ca_available_after": nil,
			"last_error_code":    nil,
		})
		if err != nil && !errors.Is(err, ErrJobTransitionConflict) {
			Logf("error", "CA queue: failed to mark job %d as failed at max attempts: %v", jobID, err)
			return
		}
		if err == nil {
			WriteCertJobLog(jobID, "ERROR", "failed", message)
			RecordAuditLog("system", "签发失败", "证书任务", FormatAuditDetail(AuditJobPart(jobID), AuditResultPart("max_attempts")), "")
		}
		return
	}

	// available 已是 UTC（上方写入侧口径），不再重复调 .UTC()。
	err := transitionJob(db.DB, jobID, nonTerminalJobStatuses, "waiting_ca", map[string]any{
		"message":            "等待 CA 频率限制冷却",
		"ca_available_after": available.Format("2006-01-02 15:04:05"),
		"last_error_code":    "429",
		"renewal_attempts":   attempts,
	})
	if err != nil && !errors.Is(err, ErrJobTransitionConflict) {
		Logf("error", "CA queue: failed to mark job %d as waiting_ca: %v", jobID, err)
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

// failJobTransition 是失败终态迁移的共享实现（起
// failJobFromStatus 无调用方已删除，本函数唯一消费方为 failJob）：尝试次数
// 封顶文案、消息截断、UPDATE、留痕。
func failJobTransition(jobID int, fromSet []string, message string) {
	// 上限只读一次并复用：getCertRenewalAttempts 每次都点查 global_config（含
	// 越界留痕分支），CA 故障时 N 个任务同轮失败会白读 2N 次并重复写降级告警。
	// 该函数恒返回正数（无效值降级默认并留痕），故无需再判零。
	maxAttempts := getCertRenewalAttempts()
	if attempts := currentRenewalAttempts(jobID); attempts+1 >= maxAttempts {
		message = maxRenewalAttemptsMessage(message, maxAttempts)
	}
	message = truncateJobMessage(message)
	err := transitionJob(db.DB, jobID, fromSet, "failed", map[string]any{
		"message":          message,
		"renewal_attempts": jobSQLExpression("COALESCE(renewal_attempts,0)+1"),
	})
	recordFailedJobTransition(jobID, message, err)
}

// failJob 把任务标记为 failed（来源=任意非终态状态）。
//
// 材料在身的部署生命周期任务（downloaded/cleanup_dns/cleanup_warning）例外：
// 终态 failed 会把新证书从全部自动恢复通道摘除（续期扫描看新证不在窗口、
// 首发重试要求 expires_at IS NULL、部署补扫只收 downloaded/cleanup_*、启动恢复
// 跳过终态、对账只重建 issued/downloaded）→ 材料搁浅且规则无 TLS。与执行超时/
// 生命周期取消同口径：保持可部署态并把部署窗口推到 now，由 30s 补扫接管。
// 代价=失败路径多一次单行读（失败本就是低频路径）。
func failJob(jobID int, message string) {
	if deferDeploymentForMaterialBearingJob(jobID, "deployment_deferred", "签发失败："+message+"（证书材料已落库，等待重新部署）") {
		return
	}
	failJobTransition(jobID, nonTerminalJobStatuses, message)
}

// deferDeploymentForMaterialBearingJob 在任务持有证书材料且处于部署生命周期时
// 把「终态失败」降级为「保持可部署态 + 立即重排部署」。返回 true 表示已按部署
// 重试语义处理，调用方不得再写 failed。读失败/状态不符返回 false（维持既有
// failJob 语义，不因一次读故障把行留在非终态）。
func deferDeploymentForMaterialBearingJob(jobID int, logCode, message string) bool {
	status, hasMaterial, found, err := loadCertJobDeploymentState(jobID)
	if err != nil || !found {
		return false
	}
	if JobLifecycle(status) != JobLifecycleDownloaded || !hasMaterial {
		return false
	}
	// 消息截断在写库与写任务日志之前完成（单源 helper 内部也会截断，此处保持
	// 任务日志与库内文案逐字节一致）。
	message = truncateJobMessage(message)
	// 窗口 + message + updated_at 同写由单源保证（PushCertJobDeploymentWindow）。
	if _, err := PushCertJobDeploymentWindow(db.DB, jobID, CertJobDeploymentWindowPush{
		Message:   message,
		Where:     "status=?",
		WhereArgs: []any{status},
	}); err != nil {
		Logf("error", "CA queue: failed to defer deployment retry for job %d: %v", jobID, err)
		return false
	}
	// 与 deploymentFailed/failJob 同族：非终态收敛必须落 certjob-*.log 业务行。
	WriteCertJobLog(jobID, "WARN", logCode, message)
	return true
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
		Logf("error", "CA queue: failed to mark job %d as failed: %v", jobID, err)
		return
	}
	if err != nil {
		return
	}
	WriteCertJobLog(jobID, "ERROR", "failed", message)
	RecordAuditLog("system", "签发失败", "证书任务", FormatAuditDetail(AuditJobPart(jobID), AuditResultPart("failed")), "")
}
