package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

type importPhase string

const (
	importPhaseSnapshot    importPhase = "snapshot"
	importPhaseCertificate importPhase = "certificate"
	importPhaseCaddy       importPhase = "caddy"
	importPhaseVersion     importPhase = "version"
	importPhaseCommit      importPhase = "commit"
	importPhaseQueue       importPhase = "queue"
	// importPhasePrepare 事务内收尾准备（提交前产物清理计划的收集）失败：
	// 事务已回滚，库内容确定未变——此前的 coordinator 错误缺 phase，响应/
	// 审计缺「数据库未变更」结论，管理员无法判断是否已部分写入。
	importPhasePrepare importPhase = "prepare"
)

var (
	removeImportRuleLogFiles    = services.RemoveRuleLogFiles
	removeImportCertJobLogFiles = services.RemoveCertJobLogFiles
	cancelImportInFlightRuns    = func() {
		if te := services.TaskEngine(); te != nil {
			te.CancelInFlightRuns()
		}
	}
)

// 建会话前两条 500 分支（读取现有规则/开启导入事务）在正常环境不可注入失败，
// 经函数变量替换以钉测「失败必留痕」契约；生产恒为默认实现。
var (
	importRuleIDsForBegin = currentRuleIDs
	importBeginTx         = func(ctx context.Context) (*sql.Tx, error) { return db.DB.BeginTx(context.WithoutCancel(ctx), nil) }
)

type importCoordinatorError struct {
	phase         importPhase
	err           error
	caddyRejected bool
	// action 是本次操作的动作词（「导入」/「还原」）：失败描述的动作前缀必须
	// 跟随调用方语义——自动备份还原失败文案曾恒写「导入失败」，与审计动作
	// 「还原失败」形成双前缀且误导排障。
	action string
}

func (err *importCoordinatorError) actionLabel() string {
	if err.action == "" {
		return "导入"
	}
	return err.action
}

func (err *importCoordinatorError) Error() string { return importFailureAuditDescription(err) }
func (err *importCoordinatorError) Unwrap() error { return err.err }

// actionLabel 返回会话的动作词（「导入」/「还原」）；空值按「导入」处理，
// 文案与审计动作不得出现空动作词。
func (session *configImportSession) actionLabel() string {
	if session.action == "" {
		return "导入"
	}
	return session.action
}

// errImportInfraRead / importInfraReadError：导入校验链里「读取校验所需的
// 现有配置」失败（PRAGMA 列类型门、安全策略 live 回退查询）。与受信代理读
// 失败同族——载荷内容错误仍 400；DB 锁/IO 故障必须 500 + 固定文案，否则
// 管理员把基础设施故障误判为「备份内容非法」而反复更换备份文件，且响应会
// 回显 SQL 驱动文本。
var errImportInfraRead = errors.New("读取校验所需的现有配置失败")

type importInfraReadError struct{ cause error }

func (e *importInfraReadError) Error() string { return errImportInfraRead.Error() }
func (e *importInfraReadError) Unwrap() error { return e.cause }

func importInfraReadFailure(cause error) error { return &importInfraReadError{cause: cause} }

// writeImportChainReadFailure 把校验链上的「基础设施读失败」（受信代理 /
// 整数列门 / 安全策略 live 回退）统一映射为 500 + 固定文案 + 运行日志；
// 非此类错误返回 false，由调用方按 400（导入）或 invalid（预览）处理。
func writeImportChainReadFailure(c *gin.Context, chainErr error) bool {
	var proxyErr *trustedProxyReadError
	if errors.As(chainErr, &proxyErr) {
		writeInternalError(c, http.StatusInternalServerError, errTrustedProxyRead.Error(), proxyErr.Unwrap())
		return true
	}
	var infraErr *importInfraReadError
	if errors.As(chainErr, &infraErr) {
		writeInternalError(c, http.StatusInternalServerError, errImportInfraRead.Error(), infraErr.Unwrap())
		return true
	}
	return false
}

// importFailurePhaseDescription 返回与动作词无关的阶段判定（审计 detail、
// HTTP 文案共用单源）。空串=未知阶段。
//
// 「数据库未变更」的适用边界：除 commit 阶段外的中止都在事务回滚后收尾，
// 库内容确定未变；commit 阶段的失败结果不可判定（数据库/sql 在 Commit 报错
// 时无法区分「未提交」与「已提交但确认丢失」），文案必须如实表述为
// 「提交结果不确定」，不得断言未变更。
func importFailurePhaseDescription(phase importPhase, caddyRejected bool) string {
	switch phase {
	case importPhasePrepare:
		return "准备导入收尾失败，数据库未变更"
	case importPhaseSnapshot:
		return "运行配置快照失败，数据库未变更"
	case importPhaseCertificate:
		return "证书准备失败，数据库未变更"
	case importPhaseCaddy:
		if caddyRejected {
			return "Caddy 验证失败，数据库未变更"
		}
		return "Caddy 应用失败，数据库未变更"
	case importPhaseVersion:
		return "集群版本更新失败，数据库未变更"
	case importPhaseCommit:
		return "数据库提交结果不确定"
	case importPhaseQueue:
		return "数据库已提交，证书任务恢复失败"
	}
	return ""
}

// importFailureAuditDescription 返回带动作前缀的失败描述（*importCoordinatorError
// 的 Error() 与「无动作上下文的调用点」共用；有动作上下文的审计 detail 用
// importFailureAuditDetail，避免动作词重复）。
func importFailureAuditDescription(err error) string {
	var coordinatorErr *importCoordinatorError
	if !errors.As(err, &coordinatorErr) {
		return "导入失败：" + err.Error()
	}
	phase := importFailurePhaseDescription(coordinatorErr.phase, coordinatorErr.caddyRejected)
	if phase == "" {
		return coordinatorErr.actionLabel() + "失败：" + coordinatorErr.err.Error()
	}
	if coordinatorErr.phase == importPhaseQueue {
		return coordinatorErr.actionLabel() + "部分失败（" + phase + "）：" + coordinatorErr.err.Error()
	}
	return coordinatorErr.actionLabel() + "失败（" + phase + "）：" + coordinatorErr.err.Error()
}

// importFailureAuditDetail 返回审计 detail：auditAction 已携带「导入/还原失败」
// 前缀，detail 不再重复动作词（消双前缀），只描述阶段与真实错误。
func importFailureAuditDetail(err error) string {
	// 该文案同时进操作审计（全员可见）与响应：Caddy 应用阶段的失败原文含 admin
	// 端点地址/端口，必须剥离后再出（服务端日志各调用点保留原文）。
	var detail string
	var coordinatorErr *importCoordinatorError
	if !errors.As(err, &coordinatorErr) {
		detail = err.Error()
	} else if phase := importFailurePhaseDescription(coordinatorErr.phase, coordinatorErr.caddyRejected); phase == "" {
		detail = coordinatorErr.err.Error()
	} else {
		detail = phase + "：" + coordinatorErr.err.Error()
	}
	return services.RedactCaddyAdminEndpoint(detail)
}

// importFailureCause 返回协调器包装下的真实错误文本（不带动作/阶段前缀）；
// 非协调器错误原样返回。仅供上文已给出阶段说明的调用点（响应 warnings）使用，
// 避免同一句阶段描述重复两次。
func importFailureCause(err error) string {
	var coordinatorErr *importCoordinatorError
	if errors.As(err, &coordinatorErr) {
		return coordinatorErr.err.Error()
	}
	return err.Error()
}

type configImportSession struct {
	h               *Handlers
	ctx             context.Context
	tx              *sql.Tx
	recovery        importQueueRecovery
	existingRuleIDs []string
	// action 是本次会话的动作词（「导入」/「还原」，由调用方在建会话后立即
	// 写入）：commit 阶段错误必须携带该动作，失败文案/审计才不把还原写成导入。
	action                string
	runtime               *importRuntimeSnapshot
	runtimeApplyAttempted bool
	finished              bool
	closed                bool // close 幂等门：重复收尾不得再次释放共享锁。
	// beginConfigImport 期间 PauseScheduling，会话 close 时恢复——不能用作
	// begin 函数的 defer（该函数在导入体执行前就返回）。
	resumeEngine func()
	// releaseBeforeLock 释放排空之后、caddyOpMu/事务之前取得的资源锁
	// （配置导入的 WAF 文件锁）。close 在 caddyOpMu 之后释放，
	// 保持与获取顺序相反的锁序。
	releaseBeforeLock func()
	// replaceRuleArtifacts 标记本次导入是否替换了规则/证书任务数据面。
	// 仅此情形才允许清理「消失规则」与「失效证书任务」——users-only 等
	// 分类导入必须对 live 的 cert_jobs/证书文件零触碰。
	replaceRuleArtifacts bool
	// wafSnapshot 是导入落盘前的 WAF 文件快照（CRS 整树/xdb/威胁名单）。
	// 落盘发生在事务提交之前：abort 回滚数据库后必须把文件同批回退，
	// commit 成功则丢弃。nil=本次导入未写任何 WAF 文件。
	wafSnapshot *lbbakWafFileSnapshot
	// commitIndeterminate 标记 tx.Commit() 报错：数据库/sql 在 Commit 报错时
	// 无法区分「未提交」与「已提交但确认丢失」，此时文件回退会把「可能已提交
	// 的新代」换成旧代——不确定态禁止回退（只在确定回滚时执行），响应与审计
	// 必须显式给人工核对指引。
	commitIndeterminate bool
	// wafRestoreAttempted/wafRestoreErr 记录 abort 时的文件回退结论，
	// 失败响应据此显性告知文件是否与数据库分叉（不得静默）。
	wafRestoreAttempted bool
	wafRestoreErr       error
	// wafRestoreWarnings 是回退成功但运行时面需重启收敛等说明，随失败响应
	// 一并透出。
	wafRestoreWarnings []string
	// pendingCleanup 是提交成功后待执行的产物清理计划：锁内（事务视图）
	// 只收集判定集并完成 cert_jobs 必要删除，实际删文件/日志/指标的删除动作
	// 拆到 close 释放 caddyOpMu 之后执行；会话锁/窗口持续至清理收尾。
	// 提交结果不确定时同样保留（见 commit），由复核决定是否真的删除。
	pendingCleanup *importArtifactCleanupPlan
	// failureWarnings 是会话收尾阶段产生的、必须随失败响应透出的说明
	// （提交不确定态下的产物清理去向）。与 wafRestoreWarnings 分开：
	// 后者只讲规则库文件的回退结论。
	failureWarnings []string
	// postLockActions 是提交成功后、必须在 caddyOpMu 释放之后同步执行的运行期
	// 收敛动作。用于「收敛本身要自取 CaddyOpLock」的路径（例：自动封禁禁用
	// 收尾 AutobanDisableFlush——非重入锁，在导入临界区内直呼即死锁）。执行点
	// = close() 的 Unlock 之后、调度恢复（finishPostCommitCleanup）之前：恢复
	// 后的首轮任务必须看到已收敛状态。只在提交成功后登记（失败路径不执行）。
	postLockActions []func()
}

// errCertQueueDrainIncomplete 证书队列排空未完成：PauseAndDrain
// 超时后仍有执行中的签发任务——此时开始导入会让证书任务与全量替换并发，
// 明确拒绝（409）而非沿用「已排干」假设。
var errCertQueueDrainIncomplete = errors.New("证书任务执行中，请稍后重试")
var errImportTaskDrainIncomplete = errors.New("在途任务未排空，请稍后重试")

// importInFlightDrainTimeout 导入前排空在途任务的有界等待（历史
// 审计）：与证书队列 PauseAndDrain 的 30s 屏障同量级。自此超时
// fail-closed 拒绝导入（部分 Run 体不消费取消信号），恢复调度并留失败审计，
// 不再让旧任务与全量替换并发。
var importInFlightDrainTimeout = 30 * time.Second

// importCleanupBudget 提交后清理（消失规则产物/孤儿任务行）的独立预算：
// 该段已与请求生命周期解耦（context.WithoutCancel——前端超时/关页不得让
// 私钥残留），因此必须自带时间上界，避免无界后台写拖住导入收尾。
// var 而非 const：测试缝（预算耗尽分支必须可注入才可能钉测）。生产恒为本值。
var importCleanupBudget = 60 * time.Second

// importCleanupShouldStop 在逐规则删除前检查预算（var 而非直接内联
// ctx.Err()：文件/日志删除不消费 ctx，预算是否「在循环内生效」只有可注入才
// 能钉测；生产恒为 ctx.Err() != nil）。
var importCleanupShouldStop = func(ctx context.Context) bool {
	return ctx.Err() != nil
}

// configImportBeginMu 串行化整个导入会话
// Pause/Resume 是单布尔位，若两个导入都先 Pause 再抢 caddyOpMu，先结束者
// Resume 会让后者在调度已恢复的状态下执行。此锁覆盖 Pause→事务→close，
// 后到导入在暂停开始前排队。
var configImportBeginMu sync.Mutex

// importWindowActive 是导入会话的显式活动计数（非零=窗口开启）。
// configImportBusy 不得用 TryLock 探测：任何持锁者（含测试模拟窗口）都会
// 被当成真实导入，锁的生命周期与「窗口是否开启」是两个事实。计数只由
// begin/close 在锁内边界维护，读侧无锁且无假阳性。
var importWindowActive atomic.Int32

// 测试屏障（生产恒 nil）：分别在会话锁获取前与业务 prelock 获取前触发，
// 供锁序测试用通道证明到达点，替代固定 sleep。
var configImportBeginAttemptHook func()
var configImportBeforePrelockHook func()

// importPostCommitCleanupHook 测试屏障（生产恒 nil）：提交后产物清理执行前
// 触发，供锁序钉测断言 Caddy 锁已释放且导入会话锁/窗口仍有效。
var importPostCommitCleanupHook func()

// configImportBusy 探测导入会话是否持有全局导入锁（不阻塞）：启停/控制
// 常驻任务在导入期间必须 409，避免绕过 PauseAndDrain。
func configImportBusy() bool {
	return importWindowActive.Load() > 0
}

// rejectNodeWriteDuringImport：配置导入窗口内
// 节点写端点（注册/审批/拒绝/删除/改访问地址/改站点坐标/清 pin/节点上报等）
// 一律 409 fast-fail。导入事务全量替换 nodes 表：窗口内的节点写入要么被
// 导入覆盖（静默丢失），要么阻塞在 SQLite 写锁上至 busy_timeout（30s）后
// 500——两种形态都比干净 409 差。与 taskmonitor 的调度开关门共用
// configImportBusy 探测，文案同族。
func rejectNodeWriteDuringImport(c *gin.Context) bool {
	return rejectWriteDuringImport(c, "执行节点写操作")
}

// rejectWriteDuringImport 导入窗口内通用写端点快筛。
// 证书配置表（certificate_configs）与 CA 提供商表（ca_providers）都在导入全量
// 替代表清单内：排空结束、导入事务尚未开启的窗口内提交会被导入静默覆盖
// （数据丢失），事务开启后提交则阻塞至 busy_timeout(30s) 后 500。与节点写族
// 同口径 409。证书配置 Create/Update/Delete 与 CA 提供商写端点全族均走本门；
// Update/Delete 虽取 caddyOpMu，但锁只保证串行不提供 fast-fail——排队到导入
// 提交后按陈旧 id 落库同样会改写导入结果，故门必须在取锁之前。
func rejectWriteDuringImport(c *gin.Context, action string) bool {
	if !configImportBusy() {
		return false
	}
	action = strings.ReplaceAll(action, "（配置导入进行中）", "")
	c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict, Message: "配置导入进行中，暂不能" + action})
	return true
}

// failImportBegin 是「建会话前失败」的单一收尾：warn 运行日志 + 失败审计。
// 与事务内的 failImportAbort（回滚→审计）对称——这些分支没有事务可回滚，
// 但同属管理员高危操作被拒的复盘面：此前只有在途任务排空一条留痕，证书队列
// 排空（409）与读规则/开事务（500）完全静默，形成第二套方言。
// detail 是已带阶段与「未执行/未修改」结论的审计文案；审计动作按动作词取
// 字面量（词汇门禁要求静态词条）。返回 cause 供调用方直接作为 begin 的
// error 返回，响应文案与日志同源。
func failImportBegin(action, detail string, cause error) error {
	services.Logf("warn", "配置%s被拒绝：%s（%v）", action, detail, cause)
	if action == "还原" {
		services.RecordAuditLog("system", "还原失败", "配置备份", detail, "")
	} else {
		services.RecordAuditLog("system", "导入失败", "配置备份", detail, "")
	}
	return cause
}

// action 是本次会话的动作词（「导入」/「还原」）——排空失败等建会话前的审计
// 也要带正确动作，不能一律记「导入失败」（自动备份还原路径同样走本函数）。
func (h *Handlers) beginConfigImport(ctx context.Context, action string) (*configImportSession, error) {
	return h.beginConfigImportWithPrelock(ctx, prelockNone, action)
}

// prelockNone 显式表达「无预锁」——与「有预锁」区分，避免调用方误传 nil 顺序
// 参数造成可读性歧义。
func prelockNone() func() { return nil }

// beginConfigImportWithPrelock 在 Pause/Cancel/Wait 排空完成之后、取
// caddyOpMu 与开启事务之前调用 prelock（返回释放函数）。配置导入用它把
// WAF 文件锁放在排空之后：先取锁会让阻塞在 wafFileMu 的更新任务无法被取消。
func (h *Handlers) beginConfigImportWithPrelock(ctx context.Context, prelock func() func(), action string) (*configImportSession, error) {
	if action == "" {
		action = "导入"
	}
	if configImportBeginAttemptHook != nil {
		configImportBeginAttemptHook()
	}
	configImportBeginMu.Lock()
	importWindowActive.Add(1)
	releaseSession := func() {
		importWindowActive.Add(-1)
		configImportBeginMu.Unlock()
	}
	// resumeEngine 必须在 panic 收尾闭包之前声明（闭包捕获它）：引擎暂停成功
	// 后才替换成真实恢复函数，未暂停时保持 no-op。
	resumeEngine := func() {}
	// begin 段的 panic-safe 收尾：BeginMu/导入窗口、引擎暂停、CA 队列 hold、
	// Caddy 锁与 prelock 释放都收在这一个闭包里，按「已取得」标志释放。
	//
	// 为什么必须：begin 段（importRuleIDsForBegin/importBeginTx/finishImportFailure
	// 内部缺陷）一旦 panic，此前没有任何 recover——configImportBeginMu 永久锁死
	// （后续导入全挂）、导入窗口永不为 0（受门端点全 409）、CA 队列 hold 无
	// finish（签发任务停摆），只能重启恢复。清理 goroutine 早已有 recover，
	// begin 段与它不对称。panic 仍继续上抛（gin 500 + 运行日志），只是把
	// 全局资源恢复成可用态。
	var (
		recovery         importQueueRecovery
		holdEstablished  bool
		caddyLockHeld    bool
		prelockRelease   func()
		sessionHandedOff bool
	)
	defer func() {
		recovered := recover()
		if recovered == nil || sessionHandedOff {
			return
		}
		if caddyLockHeld {
			h.caddyOpMu.Unlock()
		}
		if holdEstablished {
			recovery.hold = false
			services.EndConfigImportHold()
			if recovery.manager != nil && recovery.wasActive {
				recovery.manager.Resume()
			}
		}
		resumeEngine()
		if prelockRelease != nil {
			prelockRelease()
		}
		releaseSession()
		services.Logf("error", "配置导入：建会话阶段 panic，已释放导入窗口/Caddy 锁/证书队列 hold: %v", recovered)
		panic(recovered)
	}()
	// 导入将全量替换业务数据——先暂停 tick
	// 派发并取消在途 Scheduled/Periodic/Oneshot Run（Daemon 不在范围），再有界
	// 等待其在途落定，避免其提交落在导入事务之后形成 last-writer-wins。
	// 此前只发取消信号不等待：不消费 rc.Ctx 的 Run 体会在导入期间继续跑完。
	//
	// 顺序铁律（Fix81Inf 复核）：Pause/Cancel/Wait 必须在取 caddyOpMu
	// **之前**。autoban 的 RunAutobanCycle 在 services.CaddyOpLock（=caddyOpMu）
	// 临界区内合并名单；若先持锁再等待，会形成「导入持锁等 Run 退出 ↔ Run 等
	// 锁」的互等到 30s 超时，且该 Run 仍会在导入提交后写库。Pause/Cancel/Wait
	// 不改库，无原子性损失；并发第二个导入同样先排空再阻塞在锁上（无害）。
	engine := services.TaskEngine()
	if engine != nil {
		engine.PauseScheduling()
		resumeEngine = func() { engine.ResumeScheduling() }
	}
	cancelImportInFlightRuns()
	if engine != nil {
		drainCtx, cancel := context.WithTimeout(context.Background(), importInFlightDrainTimeout)
		drained := engine.WaitInFlightRuns(drainCtx)
		cancel()
		if !drained {
			drainDetail := fmt.Sprintf("在途任务未排空（等待上限 %s），%s未执行（配置未修改）", importInFlightDrainTimeout, action)
			failImportBegin(action, drainDetail, errImportTaskDrainIncomplete)
			// 与 close 同序：先恢复本代暂停，再允许下一代导入进入。
			resumeEngine()
			releaseSession()
			return nil, errImportTaskDrainIncomplete
		}
	}
	// CA 队列 PauseAndDrain 必须先于 caddyOpMu——在途
	// 证书部署需要 CaddyOpLock（部署临界区入口即取锁，
	// certissuer.go deployIssuedCertificate/快速路径）；旧顺序「先持锁再排空」
	// 形成自锁：部署 worker 等锁、导入等排空，30s 后必然 409。与上方任务引擎
	// 「先排空再取锁」铁律同序。排空在 WAF 预锁之前，避免持 WAF 锁阻塞更新任务。
	recovery.manager = services.GetCAQueueManager()
	if recovery.manager != nil {
		recovery.wasActive = recovery.manager.IsActive()
		// 屏障先于排空建立（粘性 hold）：排空完成后常驻 cert-issuance 的
		// 有界重拉/角色对账仍可能经 StartACME 重开队列——hold 期间 Start/
		// Resume 只登记意图，导入结束由 recovery.finish 统一兑现。
		recovery.hold = true
		services.BeginConfigImportHold()
		holdEstablished = true
		// 排空结果必须被消费——未完全排空（30s 超时仍有执行中任务）
		// 不得继续导入。
		if !recovery.manager.PauseAndDrain() {
			certDetail := fmt.Sprintf("证书任务执行中，%s未执行（配置未修改）", action)
			failImportBegin(action, certDetail, errCertQueueDrainIncomplete)
			// 先解除 hold 再恢复队列/释放会话锁——否则第二个导入可在锁窗口
			// 内看到「队列 inactive」并在第一个导入 Resume 后与之并发。
			recovery.hold = false
			services.EndConfigImportHold()
			if recovery.wasActive {
				recovery.manager.Resume()
			}
			resumeEngine()
			releaseSession()
			return nil, errCertQueueDrainIncomplete
		}
	}
	releaseBeforeLock := releaseSession
	if prelock != nil {
		if configImportBeforePrelockHook != nil {
			configImportBeforePrelockHook()
		}
		if release := prelock(); release != nil {
			prelockRelease = release
			releaseBeforeLock = func() {
				release()
				releaseSession()
			}
		}
	}
	releaseBegin := func() {
		h.caddyOpMu.Unlock()
		resumeEngine()
		releaseBeforeLock()
	}
	h.caddyOpMu.Lock()
	caddyLockHeld = true
	// 会话建立后，apply→版本写入→清理判定→commit 必须不因客户端断连
	// 切换到已取消上下文；前置排空与加锁仍使用原请求上下文。
	session := &configImportSession{h: h, ctx: context.WithoutCancel(ctx), recovery: recovery, resumeEngine: resumeEngine, releaseBeforeLock: releaseBeforeLock, action: action}
	ruleIDs, err := importRuleIDsForBegin(ctx)
	if err != nil {
		// CA 已暂停：必须在释放会话锁之前恢复既有活动态——否则第二个导入可
		// 在窗口内把「队列 inactive」当作稳定状态，随后与本导入的 Resume 并发。
		err = finishImportFailure(nil, &session.recovery, fmt.Errorf("读取现有规则: %w", err))
		failImportBegin(action, fmt.Sprintf("读取现有规则失败，%s未执行（数据库未修改）", action), err)
		releaseBegin()
		return nil, err
	}
	session.existingRuleIDs = ruleIDs
	session.tx, err = importBeginTx(ctx)
	if err != nil {
		err = finishImportFailure(nil, &session.recovery, err)
		wrapped := fmt.Errorf("开始导入事务: %w", err)
		failImportBegin(action, fmt.Sprintf("开启导入事务失败，%s未执行（数据库未修改）", action), wrapped)
		releaseBegin()
		return nil, wrapped
	}
	sessionHandedOff = true
	return session, nil
}

// respondImportBeginError 导入会话建立失败的统一响应：排空未完成 → 409
// （可重试语义），其余（读规则/开事务）→ 500。
func respondImportBeginError(c *gin.Context, err error) {
	if errors.Is(err, errCertQueueDrainIncomplete) || errors.Is(err, errImportTaskDrainIncomplete) {
		c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict, Message: err.Error()})
		return
	}
	c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "建立导入会话失败，请稍后重试"})
}

func (session *configImportSession) close() {
	if session.closed {
		return
	}
	session.closed = true
	caddyLockReleased := false
	defer func() {
		if !caddyLockReleased {
			session.h.caddyOpMu.Unlock()
		}
		if recovered := recover(); recovered != nil {
			services.Logf("error", "配置%s收尾 panic: %v", session.actionLabel(), recovered)
			session.postLockActions = nil
			session.pendingCleanup = nil
			session.finishPostCommitCleanup()
		}
	}()
	if !session.finished {
		// close 兜底 abort（正常路径 commit/abort 已把 finished 置位才会走到
		// 这之外的分支）：此前 `_ =` 静默丢弃 abort 结果——「导入流程未完成」
		// 的回滚零留痕，排障只能靠翻库猜。会话不携带用户身份，与本文件其余
		// 系统留痕同口径以 system 身份补日志与审计；abort 内部的恢复失败
		// （WAF/证书/运行配置回退）已并入返回值，一并在此留痕。
		abortErr := session.abort(errors.New("导入流程未完成"))
		services.Logf("error", "配置%s收尾：导入流程未完成，已回滚: %v", session.actionLabel(), abortErr)
		services.RecordAuditLog("system", session.actionLabel()+"失败", "配置备份", "导入流程未完成，已回滚", "")
	}
	session.h.caddyOpMu.Unlock()
	caddyLockReleased = true
	// caddyOpMu 释放后立即执行「自取 CaddyOpLock」的提交后收敛（见
	// postLockActions 字段注释）。先于调度恢复：恢复后的首轮任务不得读到
	// 未收敛状态（例：导入停用自动封禁后，恢复的循环若先跑一轮会按陈旧计数桶
	// 评估）。动作自行兜住 panic 之外的一切（各自内部已留痕），此处不吞错。
	if actions := session.postLockActions; len(actions) > 0 {
		session.postLockActions = nil
		for _, action := range actions {
			action()
		}
	}
	plan := session.pendingCleanup
	session.pendingCleanup = nil
	if plan == nil || (plan.empty() && importPostCommitCleanupHook == nil) {
		session.finishPostCommitCleanup()
		return
	}
	// 仅提前释放 caddyOpMu（文件 I/O 不占 Caddy 临界区）；导入会话锁、导入
	// 窗口、任务暂停与 WAF 文件锁保持到清理结束——清理期间写端点一律 409
	// （configImportBusy 门），后台规则库更新任务等 WAF 锁。HTTP 仍在派发后
	// 立即返回。
	session.dispatchPostCommitCleanup(plan)
}

// finishPostCommitCleanup 在空计划或后台清理收尾后恢复调度并释放会话。
// Resume 必须先于串行锁释放，避免下一代 Pause 被本代 Resume 覆盖。
func (session *configImportSession) finishPostCommitCleanup() {
	if session.resumeEngine != nil {
		session.resumeEngine()
	}
	if session.releaseBeforeLock != nil {
		session.releaseBeforeLock()
	}
}

// importCleanupWG 跟踪在途的提交后清理（测试收尾等待，生产零消费）。
var importCleanupWG sync.WaitGroup

// dispatchPostCommitCleanup 异步执行提交后产物清理。清理已用
// context.WithoutCancel + 自带预算与请求生命周期解耦；caddyOpMu 已释放，
// 但会话锁/导入窗口/任务暂停只在清理（含 panic 收尾）结束后释放。
func (session *configImportSession) dispatchPostCommitCleanup(plan *importArtifactCleanupPlan) {
	importCleanupWG.Add(1)
	go func() {
		defer importCleanupWG.Done()
		defer session.finishPostCommitCleanup()
		defer func() {
			if r := recover(); r != nil {
				services.Logf("error", "导入清理：提交后产物清理 panic: %v", r)
			}
		}()
		session.runPostCommitCleanup(plan)
	}()
}

// waitImportCleanup 等待全部在途提交后清理结束（测试收尾单源；生产零调用）。
func waitImportCleanup() { importCleanupWG.Wait() }

func (session *configImportSession) abort(importErr error) error {
	if session.finished {
		return importErr
	}
	// 文件面先回退：WAF 落盘发生在事务提交之前，事务回滚后文件必须回到导入
	// 前状态，否则版本记录与文件分叉。先于下方投影回滚——投影重渲染应按已
	// 恢复的规则树进行。回退失败必须显性告警+审计，不得静默。
	if snapshot := session.wafSnapshot; snapshot != nil {
		session.wafSnapshot = nil
		if session.commitIndeterminate {
			// 提交结果不可判定：文件回退只在确定回滚时执行。此时把可能已提交的
			// 新代覆盖回旧代=制造确定分叉，故保持导入后状态、丢弃快照，并以
			// 审计留痕要求人工核对（响应侧文案由 lbbakWafRollbackWarning 的
			// 不确定态给出）。
			snapshot.discard()
			detail := "数据库提交结果不确定：规则库文件保持导入后状态（未回退）——若提交实际未落地则文件与版本记录分叉，请核对规则库页版本后重新导入或触发规则库更新收敛"
			session.wafRestoreWarnings = append([]string{}, snapshot.warnings...)
			services.Logf("error", "配置%s警告: %s", session.actionLabel(), detail)
			services.RecordAuditLog("system", session.actionLabel()+"警告", "配置备份", detail, "")
		} else {
			session.wafRestoreAttempted = true
			session.wafRestoreWarnings, session.wafRestoreErr = snapshot.restore()
			session.wafRestoreWarnings = append(append([]string{}, snapshot.warnings...), session.wafRestoreWarnings...)
			snapshot.discard()
			if session.wafRestoreErr != nil {
				detail := "规则库文件回退失败（文件与数据库可能分叉）: " + session.wafRestoreErr.Error()
				services.Logf("error", "配置%s警告: %s", session.actionLabel(), detail)
				// 会话上下文不携带用户身份（abort 各调用点自行审计），系统身份
				// 留痕保证警告必达审计库而非只进响应。
				services.RecordAuditLog("system", session.actionLabel()+"警告", "配置备份", detail, "")
			}
			for _, warning := range session.wafRestoreWarnings {
				services.RecordAuditLog("system", session.actionLabel()+"警告", "配置备份", warning, "")
			}
		}
	}
	// 会话内 CLI 预检/强制应用等渲染已按未提交导入内容
	// 重写投影文件——abort 必回滚 tx，磁盘同步回退到已提交态（零 /load；
	// 快照阶段失败等未渲染形态为同字节 no-op）。已持 caddyOpMu（begin 起）。
	session.h.caddyService.RollbackIPListProjectionsToCommittedInLock()
	if session.runtime != nil {
		if session.runtimeApplyAttempted {
			// 事务内 apply 可能已成功写入未提交配置与 LKG。先释放事务写锁，
			// 再以已提交视图重渲染/强制应用：即使恢复 /load 失败，
			// RestoreRuntimeToCommittedInLock 也会把已提交字节写回 LKG。
			certOperation := "导入失败后回退证书文件"
			var certErr error
			if session.commitIndeterminate {
				// Commit 报错不等于实际回滚：禁止先回旧制造确定分叉。已提交视图
				// 重渲染会物化仍存活规则；随后仅对已从该视图消失的受影响规则
				// 恢复快照（通常为空，用于清理未提交新规则的私钥）。
				certOperation = "提交结果不确定后按已提交视图对账证书文件"
				detail := "数据库提交结果不确定：证书文件未直接回退，按已提交视图对账；若对账失败则保留导入后文件，请核对证书后重新导入或重载收敛"
				services.Logf("error", "配置%s警告: %s", session.actionLabel(), detail)
				services.RecordAuditLog("system", session.actionLabel()+"警告", "配置备份", detail, "")
			} else {
				certErr = services.RestoreCertFiles(session.runtime.certFiles)
			}
			recovery := session.h.recoverCommittedViewAfterCommitFailure(session.tx)
			if session.commitIndeterminate {
				certErr = errors.Join(certErr, session.restoreCertsAbsentFromCommittedView())
				// 产物清理去向往响应与审计披露：计划已保留到 close 之后执行，
				// 但不确定态下读者无法从「导入失败」推断磁盘是否已收敛，
				// 必须显性说明（同族 WAF 文件面已有 lbbakWafRollbackWarning）。
				if notice := session.indeterminateCleanupNotice(); notice != "" {
					session.failureWarnings = append(session.failureWarnings, notice)
					services.Logf("warn", "配置%s警告: %s", session.actionLabel(), notice)
					services.RecordAuditLog("system", session.actionLabel()+"警告", "配置备份", notice, "")
				}
			}
			if recovery.runtime != nil {
				// 恢复已提交视图失败=运行配置可能停留在导入候选（传输失败
				// 且 Caddy 已应用/恢复 /load 再失败），而 DB 已回滚。LKG 由
				// RestoreRuntimeToCommittedInLock 钉回已提交字节，但横幅事实
				// 源此前为空——刷新页面后分叉完全不可见。与规则域 apply 失败
				// 同口径持久化失败横幅。
				session.h.recordCaddyApplyFailure(fmt.Errorf("导入失败后恢复已提交运行配置失败: %w", recovery.runtime), recovery.runtime)
			}
			if recovery.db != nil {
				session.h.recordCompensationSideEffects("导入失败后恢复已提交运行配置", recovery.db)
			}
			if certErr != nil {
				session.h.recordCompensationSideEffects(certOperation, certErr)
			}
			importErr = errors.Join(importErr, certErr, recovery.err())
			session.finished = true
			return finishImportFailure(session.tx, &session.recovery, importErr)
		}
		if restoreErr := session.h.restoreImportRuntime(*session.runtime); restoreErr != nil {
			importErr = errors.Join(importErr, fmt.Errorf("恢复运行配置失败: %w", restoreErr))
		}
		// 先回滚未提交事务再钉回（PersistCommittedViewAsLastGoodInLock 的显式
		// 调用契约：渲染读 db.DB，调用方须先回退事务——WAL 下并发读恰好能读到
		// 已提交快照，但不得依赖 journal_mode 保证）。finishImportFailure 对已
		// 回滚事务幂等（ErrTxDone 容忍），下方仍统一走它收尾。
		if rbErr := session.tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			importErr = errors.Join(importErr, fmt.Errorf("回滚未提交导入事务失败: %w", rbErr))
		}
		// 运行配置回弹经 ApplyConfig(persistLastGood=true)：若请求前运行配置
		// 带外漂移（快照≠运行配置），回弹会把该形态写进 LKG，而重启兜底
		// 只应回放「最后一次已提交且已下发」的配置。回弹后把 LKG 钉回已提交
		// 库视图（零 /load）。钉回失败不代表运行配置恢复失败，故独立留痕而
		// 不并入 importErr（避免横幅被误标成「运行配置状态未知」）。
		if pinErr := session.h.pinLastGoodAfterCompensation(); pinErr != nil {
			// 附带失败独立留痕（不与「运行配置是否恢复」混为一谈）：导入会话不携带
			// 用户身份，统一写点以系统身份落审计；不再由本处自造第二份文案，
			// 否则同一次失败会出现两行（helper 时代）或零审计（只 warn）。
			session.h.recordCompensationSideEffects(session.actionLabel()+"未生效回弹", pinErr)
		}
	}
	session.finished = true
	return finishImportFailure(session.tx, &session.recovery, importErr)
}

// restoreCertsAbsentFromCommittedView 只处理提交不确定时「已提交视图中已
// 不存在」的受影响规则。存活规则由 committed-view 渲染负责物化；此子集恢复
// 为空快照可清理实际回滚时未提交新规则遗留的证书与私钥。
func (session *configImportSession) restoreCertsAbsentFromCommittedView() error {
	if session.runtime == nil || len(session.runtime.certFiles) == 0 {
		return nil
	}
	affected := make([]string, 0, len(session.runtime.certFiles))
	for id := range session.runtime.certFiles {
		affected = append(affected, id)
	}
	absentIDs, err := absentRuleIDs(session.cleanupContext(), db.DB, affected)
	if err != nil {
		return fmt.Errorf("读取已提交规则视图以鉴定证书文件失败: %w", err)
	}
	if len(absentIDs) == 0 {
		return nil
	}
	absent := make(services.CertFilesSnapshot, len(absentIDs))
	for _, id := range absentIDs {
		absent[id] = session.runtime.certFiles[id]
	}
	if err := services.RestoreCertFiles(absent); err != nil {
		return fmt.Errorf("清理已提交视图中不存在的规则证书失败: %w", err)
	}
	return nil
}

// cleanupContext 返回导入收尾各阶段使用的 ctx：保留请求 ctx 的值（日志/审计
// 归因）但与其取消解耦——收尾阶段的产物清理/对账不得因前端关页半途而废。
func (session *configImportSession) cleanupContext() context.Context {
	if session.ctx == nil {
		return context.Background()
	}
	return context.WithoutCancel(session.ctx)
}

// absentRuleIDs 返回 ids 中在 queryer 视图里已不存在的子集（判定按视图单源：
// 事务视图用于提交前收集，已提交视图用于锁外复核）。
func absentRuleIDs(ctx context.Context, q rowsQueryer, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	currentIDs, err := ruleIDsFromQueryer(ctx, q)
	if err != nil {
		return nil, err
	}
	live := make(map[string]struct{}, len(currentIDs))
	for _, id := range currentIDs {
		live[id] = struct{}{}
	}
	absent := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, alive := live[id]; !alive {
			absent = append(absent, id)
		}
	}
	return absent, nil
}

// indeterminateCleanupNotice 描述提交结果不确定时「消失规则产物」的去向，
// 随失败响应 warnings 透出并落审计。计划已保留到 close 之后执行，但能否执行
// 取决于提交是否真的落地——此处按已提交视图给出可核对的事实，不预判结果：
// 视图仍含这些规则=提交未落地、无需清理；已不含=收尾时删除。
func (session *configImportSession) indeterminateCleanupNotice() string {
	plan := session.pendingCleanup
	if plan.empty() {
		return ""
	}
	if len(plan.disappeared) == 0 {
		return "数据库提交结果不确定：无材料规则的残留证书文件清理将按已提交视图复核后执行（实际回滚时自动跳过）"
	}
	gone, err := absentRuleIDs(session.cleanupContext(), db.DB, plan.disappeared)
	if err != nil {
		return fmt.Sprintf("数据库提交结果不确定：本次导入移除规则的证书文件/指标/日志清理未能核对已提交视图（%v）——请人工核对 certs/ 与各日志目录", err)
	}
	if len(gone) == 0 {
		return "数据库提交结果不确定：已提交视图仍包含本次导入替换的规则（提交实际未落地），无需清理产物"
	}
	return fmt.Sprintf("数据库提交结果不确定：已按已提交视图确认本次导入移除的 %d 条规则，其证书文件/指标/日志将在导入收尾后清理（实际回滚时自动跳过）", len(gone))
}

func (session *configImportSession) commit(affectedRuleIDs []string, certificates []importCertificate) error {
	runtime, err := session.h.snapshotImportRuntime(affectedRuleIDs)
	if err != nil {
		return &importCoordinatorError{phase: importPhaseSnapshot, err: session.abort(err), action: session.action}
	}
	session.runtime = &runtime
	if err := materializeImportCertificates(certificates); err != nil {
		return &importCoordinatorError{phase: importPhaseCertificate, err: session.abort(err), action: session.action}
	}
	// v2 导入事务全量重插 cert_jobs（restoreTable 保留原 id），证书
	// 候选必须读事务自身——经已提交视图会拿到将被替换的旧行，旧 PEM 覆写导入
	// 刚落盘的新证书文件。导入期 CA 队列已 PauseAndDrain，无并发证书提交。
	// 导入强制重载——证书已在上方落盘，生成期比对相等，
	// 非强制会被 errSameConfig 短路（旧证书继续服务）。

	// 2026-09-06 裁定 ④' 边界补齐：导入同样过 Caddy CLI 校验层（校验输入=
	// 事务视图渲染）。校验器不可用放行——下方 ApplyConfigFromTxCertAwareForce
	// 仍是门控（全有全无）。
	// rulesWrittenInTx=true：导入事务可能重插 lb_rules（含新 acme 规则），
	// 谓词 miss 补查必须开启（证书候选源为已提交视图时新规则会被子查询排除）。
	if err := session.h.caddyService.ValidateTxRenderViaCLI(session.tx, true); err != nil && !errors.Is(err, services.ErrCLIValidatorUnavailable) {
		return &importCoordinatorError{phase: importPhaseCaddy, err: session.abort(err), caddyRejected: services.IsConfigRejected(err), action: session.action}
	}
	session.runtimeApplyAttempted = true
	appliedConfig, applyErr := session.h.caddyService.ApplyConfigFromTxCertAwareForce(session.tx)
	if applyErr != nil {
		return &importCoordinatorError{phase: importPhaseCaddy, err: session.abort(applyErr), caddyRejected: services.IsConfigRejected(applyErr), action: session.action}
	}
	if err := services.BumpClusterVersion(session.ctx, session.tx); err != nil {
		return &importCoordinatorError{phase: importPhaseVersion, err: session.abort(err), action: session.action}
	}
	// 提交后产物清理的判定集必须在事务视图内收集（此时规则/证书任务世界
	// 已是导入后状态），cert_jobs 的必要删除也在事务内完成；实际删产物动作
	// 记录成计划，等 close 释放 caddyOpMu 后执行——千级规则导入的文件删除
	// 不再阻塞配置写/重载窗口，会话锁/窗口则延长到清理结束。
	cleanupPlan, cleanupErr := session.collectPostCommitCleanup()
	if cleanupErr != nil {
		// 事务回滚、库未变更：必须带 phase，否则响应/审计缺「数据库未变更」结论
		// （与同族 abort 文案不对称）。
		return &importCoordinatorError{phase: importPhasePrepare, err: session.abort(cleanupErr), action: session.action}
	}
	// 计划在提交前即挂到会话：提交成功时 close 在 Caddy 锁外执行；提交报错
	// （结果不确定）时同样保留——那时规则行可能已消失，本计划是这些规则
	// 私钥/指标/日志的唯一清理线索。runPostCommitCleanup 先按已提交视图复核，
	// 实际回滚时判定集为空、零删除。
	session.pendingCleanup = cleanupPlan
	if err := commitTx(session.tx); err != nil {
		// Commit 报错=结果不可判定（可能已落地但确认丢失）：先标记再 abort，
		// 文件面据此跳过回退（回退只在确定回滚时执行）。提交入口统一走
		// commitTx（测试缝单源）——导入的「不确定态」语义（WAF 文件不回退 +
		// 人工核对指引）只有可注入才可能钉测。
		session.commitIndeterminate = true
		return &importCoordinatorError{phase: importPhaseCommit, err: session.abort(err), action: session.action}
	}
	// 数据库已提交：WAF 文件保持导入后的状态，快照只服务回滚，丢弃。
	if snapshot := session.wafSnapshot; snapshot != nil {
		session.wafSnapshot = nil
		snapshot.discard()
	}
	// commit 成功后才落 last-known-good（事务内 apply 有意不写），字节即
	// 刚被 Caddy 接受的候选——导入的 LKG 因此恒为已提交视图。
	session.h.caddyService.PersistLastGoodBytesInLock(appliedConfig)
	session.runtime = nil
	// 清理计划已在提交前挂到会话（session.pendingCleanup），实际删除由 close
	// 在 Caddy 锁外执行；清理失败不否决导入（数据已提交），留痕审计 + 日志。
	if err := session.recovery.finish(); err != nil {
		session.finished = true
		return &importCoordinatorError{phase: importPhaseQueue, err: err, action: session.action}
	}
	session.finished = true
	return nil
}

func importFailurePhase(err error) importPhase {
	var coordinatorErr *importCoordinatorError
	if errors.As(err, &coordinatorErr) {
		return coordinatorErr.phase
	}
	return ""
}

func importFailureCaddyRejected(err error) bool {
	var coordinatorErr *importCoordinatorError
	return errors.As(err, &coordinatorErr) && coordinatorErr.phase == importPhaseCaddy && coordinatorErr.caddyRejected
}

// importArtifactCleanupPlan 是提交后产物清理的待删集：锁内只做判定（按事务
// 视图）与必要的事务内写，删除动作在 caddyOpMu 释放后、会话锁/窗口有效期内执行。
type importArtifactCleanupPlan struct {
	// disappeared 是本次导入后已不在库内的旧规则（证书材料/指标/日志）。
	disappeared []string
	// withoutMaterial 是仍在库内但已无任何可用证书材料的规则（仅删残留
	// 证书文件）。
	withoutMaterial []string
}

func (plan *importArtifactCleanupPlan) empty() bool {
	return plan == nil || (len(plan.disappeared) == 0 && len(plan.withoutMaterial) == 0)
}

// rowsQueryer 是「同一套判定查询既跑在事务视图也跑在已提交视图上」的查询面：
// 导入清理既在导入事务（提交前收集）又在锁外已提交视图复核，证书配置的引用
// 守卫同样一份查询既跑写入事务又在删除路径跑已提交库。两者共用本接口，避免
// 每个域各写一份同形接口（形状变化时漏改一处即编译期静默分叉）。
type rowsQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// ruleIDsFromQueryer 读取规则集（queryer=导入事务或已提交库）。
func ruleIDsFromQueryer(ctx context.Context, q rowsQueryer) ([]string, error) {
	rows, err := q.QueryContext(ctx, "SELECT caddy_id FROM lb_rules")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ruleIDs := make([]string, 0)
	for rows.Next() {
		var ruleID string
		if err := rows.Scan(&ruleID); err != nil {
			return nil, err
		}
		ruleIDs = append(ruleIDs, ruleID)
	}
	return ruleIDs, rows.Err()
}

// collectPostCommitCleanup 在导入事务视图内收集提交后待清理的产物集，并在
// 事务内完成 cert_jobs 的必要删除（孤儿行 + 已非 ACME 签发态的行）。返回 nil
// 表示本次导入未替换规则/证书任务面（users-only 等分类导入对 live 数据零触碰）。
//
// v2/v1 全量替换导入都清光 lb_rules 后重插（v1 还换新 caddy_id）：旧规则的
// 证书文件（含 ACME 私钥）此前只写不删，与 DeleteRule「规则消失→密钥删除」的
// 约定矛盾，卷读权限者可恢复管理员以为已删除的密钥；v1 路径还遗留指向已删
// caddy_id 的孤儿 cert_jobs 行（终态行永不清理，任务列表噪音）。判定必须在
// 事务视图内做——提交后按 live 视图求差会被并发写污染。
func (session *configImportSession) collectPostCommitCleanup() (*importArtifactCleanupPlan, error) {
	if !session.replaceRuleArtifacts || session.tx == nil {
		return nil, nil
	}
	ctx := session.ctx
	// 与 v2 导入事务内同语句（幂等重复无害）：两处删除都是派生数据清理，
	// 放事务内=与规则替换同生共死，失败随导入一起回滚。
	if _, err := session.tx.ExecContext(ctx,
		`DELETE FROM cert_jobs WHERE NOT EXISTS (SELECT 1 FROM lb_rules WHERE lb_rules.caddy_id = cert_jobs.rule_id)`); err != nil {
		return nil, fmt.Errorf("清理孤儿证书任务失败: %w", err)
	}
	if _, err := session.tx.ExecContext(ctx,
		`DELETE FROM cert_jobs WHERE rule_id IN (SELECT caddy_id FROM lb_rules WHERE NOT (COALESCE(enable_tls,0)=1 AND COALESCE(tls_source,'manual')='acme_dns'))`); err != nil {
		return nil, fmt.Errorf("清理失效证书任务失败: %w", err)
	}
	plan := &importArtifactCleanupPlan{}
	currentIDs, err := ruleIDsFromQueryer(ctx, session.tx)
	if err != nil {
		// 判定集读取失败不否决导入：产物清理是提交后的 best-effort，任务行
		// 已在事务内删净；留痕后按空集继续。
		services.Logf("error", "导入清理：读取导入后规则集失败（跳过消失规则产物清理）: %v", err)
		services.RecordAuditLog("system", "清理失败", "证书产物", fmt.Sprintf("导入后清理消失规则产物失败（读取导入后规则集）：%v", err), "")
	} else {
		current := make(map[string]struct{}, len(currentIDs))
		for _, id := range currentIDs {
			current[id] = struct{}{}
		}
		for _, id := range session.existingRuleIDs {
			if _, alive := current[id]; !alive {
				plan.disappeared = append(plan.disappeared, id)
			}
		}
	}
	withoutMaterial, err := rulesWithoutUsableCertMaterial(ctx, session.tx)
	if err != nil {
		services.Logf("error", "导入清理：判定无证书材料规则失败（跳过材料清理）: %v", err)
		services.RecordAuditLog("system", "清理失败", "证书产物", fmt.Sprintf("导入后清理无材料规则证书文件失败（判定集）：%v", err), "")
	} else {
		plan.withoutMaterial = withoutMaterial
	}
	return plan, nil
}

// runPostCommitCleanup 执行提交后的产物删除（证书文件/指标/规则与证书日志）。
// 调用点必须已释放 caddyOpMu，且仍持有导入会话锁/窗口直至本函数返回；
// 锁内只收集判定集。提交已落地，任何失败只留痕不否决导入。
func (session *configImportSession) runPostCommitCleanup(plan *importArtifactCleanupPlan) {
	if importPostCommitCleanupHook != nil {
		importPostCommitCleanupHook()
	}
	if plan.empty() {
		return
	}
	// 提交已落地 → 清理不受客户端生命周期左右。请求 ctx 在前端超时/关页/网关
	// 断连时被取消，旧实现据此在读取规则集处早退，整段清理（含已不在库内的
	// 规则私钥、指标、规则/证书日志）一次不执行——数据卷里保留着管理员以为
	// 已随规则删除的 ACME 私钥。WithoutCancel 保留 ctx 值（日志/审计归因）并
	// 叠加有界预算，避免无界后台写。预算必须覆盖循环内的每一项：文件/日志
	// 删除不消费 ctx，逐规则千级时会把「导入窗口 409」拖成无上界。
	ctx, cancel := context.WithTimeout(session.cleanupContext(), importCleanupBudget)
	defer cancel()
	// 删除前按已提交视图复核，过滤带外复活/已有材料的规则。正常下一代导入
	// 与证书写操作由持续导入窗口排在本清理之后，不会再穿越「复核 → 删除」；
	// RemoveCertFiles 与证书写入另共用证书锁，避免撕裂进行中的文件写入。
	disappeared, err := absentRuleIDs(ctx, db.DB, plan.disappeared)
	if err != nil {
		services.Logf("error", "导入清理：读取当前规则失败（跳过孤儿清理）: %v", err)
		services.RecordAuditLog("system", "清理失败", "证书产物", fmt.Sprintf("导入后清理消失规则产物失败（读取规则集）：%v", err), "")
		return
	}
	withoutMaterial := plan.withoutMaterial
	if len(withoutMaterial) > 0 {
		liveWithoutMaterial, err := rulesWithoutUsableCertMaterial(ctx, db.DB)
		if err != nil {
			services.Logf("error", "导入清理：复核无证书材料规则失败（跳过材料清理）: %v", err)
			services.RecordAuditLog("system", "清理失败", "证书产物", fmt.Sprintf("导入后清理无材料规则证书文件失败（复核判定集）：%v", err), "")
			withoutMaterial = nil
		} else {
			still := make(map[string]struct{}, len(liveWithoutMaterial))
			for _, id := range liveWithoutMaterial {
				still[id] = struct{}{}
			}
			filtered := make([]string, 0, len(withoutMaterial))
			for _, id := range withoutMaterial {
				if _, ok := still[id]; ok {
					filtered = append(filtered, id)
				}
			}
			withoutMaterial = filtered
		}
	}
	// 逐项计数：摘要审计必须按实际结果给出口径（成功 / 部分失败 / 预算耗尽），
	// 否则失败项被「已清理证书文件、指标与日志」掩盖，运维据此误判磁盘已收敛。
	var cleaned, failedCert, failedMetrics, failedRuleLog, failedCertJobLog, unprocessed int
	for index, id := range disappeared {
		if importCleanupShouldStop(ctx) {
			unprocessed = len(disappeared) - index
			break
		}
		cleaned++
		if err := services.RemoveCertFiles(id); err != nil {
			failedCert++
			services.Logf("warn", "导入清理：删除消失规则 %s 的证书文件失败: %v", id, err)
			// 与「无材料规则」路径（removeCertFilesForRules）同口径：同一类
			// 失败必须同样进审计页，不能只有 warn。
			services.RecordAuditLog("system", "清理失败", "证书产物", fmt.Sprintf("导入后清理规则 %s 的证书文件失败：%v", id, err), "")
		}
		if db.MetricsDB != nil {
			if _, err := db.MetricsDB.ExecContext(ctx, "DELETE FROM metrics_history WHERE rule_id=?", id); err != nil {
				failedMetrics++
				services.Logf("error", "导入清理：删除消失规则 %s 的指标失败: %v", id, err)
			}
		}
		if err := removeImportRuleLogFiles(id); err != nil {
			failedRuleLog++
			services.Logf("error", "导入清理：删除消失规则 %s 的规则日志失败: %v", id, err)
			services.RecordAuditLog("system", "清理失败", "规则日志", fmt.Sprintf("导入后清理规则 %s 的规则日志失败：%v", id, err), "")
		}
		if err := removeImportCertJobLogFiles(id); err != nil {
			failedCertJobLog++
			services.Logf("error", "导入清理：删除消失规则 %s 的证书日志失败: %v", id, err)
			services.RecordAuditLog("system", "清理失败", "证书日志", fmt.Sprintf("导入后清理规则 %s 的证书日志失败：%v", id, err), "")
		}
	}
	cleanedMaterial := 0
	materialUnprocessed := 0
	if importCleanupShouldStop(ctx) {
		materialUnprocessed = len(withoutMaterial)
	} else {
		cleanedMaterial, materialUnprocessed = removeCertFilesForRules(ctx, withoutMaterial)
	}
	unprocessed += materialUnprocessed
	if unprocessed > 0 {
		detail := fmt.Sprintf("导入后产物清理预算（%s）耗尽：剩余 %d 条规则的证书文件/指标/日志未处理，请核对 certs/ 与日志目录后人工清理", importCleanupBudget, unprocessed)
		services.Logf("error", "导入清理：%s", detail)
		services.RecordAuditLog("system", "清理失败", "证书产物", detail, "")
	}
	if cleanedMaterial > 0 {
		services.RecordAuditLog("system", "清理", "证书产物", fmt.Sprintf("导入后 %d 条规则已无任何可用证书材料，其残留证书文件已清理", cleanedMaterial), "")
	}
	if total := len(disappeared); total > 0 {
		failures := failedCert + failedMetrics + failedRuleLog + failedCertJobLog
		if failures == 0 && unprocessed == 0 {
			services.RecordAuditLog("system", "清理", "证书产物", fmt.Sprintf("导入移除 %d 条规则，已清理其证书文件、指标与日志（证书任务行随导入事务清理）", total), "")
		} else {
			// 审计真实性：有失败/未处理项时不得断言「已清理」。
			services.RecordAuditLog("system", "清理失败", "证书产物", fmt.Sprintf(
				"导入移除 %d 条规则，产物清理未全部完成：已处理 %d 条（证书文件失败 %d、指标失败 %d、规则日志失败 %d、证书日志失败 %d），预算耗尽未处理 %d 条——明细见同批次「清理失败」记录",
				total, cleaned, failedCert, failedMetrics, failedRuleLog, failedCertJobLog, unprocessed), "")
		}
	}
}

// rulesWithoutUsableCertMaterial 返回「仍存在但已无任何可用证书材料」的规则
// id：手动证书材料在库（tls_source=manual 且 cert/key 非空）或有域名适用的
// 任务材料时跳过。tls_source 读取口径与渲染/写侧全族一致
// （COALESCE(tls_source,'manual')）：NULL 存量行按渲染口径视为 manual——渲染
// 会按 manual 供证，清理判定若按空串处理会把仍在服务的证书文件删掉（磁盘/DB
// 分叉）。只做判定不删文件——判定集在导入事务视图内收集、删除动作在
// 锁外执行或复核（见 collectPostCommitCleanup/runPostCommitCleanup）。
//
// 查询面固定为两条（规则集 + 材料行集）并在内存中配对：原实现逐规则 2 次查询
// （域名 + 任务材料）是 N+1，千级规则导入在持 caddyOpMu 的提交窗口里放大 2N 次
// DB 往返，把配置写/重载全部阻塞在该窗口。
func rulesWithoutUsableCertMaterial(ctx context.Context, q rowsQueryer) ([]string, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT caddy_id, COALESCE(tls_source,'manual'), COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(domain,'') FROM lb_rules`)
	if err != nil {
		return nil, fmt.Errorf("读取规则证书形态: %w", err)
	}
	type ruleCertShape struct {
		id        string
		tlsSource string
		domain    string
		hasManual bool
	}
	var rules []ruleCertShape
	for rows.Next() {
		var rule ruleCertShape
		var tlsCert, tlsKey string
		if err := rows.Scan(&rule.id, &rule.tlsSource, &tlsCert, &tlsKey, &rule.domain); err != nil {
			rows.Close()
			return nil, fmt.Errorf("读取规则行: %w", err)
		}
		rule.hasManual = rule.tlsSource == "manual" && strings.TrimSpace(tlsCert) != "" && strings.TrimSpace(tlsKey) != ""
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("遍历规则集: %w", err)
	}
	rows.Close()

	// 一次取全部「持有可用材料」的任务行（谓词单源：非 disabled + PEM 非空，
	// 与渲染候选/启动物化/文件对账同语义）。
	materialByRule := make(map[string][]string)
	materialRows, err := q.QueryContext(ctx, `SELECT rule_id, COALESCE(domain,'') FROM cert_jobs
		WHERE `+services.CertJobMaterialPredicateSQL(""))
	if err != nil {
		// 判定面不可读时不得按「无材料」清理（会误删仍在服务的证书文件）。
		return nil, fmt.Errorf("查询任务材料: %w", err)
	}
	for materialRows.Next() {
		var ruleID, jobDomain string
		// 逐行 Scan 失败必须与规则行同一收尾（关闭并返回错误）：rows.Err() 不
		// 覆盖 Scan 错误，静默 continue 会把「读取未知」降级成「该行无材料」，
		// 对应规则随即被判为无材料并在导入清理中删除仍在服务的证书文件——
		// 与本函数 fail-closed 契约相反。
		if err := materialRows.Scan(&ruleID, &jobDomain); err != nil {
			materialRows.Close()
			return nil, fmt.Errorf("读取任务材料行: %w", err)
		}
		materialByRule[ruleID] = append(materialByRule[ruleID], jobDomain)
	}
	if err := materialRows.Err(); err != nil {
		materialRows.Close()
		return nil, fmt.Errorf("遍历任务材料集: %w", err)
	}
	materialRows.Close()

	ids := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.hasManual {
			continue
		}
		// 域名适用性复核（旧域残留行不算可用材料）——与 certJobRuleApplicable
		// 同语义：两侧均须可规范化且规范形式全等。口径声明：域名等值是比
		// 证书覆盖更严的近似（证书 SAN 可能覆盖规则域名之外的名称，反向不
		// 成立——任务域名与规则域名等价才认定材料可用），误删方向从严。
		usable := 0
		ruleCanonical, ruleErr := services.CanonicalACMEDomains(rule.domain)
		if ruleErr == nil {
			for _, jobDomain := range materialByRule[rule.id] {
				if jobCanonical, jobErr := services.CanonicalACMEDomains(jobDomain); jobErr == nil && jobCanonical == ruleCanonical {
					usable++
					break
				}
			}
		}
		if usable > 0 {
			continue
		}
		ids = append(ids, rule.id)
	}
	return ids, nil
}

// removeCertFilesForRules 删除给定规则的残留证书/私钥文件，返回（实际清理
// 数, 预算耗尽未处理数）（幂等 best-effort，单规则失败仅告警留痕）。
//
// 逐项检查 importCleanupShouldStop：此前本通道只在进入前判一次 60s 预算，
// 「无材料规则」批量（可含全部非 TLS 规则）会在预算耗尽后继续跑完——导入
// 会话锁（写端点 409）与任务调度暂停被无上界拖长，慢卷/NFS 挂起时单次
// RemoveCertFiles 无超时。
func removeCertFilesForRules(ctx context.Context, ruleIDs []string) (cleaned, unprocessed int) {
	for index, id := range ruleIDs {
		if importCleanupShouldStop(ctx) {
			unprocessed = len(ruleIDs) - index
			break
		}
		if err := services.RemoveCertFiles(id); err != nil {
			services.Logf("warn", "导入清理：删除无材料规则 %s 的证书文件失败: %v", id, err)
			services.RecordAuditLog("system", "清理失败", "证书产物", fmt.Sprintf("导入后清理规则 %s 的残留证书文件失败：%v", id, err), "")
			continue
		}
		cleaned++
	}
	return cleaned, unprocessed
}
