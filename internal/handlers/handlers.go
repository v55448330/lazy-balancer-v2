package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

const compensationTimeout = 10 * time.Second

type Handlers struct {
	cfg               *config.Config
	caddyService      *services.CaddyService
	metricsService    *services.MetricsService
	syncService       *services.SyncService
	clusterService    *services.ClusterService
	caProviderService *services.CAProviderService
	removeCertFiles   func(string) error
	caddyOpMu         caddyOpMutex // 委托 services 共享实例（零值可用——测试直构安全）
}

type Dependencies struct {
	Config            *config.Config
	CaddyService      *services.CaddyService
	MetricsService    *services.MetricsService
	SyncService       *services.SyncService
	ClusterService    *services.ClusterService
	CAProviderService *services.CAProviderService
}

func (h *Handlers) removeRuleCertFiles(ruleID string) error {
	if h.removeCertFiles != nil {
		return h.removeCertFiles(ruleID)
	}
	return services.RemoveCertFiles(ruleID)
}

func NewHandlers(deps Dependencies) *Handlers {
	return &Handlers{
		cfg:               deps.Config,
		caddyService:      deps.CaddyService,
		metricsService:    deps.MetricsService,
		syncService:       deps.SyncService,
		clusterService:    deps.ClusterService,
		caProviderService: deps.CAProviderService,
	}
}

// caddyOpMutex 零值锁类型：全部操作委托 services.CaddyOpLock 共享实例
// （后台 Force 重载与 handler 写路径全程互斥；零值可用——测试中
// &Handlers{...} 直构无需初始化）。
type caddyOpMutex struct{}

func (caddyOpMutex) Lock()         { services.CaddyOpLock.Lock() }
func (caddyOpMutex) Unlock()       { services.CaddyOpLock.Unlock() }
func (caddyOpMutex) TryLock() bool { return services.CaddyOpLock.TryLock() }

func compensationContext(requestCtx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(requestCtx), compensationTimeout)
}

// caddyWriteCtx 返回 Caddy 写事务内语句的 ctx：保留请求值（日志/追踪字段），
// 但解除客户端断连/超时。事务本身已经用同一口径 BEGIN（见 beginCaddyWriteTx）
// ——若语句仍绑请求 ctx，断连会精确落在写库段把已开始的渲染/校验/提交链中止，
// 与「已开始的渲染、CLI 校验与 /load 必须继续在同一数据库视图完成」的契约相反
// （表现是「保存被放弃」+ 请求 ctx 的 context canceled，而 BEGIN 的解耦毫无意义）。
func caddyWriteCtx(c *gin.Context) context.Context {
	return context.WithoutCancel(c.Request.Context())
}

// beginCaddyWriteTx 保持请求值但解除客户端断连/超时对事务的隐式回滚。
// 已开始的渲染、CLI 校验与 /load 必须继续在同一数据库视图完成并走既有
// 提交/补偿分类，不能让 database/sql 在后台回滚后把中止误报成配置拒绝。
// 事务内的每条语句必须用 caddyWriteCtx(c)（同一口径），否则契约只在 BEGIN 成立。
func beginCaddyWriteTx(c *gin.Context) (*sql.Tx, error) {
	return db.DB.BeginTx(caddyWriteCtx(c), nil)
}

type EnableCertJobAction int

const (
	EnableCertJobCreate EnableCertJobAction = iota
	EnableCertJobKeep
	EnableCertJobResume
	EnableCertJobRetry
	EnableCertJobRenew
	EnableCertJobInProgress
)

func ShouldRenewIssuedCert(now, expiresAt time.Time, renewalDays int) bool {
	renewalTime := expiresAt.AddDate(0, 0, -renewalDays)
	return !now.Before(renewalTime)
}

func ResolveEnableCertJobAction(hasJob bool, status string, expiresAt *time.Time, now time.Time, renewalDays int) EnableCertJobAction {
	if !hasJob {
		return EnableCertJobCreate
	}
	if (status == "issued" || status == "disabled" || status == "failed") && expiresAt != nil {
		if !ShouldRenewIssuedCert(now, *expiresAt, renewalDays) {
			if status == "issued" {
				return EnableCertJobKeep
			}
			return EnableCertJobResume
		}
		if status == "issued" {
			return EnableCertJobRenew
		}
		return EnableCertJobRetry
	}
	// issued 但缺到期日无从判定是否
	// 临期——此前落 InProgress，续签扫描按 expires_at 非空查询故永不可见。
	// 按 Retry 重排队（与 failed/disabled 的同形兜底一致）。
	if status == "issued" && expiresAt == nil {
		return EnableCertJobRetry
	}
	if status == "failed" || status == "disabled" {
		return EnableCertJobRetry
	}
	return EnableCertJobInProgress
}

func boolText(value bool) string {
	if value {
		return "启用"
	}
	return "禁用"
}

// caddyApplyFailureLabel 是应用失败横幅的状态断言（两态，单源）：
//   - 恢复（快照重放/已提交视图重载）成功 ⇒ 「旧配置已保留」是事实；
//   - 恢复失败 ⇒ 运行配置可能停留候选态，「旧配置已保留」会与事实相反
//     （管理员据此判断要不要回退），必须显式降级为状态未知。
const caddyApplyRestoreFailedLabel = "运行配置状态未知，恢复失败"
const caddyApplyOldConfigKeptLabel = "旧配置已保留"

func caddyApplyFailureLabel(restoreErr error) string {
	if restoreErr != nil {
		return caddyApplyRestoreFailedLabel
	}
	return caddyApplyOldConfigKeptLabel
}

// recordCaddyApplyResult persists the last apply outcome and leaves an audit
// trail. Failures keep the previous Caddy config running, so the error must
// survive restarts and async paths to stay visible to operators.
func (h *Handlers) recordCaddyApplyResult(err error) {
	if err == nil {
		// 渲染降级（如受信代理设置读取失败按未启用渲染）已随
		// 配置成功应用——降级不是应用失败，横幅不得被成功清除吞掉。事务内
		// apply 不写主库（避免与未提交事务争写锁），由本函数在 commit 后落库；
		// 下次干净渲染（LastRenderDegradation 归空）恢复常规清除。
		if degraded := services.LastRenderDegradation(); degraded != "" {
			// 事务内 apply 暂缓的降级审计在此补落（commit 已成功，
			// 降级描述的是真实生效的已提交配置）；非事务路径已即时落过，取不到。
			if pending := services.TakePendingRenderDegradationAudit(); pending != "" {
				services.RecordAuditLog("system", "应用降级", "Caddy配置", pending, "")
			}
			persistCaddyApplyBanner(degraded)
			return
		}
		if db.DB != nil {
			if _, err := db.DB.Exec(`UPDATE global_config SET caddy_apply_error='' WHERE id=1 AND caddy_apply_error<>''`); err != nil {
				services.Logf("warn", "caddy_apply_error_clear_failed: 清除 caddy_apply_error 失败(陈旧失败横幅可能滞留): %v", err)
			}
		}
		return
	}
	h.recordCaddyApplyFailure(err, nil)
}

// applyFailureSubject 把横幅正文的失败对象短语、操作日志动作与事件对象绑成一个
// 值——三者是同一事实的三面，必须同时给出。动作列恒为「应用失败」会让提交失败
// （数据库）与证书文件清理失败（文件系统）在审计页被读成「Caddy 拒绝了配置」，
// 按动作过滤/检索的人因此走向错误的排障方向。
type applyFailureSubject struct {
	action   string // 操作日志「动作」列
	resource string // 操作日志「事件对象」列
	object   string // 横幅正文的失败对象短语
}

// caddyApplyFailureSubject 是 apply 面的默认主体（Caddy 拒绝/传输/渲染失败）。
func caddyApplyFailureSubject(object string) applyFailureSubject {
	return applyFailureSubject{action: "应用失败", resource: "Caddy配置", object: object}
}

var (
	// commitSaveFailedSubject 提交失败：Commit 报错无法区分「未提交」与「已提交
	// 但确认丢失」（见 commitUncertainLabel），退出路径在数据库而不在配置内容。
	commitSaveFailedSubject = applyFailureSubject{action: "保存失败", resource: "Caddy配置", object: postCommitSaveFailedBanner}
	// certJobEnqueueFailedSubject 提交后证书任务入队失败：处置对象是任务队列。
	certJobEnqueueFailedSubject = applyFailureSubject{action: "创建失败", resource: "证书任务", object: "证书任务入队失败"}
	// certFileCleanupFailedSubject 提交后证书文件清理失败：处置对象是文件系统。
	certFileCleanupFailedSubject = applyFailureSubject{action: "清理失败", resource: "证书文件", object: "证书文件清理失败"}
)

// recordCaddyApplyFailure 是「配置应用失败」横幅/系统审计的写点。restoreErr
// 非空（恢复运行配置失败）时横幅改走「状态未知」文案——apply 错误本身可能来自
// /load 传输失败（请求超时/响应丢失发生在 Caddy 已 provision 之后），此时
// 断言「旧配置已保留」或「运行配置未生效」都与事实可能相反。
//
// restoreErr 只允许承载「运行配置是否已恢复」这一个事实（两态标签的唯一
// 驱动）。附带失败（LKG 钉回、证书文件清理、未提交事务回滚、DB 快照回退）
// 不影响该事实，走 recordCompensationSideEffects 独立留痕，禁止并进本参数。
func (h *Handlers) recordCaddyApplyFailure(err, restoreErr error) {
	h.writeApplyFailureBanner(caddyApplyFailureSubject("Caddy 配置应用失败"), err, restoreErr)
}

// persistCaddyApplyBanner 是 caddy_apply_error 列的唯一写点（清空分支除外）。
// 该列是全员可见的全局信号（前端横幅 + /caddy/status，含只读 API Key 可见），
// 而 /load 传输失败的 *url.Error 文本恒含「Post "http://<adminURL>/load"」与
// 「dial tcp <admin>」——自定义 caddy_admin_url 时等于把内部控制面地址与端口
// 披露给任意登录用户。所有写点统一经本函数剥离；服务端日志保留原文（仅运维
// 可见）。
func persistCaddyApplyBanner(text string) {
	if db.DB == nil {
		return
	}
	visible := services.RedactCaddyAdminEndpoint(text)
	if _, derr := db.DB.Exec(`UPDATE global_config SET caddy_apply_error=? WHERE id=1`, visible); derr != nil {
		services.Logf("warn", "caddy_apply_error_persist_failed: 持久化 caddy_apply_error 失败(重启后真实失败不可见): %v", derr)
	}
}

// caddyFailureAuditDetail 是「Caddy 交互失败」审计 detail 的唯一构造点。err
// 文本可能来自指向 admin 端点的 *url.Error（/load、/config、/adapt 的请求
// 地址与拨号目标），而操作审计列表全员可见——先剥离端点再入 detail，服务端
// 日志仍保留原文。
func caddyFailureAuditDetail(prefix string, err error) string {
	return services.FormatAuditDetail(prefix, services.RedactCaddyAdminEndpoint(err.Error()), services.AuditResultPart("failure"))
}

// writeApplyFailureBanner 是横幅/系统审计的唯一落盘点。subject 决定横幅正文
// 对象与审计的动作/事件对象——提交失败、证书清理失败、任务入队失败不得沿用
// 「Caddy 配置应用失败」模板（错称会让运维按配置内容排障，而处置对象是数据库/
// 文件系统/任务队列）。
func (h *Handlers) writeApplyFailureBanner(subject applyFailureSubject, err, restoreErr error) {
	wrapped := fmt.Sprintf("%s（%s）：%v", subject.object, caddyApplyFailureLabel(restoreErr), err)
	services.Logf("error", "%s", wrapped)
	// 全员可见面（审计列表 + 刷新后仍可见的横幅）剥离 admin 端点地址。
	services.RecordAuditLog("system", subject.action, subject.resource, services.RedactCaddyAdminEndpoint(wrapped), "")
	persistCaddyApplyBanner(wrapped)
}

// postCommitSaveFailedBanner 提交失败横幅的失败对象短语：SQLite 的 Commit
// 错误无法区分「未提交」与「已提交但确认丢失」，横幅不得断言「配置应用
// 失败」（apply 已发生过）。
const postCommitSaveFailedBanner = "配置保存失败（数据库提交结果不确定）"

// recordPostCommitRestoreFailure 提交后失败分支的统一收尾（横幅 + 附带失败
// 留痕），两通道分离：
//   - runtimeErr：运行配置恢复结果，唯一驱动两态标签与横幅（nil = 恢复成功，
//     库态与运行态一致，不写横幅——写只会长亮假告警）；
//   - sideErr：附带失败（LKG 钉回 / 证书文件清理 / 未提交事务回滚 / DB 快照
//     回退），与「运行配置是否已恢复」无关，独立留痕。
//
// subject 见 writeApplyFailureBanner；提交失败请用 commitSaveFailedSubject。
func (h *Handlers) recordPostCommitRestoreFailure(subject applyFailureSubject, opErr, runtimeErr, sideErr error) {
	h.recordCompensationSideEffects(subject.object, sideErr)
	if runtimeErr == nil {
		return
	}
	h.writeApplyFailureBanner(subject, errors.Join(opErr, runtimeErr), runtimeErr)
}

// recordCompensationSideEffects 提交后补偿的附带失败留痕。LKG 钉回失败意味着
// 重启兜底可能回放漂移形态，混入横幅会被读成「运行配置未恢复」；故独立
// 日志 + 系统审计（刷新页面可见于操作日志）。
func (h *Handlers) recordCompensationSideEffects(failureObject string, sideErr error) {
	if sideErr == nil {
		return
	}
	text := fmt.Sprintf("%s：附带补偿失败（不改变运行配置是否已恢复）：%v", failureObject, sideErr)
	services.Logf("error", "%s", text)
	services.RecordAuditLog("system", "补偿失败", "Caddy配置", text, "")
}

// recordCaddyApplySavedNotLive 退化提交形态（DB 已提交、运行配置可能未生效）
// 的横幅写点。文案必须是不确定口径：触发本形态的主力是 /load 传输失败
// （超时/连接重置/响应丢失），Caddy 可能已经 provision 成功——断言「未生效」
// 会诱导管理员重复提交或错误回退。与 recordCaddyApplyResult 的失败分支
// （未保存）同样两态化，避免共用一句被误读为「没保存」。
// 本形态的业务/重载审计由调用方按操作者归因落盘，此处只写横幅事实源 + 错误
// 日志（不再补系统级「应用失败」审计）。
func (h *Handlers) recordCaddyApplySavedNotLive(err error) {
	text := fmt.Sprintf("配置已保存，但 Caddy 应用失败（运行配置可能未生效，请核对后重试）：%v", err)
	services.Logf("error", "%s", text)
	// 横幅是全员可见面：触发本形态的主力正是 /load 传输失败，错误文本含 admin
	// 端点原文，必须经 persistCaddyApplyBanner 剥离后再落库。
	persistCaddyApplyBanner(text)
}

// caddyApplyNoteLocked 返回应用失败时的响应文案后缀（空=配置干净应用）。
// 已持 caddyOpMu 的后台/会话内路径使用（Start/Restart Caddy、集群应用、
// 导入会话内重播种）；applyCaddyConfigE 不可重入，未持锁路径必须用它。
//
// 重载审计的留痕通道（契约：触发重载必须留痕。69d809b4 曾误以为单一入口
// 全覆盖而删光其余通道的手动审计，导致删除/启用规则等操作重载不留痕）。
// 三条通道（按入口形态命名，不使用数字编号——「家族 N」在配置域已被
// 门控提交族占用，两套编号同名曾导致阅读歧义）：
//  1. caddyApplyNoteLocked — 已持 caddyOpMu 的后台/会话内路径（Start/
//     Restart Caddy、集群应用、导入会话内重播种）仅保证失败留痕+横幅；
//     Start/Stop/Restart 的成功动作审计由 Generic 中间件动作映射承担，
//     不产生「重载」审计；
//  2. applyFromTxNote      — 事务内应用（规则生命周期 ×5、UpdateConfig、
//     finishTxApply 各调用点）：重载发生在 Commit 前、审计只能落在 Commit 后，
//     两点必然分离，由返回的 note 闭包绑定，漏调即编译错误。
//     严格/退化差异按调用点，不按本通道：直接调用 applyFromTxNote 的六个
//     调用点是严格形态（规则 ×5 + UpdateConfig——任何 applyErr 含传输失败都
//     回滚事务并返回 400/500）；经 finishTxApply 的调用点在其上叠加退化分支
//     （传输/系统失败 → 提交 + 横幅 + 200 带告警）。两形态由
//     handlers/caddy.go 的 UpdateConfig、rules.go 五调用点与钉测固化。
//  3. applyCaddyConfigE    — 未持锁的手动重载（POST /caddy/reload 等），
//     自取 caddyOpMu 并持久化应用结果。
//
// 不经 tx 渲染的变体：PutCaddyConfig（ApplyConfig 原始载荷）与备份导入 ×2
// （协调器内应用）各自在成功尾部补记，同受契约约束。
const caddyApplyFailureNotePrefix = "；但 Caddy 配置应用失败："

// caddyLifecycleApplyFailureMessage 组合启停动作与统一失败后缀；note 已含
// 「但 Caddy 配置应用失败」，调用方不得再拼一份同义句首。
func caddyLifecycleApplyFailureMessage(action, note string) string {
	return action + note
}

func (h *Handlers) caddyApplyNoteLocked() string {
	err := h.caddyService.GenerateAndApplyConfig()
	if services.IsSameConfig(err) {
		err = nil // 同字节短路：无真实重载，也非失败（2026-09-25 审计真实性裁定）
	}
	h.recordCaddyApplyResult(err)
	if err != nil {
		return caddyApplyFailureNotePrefix + err.Error()
	}
	return ""
}

// txApplyNote 事务内应用的收尾句柄（重载发生在 Commit 之前，审计只能等
// Commit 成功后才落盘）。两段式：
//   - auditReload()：只落「重载」审计（幂等）。提交后的失败分支也必须调用
//     ——真实 /load 已经发生，「触发重载必须留痕」不因随后失败而豁免。
//   - finalize()：成功收尾（LKG 补写 → 清横幅 → 重载审计 → 计时）。若后续
//     强制重载已成功并写入更新的 LKG，首轮载荷即被 supersede，finalize 只执行
//     清横幅/审计等收尾，不再回写旧载荷。失败分支**不得**调用：它会清掉失败横幅
//     并（在补偿回滚场景下）把候选字节写进 LKG，制造假恢复信号。
type txApplyNote struct {
	audited            bool
	lastGoodSuperseded bool
	audit              func()
	persistLastGood    func()
	finish             func()
}

// auditReload 落一次「重载」审计（重复调用无副作用）。nil 句柄（应用失败）
// 安全跳过。
func (n *txApplyNote) auditReload() {
	if n == nil || n.audited || n.audit == nil {
		return
	}
	n.audited = true
	n.audit()
}

// markLastGoodSuperseded 标记后续强制重载已写入更新的 LKG。只能在该重载成功后
// 调用；失败路径保持原补偿链，不改变首轮 note 的状态。
func (n *txApplyNote) markLastGoodSuperseded() {
	if n != nil {
		n.lastGoodSuperseded = true
	}
}

// finalize 成功收尾。顺序与拆分前一致（LKG → 清横幅 → 审计 → 计时）。
func (n *txApplyNote) finalize() {
	if n == nil {
		return
	}
	if !n.lastGoodSuperseded && n.persistLastGood != nil {
		n.persistLastGood()
	}
	if n.finish != nil {
		n.finish()
	}
	n.auditReload()
}

// applyFromTxNote 是事务内应用通道的统一入口（ApplyConfigFromTx，
// 应用失败即回滚，DB 与运行配置不分叉）。重载发生在 Commit 之前，而提交
// 失败会回滚并恢复运行配置快照——审计必须等 Commit 成功后才落盘，否则会
// 留下从未真正生效的「重载」行。因此这里把「应用」与「审计登记」绑定在
// 同一次调用里，返回提交成功后必须调用 finalize 的句柄：漏调后变量未使用
// 即 compile error，69d809b4 式的静默删行在此形态下不再可能。归因明细由
// 调用点提供（txReloadDetail 或固定文案）。
// rulesWrittenInTx：事务是否写过 lb_rules（ACME 谓词 miss 补查门控——
// 规则写路径 true；UpdateConfig/名单/策略等不触碰 lb_rules 的路径 false）。
func (h *Handlers) applyFromTxNote(c *gin.Context, tx *sql.Tx, reloadDetail string, rulesWrittenInTx bool) (*txApplyNote, error) {
	// 裁定 ④'：Caddy CLI 层预检（真 validate-only，零运行时副作用）——校验
	// 输入即事务视图的最终渲染。校验器不可用时放行（记日志），事务内应用
	// 仍是最终门控。
	cliValidated := true
	cliStart := time.Now()
	if err := h.caddyService.ValidateTxRenderViaCLI(tx, rulesWrittenInTx); err != nil {
		if !errors.Is(err, services.ErrCLIValidatorUnavailable) {
			return nil, err
		}
		cliValidated = false
		services.Logf("warn", "caddy CLI 校验器不可用，跳过预检（事务内应用仍门控）: %v", err)
	}
	services.Logf("info", "保存链计时: cli_validate=%dms", time.Since(cliStart).Milliseconds())
	applyStart := time.Now()
	appliedConfig, err := h.caddyService.ApplyConfigFromTx(tx, rulesWrittenInTx)
	if err != nil {
		// 审计真实性裁定（2026-09-25 用户裁定）：同字节短路=未发生真实重载——
		// 按成功收尾但 note 不落「重载」审计（否则出现从未发生的重载记录）。
		if services.IsSameConfig(err) {
			return &txApplyNote{finish: func() { h.recordCaddyApplyResult(nil) }}, nil
		}
		// 乱填保障（2026-09-06 补充裁定）：应用失败且配置未经任何 Caddy 级
		// 校验（CLI 不可用 + 传输失败同时发生）——无法排除坏配置，标记为
		// 不可退化提交，调用方必须回滚。
		if !cliValidated && !services.IsConfigRejected(err) {
			return nil, fmt.Errorf("%w: %v", services.ErrUnvalidatedApply, err)
		}
		return nil, err
	}
	return &txApplyNote{
		audit: func() {
			recordAudit(c, "重载", "Caddy服务", reloadDetail)
		},
		persistLastGood: func() {
			// commit 成功后才写 last-known-good（事务内 apply 有意不落盘）：
			// 本闭包在全部调用点都只在 tx.Commit() 成功返回后执行——LKG 的语义
			// 因此恒为「已提交且已下发」的配置，进程中断窗口不再把从未提交的
			// 候选固化成启动兜底。
			h.caddyService.PersistLastGoodBytesInLock(appliedConfig)
		},
		finish: func() {
			// 成功重载后清除既往失败标记；supersede 只跳过上方旧 LKG 载荷，
			// 不影响这里的横幅与计时收尾。
			h.recordCaddyApplyResult(nil)
			services.Logf("info", "保存链计时: apply_total=%dms（含渲染+Caddy 重载）", time.Since(applyStart).Milliseconds())
		},
	}, nil
}

// commitUncertainLabel 事务提交失败的用户/审计文案单源（与导入协调器
// importFailurePhaseDescription 的 importPhaseCommit 同口径）：SQLite 在
// Commit 返回错误时无法区分「未提交」与「已提交但确认丢失」，断言「失败/未
// 生效」会诱导操作者重试并产生重复写入（重复审计行/重复创建），与「审计不得
// 出现与事实相反的记录」相悖。全部提交失败分支（finishTxApply 家族与名单热
// 路径）共用本常量，禁止各自另写文案。
const commitUncertainLabel = "数据库提交结果不确定（可能已生效，请先核对）"

// txReloadDetail 生成规则生命周期路径的重载审计明细（来源 + 规则归因 + 结果）。
func txReloadDetail(source, ruleID string) string {
	return services.FormatAuditDetail(services.AuditSourcePart(source), services.AuditRulePart(ruleID), services.AuditResultPart("success"))
}

// txCommitForTest 仅测试注入提交失败（nil = 生产直通）。测试实现必须先回滚
// 事务再返回错误，确保恢复逻辑读到的是已提交视图（与 ipListCommitTxForTest
// 同型）——提交失败分支的横幅/审计/响应只有可注入才可能钉测。
var txCommitForTest func(*sql.Tx) error

// commitTx 是配置/设置域事务提交的唯一入口（测试缝收口）。
func commitTx(tx *sql.Tx) error {
	if txCommitForTest != nil {
		return txCommitForTest(tx)
	}
	return tx.Commit()
}

// txRollbackForTest 仅测试注入回滚失败（nil = 生产直通）。同 txCommitForTest：
// 测试实现必须先把事务真正回滚再返回错误（否则恢复路径读已提交视图会撞在
// 泄漏的写锁上）。提交失败恢复的两条通道（库态 / 运行配置）只有可注入才可能
// 钉住「未提交事务回滚失败不得被写成运行配置恢复失败」。
var txRollbackForTest func(*sql.Tx) error

// rollbackTx 是提交失败恢复路径的事务回滚唯一入口（测试缝收口）。
func rollbackTx(tx *sql.Tx) error {
	if txRollbackForTest != nil {
		return txRollbackForTest(tx)
	}
	return tx.Rollback()
}

// txApplyFinish 是 finishTxApply 的收尾选项。Resource/AuditAction/AuditDetail/
// SuccessMsg 必填；SuccessStatus 默认 200；ReloadDetail 默认「配置变更后自动重载」。
// RulesWrittenInTx：事务是否写过 lb_rules（ACME 谓词 miss 补查门控，默认 false
// ——安全策略/名单等路径不触碰 lb_rules；规则写路径必须显式置 true）。
type txApplyFinish struct {
	Resource         string
	AuditAction      string
	AuditDetail      string
	SuccessMsg       string
	SuccessStatus    int
	Data             any
	ReloadDetail     string
	RulesWrittenInTx bool
}

// finishTxApply 事务内应用的统一收尾（2026-09-06 裁定 ①②：只有可渲染配置可落库，
// 杜绝坏配置持久化后重启全停）。调用方完成事务内写库后调用本方法，三分支：
//
//	渲染拒绝（Caddy 4xx / 生成失败）→ 不提交（调用方 defer 回滚）+ 失败审计
//	  + 400「Caddy 配置应用失败，<Resource>未保存: <原因>」；
//	传输/系统失败（Caddy down 等）→ 退化语义（= 已持锁直应用通道的收尾口径）：
//	  提交 + 业务审计 + 重载失败审计 + caddy_apply_error 标记 +
//	  200「<SuccessMsg>；但 Caddy 配置应用失败：…」；
//	成功 → 提交 + 业务审计 + 重载审计 + 200/201。
//
// 本方法自行提交或放行回滚；调用方的 rollback defer 必须容忍 ErrTxDone
// （既有各 defer 均已容忍）。返回后请求即已终结，调用方立即 return。
func (h *Handlers) finishTxApply(c *gin.Context, tx *sql.Tx, f txApplyFinish) {
	reloadNote, applyErr := h.applyFromTxNote(c, tx, reloadDetailFor(f), f.RulesWrittenInTx)
	status := f.SuccessStatus
	if status == 0 {
		status = http.StatusOK
	}
	// CLI 拒绝与应用拒绝共用失败文案口径（重载审计详情由 applyFromTxNote 内的
	// note 闭包按 reloadDetailFor(f) 落盘）。
	if applyErr == nil {
		if err := commitTx(tx); err != nil {
			// 2026-09-07：SQLite commit 失败极罕见（磁盘满/IO 错误）。
			// apply 已按未提交事务视图 /load 并把同一内容写入 LKG，
			// commit 失败必须把运行配置/LKG/投影/证书统一回退到已提交视图。
			recovery := h.recoverCommittedViewAfterCommitFailure(tx)
			joined := errors.Join(err, recovery.err())
			// 真实 /load 已发生（重载审计）+ 恢复失败时的分叉横幅。
			reloadNote.auditReload()
			h.recordPostCommitRestoreFailure(commitSaveFailedSubject, err, recovery.runtime, recovery.db)
			recordAudit(c, f.AuditAction+"失败", f.Resource, services.FormatAuditDetail(commitUncertainLabel, joined.Error(), services.AuditResultPart("failure")))
			writeInternalError(c, http.StatusInternalServerError, commitUncertainLabel, joined)
			return
		}
		recordAudit(c, f.AuditAction, f.Resource, f.AuditDetail)
		// 重载审计与失败横幅清除的唯一收口（此前上方已先清一次、
		// 此处 reloadNote 内又清一次 = 同请求重复 UPDATE global_config；
		// 同字节短路形态也由 note 覆盖）。
		reloadNote.finalize()
		c.JSON(status, models.APIResponse{Code: 0, Message: f.SuccessMsg, Data: f.Data})
		return
	}
	if services.IsConfigRejected(applyErr) {
		// CLI 校验拒绝与 admin 4xx 同口径：不落库 + 400 + 失败审计。
		// 渲染副作用（稳定命名投影+证书物化）已按未提交
		// 内容落盘——tx 回滚的同时把磁盘回退到已提交态（零 /load）。
		h.caddyService.RollbackIPListProjectionsToCommittedInLock()
		recordAudit(c, f.AuditAction+"失败", f.Resource, caddyFailureAuditDetail("Caddy 校验未通过", applyErr))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置校验未通过，" + f.Resource + "未保存: " + applyErr.Error()})
		return
	}
	// 乱填保障（2026-09-06 补充裁定）：CLI 不可用 + 应用传输失败 = 未经任何
	// Caddy 级校验——不得退化提交（无法排除坏配置），回滚 + 明确提示。
	if errors.Is(applyErr, services.ErrUnvalidatedApply) {
		// 同收口：回滚分支磁盘回退到已提交态（零 /load）。
		h.caddyService.RollbackIPListProjectionsToCommittedInLock()
		// 传输错误可能发生在 Caddy 已应用候选之后（请求断连/
		// 超时）——只回滚 DB/投影会让运行配置停滞候选态，而看门狗只比对路由
		// id（纯策略/限流变化不触发漂移横幅）。复用提交失败的统一恢复：
		// 回滚事务 + 以已提交视图重渲染 /load + 回退 LKG/投影/证书副作用。
		recovery := h.recoverCommittedViewAfterCommitFailure(tx)
		// 两通道分开陈述：库态（未提交事务回滚失败）与运行配置恢复是两件事，
		// 把前者包成「回滚到已提交运行配置失败」会让同一次响应的正文
		// （下方 restoreNote 只看 runtime）与审计/日志给出相反结论。
		joined := applyErr
		if recovery.db != nil {
			joined = errors.Join(joined, recovery.db)
		}
		if recovery.runtime != nil {
			joined = errors.Join(joined, fmt.Errorf("回滚到已提交运行配置失败: %w", recovery.runtime))
		}
		h.recordCompensationSideEffects("Caddy 应用失败且 CLI 校验不可用", recovery.db)
		h.recordCaddyApplyFailure(joined, recovery.runtime)
		recordAudit(c, f.AuditAction+"失败", f.Resource, caddyFailureAuditDetail("Caddy 应用失败且 CLI 校验不可用", joined))
		restoreNote := "已回滚到已提交运行配置"
		if recovery.runtime != nil {
			restoreNote = "回滚到已提交运行配置失败，请立即检查 Caddy 状态"
		}
		// 5xx 响应只回固定文案（business 组任意登录用户可读）：错误详情
		// （含 /load 传输错误里的 Caddy admin 地址）由上方日志与审计留痕。
		writeInternalError(c, http.StatusInternalServerError, "Caddy 应用失败且 CLI 校验不可用，"+f.Resource+"未保存（"+restoreNote+"，恢复 Caddy/CLI 后重试）", joined)
		return
	}
	if err := commitTx(tx); err != nil {
		// 退化提交分支同样可能已按未提交视图重写投影/证书并（若
		// 传输失败前 /load 已生效）留下运行配置分叉——与成功分支同一收口。
		recovery := h.recoverCommittedViewAfterCommitFailure(tx)
		joined := errors.Join(err, recovery.err())
		// apply 失败（applyErr != nil）时 reloadNote 为 nil——auditReload 安全
		// 跳过；恢复失败仍须落横幅（提交结果不确定 + 运行态可能滞留候选）。
		reloadNote.auditReload()
		h.recordPostCommitRestoreFailure(commitSaveFailedSubject, err, recovery.runtime, recovery.db)
		recordAudit(c, f.AuditAction+"失败", f.Resource, services.FormatAuditDetail(commitUncertainLabel, services.RedactCaddyAdminEndpoint(joined.Error()), services.AuditResultPart("failure")))
		writeInternalError(c, http.StatusInternalServerError, commitUncertainLabel, joined)
		return
	}
	// 退化提交（DB 已提交、运行配置未生效）：横幅文案与「未保存（旧配置
	// 已保留）」分两态——误读为「没保存」会诱发重复提交（重复对象）。
	// 200 响应面向任意登录用户（business 组），错误文本与上方「重载失败」
	// 审计同口径经 RedactCaddyAdminEndpoint 脱敏（/load 传输错误携带 admin
	// 地址），详情仍由日志与审计留痕。
	h.recordCaddyApplySavedNotLive(applyErr)
	recordAudit(c, f.AuditAction, f.Resource, f.AuditDetail)
	recordAudit(c, "重载失败", "Caddy服务", services.RedactCaddyAdminEndpoint(applyErr.Error()))
	c.JSON(status, models.APIResponse{Code: 0, Message: f.SuccessMsg + "；但 Caddy 配置应用失败：" + services.RedactCaddyAdminEndpoint(applyErr.Error()), Data: f.Data})
}

// postCommitRecovery 提交失败统一恢复的结果，两通道分离：
//   - runtime：运行配置是否已恢复（唯一驱动横幅两态标签）；
//   - db：未提交事务回滚失败（影响库态确定性，与运行配置是否恢复无关）。
//
// err() 只用于响应/审计文本（两通道都要点名）；横幅与标签只消费 runtime。
type postCommitRecovery struct {
	runtime error
	db      error
}

func (r postCommitRecovery) err() error {
	return errors.Join(r.db, r.runtime)
}

// recoverCommittedViewAfterCommitFailure 是事务提交失败的统一恢复
// 先回滚未提交事务（释放 SQLite 写锁，否则 db.DB 读会被阻塞），再以已提交
// 视图重渲染并 /load——运行配置、last-known-good、名单投影与证书物化副作用
// 全部回退到已提交状态。
//
// 调用契约：调用方处于写路径临界区（已持 caddyOpMu），且此后不得再使用 tx。
func (h *Handlers) recoverCommittedViewAfterCommitFailure(tx *sql.Tx) postCommitRecovery {
	var out postCommitRecovery
	if err := rollbackTx(tx); err != nil {
		if errors.Is(err, sql.ErrTxDone) {
			// database/sql 在 Commit 失败后把 Tx 标记为 done 且
			// 不会调用 driver.Rollback（releaseConn 直接归还连接）。SQLite 的
			// deferred 约束/IO 类失败会让底层事务保持活动——连接归还池后，
			// 任何复用该连接的读都会看到未提交数据（已提交视图重渲染因此
			// 读到候选值，恢复等于空转、LKG 滞留未提交字节）。在池上补一次
			// ROLLBACK：泄漏事务仍持写锁，其他写事务不可能占用该连接，
			// 因此不会误伤他人；无事务活动时报错忽略即可。
			rollbackLeakedTx()
		} else {
			out.db = fmt.Errorf("回滚未提交事务失败: %w", err)
		}
	}
	if err := h.caddyService.RestoreRuntimeToCommittedInLock(); err != nil {
		out.runtime = fmt.Errorf("恢复已提交视图运行配置失败: %w", err)
	}
	return out
}

// rollbackLeakedTx 在事务提交失败后补发 ROLLBACK（见调用点注释）。
// 连接池按 LIFO 复用，刚归还的泄漏连接会被优先取到；若取到的是无活动事务
// 的其它空闲连接（池内有竞争），重试直到命中或次数用尽——此时泄漏事务仍
// 持写锁，其它连接不可能有写事务，重复 ROLLBACK 不会误伤。
//
// var 而非 func：测试缝（部署/回滚路径的可观测性断言——提交失败分支必须
// 恰好走一次统一补发，不得自造 tx.Rollback 吞掉 ErrTxDone）。生产恒为本实现。
var rollbackLeakedTx = func() {
	if db.DB == nil {
		return
	}
	for attempt := range 5 {
		_, err := db.DB.Exec("ROLLBACK")
		if err == nil {
			return
		}
		if strings.Contains(err.Error(), "no transaction is active") {
			continue
		}
		services.Logf("warn", "提交失败后补发 ROLLBACK 失败（第 %d 次）: %v", attempt+1, err)
	}
}

// reloadDetailFor 返回收尾选项的重载审计明细（默认「配置变更后自动重载」）。
func reloadDetailFor(f txApplyFinish) string {
	if f.ReloadDetail != "" {
		return f.ReloadDetail
	}
	return "配置变更后自动重载"
}

// applyCaddyConfigE serializes against rule/config writes (caddyOpMu) and
// persists the apply outcome; all manual re-apply entry points must use it.
// 改用强制变体——手动重载（HTTP /caddy/reload 与 MCP
// reload_caddy）的语义就是「强制收敛」，必须能击穿 errSameConfig 短路
// （磁盘数据变化而 JSON 相同的场景），否则文档承诺的收敛能力不存在。
func (h *Handlers) applyCaddyConfigE() error {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	err := h.caddyService.GenerateAndApplyConfigForceInLock() // 已持 caddyOpMu（=CaddyOpLock）——重入取锁死锁
	h.recordCaddyApplyResult(err)
	return err
}

// rulePayloadInput 是规则保存字段层校验的归一视图：Create 取原值，Update
// 解引用指针（nil=零值）。视图与 models.CreateRuleRequest /
// UpdateRuleRequest 是平行字段清单——保留归一实现但加 parity 门禁
// （b_core_regression_01_test.go 的 TestRulePayload_inputParityWithModels：
// 模型字段要么在此声明、要么显式登记由
// ruleFeatureInput 等单源校验豁免），新增模型字段漏登记即测试红。上游直接
// 复用 models.Upstream（不再维护第二份上游镜像结构）。
type rulePayloadInput struct {
	Protocol                      string
	Domain                        string
	ListenPort                    int
	Strategy                      string
	DynamicDNS                    bool
	DnsServer                     string
	DnsFamily                     string
	HealthCheckPath               string
	HealthCheckInterval           int
	HealthCheckTimeout            int
	HealthCheckUnhealthyThreshold int
	HealthCheckHealthyThreshold   int
	EnableTLS                     bool
	TLSSource                     string
	ACMEConfigID                  int
	CAProviderID                  int
	TLSCert                       string
	TLSKey                        string
	TLSHTTPRedirect               bool
	EnableCompress                bool
	CompressTypes                 string
	EnableActiveHealthCheck       bool
	HostHeader                    string
	HealthCheckHost               string
	RequestBodyMaxSizeMB          int
	UpstreamKeepaliveTimeout      int
	ServerTokensHidden            int
	BlockPageStage1ID             int
	BlockPageStage1Status         int
	BlockPageStage3ID             int
	BlockPageStage3Status         int
	Upstreams                     []models.Upstream
}

// validateRuleHostHeader 是 Host 头写侧唯一形状门；保存与两种备份导入共用。
func validateRuleHostHeader(hostHeader string) error {
	for _, r := range hostHeader {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("后端域名含非法字符")
		}
	}
	return nil
}

func validateRuleHealthCheckPath(path string) error {
	if path != "" && !strings.HasPrefix(path, "/") {
		return fmt.Errorf("健康检查路径必须以 / 开头")
	}
	return nil
}

// upstreamDedupeHost 是「同一后端」判重的单源主机形态。
//
// 判重必须按地址语义而不是文本：2001:db8::1 与 2001:0db8:0:0:0:0:0:1 是同一个
// 地址的两种合法写法（isValidHost 用 net.ParseIP，两种都过形状门），按文本
// 比较会当成两个上游落库——权重翻倍、健康检查对同一地址跑两遍、失败计数分裂。
// IPv4-mapped 形态（::ffff:10.0.0.1 与 10.0.0.1）同理按 Unmap 后视为同一后端。
// 主机名保持文本归一（去首尾空白 + 小写，DNS 不区分大小写）。方括号形态
// （[::1]）不在此归一：isValidHost 拒绝方括号，写侧在判重后必然 400；若在此
// 剥括号反而会让后续渲染 JoinHostPort 二次加括号成 [[::1]]。
func upstreamDedupeHost(host string) string {
	trimmed := strings.TrimSpace(host)
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return addr.Unmap().String()
	}
	return strings.ToLower(trimmed)
}

// validateRuleUpstreams 校验一组实际上游。requireEnabled 用于 Create/Update
// 与 v1 的表单语义；v2 备份是存量行还原，保留渲染层支持的零上游/零启用
// 形态，但所有携带行仍逐项经过完全相同的值域、查重与协议校验。
func validateRuleUpstreams(protocol string, dynamicDNS bool, upstreams []models.Upstream, requireEnabled bool) (int, error) {
	if requireEnabled && len(upstreams) == 0 {
		return 0, fmt.Errorf("至少需要一个上游服务器")
	}
	enabledUpstreamCount := 0
	enabledProtocols := make(map[string]bool, 2)
	hostPortSeen := make(map[string]bool)
	for i, u := range upstreams {
		if u.Host == "" {
			return 0, fmt.Errorf("上游 #%d：主机地址不能为空", i+1)
		}
		if u.Port < 1 || u.Port > 65535 {
			return 0, fmt.Errorf("上游 #%d：端口 %d 无效（必须在 1-65535 之间）", i+1, u.Port)
		}
		// （裁定）：weight<1 响亮拒绝——0→1 静默归一废除
		//（保存/导入同口径，导入侧见 config_backup.go 备份校验）；禁用行的
		// 权重字段无业务意义但同样不得落 0（UI 载荷边界为禁用行送 1）。
		if u.Weight < 1 {
			return 0, fmt.Errorf("上游 #%d：权重必须为不小于 1 的整数", i+1)
		}
		if protocol == "http" {
			if u.Protocol != "" && u.Protocol != "http" && u.Protocol != "https" {
				return 0, fmt.Errorf("上游 #%d：协议 '%s' 无效（HTTP 规则仅支持 http/https）", i+1, u.Protocol)
			}
		} else if u.Protocol != "" && u.Protocol != "tcp" && u.Protocol != "tls" {
			return 0, fmt.Errorf("上游 #%d：协议 '%s' 无效（TCP 规则仅支持 tcp/tls）", i+1, u.Protocol)
		}
		if u.MaxConnections < 0 {
			return 0, fmt.Errorf("上游 #%d：最大连接数不能为负数", i+1)
		}

		key := net.JoinHostPort(upstreamDedupeHost(u.Host), strconv.Itoa(u.Port))
		if hostPortSeen[key] {
			return 0, fmt.Errorf("上游 %s 重复", key)
		}
		hostPortSeen[key] = true
		if !isValidHost(u.Host) {
			return 0, fmt.Errorf("上游 #%d：主机 '%s' 无效", i+1, u.Host)
		}
		if u.OriginDomain != "" {
			if protocol != "http" {
				return 0, fmt.Errorf("上游 #%d：回源域名仅 HTTP 规则支持", i+1)
			}
			if dynamicDNS {
				return 0, fmt.Errorf("上游 #%d：动态上游模式不支持回源域名（请使用规则级后端域名）", i+1)
			}
			if !isValidHost(u.OriginDomain) {
				return 0, fmt.Errorf("上游 #%d：回源域名 %q 无效（仅支持主机名，不带端口）", i+1, u.OriginDomain)
			}
		}
		if u.Enabled {
			enabledUpstreamCount++
			proto := u.Protocol
			if proto == "" {
				proto = "http"
			}
			enabledProtocols[proto] = true
		}
	}
	if protocol == "http" && enabledProtocols["http"] && enabledProtocols["https"] {
		return 0, fmt.Errorf("同一 HTTP 规则的启用上游协议须一致（http/https 混布时 http 上游会被 TLS 化静默全灭；如需共存请拆分为两条规则）")
	}
	if requireEnabled && enabledUpstreamCount == 0 {
		return 0, fmt.Errorf("至少需要一个启用的上游服务器")
	}
	return enabledUpstreamCount, nil
}

// validateRulePayloadBeforeSave 是规则保存的后端字段层校验（三层校验第 2 层，
// 裁定 2026-09-06 ④'）：协议/端口/策略/域名/上游（主机/端口/权重/协议/查重/
// 启用数）/动态 DNS/健康检查/ACME 引用。Caddy 层由 applyFromTxNote 内的
// CLI 预检（真 validate-only）+ 事务内 ApplyConfigFromTx（最终门控）承担，
// 校验与应用的输入同为事务视图最终渲染——原「候选并入运行配置」的 merged
// /load 探针（validateCaddyConfigBeforeSave，运行时副作用+平行渲染双轨）已撤。
func (h *Handlers) validateRulePayloadBeforeSave(req interface{}) error {
	var data rulePayloadInput

	switch r := req.(type) {
	case models.CreateRuleRequest:
		data.Protocol = r.Protocol
		data.Domain = r.Domain
		data.ListenPort = r.ListenPort
		data.Strategy = r.Strategy
		data.DynamicDNS = r.DynamicDNS
		data.DnsServer = r.DnsServer
		data.DnsFamily = r.DnsFamily
		data.HealthCheckPath = r.HealthCheckPath
		data.HealthCheckInterval = r.HealthCheckInterval
		data.HealthCheckTimeout = r.HealthCheckTimeout
		data.HealthCheckUnhealthyThreshold = r.HealthCheckUnhealthyThreshold
		data.HealthCheckHealthyThreshold = r.HealthCheckHealthyThreshold
		data.EnableTLS = r.EnableTLS
		data.TLSSource = r.TLSSource
		data.ACMEConfigID = r.ACMEConfigID
		data.CAProviderID = r.CAProviderID
		data.TLSCert = r.TLSCert
		data.TLSKey = r.TLSKey
		data.TLSHTTPRedirect = r.TLSHTTPRedirect
		data.EnableCompress = r.EnableCompress
		data.CompressTypes = r.CompressTypes
		data.EnableActiveHealthCheck = r.EnableActiveHealthCheck
		data.HostHeader = r.HostHeader
		data.HealthCheckHost = r.HealthCheckHost
		data.RequestBodyMaxSizeMB = r.RequestBodyMaxSizeMB
		data.UpstreamKeepaliveTimeout = r.UpstreamKeepaliveTimeout
		data.ServerTokensHidden = r.ServerTokensHidden
		data.BlockPageStage1ID = r.BlockPageStage1ID
		data.BlockPageStage1Status = r.BlockPageStage1Status
		data.BlockPageStage3ID = r.BlockPageStage3ID
		data.BlockPageStage3Status = r.BlockPageStage3Status
		data.Upstreams = r.Upstreams
	case models.UpdateRuleRequest:
		data.Protocol = r.Protocol
		data.Domain = r.Domain
		data.ListenPort = r.ListenPort
		data.Strategy = r.Strategy
		if r.DynamicDNS != nil {
			data.DynamicDNS = *r.DynamicDNS
		}
		data.DnsServer = derefStr(r.DnsServer)
		data.DnsFamily = r.DnsFamily
		data.HealthCheckPath = derefStr(r.HealthCheckPath)
		data.HealthCheckInterval = r.HealthCheckInterval
		data.HealthCheckTimeout = r.HealthCheckTimeout
		if r.HealthCheckUnhealthyThreshold != nil {
			data.HealthCheckUnhealthyThreshold = *r.HealthCheckUnhealthyThreshold
		}
		if r.HealthCheckHealthyThreshold != nil {
			data.HealthCheckHealthyThreshold = *r.HealthCheckHealthyThreshold
		}
		if r.EnableTLS != nil {
			data.EnableTLS = *r.EnableTLS
		}
		data.TLSSource = r.TLSSource
		data.ACMEConfigID = r.ACMEConfigID
		if r.CAProviderID != nil {
			data.CAProviderID = *r.CAProviderID
		}
		data.TLSCert = r.TLSCert
		data.TLSKey = r.TLSKey
		if r.TLSHTTPRedirect != nil {
			data.TLSHTTPRedirect = *r.TLSHTTPRedirect
		}
		if r.EnableCompress != nil {
			data.EnableCompress = *r.EnableCompress
		}
		data.CompressTypes = r.CompressTypes
		if r.EnableActiveHealthCheck != nil {
			data.EnableActiveHealthCheck = *r.EnableActiveHealthCheck
		}
		data.HostHeader = derefStr(r.HostHeader)
		data.HealthCheckHost = derefStr(r.HealthCheckHost)
		if r.RequestBodyMaxSizeMB != nil {
			data.RequestBodyMaxSizeMB = *r.RequestBodyMaxSizeMB
		}
		if r.UpstreamKeepaliveTimeout != nil {
			data.UpstreamKeepaliveTimeout = *r.UpstreamKeepaliveTimeout
		}
		if r.ServerTokensHidden != nil {
			data.ServerTokensHidden = *r.ServerTokensHidden
		}
		if r.BlockPageStage1ID != nil {
			data.BlockPageStage1ID = *r.BlockPageStage1ID
		}
		if r.BlockPageStage1Status != nil {
			data.BlockPageStage1Status = *r.BlockPageStage1Status
		}
		if r.BlockPageStage3ID != nil {
			data.BlockPageStage3ID = *r.BlockPageStage3ID
		}
		if r.BlockPageStage3Status != nil {
			data.BlockPageStage3Status = *r.BlockPageStage3Status
		}
		data.Upstreams = r.Upstreams
	default:
		// 未知请求类型此前静默放行（零校验通过）——调用方
		// 只传 Create/Update，落此分支即契约破坏，须显性失败而非放过。
		return fmt.Errorf("不支持的规则请求类型 %T", req)
	}

	if data.Strategy == "" {
		data.Strategy = "weighted_round_robin"
	}
	// 库值唯一真相（批 1+2）：健康检查族为类型①值型列——0=未设置的静默归一
	// （0→10/2/3/2）废除，0 值由下方 <1 边界 400（前端表单初值=默认，清空提交
	// 被拦）；UpdateRule 非 nil 指针/合并区先沿用存量再抵达本门。CompressTypes
	// 空串归 gzip 为 HTTP 渲染语义（非本批治理字段）。
	if data.CompressTypes == "" {
		data.CompressTypes = "gzip"
	}

	if data.Protocol != "http" && data.Protocol != "tcp" {
		return fmt.Errorf("无效的协议：仅支持 http 或 tcp")
	}

	// host_header 直写 reverse_proxy 头部——CRLF/控制字符可注入额外
	// 头(请求拆分面);拒绝不可见字符,可见 ASCII 与常规 Unicode 放行。
	if err := validateRuleHostHeader(data.HostHeader); err != nil {
		return err
	}
	// dns_server 形状校验(host[:port])——垃圾串直写 caddy dns 模块
	// 配置,渲染层报错位置深且难归因。
	if err := validateDnsServerShape(data.DnsServer); err != nil {
		return err
	}

	if data.ListenPort < 1 || data.ListenPort > 65535 {
		return fmt.Errorf("无效的监听端口：必须在 1-65535 之间")
	}

	// 策略白名单委托共享实现——此前此处内联
	// httpStrategies/tcpStrategies 双 map 与 validateStrategyForProtocol
	// 重复（保存链双重判定，两份 map 是漂移种子）。空 strategy 放行
	// （渲染侧默认 weighted_round_robin；Create/Update 入口已默认/合并，
	// 空值不可达）。
	if err := validateStrategyForProtocol(data.Protocol, data.Strategy); err != nil {
		return err
	}

	if data.Domain != "" && data.Protocol == "http" {
		domains := strings.Split(data.Domain, ",")
		for _, d := range domains {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if !isValidDomain(d) {
				return fmt.Errorf("无效的域名格式：'%s'", d)
			}
		}
	}

	enabledUpstreamCount, err := validateRuleUpstreams(data.Protocol, data.DynamicDNS, data.Upstreams, true)
	if err != nil {
		return err
	}

	if data.DynamicDNS && enabledUpstreamCount > 1 {
		return fmt.Errorf("动态 DNS 模式仅支持一个启用的上游（DNS 会解析出多个 IP）")
	}
	// dns_family 是「开关 + 值」的一体配置面：值域门不随 dynamic_dns 关闭而
	// 失效——关闭态落库的非法枚举渲染零消费，却会随导出/备份/集群快照放大，
	// 并在用户后续只切换开关时命中指向本次未提交字段的 400。空值放行
	//（Create 归 ipv4、Update 沿用存量）。
	if data.DnsFamily != "" && data.DnsFamily != "ipv4" && data.DnsFamily != "ipv6" && data.DnsFamily != "both" {
		return fmt.Errorf("无效的 DNS 协议栈 '%s'（仅支持 ipv4、ipv6 或 both）", data.DnsFamily)
	}

	// 健康检查路径只在主动健康检查启用时被渲染消费（caddy.go 的
	// health_checks.active 块）——未启用时属死字段，不参与形状校验：否则
	// 存量死组合（enable=0 + path 无前导 /）的任何无关编辑恒 400，且新建与
	// 更新的校验/清零先后顺序会给出不同结果。健康检查域名仍无条件走形状门
	// （畸形值在任何状态下都不得落库）。
	if data.EnableActiveHealthCheck {
		if err := validateRuleHealthCheckPath(data.HealthCheckPath); err != nil {
			return err
		}
	}

	// 健康检查域名（2026-10-10）：probe 的 Host 头（health_checks.active.headers.
	// Host 特判，不带端口）；仅 HTTP 规则渲染消费（TCP 健康检查走端口探测）。
	if data.HealthCheckHost != "" {
		if data.Protocol != "http" {
			return fmt.Errorf("健康检查域名仅 HTTP 规则支持")
		}
		if !isValidHost(data.HealthCheckHost) {
			return fmt.Errorf("健康检查域名 %q 无效（仅支持主机名，不带端口）", data.HealthCheckHost)
		}
	}

	// 证书来源白名单与规则级请求体上限收进共享保存门——
	// 四条调用路径（Create/Update/Duplicate/未来写入口）不再靠调用方自觉。
	// 此前 tls_source 白名单在 Create/Update/存量启用门各写一遍，复制路径靠
	// 「副本默认禁用 + 启用侧 stored 门」兜底（在导入侧实证的漂移形态
	// enable_tls=1 + tls_source 非白名单值 → 渲染 availableCerts 不认 → TLS
	// 端口明文服务）；request_body_max_size_mb 同样在三处各调一次。
	if data.EnableTLS && data.TLSSource != "manual" && data.TLSSource != "acme_dns" {
		return fmt.Errorf("启用 TLS 时必须选择证书来源（manual 或 acme_dns）")
	}
	// 关闭 TLS 时同样校验值域（无条件枚举门）：非空非法值不得落库——渲染
	// 零消费，但会随导出/备份/集群快照放大，且用户后续只开 TLS 时才报错。
	// 空值放行（Create/Update 写侧归默认）。
	if data.TLSSource != "" && data.TLSSource != "manual" && data.TLSSource != "acme_dns" {
		return fmt.Errorf("无效的证书来源 '%s'（仅支持 manual 或 acme_dns）", data.TLSSource)
	}
	if err := validateRuleRequestBodyMaxSizeMB(data.RequestBodyMaxSizeMB); err != nil {
		return err
	}

	if data.EnableTLS && data.TLSSource == "acme_dns" {
		// （写侧）→ 发现4 共享门：0 值、悬挂 id 与引用已禁用
		// （enabled=0）配置/提供商一律 400——与签发侧 certissuer.go 的
		// AND enabled=1 口径对齐，悬挂/禁用引用会静默落库并在签发期单任务失败。
		if err := validateRuleACMEReferences(acmeReferenceInput{
			EnableTLS: data.EnableTLS, TLSSource: data.TLSSource,
			ACMEConfigID: data.ACMEConfigID, CAProviderID: data.CAProviderID,
		}); err != nil {
			return err
		}
		if data.Domain == "" {
			return fmt.Errorf("ACME DNS 证书需要填写域名")
		}
		if err := services.ValidateACMEDomainsForIssuance(data.Domain); err != nil {
			return err
		}
	}

	if data.HealthCheckInterval < 1 {
		return fmt.Errorf("健康检查间隔必须 ≥ 1 秒")
	}

	if data.HealthCheckTimeout < 1 {
		return fmt.Errorf("健康检查超时必须 ≥ 1 秒")
	}

	// 曾钉「负值 400（>=0 放行，0=默认语义）」；库值唯一真相批 1+2
	// 阈值列转类型①值型，0 无效（渲染兜底 3/2 废除），<1 一律 400——
	// UpdateRule 显式 0（指针可表达）由此拦截。
	if data.HealthCheckUnhealthyThreshold < 1 {
		return fmt.Errorf("健康检查失败阈值必须 ≥ 1")
	}

	if data.HealthCheckHealthyThreshold < 1 {
		return fmt.Errorf("健康检查恢复阈值必须 ≥ 1")
	}

	// 阶段拦截页覆盖层：页引用存在性 + 状态码集合（Update nil 已合并为 0=
	// 未配，存在性校验仅作用于显式提供值；存量保留值不经此门——页删除侧
	// 引用检查与渲染侧「已失效」回落承担）。
	if err := validateStageBlockPageRef(data.BlockPageStage1ID, data.BlockPageStage1Status, "阶段 1（IP 访问控制/地域拦截）"); err != nil {
		return err
	}
	if err := validateStageBlockPageRef(data.BlockPageStage3ID, data.BlockPageStage3Status, "阶段 3（WAF）"); err != nil {
		return err
	}
	return nil
}

// clampAuditRetentionMonthsOnStartup 将存量越界 audit_retention_months 钳位到
// [1,12] 最近边界并记日志：写侧已加范围校验，历史越界值（超大值使
// 年龄裁剪 datetime 越界静默失效，仅剩条数兜底）在启动时收敛。
// 注：不得移入 caddy.go——TestCaddySectionKeys_matchUpdateSQL 按文本定位
// caddy.go 内首个 "UPDATE global_config SET" 提取 UpdateConfig 的列集合。
func clampAuditRetentionMonthsOnStartup() {
	var months int
	if err := db.DB.QueryRow(`SELECT COALESCE(audit_retention_months,3) FROM global_config WHERE id=1`).Scan(&months); err != nil {
		services.Logf("error", "读取日志保留月数失败，跳过启动钳位: %v", err)
		return
	}
	clamped := months
	if clamped < 1 {
		clamped = 1
	}
	if clamped > 12 {
		clamped = 12
	}
	if clamped == months {
		return
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_retention_months=? WHERE id=1`, clamped); err != nil {
		services.Logf("error", "钳位日志保留月数失败: %v", err)
		return
	}
	services.Logf("info", "日志保留月数 %d 超出 1-12 范围，已钳位为 %d", months, clamped)
}

// caddyRestartTriggerFile 是监督器(entrypoint)在 Caddy 进程重启后写入的
// 触发标记——watcher 检测到后调用 ApplyConfigOnStartup 走与容器启动完全
// 相同的配置载入流程(DB 渲染→校验→admin API 应用),修正 last_good 快照可能
// 滞后于 DB 的窗口( 用户裁定:自愈配置恢复须与启动初始化同一流程)。
const caddyRestartTriggerFile = "/tmp/caddy-restarted"

// caddyRestartProcessStart 进程启动时刻
// mtime 早于此的文件属上一进程生命周期残留——删除不执行（启动应用已在启动
// 流程完成，重放无意义）。
var caddyRestartProcessStart = time.Now()

// CaddyRestartWatcherOnce 是 caddy-restart-watcher daemon（RunTicker 2s 节拍）
// 的单轮工作体；原 StartCaddyRestartWatcher 的自建 goroutine/ticker 泵已按
// task-engine 标准 v2.2 退役——main 经 services.SetCaddyRestartWatcherRound
// 注入本函数，节拍与生命周期归任务引擎。
func (h *Handlers) CaddyRestartWatcherOnce() {
	h.caddyRestartWatcherOnce(caddyRestartTriggerFile, caddyRestartProcessStart)
}

// caddyRestartBackoff 是 caddy-restart 重试的退避状态（指数退避 + 落行降频）：
// watcher 每 2s 轮询触发文件，失败时按 2s→4s→…→30s 退避（未到点静默跳过），
// 且只有「首次 / 状态变化 / 每 N 轮」的重试走 RunSync 落 task_runs 行，其余
// 轮走 RunSyncQuiet（执行同一 Run 体、不落行）——此前持续失败（Caddy 长期不可达）
// 每 2s 落一条失败行，任务历史被淹没。
const (
	caddyRestartBackoffBase  = 2 * time.Second
	caddyRestartBackoffMax   = 30 * time.Second
	caddyRestartRecordEveryN = 10
)

var caddyRestartBackoff struct {
	mu            sync.Mutex
	attempts      int       // 连续失败轮数
	nextAttempt   time.Time // 下次允许尝试的时刻
	lastStatus    string    // 上次结果（ok/failed）
	triggerMod    time.Time // 退避状态对应的触发文件 mtime
	appliedMod    time.Time // 已成功应用且等待删除的触发文件 mtime
	removalWarned time.Time // 删除失败已留痕的触发文件 mtime（同一触发只报一次）
	statWarned    bool      // 触发文件探测失败已留痕（恢复后补 info 并清零）
}

// caddyRestartStat 是触发文件探测入口（测试缝：注入 stat 失败形态）。
var caddyRestartStat = os.Stat

// markCaddyRestartTriggerApplied 记录「该 mtime 的触发事件已成功应用」：
// 触发文件删除失败（只读/异常挂载）时，watcher 据此不再每个 tick 重跑全量
// 渲染 + /load。成功收尾会把退避清零/置 ok，若只按文件存在与否判定，下一轮
// 尝试数恒为 1 且 lastStatus=ok，退避与落行降频全部失效——持续重载 Caddy
// 配置且任务历史膨胀。
func markCaddyRestartTriggerApplied(mod time.Time) {
	caddyRestartBackoff.mu.Lock()
	caddyRestartBackoff.appliedMod = mod
	caddyRestartBackoff.mu.Unlock()
}

// caddyRestartTriggerAlreadyApplied 返回该触发事件是否已成功应用过。
func caddyRestartTriggerAlreadyApplied(mod time.Time) bool {
	caddyRestartBackoff.mu.Lock()
	defer caddyRestartBackoff.mu.Unlock()
	return !caddyRestartBackoff.appliedMod.IsZero() && caddyRestartBackoff.appliedMod.Equal(mod)
}

// caddyRestartNoteRemovalFailure 删除触发文件失败时留一条 warn（同一触发
// mtime 只报一次；ENOENT 属并发删除的正常终态，不报）。此前两处删除失败均
// 静默丢弃错误，文件残留导致的持续重应用无任何日志指向根因。
func caddyRestartNoteRemovalFailure(mod time.Time, err error) {
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return
	}
	caddyRestartBackoff.mu.Lock()
	alreadyWarned := caddyRestartBackoff.removalWarned.Equal(mod)
	if !alreadyWarned {
		caddyRestartBackoff.removalWarned = mod
	}
	caddyRestartBackoff.mu.Unlock()
	if !alreadyWarned {
		services.Logf("warn", "Caddy 重启触发文件删除失败（已应用的配置不会重复执行，请检查目录权限/挂载）: %v", err)
	}
}

// caddyRestartNoteStatFailure 区分触发文件探测的错误类别：文件不存在与成功
// 同属常态（无待处理事件），任何其它错误（权限收紧、异常只读挂载）都会让
// 崩溃自愈链永久静默停摆——按状态只留一条 warn，恢复探测后补一条 info。
// 此前该分支裸 return，四类留痕面（运行日志/任务日志/审计/横幅）全无信号。
func caddyRestartNoteStatFailure(err error) {
	unexpected := err != nil && !errors.Is(err, os.ErrNotExist)
	caddyRestartBackoff.mu.Lock()
	alreadyWarned := caddyRestartBackoff.statWarned
	caddyRestartBackoff.statWarned = unexpected
	caddyRestartBackoff.mu.Unlock()
	switch {
	case unexpected && !alreadyWarned:
		services.Logf("warn", "Caddy 重启触发文件探测失败（崩溃自愈链停摆，请检查 /tmp 触发文件所在目录的权限/挂载）: %v", err)
	case !unexpected && alreadyWarned:
		services.Logf("info", "Caddy 重启触发文件探测恢复")
	}
}

// observeCaddyRestartTrigger 以触发文件 mtime 标识「本轮重启事件」：新事件
// （mtime 变化）重置退避——退避只约束同一事件的连续重试，新一轮 Caddy 重启
// 必须立即尝试（否则上一轮的长退避会拖住新事故的恢复）。
func observeCaddyRestartTrigger(mod time.Time) {
	caddyRestartBackoff.mu.Lock()
	if !caddyRestartBackoff.triggerMod.Equal(mod) {
		caddyRestartBackoff.triggerMod = mod
		caddyRestartBackoff.attempts = 0
		caddyRestartBackoff.nextAttempt = time.Time{}
		caddyRestartBackoff.lastStatus = ""
	}
	caddyRestartBackoff.mu.Unlock()
}

// caddyRestartShouldAttempt 返回本轮是否允许尝试（退避窗口内直接跳过）。
func caddyRestartShouldAttempt(now time.Time) bool {
	caddyRestartBackoff.mu.Lock()
	defer caddyRestartBackoff.mu.Unlock()
	return !now.Before(caddyRestartBackoff.nextAttempt)
}

// caddyRestartBeginAttempt 登记一次尝试并返回本轮是否落 task_runs 行
// （首次 / 连续失败流中的状态变化 / 每 N 轮），以及当前连续失败轮数。
func caddyRestartBeginAttempt(now time.Time) (record bool, attempts int) {
	caddyRestartBackoff.mu.Lock()
	defer caddyRestartBackoff.mu.Unlock()
	caddyRestartBackoff.attempts++
	attempts = caddyRestartBackoff.attempts
	// 上次成功（或本轮为首次）→ 本轮结果属状态变化，必须落行；持续失败流
	// 只每 N 轮落一行。
	record = attempts == 1 || caddyRestartBackoff.lastStatus == "ok" || attempts%caddyRestartRecordEveryN == 0
	return record, attempts
}

// caddyRestartEndAttempt 记录本轮结果并安排下次尝试时刻：成功清零退避、
// 失败以尝试结束时刻为基准按指数退避（上限 30s）。状态变化（failed→ok 或 ok→failed）
// 强制落行。now 由调用方显式传入（与 caddyRestartShouldAttempt/BeginAttempt 的
// now 同源）——收尾时刻是「下一次尝试」的基准，真实时钟散落在被测函数内部
// 会让退避窗口断言只能靠区间猜测。
func caddyRestartEndAttempt(now time.Time, ok bool) {
	caddyRestartBackoff.mu.Lock()
	defer caddyRestartBackoff.mu.Unlock()
	status := "failed"
	if ok {
		status = "ok"
		caddyRestartBackoff.attempts = 0
		caddyRestartBackoff.nextAttempt = time.Time{}
	} else {
		delay := caddyRestartBackoffBase
		for i := 1; i < caddyRestartBackoff.attempts && delay < caddyRestartBackoffMax; i++ {
			delay *= 2
		}
		if delay > caddyRestartBackoffMax {
			delay = caddyRestartBackoffMax
		}
		caddyRestartBackoff.nextAttempt = now.Add(delay)
	}
	caddyRestartBackoff.lastStatus = status
}

// caddyRestartWatcherOnce 单轮处理
//   - 存量文件（mtime 早于进程启动）→ 删除不执行；
//   - 新触发 → 先 RunSync 成功后才删文件——失败保留下轮重试（曾先删后跑，
//     重应用失败即丢重试机会）；
//   - 失败按指数退避（2s→30s），且仅在首次/状态变化/每 10 轮落 task_runs 行
//     （其余轮 RunSyncQuiet 执行同体不落行）——持续失败行数有界。
func (h *Handlers) caddyRestartWatcherOnce(triggerFile string, processStart time.Time) {
	st, err := caddyRestartStat(triggerFile)
	if err != nil {
		// 文件不存在是常态（无待处理事件）；其余错误会让 watcher 永久静默
		// 跳过，必须留痕，否则崩溃自愈链停摆只能靠翻库/猜。
		caddyRestartNoteStatFailure(err)
		return
	}
	caddyRestartNoteStatFailure(nil)
	if st.ModTime().Before(processStart) {
		if err := os.Remove(triggerFile); err != nil {
			// 存量文件删不掉（只读目录/异常挂载）时每个 tick 都会重进本分支：
			// 按触发 mtime 只留一条 warn，不再重复 info。
			caddyRestartNoteRemovalFailure(st.ModTime(), err)
			return
		}
		services.Logf("info", "检测到存量 Caddy 重启触发文件（mtime 早于进程启动），按上一进程残留清理不执行")
		return
	}
	if caddyRestartTriggerAlreadyApplied(st.ModTime()) {
		// 同一触发事件已成功应用，只是文件没能删除：只重试删除，不得每 2s
		// 重跑一次全量渲染 + /load（成功收尾清零退避，存在性判据会无限重放）。
		if err := os.Remove(triggerFile); err != nil {
			caddyRestartNoteRemovalFailure(st.ModTime(), err)
		}
		return
	}
	now := time.Now()
	observeCaddyRestartTrigger(st.ModTime())
	if !caddyRestartShouldAttempt(now) {
		return // 退避窗口内：静默跳过（不执行、不落行、不刷日志）
	}
	record, attempts := caddyRestartBeginAttempt(now)
	services.Logf("info", "检测到 Caddy 进程重启，经任务引擎调度配置载入（DB 渲染；第 %d 次重试，落行=%v）", attempts, record)
	// 一切任务统一引擎调度——曾直调
	// ApplyConfigOnStartup 绕过引擎（无 task_runs/[start]/[done]/单飞，
	// 审计+任务日志双行）。Run 体触发门已放行 caddy-restart。
	// 落行降频：连续失败时只有首次/状态变化/每 10 轮走 RunSync（落 task_runs），
	// 其余轮走 RunSyncQuiet 执行同一 Run 体不落行。
	var runErr error
	if te := services.TaskEngine(); te != nil {
		if record {
			_, runErr = te.RunSync("startup:config-load", "caddy-restart", "")
		} else {
			_, runErr = te.RunSyncQuiet("startup:config-load", "caddy-restart", "")
		}
	} else { // 引擎缺席（测试环境）回退
		runErr = h.ApplyConfigOnStartup("")
	}
	if runErr != nil {
		caddyRestartEndAttempt(now, false)
		services.Logf("error", "Caddy 重启后配置重应用失败（触发文件保留，按退避重试）: %v", runErr)
		return
	}
	caddyRestartEndAttempt(now, true)
	services.Logf("info", "Caddy 重启后配置重应用完成（引擎调度，与启动流程同源）")
	markCaddyRestartTriggerApplied(st.ModTime())
	if err := os.Remove(triggerFile); err != nil {
		caddyRestartNoteRemovalFailure(st.ModTime(), err)
	}
}

// startupUsersLookupFailedLabel 是「启动守卫的用户计数查询失败」留痕前缀
// （测试按此断言；守卫本轮失明属可查事实，不得静默）。
const startupUsersLookupFailedLabel = "启动守卫：用户计数查询失败（本次无法判定实例是否已初始化）"

// countStartupUsers 读取用户数，作为「实例是否已初始化」的证据。查询失败时
// 留痕 warn 并返回 ok=false——调用方按「无正向证据」保持原有放行取舍（与
// 「外来路由探测失败即放行」同口径，启动可用性不回退），但守卫失明必须可查：
// 此前失败与 userCount>0 合并在同一 case，守卫静默失效零留痕。
func countStartupUsers(database *sql.DB) (int, bool) {
	var userCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
		services.Logf("warn", "问题: %s: %v", startupUsersLookupFailedLabel, err)
		return 0, false
	}
	return userCount, true
}

// ApplyConfigOnStartup 系统配置载入（startup:config-load Run 体唯一执行通道：
// BootSync 启动传空 operator、手动重载经 wire 传操作者）。
// operator 非空=手动触发，载入审计归因操作者；空=system。
func (h *Handlers) ApplyConfigOnStartup(operator string) error {
	actor := operator
	if actor == "" {
		actor = "system"
	}
	// 存量越界 audit_retention_months 启动钳位（写侧已加 1-12 校验）。
	clampAuditRetentionMonthsOnStartup()
	// 启动路径补存量规则校验（保存/导入/启用路径已有自环与遮蔽拦截），
	// 命中即响亮报错并记审计，但不阻断启动：单条坏规则不应拖垮整个服务，与
	// 「启动应用失败仅记日志保旧配置」的既有取舍一致（main.go 调用侧同样不退出）。
	if err := validateEnabledStoredRuleConfigs(context.Background()); err != nil {
		services.Logf("error", "启动校验发现无效规则配置，继续启动（保留旧配置）：%v", err)
		services.RecordAuditLog(actor, "启动警告", "系统配置", "启动校验发现无效规则配置："+err.Error(), "")
	}

	// 启动竞态修复：先等监督器「启动回放阶段完成」标记再继续——
	// 监督器首启 last-good 回放与本 BootSync 应用各等 admin 就绪即写，先后为
	// 硬币；本应用先落时监督器回放旧 LKG 覆盖新渲染（v2.3.7-beta 发版实锤）。
	// 等标记把时序定死为「回放→标记→应用」。监督器不在场（测试/裸跑）立即
	// 返回；标记缺失等满超时放行（waitStartupReplayDone 内注释）。
	waitStartupReplayDone()

	// Wait for Caddy to be ready (up to 10 seconds)
	maxRetries := 20
	retryDelay := 500 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		// 共享客户端（Transport 复用）+ 每请求 2s 超时（context 承载）。
		// 即使 err!= nil，resp 也可能非 nil（如重定向），需统一关闭。
		resp, err := caddyAdminGet(context.Background(), h.cfg.CaddyAdminURL, "/config/", 2*time.Second) // 就绪探针与 GetCaddyStatus 同源取配置地址，不再硬编码 localhost:2019
		if resp != nil {
			resp.Body.Close()
		}
		if err == nil && resp.StatusCode < 500 {
			break
		}
		time.Sleep(retryDelay)
	}

	rows, err := db.DB.Query(`SELECT caddy_id FROM lb_rules WHERE enabled = 1`)
	if err != nil {
		return err
	}
	defer rows.Close()

	count := 0
	ownRouteIDs := make(map[string]bool)
	for rows.Next() {
		var caddyID string
		if err := rows.Scan(&caddyID); err != nil {
			return err
		}
		count++
		ownRouteIDs[caddyID] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// C 加固（2026-09-25 漂移根因裁定）：host 网络下默认 admin 地址无鉴权共享，
	// 外来实例误指会把自身配置 /load 进本实例 Caddy（09-18 多余路由、09-24
	// 清空路由两次实证）。启动应用前发现运行配置含非本库规则路由时响亮留痕——
	// 覆盖方（生产恢复）与被覆盖方（误指实例）下次启动都会在审计中可见；
	// 应用照常执行，恢复性收敛不可阻断。探测失败按无正向证据跳过。
	if foreign, probeErr := services.ForeignRunningRuleRoutes(h.cfg.CaddyAdminURL, ownRouteIDs); probeErr == nil && len(foreign) > 0 {
		shown := foreign
		if len(shown) > 5 {
			shown = shown[:5]
		}
		wrapped := fmt.Sprintf("运行配置含非本库规则路由（%s，共 %d 条）——疑似 Caddy Admin 地址误配或外来实例曾写入本实例 Caddy，本次启动应用将覆盖收敛", strings.Join(shown, "、"), len(foreign))
		services.Logf("error", "问题: %s", wrapped)
		services.RecordAuditLog(actor, "启动警告", "系统配置", wrapped, "")
	}

	// 未初始化实例（无任何用户）空库
	// 启动时，若 Caddy 运行配置仍含规则路由，跳过本次应用——几乎必然是数据
	// 目录/Admin 地址误配（2026-09-24 实证：dev 实例误指生产 admin 清空运行
	// 配置）。运行配置保持原样，分叉由看门狗「多余规则路由」横幅持续上报；
	// 探测失败（admin 不可达等）按无正向证据放行。已初始化实例（≥1 用户）
	// 的 0 规则状态视为管理意图（规则删除时即已即时应用收敛），不在此守卫
	// 范围——否则「删光规则后重启」永远无法收敛到空配置（评审截获的陷阱）。
	// 用户计数查询失败（库损坏/未建表/锁）时 countStartupUsers 留痕 warn 并
	// 按「无法判定」放行——守卫本轮失明，但不因此阻断启动可用性。
	if count == 0 {
		userCount, usersKnown := countStartupUsers(db.DB)
		if usersKnown && userCount == 0 {
			if hasRoutes, probeErr := services.RunningConfigHasRuleRoutes(h.cfg.CaddyAdminURL); probeErr == nil && hasRoutes {
				wrapped := "启动守卫：未初始化实例（无用户、无启用规则），但 Caddy 运行配置仍含规则路由——跳过本次启动应用（疑似数据目录或 Caddy Admin 地址误配），运行配置保持原样；漂移状态由看门狗持续上报"
				services.Logf("error", "问题: %s", wrapped)
				services.RecordAuditLog(actor, "启动警告", "系统配置", wrapped, "")
				// 与同函数成功/回退分支一致，守卫命中属真实
				// 执行轮结论，须在 tasks/startup:config-load.log 留业务摘要行
				// （此前只有 Logf+审计，任务日志看似「跑了但无结论」）。
				services.TaskLogf("startup:config-load", "caddy", "启动守卫命中：已跳过配置应用（运行配置含非本库规则路由）")
				return nil
			}
		}
	}
	services.Logf("info", "Applying Caddy config on startup (enabled rules: %d)", count)
	// 崩溃窗口收敛点：IP 名单投影（tp.txt / u-* / p*）是渲染的磁盘副作用，
	// 写路径在事务提交前落盘——进程在「投影已写、事务未提交」之间被杀会留下
	// 未提交内容。本次启动渲染以已提交库值为唯一真相源，逐 scope 重写在役
	// 投影（内容不一致→原子换内容），因此渲染成功即在役投影=已提交视图，
	// 无需额外回滚动作。
	// 窗口上界与跳过形态：①渲染成功前，监督器回放的 last-known-good 配置可能
	// 仍引用崩溃窗口写入的投影（上界=「回放→标记→应用」之间的秒级时长，应用
	// 完成即收敛）；②已提交视图渲染失败（库数据损坏）时没有可收敛目标——按
	// 下方裁定回退 last-known-good，投影部分维持原状（需「崩溃窗口+数据损坏」
	// 双故障才可达）；③未初始化实例的启动守卫跳过整轮应用，该形态不可能产生
	// 本实例的名单写入（写名单需认证用户），无待收敛窗口。已提交视图不再引用
	// 的孤儿投影（策略解绑/规则删除后的旧 scope）不被重写，由 24h GC 回收。
	if err := h.applyCaddyConfigE(); err != nil {
		// 2026-09-06 裁定 ③：DB 渲染被拒时回退最后已知正确配置——负载均衡
		// 可用性优先。caddy_apply_error 标记已由 applyCaddyConfigE 落下，
		// DB↔运行配置分叉对看门狗/前端横幅保持可见，等待人工修复。
		if fbErr := h.caddyService.ApplyLastKnownGood(); fbErr == nil {
			wrapped := fmt.Sprintf("启动时数据库渲染的配置被 Caddy 拒绝，已回退最后已知正确配置（负载均衡保持可用，运行配置与数据库分叉待修复）：%v", err)
			services.TaskLogf("startup:config-load", "caddy", "Caddy 应用被拒，已回退最后已知正确配置：%v", err)
			services.Logf("error", "问题: %s", wrapped)
			services.RecordAuditLog(actor, "启动警告", "系统配置", wrapped, "")
			// 2026-09-07 裁定：从节点追加补偿标记——Pull 的 304 分支识别后
			// 全量重拉，消除「同步正常+运行旧配置」静默窗口；主节点不经 Pull
			// 消费该标记，故不写。
			if isMaster, mErr := services.RoleOf(context.Background(), db.DB); mErr == nil && !isMaster {
				if mErr := services.MarkStartupFallbackPending(context.Background(), db.DB); mErr != nil {
					services.Logf("error", "startup fallback: write compensation marker failed: %v", mErr)
				}
			}
			return nil
		} else {
			services.Logf("error", "last-known-good fallback failed: %v", fbErr)
			// 双失败（渲染被拒+回退失败）从节点同样
			// 写补偿标记——无标记时 Pull 的 304 分支永远判「同步正常」，运行配置
			// 与数据库的未知分叉静默存活（自愈失明）；标记触发下轮全量重拉。
			if isMaster, mErr := services.RoleOf(context.Background(), db.DB); mErr == nil && !isMaster {
				if mErr := services.MarkStartupFallbackFailed(context.Background(), db.DB, fbErr); mErr != nil {
					services.Logf("error", "startup fallback: write double-failure compensation marker failed: %v", mErr)
				}
			}
		}
		return fmt.Errorf("apply Caddy config on startup: %w", err)
	}
	services.Logf("info", "启动：Caddy 配置已载入（启用规则 %d 条）", count)
	services.TaskLogf("startup:config-load", "caddy", "Caddy 配置渲染应用成功（启用规则 %d 条）", count)
	services.RecordAuditLog(actor, "载入", "系统配置", fmt.Sprintf("从数据库载入配置并应用 Caddy；启用规则 %d 条（触发源见任务运行历史）", count), "")

	return nil
}

func (h *Handlers) validatePortFromDB(protocol string, port int, excludeCaddyID string) error {
	// Check conflict with existing rules:
	// - HTTP rules may share a port (Caddy routes by host), but cannot share with TCP.
	// - TCP rules are L4 and cannot share a port with any other rule (HTTP or TCP).
	// 仅统计启用中的规则：禁用规则不占用端口，创建/更新时不应被其阻塞；启用时
	// 本函数同样按 enabled=1 过滤，第二条禁用规则启用时会看到第一条已启用而冲突。
	var count int
	var err error
	if excludeCaddyID != "" {
		if protocol == "tcp" {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND caddy_id != ? AND enabled = 1", port, excludeCaddyID).Scan(&count)
		} else {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND caddy_id != ? AND protocol = 'tcp' AND enabled = 1", port, excludeCaddyID).Scan(&count)
		}
	} else {
		if protocol == "tcp" {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND enabled = 1", port).Scan(&count)
		} else {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND protocol = 'tcp' AND enabled = 1", port).Scan(&count)
		}
	}
	if err != nil {
		return fmt.Errorf("验证端口时数据库错误: %v", err)
	}

	if count > 0 {
		return fmt.Errorf("端口 %d 已被其他规则占用", port)
	}

	return nil
}

// checkPortTLSMix:同端口 TLS/明文混布拦截——Caddy 监听器
// 按端口二选一,混布会把整个端口监听器切为 TLS,明文规则流量全部握手失败。
// 判定键=enable_tls 意图(不看证书存在性:ACME 签发中/延迟翻转的同端口规则
// 同样会被监听器形态波及);仅统计启用中的规则。
func checkPortTLSMix(excludeCaddyID string, port int, enableTLS bool) error {
	opposite := 1
	if enableTLS {
		opposite = 0
	}
	// 对齐全仓 IIF 归一口径——NULL 行（远古存量/直改 DB）归一为
	// 明文（0）参与混布判定；裸 enable_tls=? 比较下 NULL 行漏检。
	query := "SELECT COUNT(*) FROM lb_rules WHERE listen_port=? AND protocol='http' AND enabled=1 AND IIF(enable_tls IN ('1',1),1,0)=?"
	args := []any{port, opposite}
	if excludeCaddyID != "" {
		query += " AND caddy_id!=?"
		args = append(args, excludeCaddyID)
	}
	var count int
	if err := db.DB.QueryRow(query, args...).Scan(&count); err != nil {
		return fmt.Errorf("验证端口 TLS 形态时数据库错误: %v", err)
	}
	if count > 0 {
		other := "TLS"
		if enableTLS {
			other = "明文"
		}
		return fmt.Errorf("端口 %d 已被%s规则使用，TLS 与明文规则不能混布同一端口（该端口监听器将整体切换为 TLS）", port, other)
	}
	return nil
}

// validateDnsServerShape:DNS 服务器地址形状校验——host[:port];
// 裸 host 容错(SplitHostPort 报 missing port 时按裸 host 处理),拒绝空
// host、非数字/越界端口与控制字符。
// validateDnsServerShape(2026-10-04 多地址守卫):先按逗号/中文逗号/空格/分号
// 拆分,逐地址跑单地址校验——此前整串当单 host 放过,垃圾地址逐个通过。
func validateDnsServerShape(raw string) error {
	for _, addr := range services.SplitDnsAddresses(raw) {
		if err := validateSingleDnsAddress(addr); err != nil {
			return err
		}
	}
	return nil
}

// validateSingleDnsAddress 单地址校验:host[:port] 形态;host 须为 IP(netip)
// 或含点的 FQDN 或 localhost;端口 1-65535;拒绝空 host 与控制字符。
// 含冒号的输入只接受合法 host:port（含 [v6]:port）——SplitHostPort
// 失败的多冒号/空端口/括号畸形一律拒绝，不得回落「含点即 FQDN」（原实现让
// bad.example.com:80:90 这类串整串当 host 通过字段门）。
func validateSingleDnsAddress(server string) error {
	server = strings.TrimSpace(server)
	if server == "" {
		return fmt.Errorf("DNS 服务器地址无效")
	}
	// 裸 IP（含裸 IPv6 字面量、带 zone 形态）：无端口，直接接受。
	if _, err := netip.ParseAddr(server); err == nil {
		return nil
	}
	// 方括号裸 IPv6（[::1]，无端口）：容错接受并校验内部字面量。
	if strings.HasPrefix(server, "[") && strings.HasSuffix(server, "]") {
		if _, err := netip.ParseAddr(server[1 : len(server)-1]); err != nil {
			return fmt.Errorf("DNS 服务器地址无效: %s", server)
		}
		return nil
	}
	host := server
	if strings.Contains(server, ":") {
		h, p, err := net.SplitHostPort(server)
		if err != nil {
			return fmt.Errorf("DNS 服务器地址格式无效（须为 IP、域名或 host:port）: %s", server)
		}
		if p == "" {
			return fmt.Errorf("DNS 服务器端口不能为空")
		}
		port, perr := strconv.Atoi(p)
		if perr != nil || port < 1 || port > 65535 {
			return fmt.Errorf("DNS 服务器端口必须在 1-65535 之间")
		}
		host = h
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("DNS 服务器地址无效")
	}
	for _, r := range host {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("DNS 服务器地址含非法字符")
		}
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if host == "localhost" {
		return nil
	}
	// host 部分复用 isValidHost 的标签字母表/首尾校验——
	// 此前只判「不含控制字符 + 含点」，`a!b.example.com`、`x/y.example.com`
	// 等畸形串通过字段门并落库；渲染侧把该串直接放进 resolver.addresses，
	// Caddy 接受地址但不做可达性校验 → 动态上游解析静默失败（规则 502），
	// 保存时零提示。isValidHost 保留了下划线放宽语义（Docker 服务名），
	// 并已统一拒绝全数字点分的非法 IP 假象（999.1.1.1、1.2.3.4.5）。
	if !strings.Contains(host, ".") || !isValidHost(host) {
		return fmt.Errorf("DNS 服务器地址须为 IP 或完整域名: %s", server)
	}
	return nil
}
