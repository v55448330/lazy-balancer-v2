package services

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

const (
	JobLifecycleQueued     = "queued"
	JobLifecycleActive     = "active"
	JobLifecycleDownloaded = "downloaded"
	JobLifecycleIssued     = "issued"
	JobLifecycleFailed     = "failed"
	JobLifecycleWaitingCA  = "waiting_ca"
	JobLifecycleDisabled   = "disabled"
)

var (
	ErrJobTransitionConflict = errors.New("certificate job status transition conflict")
	// allJobStatuses 派生自 db.CertJobStatuses()（单源：cert_jobs 的
	// CHECK 枚举与 DDL 由同一列表生成；services 依赖 db，反向不可行）。
	allJobStatuses         = db.CertJobStatuses()
	nonTerminalJobStatuses = withoutJobStatuses("issued", "failed", "disabled")
	jobLifecycleByStatus   = map[string]string{
		"queued":              JobLifecycleQueued,
		"pending":             JobLifecycleActive,
		"processing":          JobLifecycleActive,
		"creating_account":    JobLifecycleActive,
		"creating_order":      JobLifecycleActive,
		"order_created":       JobLifecycleActive,
		"cleanup_dns":         JobLifecycleDownloaded,
		"cleanup_warning":     JobLifecycleDownloaded,
		"presenting_dns":      JobLifecycleActive,
		"waiting_propagation": JobLifecycleActive,
		"dns_propagated":      JobLifecycleActive,
		"accepting_challenge": JobLifecycleActive,
		"validating":          JobLifecycleActive,
		"validated":           JobLifecycleActive,
		"finalizing":          JobLifecycleActive,
		"finalized":           JobLifecycleActive,
		"downloading":         JobLifecycleActive,
		"downloaded":          JobLifecycleDownloaded,
		"issued":              JobLifecycleIssued,
		"failed":              JobLifecycleFailed,
		"waiting_ca":          JobLifecycleWaitingCA,
		"disabled":            JobLifecycleDisabled,
		"waiting_order_ready": JobLifecycleActive,
		"order_ready":         JobLifecycleActive,
		"waiting_order_valid": JobLifecycleActive,
		"order_valid":         JobLifecycleActive,
	}
)

// deploymentLifecycleJobStatuses / DeploymentLifecycleJobStatusSQL 由
// jobLifecycleByStatus 派生（JobLifecycle==downloaded 单源）——状态集新增时
// 只改映射表，切片与 SQL IN 片段不再双份真源。消费方：transitionJob 的
// from 集合、启动/补扫装载的 CAS 源态集、cluster_report 与 handlers 的 SQL IN
// （跨包消费方无法触达切片，必须走导出的 SQL 片段）。
var (
	deploymentLifecycleJobStatuses = func() []string {
		statuses := make([]string, 0, 3)
		for status, lifecycle := range jobLifecycleByStatus {
			if lifecycle == JobLifecycleDownloaded {
				statuses = append(statuses, status)
			}
		}
		sort.Strings(statuses)
		return statuses
	}()
	// DeploymentLifecycleJobStatusSQL 供 SQL IN (...) 复用（由同一切片派生，
	// 非编译期常量——拼接点均为运行时字符串构造）。
	DeploymentLifecycleJobStatusSQL = "'" + strings.Join(deploymentLifecycleJobStatuses, "','") + "'"
	// deploymentCleanupJobStatuses 是部署生命周期中「仅剩 DNS 清理窗口」的子集：
	// downloaded 之外的部署态行由补扫的时间窗/settle 分支单独处理（它们不带
	// window 判据），cleanup_* 行则可能连窗口列都没写成功，必须无条件拾起。
	deploymentCleanupJobStatuses = func() []string {
		statuses := make([]string, 0, len(deploymentLifecycleJobStatuses))
		for _, status := range deploymentLifecycleJobStatuses {
			if status != "downloaded" {
				statuses = append(statuses, status)
			}
		}
		return statuses
	}()
	// DeploymentCleanupJobStatusSQL 同上，供补扫 cleanup 分支的 SQL IN 复用
	// （该分支刻意不覆盖 downloaded——否则 downloaded 行会绕过窗口与沉降判据）。
	DeploymentCleanupJobStatusSQL = "'" + strings.Join(deploymentCleanupJobStatuses, "','") + "'"
	// deploymentPersistenceJobStatuses = 部署生命周期 + downloading：
	// downloading 是唯一「ACME 证书字节已到手、但 downloaded 进度行未落库」的
	// active 形态（issuer 的 stage 序列为 …finalized→waiting_order_valid→
	// order_valid→downloading→downloaded），一次瞬时 DB 写失败就让行停在这里。
	// 若部署链只用部署生命周期求值，失败回写首查 0 行提前返回：刚签发的材料
	// 只存在内存、任务滞留 active 且无周期通道（补扫只收 downloaded/cleanup_*，
	// 启动恢复只收非终态）。
	// 其余 active 签发态刻意不在集合内：它们发生在证书字节到手之前，走到部署
	// 失败回写的材料必然来自更早的尝试（并发 requeue/取消后的陈旧回调），把行
	// 写回 downloaded 会越权改写正在进行的签发（见
	// doesNotDowngradeOutsideDeployableLifecycle 契约）。queued/waiting_ca 同理
	// 由队列/CA 退避链维护。
	deploymentPersistenceJobStatuses = func() []string {
		statuses := make([]string, 0, len(deploymentLifecycleJobStatuses)+1)
		statuses = append(statuses, deploymentLifecycleJobStatuses...)
		statuses = append(statuses, "downloading")
		sort.Strings(statuses)
		return statuses
	}()
)

type jobTransitionExecutor interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// AllJobStatuses 返回 cert_jobs.status 规范枚举的副本（单一真源
// 与 db.CertJobStatuses()/fresh DDL CHECK/迁移白名单同源）。调用方可安全修改
// 返回值，不影响状态机。
func AllJobStatuses() []string { return db.CertJobStatuses() }

func withoutJobStatuses(excluded ...string) []string {
	exclude := make(map[string]struct{}, len(excluded))
	for _, status := range excluded {
		exclude[status] = struct{}{}
	}
	statuses := make([]string, 0, len(allJobStatuses)-len(exclude))
	for _, status := range allJobStatuses {
		if _, skip := exclude[status]; !skip {
			statuses = append(statuses, status)
		}
	}
	return statuses
}

func JobLifecycle(status string) string {
	if lifecycle, exists := jobLifecycleByStatus[status]; exists {
		return lifecycle
	}
	return JobLifecycleFailed
}

func JobIsTerminal(status string) bool {
	switch JobLifecycle(status) {
	case JobLifecycleIssued, JobLifecycleFailed, JobLifecycleDisabled:
		return true
	default:
		return false
	}
}

// maxJobMessageBytes 限制写入 cert_jobs.message 的任务消息大小。CA 错误详情等外部
// 文本可能无界嵌入错误链，而 message 列会同步到从节点并展示在 UI（历史
// 各写入点（failJob/jobLogger.Log/deploymentFailed）统一截断。
const maxJobMessageBytes = 1024

// truncateJobMessage 将任务消息截断到 maxJobMessageBytes 字节内，并回退到合法
// UTF-8 边界，避免 LimitReader 式按字节截断留下多字节字符残片。
func truncateJobMessage(message string) string {
	if len(message) <= maxJobMessageBytes {
		return message
	}
	return string(truncateValidUTF8Tail([]byte(message[:maxJobMessageBytes])))
}

// appendJobMessageNote 给任务消息追加终态/状态说明（上限说明、慢速重试说明
// 等）：先截断 base 到「上限-说明长度」预算再追加，说明恒完整保留且整体不超
// maxJobMessageBytes。此前各写点「先追加后截断」——base 过长时尾部说明被整段
// 截掉（终态语义丢失，UI 看不出已停止自动重试/已转慢速重试）。
func appendJobMessageNote(base, note string) string {
	budget := maxJobMessageBytes - len(note)
	if budget < 0 {
		budget = 0
	}
	return truncateJobMessageTo(base, budget) + note
}

// truncateJobMessageTo 按指定字节预算截断并回退合法 UTF-8 边界
// （truncateJobMessage 的预算参数化单源）。
func truncateJobMessageTo(message string, budget int) string {
	if len(message) <= budget {
		return message
	}
	if budget <= 0 {
		return ""
	}
	return string(truncateValidUTF8Tail([]byte(message[:budget])))
}

// issuedFinalizeResetFields 是 issued 成功终态必须清零的失败预算单源：
// renewal_attempts/ca_available_after/last_error_code。证书成功签发即新一代
// 开始，上一代的失败计数/退避窗口不得跨世代携带——否则配置上限附近的行在
// 下一轮续期首次失败即触顶，自动续签停摆。全部 issued 终态写点（主签发路径、
// 快速重部署两出口、启动恢复「已有有效证书」出口）必须并入本字段集，禁止各
// 写点再自持一份（历史上三处漂移即由此产生）。
func issuedFinalizeResetFields() map[string]any {
	return map[string]any{
		"renewal_attempts":   0,
		"ca_available_after": nil,
		"last_error_code":    nil,
	}
}

// IssuedFinalizeResetSQL 是 issued 终态失败预算清零的 SQL 片段单源（供
// handlers 侧 resume 写点复用——issuedFinalizeFields 的 map 形态跨包不可达，
// SQL 片段与 map 字段集同源派生，由 TestIssuedFinalizeResetSQL_matchesFields
// 对账钉住）。形态：逗号前置键值串，拼入 UPDATE cert_jobs SET 子句。
func IssuedFinalizeResetSQL() string {
	parts := make([]string, 0, len(issuedFinalizeResetFields()))
	for _, key := range []string{"renewal_attempts", "ca_available_after", "last_error_code"} {
		v := issuedFinalizeResetFields()[key]
		if v == nil {
			parts = append(parts, key+"=NULL")
		} else {
			parts = append(parts, fmt.Sprintf("%s=%v", key, v))
		}
	}
	return strings.Join(parts, ",")
}

// issuedFinalizeFields 组装 issued 终态写入字段：失败预算清零（单源）+
// 调用方附加字段（message/expires_at/部署簿记等）。附加键不得覆盖预算键
// （renewal_attempts/ca_available_after/last_error_code）——携带即 panic
// 响亮拒绝：静默覆盖会让失败计数/退避窗口跨证书世代携带，破坏清零单源。
func issuedFinalizeFields(extra map[string]any) map[string]any {
	fields := issuedFinalizeResetFields()
	for key, value := range extra {
		if _, budget := fields[key]; budget {
			panic(fmt.Sprintf("issuedFinalizeFields: 附加键 %q 不得覆盖失败预算键（清零单源 issuedFinalizeResetFields）", key))
		}
		fields[key] = value
	}
	return fields
}

// certJobOutcomeNotifier 是终态通知发布的测试缝（生产恒 notifyCertJobOutcome）；
// 钉「事务内迁移不在提交前发布通知」（见 transitionJobDeferringNotification）。
var certJobOutcomeNotifier = notifyCertJobOutcome

func transitionJob(tx jobTransitionExecutor, id int, from []string, to string, fields map[string]any) error {
	if err := transitionJobUpdate(tx, id, from, to, fields, "", nil); err != nil {
		return err
	}
	fireCertJobOutcomeNotification(id, to, from, fields)
	return nil
}

// transitionJobDeferringNotification 执行迁移但不立即发布终态通知，返回的
// afterCommit 闭包由调用方在**事务提交成功后**调用（提交失败/回滚=不发布）。
// 事务内直接 transitionJob 会在 commit 之前发通知：回滚后用户已收到
// 「签发成功」，而库里仍是旧状态（假通知）。非事务调用方继续用 transitionJob。
func transitionJobDeferringNotification(tx jobTransitionExecutor, id int, from []string, to string, fields map[string]any) (afterCommit func(), err error) {
	if err := transitionJobUpdate(tx, id, from, to, fields, "", nil); err != nil {
		return nil, err
	}
	if !certJobOutcomeNotifies(to, from) {
		return nil, nil
	}
	return func() { fireCertJobOutcomeNotification(id, to, from, fields) }, nil
}

// transitionJobGuarded 是 transitionJob 的可附加守卫变体：guardSQL（+参数）
// 追加在状态 CAS 之后，0 行命中同归 ErrJobTransitionConflict。用于「扫描判定
// 通过 → 迁移落库」之间上游前提可能已变的入队迁移（续期/补扫的规则域守卫）。
func transitionJobGuarded(tx jobTransitionExecutor, id int, from []string, to string, fields map[string]any, guardSQL string, guardArgs ...any) error {
	return transitionJobUpdate(tx, id, from, to, fields, guardSQL, guardArgs)
}

// certJobOutcomeNotifies 是「哪些迁移发布终态通知」的单源判据：
//   - →issued：签发成功（域名）；
//   - →failed 且 from 集不含部署生命周期态（downloaded/issued）：签发失败
//     （部署失败走快速重部署链自动收敛，不按「签发失败」通知）。
func certJobOutcomeNotifies(to string, from []string) bool {
	return to == "issued" || (to == "failed" && !slices.Contains(from, "downloaded") && !slices.Contains(from, "issued"))
}

func fireCertJobOutcomeNotification(id int, to string, from []string, fields map[string]any) {
	if !certJobOutcomeNotifies(to, from) {
		return
	}
	certJobOutcomeNotifier(id, to, fields["message"])
}

// transitionJobUpdate 是全部 cert_jobs 状态迁移的单条 UPDATE 落点（守卫变体与
// 通知变体共用）：状态 CAS 之外可选追加调用方守卫（guardSQL 追加在
// id/status CAS 之后；0 行命中同归 ErrJobTransitionConflict——「状态不再满足」
// 与「规则已改域/停用」在入队语义里同属「本次不迁移」）。
func transitionJobUpdate(tx jobTransitionExecutor, id int, from []string, to string, fields map[string]any, guardSQL string, guardArgs []any) error {
	if len(from) == 0 {
		return fmt.Errorf("transition certificate job %d to %s: %w", id, to, ErrJobTransitionConflict)
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	assignments := []string{"status=?"}
	args := []any{to}
	for _, key := range keys {
		assignments = append(assignments, key+"=?")
		args = append(args, fields[key])
	}
	assignments = append(assignments, "updated_at=datetime('now')")

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(from)), ",")
	args = append(args, id)
	for _, status := range from {
		args = append(args, status)
	}
	query := "UPDATE cert_jobs SET " + strings.Join(assignments, ",") + " WHERE id=? AND status IN (" + placeholders + ")"
	if guardSQL != "" {
		query += " AND (" + guardSQL + ")"
		args = append(args, guardArgs...)
	}
	result, err := tx.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("transition certificate job %d to %s: %w", id, to, err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read certificate job %d transition result: %w", id, err)
	}
	if updated != 1 {
		return fmt.Errorf("transition certificate job %d to %s: %w", id, to, ErrJobTransitionConflict)
	}
	return nil
}

// notifyCertJobOutcome 证书签发终态通知（jobstate 单点覆盖全部转换路径——
// 签发/恢复/续签/部署完成）。
func notifyCertJobOutcome(jobID int, status string, message any) {
	var domain string
	if err := db.DB.QueryRow("SELECT COALESCE(domain,'') FROM cert_jobs WHERE id=?", jobID).Scan(&domain); err != nil {
		Logf("warn", "证书任务通知读取域名失败（job=%d status=%s）: %v", jobID, status, err)
		return
	}
	msg, _ := message.(string)
	eventType := notify.EvtCertIssued
	fields := map[string]string{"1": domain, "2": "已部署生效"}
	if status == "failed" {
		eventType = notify.EvtCertFailed
		fields = map[string]string{"1": domain, "2": msg}
	}
	notify.Publish(notify.Event{Type: eventType, Fields: fields})
}
