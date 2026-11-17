package services

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"lazy-balancer-v2/internal/db"
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

func transitionJob(tx jobTransitionExecutor, id int, from []string, to string, fields map[string]any) error {
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
	result, err := tx.Exec(
		"UPDATE cert_jobs SET "+strings.Join(assignments, ",")+" WHERE id=? AND status IN ("+placeholders+")",
		args...,
	)
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
