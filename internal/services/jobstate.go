package services

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	allJobStatuses           = []string{
		"queued", "pending", "processing", "creating_account", "creating_order", "order_created",
		"cleanup_dns", "cleanup_warning", "presenting_dns", "waiting_propagation", "dns_propagated",
		"accepting_challenge", "validating", "validated", "finalizing", "finalized", "downloading",
		"downloaded", "issued", "failed", "waiting_ca", "disabled", "waiting_order_ready", "order_ready",
		"waiting_order_valid", "order_valid",
	}
	jobStatusesExceptDisabled = withoutJobStatuses("disabled")
	nonTerminalJobStatuses    = withoutJobStatuses("issued", "failed", "disabled")
	jobLifecycleByStatus      = map[string]string{
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

type jobTransitionExecutor interface {
	Exec(query string, args ...any) (sql.Result, error)
}

type jobSQLExpression string

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
// 文本可能无界嵌入错误链，而 message 列会同步到从节点并展示在 UI（Round 34
// F-R34-3），各写入点（failJob/jobLogger.Log/deploymentFailed）统一截断。
const maxJobMessageBytes = 1024

// truncateJobMessage 将任务消息截断到 maxJobMessageBytes 字节内，并回退到合法
// UTF-8 边界，避免 LimitReader 式按字节截断留下多字节字符残片。
func truncateJobMessage(message string) string {
	if len(message) <= maxJobMessageBytes {
		return message
	}
	return string(truncateValidUTF8Tail([]byte(message[:maxJobMessageBytes])))
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
		if expression, ok := fields[key].(jobSQLExpression); ok {
			assignments = append(assignments, key+"="+string(expression))
			continue
		}
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
