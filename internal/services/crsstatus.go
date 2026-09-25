package services

import (
	"path/filepath"

	"lazy-balancer-v2/internal/db"
)

func storedStatusSnapshot() CRSUpdateStatusSnapshot {
	var stored struct {
		status, trigger, startedAt, finishedAt, message, version string
	}
	err := db.DB.QueryRow(`SELECT COALESCE(update_status,'idle'), COALESCE(trigger,''),
		COALESCE(started_at,''), COALESCE(finished_at,''), COALESCE(message,''), version
		FROM security_crs_version WHERE id=1`).
		Scan(&stored.status, &stored.trigger, &stored.startedAt, &stored.finishedAt, &stored.message, &stored.version)
	if err != nil {
		// DB 读失败静默回退 idle 会丢可回溯性（第 56 轮 P5）：留 warn 后回退。
		Logf("warn", "CRS 状态: 读取存储快照失败，回退 idle: %v", err)
		return CRSUpdateStatusSnapshot{Status: string(CRSStatusIdle)}
	}
	return CRSUpdateStatusSnapshot{
		Status:     stored.status,
		Trigger:    stored.trigger,
		StartedAt:  stored.startedAt,
		FinishedAt: stored.finishedAt,
		Message:    stored.message,
		Version:    stored.version,
	}
}

func snapshotFromState(state crsTaskState) CRSUpdateStatusSnapshot {
	snap := CRSUpdateStatusSnapshot{
		Status:  string(state.status),
		Trigger: state.trigger,
		Message: state.message,
		Version: state.version,
	}
	if !state.startedAt.IsZero() {
		snap.StartedAt = state.startedAt.Format(crsTimeLayout)
	}
	if !state.finishedAt.IsZero() {
		snap.FinishedAt = state.finishedAt.Format(crsTimeLayout)
	}
	return snap
}

// IsActiveCRSStatus reports whether the status describes an in-flight update.
func IsActiveCRSStatus(status string) bool {
	switch CRSUpdateStatus(status) {
	case CRSStatusChecking, CRSStatusDownloading, CRSStatusInstalling, CRSStatusReloading:
		return true
	}
	return false
}

// RuleCount returns the cached SecRule count, scanning the live rules dir on
// first use.
func (m *CRSUpdateManager) RuleCount() int {
	m.mu.Lock()
	if m.hasRuleCount {
		defer m.mu.Unlock()
		return m.ruleCount
	}
	m.mu.Unlock()
	count, err := countSecRules(filepath.Join(m.crsDir, "rules"))
	if err != nil {
		Logf("error", "crs update: failed to count SecRules: %v", err)
		return 0
	}
	// CRS25-5(第 25 轮审计):放锁扫描期间 rescan 可能已写入新值——
	// 重锁写回前双重检查,不覆盖更新值(展示层一致性)。
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hasRuleCount {
		return m.ruleCount
	}
	m.ruleCount = count
	m.hasRuleCount = true
	return count
}

func (m *CRSUpdateManager) rescanRuleCount() {
	count, err := countSecRules(filepath.Join(m.crsDir, "rules"))
	if err != nil {
		Logf("error", "crs update: failed to rescan SecRules: %v", err)
		return
	}
	m.mu.Lock()
	m.ruleCount = count
	m.hasRuleCount = true
	m.mu.Unlock()
}
