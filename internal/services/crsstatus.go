package services

import (
	"log"
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
		log.Printf("crs update: failed to count SecRules: %v", err)
		return 0
	}
	m.mu.Lock()
	m.ruleCount = count
	m.hasRuleCount = true
	m.mu.Unlock()
	return count
}

func (m *CRSUpdateManager) rescanRuleCount() {
	count, err := countSecRules(filepath.Join(m.crsDir, "rules"))
	if err != nil {
		log.Printf("crs update: failed to rescan SecRules: %v", err)
		return
	}
	m.mu.Lock()
	m.ruleCount = count
	m.hasRuleCount = true
	m.mu.Unlock()
}
