package services

import (
	"time"

	"lazy-balancer-v2/internal/db"
)

type ip2RegionTaskState struct {
	status     IP2RegionUpdateStatus
	trigger    string
	startedAt  time.Time
	finishedAt time.Time
	message    string
	version    string
}

// IP2RegionUpdateStatusSnapshot is the point-in-time view served to handlers.
type IP2RegionUpdateStatusSnapshot struct {
	Status     string
	Trigger    string
	StartedAt  string
	FinishedAt string
	Message    string
	Version    string
}

// StatusSnapshot returns the in-memory task view, falling back to the stored
// terminal state when no update has run since process start.
func (m *IP2RegionUpdateManager) StatusSnapshot() IP2RegionUpdateStatusSnapshot {
	m.mu.Lock()
	state := m.state
	m.mu.Unlock()
	if state.trigger != "" || !state.startedAt.IsZero() {
		return ip2RegionSnapshotFromState(state)
	}
	return ip2RegionStoredStatusSnapshot()
}

func ip2RegionStoredStatusSnapshot() IP2RegionUpdateStatusSnapshot {
	var stored struct {
		status, trigger, startedAt, finishedAt, message, version string
	}
	err := db.DB.QueryRow(`SELECT COALESCE(update_status,'idle'), COALESCE(trigger,''),
		COALESCE(started_at,''), COALESCE(finished_at,''), COALESCE(message,''), version
		FROM security_ip2region_version WHERE id=1`).
		Scan(&stored.status, &stored.trigger, &stored.startedAt, &stored.finishedAt, &stored.message, &stored.version)
	if err != nil {
		return IP2RegionUpdateStatusSnapshot{Status: string(IP2RegionStatusIdle)}
	}
	return IP2RegionUpdateStatusSnapshot{
		Status:     stored.status,
		Trigger:    stored.trigger,
		StartedAt:  stored.startedAt,
		FinishedAt: stored.finishedAt,
		Message:    stored.message,
		Version:    stored.version,
	}
}

func ip2RegionSnapshotFromState(state ip2RegionTaskState) IP2RegionUpdateStatusSnapshot {
	snap := IP2RegionUpdateStatusSnapshot{
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

// IsActiveIP2RegionStatus reports whether the status describes an in-flight update.
func IsActiveIP2RegionStatus(status string) bool {
	switch IP2RegionUpdateStatus(status) {
	case IP2RegionStatusChecking, IP2RegionStatusDownloading, IP2RegionStatusInstalling, IP2RegionStatusReloading:
		return true
	}
	return false
}
