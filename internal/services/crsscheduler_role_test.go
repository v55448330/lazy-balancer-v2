package services

import (
	"testing"
	"time"
)

func TestUpdateRetryBackoff_sequence(t *testing.T) {
	// 连续失败指数退避：1h→2h→4h→8h→24h 封顶（R35 I1）
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{0, time.Hour},
		{1, time.Hour},
		{2, 2 * time.Hour},
		{3, 4 * time.Hour},
		{4, 8 * time.Hour},
		{5, 24 * time.Hour},
		{6, 24 * time.Hour},
		{10, 24 * time.Hour},
	}
	for _, c := range cases {
		if got := updateRetryBackoff(c.failures); got != c.want {
			t.Errorf("updateRetryBackoff(%d)=%v, want %v", c.failures, got, c.want)
		}
	}
}

func TestCRSUpdateManager_SetMasterRoleStartsAndStopsScheduler(t *testing.T) {
	// Given
	newClusterTestService(t)
	m := newCRSUpdateManager(func() error { return nil })
	t.Cleanup(m.StopScheduler)
	schedulerRunning := func() bool {
		m.schedulerMu.Lock()
		defer m.schedulerMu.Unlock()
		return m.schedulerStop != nil
	}

	// When / Then: slave role keeps the scheduler stopped
	m.SetMasterRole(false)
	if schedulerRunning() {
		t.Fatal("slave role must not run the scheduler")
	}

	// When / Then: master role starts it, and repeated calls are idempotent
	m.SetMasterRole(true)
	if !schedulerRunning() {
		t.Fatal("master role must start the scheduler")
	}
	m.schedulerMu.Lock()
	first := m.schedulerStop
	m.schedulerMu.Unlock()
	m.SetMasterRole(true)
	m.schedulerMu.Lock()
	second := m.schedulerStop
	m.schedulerMu.Unlock()
	if first != second {
		t.Fatal("repeated master role must not restart the scheduler")
	}

	// When / Then: demotion stops it, promotion restarts it
	m.SetMasterRole(false)
	if schedulerRunning() {
		t.Fatal("demotion to slave must stop the scheduler")
	}
	m.SetMasterRole(true)
	if !schedulerRunning() {
		t.Fatal("promotion after demotion must restart the scheduler")
	}
}
