package services

import (
	"testing"

	"lazy-balancer-v2/internal/taskengine"
)

func TestClusterSyncStatusMirrorProjectsHaltedSlave(t *testing.T) {
	previous := TaskEngine()
	engine := taskengine.NewEngine(taskengine.Options{StartPaused: true})
	SetTaskEngineForTest(engine)
	t.Cleanup(func() {
		SetTaskEngineForTest(previous)
		engine.Stop()
		SetSyncLifecycleHaltedProbe(nil)
	})

	engine.SetRole(false)
	SetSyncLifecycleHaltedProbe(func() bool { return true })
	if got := clusterSyncStatusMirror(); got != string(TaskStatusFailed) {
		t.Fatalf("halted slave status=%q, want failed", got)
	}

	engine.SetRole(true)
	if got := clusterSyncStatusMirror(); got != "" {
		t.Fatalf("master status=%q, want no slave sync mirror", got)
	}

	engine.SetRole(false)
	SetSyncLifecycleHaltedProbe(func() bool { return false })
	if got := clusterSyncStatusMirror(); got != "" {
		t.Fatalf("healthy slave status=%q, want execution-state fallback", got)
	}
}
