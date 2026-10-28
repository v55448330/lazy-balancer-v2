package taskengine

import (
	"testing"
	"time"
)

func waitForEngine(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("等待超时：%s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func waitForEngineSignal(t *testing.T, what string, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("等待超时：%s", what)
	}
}

type engineFieldSnapshot struct {
	loopEnabled bool
	slot        time.Time
	done        time.Time
	retry       time.Time
	streak      int
}

func fieldSnapshot(t *testing.T, e *Engine, id string) engineFieldSnapshot {
	t.Helper()
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		t.Fatalf("任务 %s 未注册", id)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return engineFieldSnapshot{loopEnabled: r.loopEnabled, slot: r.nextScheduledTime, done: r.schedDoneSlot, retry: r.schedRetryAfter, streak: r.schedFailStreak}
}
