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

// regOf 取注册项指针（判空响亮失败）——各测试文件曾逐字复制
// 「RLock→regs 取项→RUnlock」快照模板，取项单源在此。
func regOf(t *testing.T, e *Engine, id string) *registration {
	t.Helper()
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		t.Fatalf("任务 %s 未注册", id)
	}
	return r
}

// setLogDirForTest 切换任务日志目录并在用例结束恢复旧值——曾有用例把包级
// 目录还原成空串而非旧值（归零而非复原，前序用例设置的目录被静默清掉）。
func setLogDirForTest(t *testing.T, dir string) {
	t.Helper()
	old := LogDir()
	SetLogDir(dir)
	t.Cleanup(func() { SetLogDir(old) })
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
	r := regOf(t, e, id)
	r.mu.Lock()
	defer r.mu.Unlock()
	return engineFieldSnapshot{loopEnabled: r.loopEnabled, slot: r.nextScheduledTime, done: r.schedDoneSlot, retry: r.schedRetryAfter, streak: r.schedFailStreak}
}

// loopEnabledOf 读取任务的调度开关（装配字段，测试内直接读）。
func loopEnabledOf(t *testing.T, e *Engine, id string) bool {
	t.Helper()
	return fieldSnapshot(t, e, id).loopEnabled
}

// scheduleStateOf 读取 Scheduled 注册项的槽缓存/消费水位/退避状态（测试用）。
func scheduleStateOf(t *testing.T, e *Engine, id string) (slot, done, retry time.Time, streak int) {
	t.Helper()
	s := fieldSnapshot(t, e, id)
	return s.slot, s.done, s.retry, s.streak
}
