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

// mustRegisterTaskForTest 测试注册失败必须响亮（Register 校验/重名/停止态
// 错误被丢弃会让用例在「任务实际未注册」的空转态假绿；（回归） 全量附录）。
func mustRegisterTaskForTest(t *testing.T, e *Engine, d Descriptor) {
	t.Helper()
	if err := e.Register(d); err != nil {
		t.Fatalf("注册任务 %s 失败: %v", d.ID, err)
	}
}

// driveTicks 确定性驱动 n 个调度 tick：负断言（「窗口内不得再执行」）不得
// 依赖 300–350ms 墙钟窗口——慢机/调度抖动会让窗口内 tick 数不可控，且「没
// 观察到」不等于「不会发生」（回归） 全量附录：墙钟负断言）。
func driveTicks(e *Engine, n int) {
	for range n {
		e.tick()
	}
}

// settleTaskRuns 等任务的在途轮落定（终态行与退避/槽水位在 executeRun 尾部
// 写入，晚于 Run 体返回，占位释放在其后）。负断言前的驱动必须先在稳定态下
// 发生：在途占位会让整批 tick 被单飞门跳过（断言空转通过）。
func settleTaskRuns(t *testing.T, e *Engine, id string) {
	t.Helper()
	waitForEngine(t, "任务在途轮落定（"+id+"）", 5*time.Second, func() bool { return !e.IsTaskInFlight(id) })
}

// driveTicksSettled 驱动 n 个 tick 并等这批 tick 准入的轮次落定，供
// 「窗口内不得再执行/不得再落行」类负断言使用：tick 内的准入（running CAS）
// 同步完成——driveTicks 返回时被派发的轮次或已落定、或仍在途；后者须等落定
// 后计数才是终值（派发 goroutine 异步才跑到 Run 体，紧跟 driveTicks 读计数
// 会读到旧值，负断言空转通过）。
func driveTicksSettled(t *testing.T, e *Engine, n int, id string) {
	t.Helper()
	driveTicks(e, n)
	if e.IsTaskInFlight(id) {
		settleTaskRuns(t, e, id)
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
