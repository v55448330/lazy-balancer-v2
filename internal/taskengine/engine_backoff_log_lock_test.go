package taskengine

// Scheduled 退避留痕的锁边界钉测：executeRun 尾部退避分支的 [warn]/[error]
// 日志写入不得持 r.mu——taskLogAppendContext 的尺寸求值（sizeFn 生产读库）
// 可被阻塞，持锁会把同任务的 Cancel/IsRunning/StopLoop 一起拖住。
// 与 [done] 行同形：锁内只算状态，锁外按快照写日志。

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Given Scheduled 任务在途自动轮失败且槽未推进，退避 WARN 的尺寸求值被
// 阻塞（真实 sizeFn 缝，生产形态=读库被 busy_timeout 拖住）。
// When 并发调用 Cancel。
// Then Cancel 限时返回（不被日志写入拖住）；解除阻塞后 WARN 行完整落盘。
func TestEngine_ScheduledBackoffLogOutsideRegistrationLock(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	pastSlot := time.Now().Add(-time.Minute)
	const id = "t-backoff-log-lock"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "退避日志锁边界", Kind: KindScheduled, RunsOn: RoleAny, Cancelable: true,
		NextSlotFn: func() time.Time { return pastSlot },
		Run: func(RunContext) error {
			return errors.New("boom")
		},
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)
	dir := t.TempDir()
	setLogDirForTest(t, dir)
	r := regOf(t, e, id)
	r.mu.Lock()
	r.nextScheduledTime = pastSlot
	r.mu.Unlock()

	sizeEntered := make(chan struct{})
	releaseSize := make(chan struct{})
	var entered atomic.Bool
	SetTaskLogSizeBytesFn(func(context.Context) int64 {
		if entered.CompareAndSwap(false, true) {
			close(sizeEntered)
			<-releaseSize
		}
		return 1 << 20
	})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseSize) }) }
	t.Cleanup(func() {
		release()
		SetTaskLogSizeBytesFn(nil)
	})

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_, _ = e.RunSync(id, "auto", "")
	}()
	waitForEngineSignal(t, "失败轮进入退避日志的尺寸求值", sizeEntered)

	cancelDone := make(chan bool, 1)
	go func() { cancelDone <- e.Cancel(id) }()
	select {
	case <-cancelDone:
		// 锁外写日志：Cancel 不被尺寸求值阻塞拖住。
	case <-time.After(2 * time.Second):
		t.Fatal("退避日志持 r.mu：尺寸求值阻塞期间 Cancel 被拖住（锁内只算状态，日志必须锁外写）")
	}

	release()
	waitForEngineSignal(t, "失败轮执行落定", runDone)
	body, err := os.ReadFile(TaskLogPath(id))
	if err != nil {
		t.Fatalf("读取任务日志: %v", err)
	}
	if !strings.Contains(string(body), "[warn] 排程槽未推进") {
		t.Fatalf("退避 WARN 必须完整落盘（锁外写不得丢行）:\n%s", body)
	}
}
