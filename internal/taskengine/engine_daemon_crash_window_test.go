package taskengine

// 常驻异常退出补记的 failed 行必须落在 24h 统计窗口内：长运行 daemon
// 在启动 24h 边界刚过时崩溃，若 started_at 回填原启动时刻，行会落在
// started_at 窗口之外——状态列 failed 而 Fail24h=0，两个各自正确的口径
// 联动产出计数背离。failed 行按崩溃时刻落 started_at（事件行），
// duration_ms 仍为真实运行时长。

import (
	"errors"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// Given 常驻任务已运行约 24h（启动时刻刚滑出统计窗，崩溃发生在窗内）。
// When Run 异常退出（返回错误，非取消）。
// Then failed 行 started_at=崩溃时刻（24h 窗口内），Stats24h.Fail=1，
// duration_ms 保持真实运行时长。
func TestEngine_DaemonCrashRowCountsIn24hWindow(t *testing.T) {
	// 计时起点置零值（daemonStartHookForTest 注入缝）：异常退出的时间推导
	// （start+dur）会落到 24h 窗外——与「启动刚满 24h 即崩溃」的真实形态
	// 同窗效应；修复后 failed 行按崩溃时刻落 started_at，不受起点影响。
	daemonStartHookForTest = func() time.Time { return time.Time{} }
	t.Cleanup(func() { daemonStartHookForTest = nil })

	e := newTestEngineWithOptions(t, Options{TickInterval: 10 * time.Millisecond,
		DaemonRestartDelays: []time.Duration{time.Hour}})
	booted := make(chan struct{})
	crashed := make(chan struct{})
	mustRegisterTaskForTest(t, e, Descriptor{ID: "t-longcrash", Family: "t", Name: "长运行崩溃常驻", Kind: KindDaemon, RunsOn: RoleAny,
		Run: func(RunContext) error {
			close(booted)
			<-crashed
			return errors.New("long-running daemon crashed")
		}})
	e.SetRole(true)
	e.StartLoop("t-longcrash")
	waitForEngineSignal(t, "长运行常驻启动", booted)

	// boot success 行回拨到 24h+2s 前（真实形态：启动行刚滑出 24h 窗口）。
	boot := time.Now().Add(-24*time.Hour - 2*time.Second)
	if _, err := db.DB.Exec(`UPDATE task_runs SET started_at=? WHERE task_id='t-longcrash' AND status='success'`,
		boot.In(engineLocPtr()).Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	if st := e.Stats24h("t-longcrash"); st.Fail != 0 || st.Runs != 0 {
		t.Fatalf("崩溃前 24h 统计应全零（boot 行已在窗外）, got %+v", st)
	}

	close(crashed) // Run 返回错误=异常退出
	waitForEngine(t, "崩溃 failed 行进入 24h 统计", 3*time.Second, func() bool {
		return e.Stats24h("t-longcrash").Fail == 1
	})

	// failed 行 started_at 必须在窗口内（崩溃时刻），duration 仍为真实时长。
	var startedAt string
	var dur int64
	if err := db.DB.QueryRow(`SELECT started_at, duration_ms FROM task_runs WHERE task_id='t-longcrash' AND status='failed'`).Scan(&startedAt, &dur); err != nil {
		t.Fatalf("read crash row: %v", err)
	}
	crashInstant, err := time.ParseInLocation("2006-01-02 15:04:05", startedAt, engineLocPtr())
	if err != nil {
		t.Fatalf("parse crash started_at %q: %v", startedAt, err)
	}
	if d := time.Since(crashInstant); d < 0 || d > time.Minute {
		t.Fatalf("failed 行 started_at=%q 距崩溃时刻 %s，应为崩溃时刻（回填原启动时刻会落 24h 窗外）", startedAt, d)
	}
	if dur < 0 {
		t.Fatalf("duration_ms=%d, want 非负真实时长", dur)
	}
	e.StopLoop("t-longcrash")
}
