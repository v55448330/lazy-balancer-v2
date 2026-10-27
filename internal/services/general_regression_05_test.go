package services

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func setupU05ServicesDB(t *testing.T) {
	t.Helper()
	setupIsolatedDB(t)
}

// panic（runGuarded 会把它转成 failed 并判定 daemon 已死）时，已启动的
// ACME 队列/同步循环必须被清理，否则角色翻转后仍写库/签发（修复前 stop
// 是顺序调用，panic 即跳过）。
func TestDaemonLifecycleRun_stopStillRunsWhenStartPanics(t *testing.T) {
	var stopped bool
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("start panic 必须向上传播（由引擎 runGuarded 隔离）")
			}
		}()
		_ = daemonLifecycleRun(taskengine.RunContext{Ctx: context.Background()},
			func() { panic("start boom") },
			func() { stopped = true })
	}()
	if !stopped {
		t.Fatal("start panic 时 stop 仍必须执行（deferred）")
	}
}

func TestDaemonLifecycleRun_stopsAfterCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started, stopped := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- daemonLifecycleRun(taskengine.RunContext{Ctx: ctx},
			func() { close(started) },
			func() { close(stopped) })
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("daemonLifecycleRun: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 取消后 daemonLifecycleRun 未返回")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("ctx 取消后 stop 未执行")
	}
}

// ——旧方案 A 曾将 waiting_ca 单列「排队中」；2026-10-22 用户裁定状态列词表
// 收敛三态后，限流停车与处理中统一为 running（停车语义归业务文本）。
func TestCollectCertJobRows_waitingCAMappedRunning(t *testing.T) {
	setupU05ServicesDB(t)
	seedCertJobRowForTaskMonitor(t, "lb_tm_waiting", "waiting.example.com", "waiting_ca")

	rows, _ := collectCertJobRows()
	var got *TaskInfo
	for i := range rows {
		if strings.HasSuffix(rows[i].Name, "waiting.example.com") {
			got = &rows[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("waiting_ca 行缺失: %+v", rows)
	}
	if got.Status != TaskStatusRunning {
		t.Fatalf("waiting_ca 状态=%s, want running（未完成工作项；停车语义归业务文本）", got.Status)
	}
	// 回归形状：处理中阶段仍为 running
	seedCertJobRowForTaskMonitor(t, "lb_tm_validating", "validating.example.com", "validating")
	rows, _ = collectCertJobRows()
	for i := range rows {
		if strings.HasSuffix(rows[i].Name, "validating.example.com") {
			if rows[i].Status != TaskStatusRunning {
				t.Fatalf("validating 状态=%s, want running", rows[i].Status)
			}
			return
		}
	}
	t.Fatal("validating 行缺失")
}

// 呈现 failed（修复前恒 idle「空闲」，采集/签发永久静默停摆无任何信号）。
func TestCollectEngineFamilies_daemonAbnormalExitShowsFailed(t *testing.T) {
	setupU05ServicesDB(t)
	e := taskengine.NewEngine(taskengine.Options{TickInterval: 10 * time.Millisecond,
		DaemonRestartDelays: []time.Duration{time.Hour}}) // 退避窗口内保持「已死」供断言
	t.Cleanup(e.Stop)
	e.Register(taskengine.Descriptor{ID: "t-crash-daemon", Family: "t", Name: "崩溃常驻",
		Category: "系统", Kind: taskengine.KindDaemon, RunsOn: taskengine.RoleAny,
		Run: func(taskengine.RunContext) error { return errors.New("boom") }})
	e.StartLoop("t-crash-daemon")

	// 等到异常退出落定（running=false 且最近一行 failed）
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		run := e.LatestRun("t-crash-daemon")
		if run != nil && run.Status == "failed" {
			broken := false
			for _, m := range e.DescribeAll() {
				if m.ID == "t-crash-daemon" && !m.Running && m.LoopOn {
					broken = true
				}
			}
			if broken {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	status := func() TaskStatus {
		for _, ti := range collectEngineFamilies(e) {
			if ti.ID == "t-crash-daemon" {
				return ti.Status
			}
		}
		t.Fatal("t-crash-daemon 未出现在聚合视图")
		return ""
	}
	if got := status(); got != TaskStatusFailed {
		t.Fatalf("异常退出后状态=%s, want failed（修复前 idle 掩盖停摆）", got)
	}
	// 回归形状：用户停止调度后（loop_on=false）→ idle
	e.StopLoop("t-crash-daemon")
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if status() != TaskStatusFailed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := status(); got != TaskStatusIdle {
		t.Fatalf("显式停止后状态=%s, want idle", got)
	}
}

// 与逐任务查询完全一致（最近=最大 id；24h 窗口外行不计入）。
func TestEngineRunOverview_matchesPerTaskQueries(t *testing.T) {
	setupU05ServicesDB(t)
	e := taskengine.NewEngine(taskengine.Options{TickInterval: time.Second})
	t.Cleanup(e.Stop)
	loc := CurrentLocation()
	now := time.Now().In(loc)
	recent := now.Add(-time.Hour).Format("2006-01-02 15:04:05")
	old := now.Add(-48 * time.Hour).Format("2006-01-02 15:04:05")
	insert := func(taskID, status, startedAt string) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at) VALUES (?,?,?,?,?)`,
			taskID, "t", "auto", status, startedAt); err != nil {
			t.Fatalf("insert run: %v", err)
		}
	}
	insert("task-a", "success", recent)
	insert("task-a", "failed", recent)
	insert("task-b", "success", old)

	latest, stats := e.RunOverview()
	if got := stats["task-a"]; got.Runs != 2 || got.Success != 1 || got.Fail != 1 {
		t.Fatalf("task-a stats=%+v, want {2 1 1}", got)
	}
	if got := stats["task-b"]; got.Runs != 0 || got.Success != 0 || got.Fail != 0 {
		t.Fatalf("task-b 24h 窗口外行不得计入, stats=%+v", got)
	}
	if latest["task-a"] == nil || latest["task-a"].Status != "failed" {
		t.Fatalf("task-a latest=%+v, want 最新 failed 行", latest["task-a"])
	}
	if latest["task-b"] == nil || latest["task-b"].Status != "success" {
		t.Fatalf("task-b latest=%+v, want success", latest["task-b"])
	}
	// 等价性：与逐任务查询同值
	for _, id := range []string{"task-a", "task-b"} {
		want := e.LatestRun(id)
		got := latest[id]
		if (want == nil) != (got == nil) {
			t.Fatalf("%s latest 空值形态不一致", id)
		}
		if want != nil && (want.ID != got.ID || want.Status != got.Status) {
			t.Fatalf("%s latest=(%d,%s), want (%d,%s)", id, got.ID, got.Status, want.ID, want.Status)
		}
		if perTask := e.Stats24h(id); perTask != stats[id] {
			t.Fatalf("%s stats=%+v, want %+v", id, stats[id], perTask)
		}
	}
}

// 该槽被记为已完成（下次补跑被跳过），而实际没有任何备份落盘。
func TestAutoBackupScheduled_cancelDoesNotAdvanceWatermark(t *testing.T) {
	setupAutoBackupTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='daily', auto_backup_time='03:00', auto_backup_last_run=NULL WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	SetAutoBackupExecutor(func(runCtx context.Context, trigger, operator string, engineRunID int64) error {
		if runCtx != ctx {
			t.Error("执行器必须收到引擎 Run 上下文")
		}
		return runCtx.Err()
	})
	t.Cleanup(func() { SetAutoBackupExecutor(nil) })
	cancel()

	if err := runAutoBackupScheduledAt(ctx, 0, time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
	var lastRun sql.NullString
	if err := db.DB.QueryRow(`SELECT auto_backup_last_run FROM global_config WHERE id=1`).Scan(&lastRun); err != nil {
		t.Fatal(err)
	}
	if lastRun.Valid {
		t.Fatalf("取消后水位线被推进为 %q——该槽将被记作已完成（漏备份）", lastRun.String)
	}
}
