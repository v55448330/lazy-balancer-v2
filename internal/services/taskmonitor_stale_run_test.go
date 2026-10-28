package services

// 「运行中」只由引擎真实在途执行支撑：task_runs 终态更新失败的残留 running
// 行不得让任务视图恒显运行中并禁用「运行」按钮；真实在途轮仍呈现运行中。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func registerMonitorTestTask(t *testing.T, e *taskengine.Engine, id string, run func(taskengine.RunContext) error) {
	t.Helper()
	if err := e.Register(taskengine.Descriptor{
		ID: id, Family: "t", Name: id, Kind: taskengine.KindPeriodic,
		IntervalFn: func() time.Duration { return time.Hour },
		Run:        run,
	}); err != nil {
		t.Fatal(err)
	}
}

func findTaskInfo(t *testing.T, rows []TaskInfo, id string) TaskInfo {
	t.Helper()
	for _, ti := range rows {
		if ti.ID == id {
			return ti
		}
	}
	t.Fatalf("任务 %s 不在聚合视图", id)
	return TaskInfo{}
}

func alignMonitorEngineLocation(t *testing.T) {
	t.Helper()
	previous := CurrentLocation().String()
	if _, err := ConfigureLocation("Asia/Shanghai"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if previous == "CST" {
			previous = "Asia/Shanghai"
		}
		_, _ = ConfigureLocation(previous)
	})
}

func TestCollectEngineFamilies_staleRunningRowIsNotRunning(t *testing.T) {
	newClusterTestService(t)
	alignMonitorEngineLocation(t)
	e := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	t.Cleanup(e.Stop)
	registerMonitorTestTask(t, e, "t-stale-run", func(taskengine.RunContext) error { return nil })

	startedAt := time.Now().In(CurrentLocation()).Add(-5 * time.Minute).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at)
		VALUES ('t-stale-run', 't', 'auto', 'running', ?)`, startedAt); err != nil {
		t.Fatal(err)
	}

	ti := findTaskInfo(t, collectEngineFamilies(e), "t-stale-run")
	if ti.Status == TaskStatusRunning {
		t.Fatal("进程内已无在途执行时，残留 running 行不得呈现运行中（运行按钮被永久禁用）")
	}
	if ti.Status != TaskStatusFailed {
		t.Fatalf("残留 running 行应呈现 failed, got %q", ti.Status)
	}
	if ti.LastRun == nil || ti.LastRun.Result != "interrupted" {
		t.Fatalf("最近运行结果应按中断呈现, got %+v", ti.LastRun)
	}
	if ti.LastRun.Message == "" {
		t.Fatal("残留行应说明终态未落库，避免与正常中断同形")
	}
}

func TestCollectEngineFamilies_youngRunningRowStaysRunningWithinGrace(t *testing.T) {
	// 行快照与内存快照之间的瞬态：刚写入的 running 行 + 内存已空闲（该轮
	// 在两次取数之间完成）不得立即呈现失败/中断。
	newClusterTestService(t)
	alignMonitorEngineLocation(t)
	e := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	t.Cleanup(e.Stop)
	registerMonitorTestTask(t, e, "t-young-run", func(taskengine.RunContext) error { return nil })

	startedAt := time.Now().In(CurrentLocation()).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at)
		VALUES ('t-young-run', 't', 'auto', 'running', ?)`, startedAt); err != nil {
		t.Fatal(err)
	}

	ti := findTaskInfo(t, collectEngineFamilies(e), "t-young-run")
	if ti.Status != TaskStatusRunning {
		t.Fatalf("宽限期内的 running 行应保持运行中（瞬态自愈），got %q", ti.Status)
	}
	if ti.LastRun != nil && ti.LastRun.Result == "interrupted" {
		t.Fatalf("宽限期内不得按中断呈现, got %+v", ti.LastRun)
	}
}

func TestCollectEngineFamilies_inFlightRunStaysRunning(t *testing.T) {
	newClusterTestService(t)
	alignMonitorEngineLocation(t)
	e := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	t.Cleanup(e.Stop)
	registerMonitorTestTask(t, e, "t-live-run", func(rc taskengine.RunContext) error {
		<-rc.Ctx.Done()
		return rc.Ctx.Err()
	})
	if err := e.RunAsync("t-live-run", "manual", ""); err != nil {
		t.Fatal(err)
	}

	waitForCond(t, 2*time.Second, func() bool {
		ti := findTaskInfo(t, collectEngineFamilies(e), "t-live-run")
		return ti.Status == TaskStatusRunning && ti.LastRun != nil
	})
	ti := findTaskInfo(t, collectEngineFamilies(e), "t-live-run")
	if ti.LastRun.Result != "running" {
		t.Fatalf("在途轮最近运行结果应保持 running, got %+v", ti.LastRun)
	}
}

// Given 终态 UPDATE 失败的残留行（库 running + 进程内无在途执行）。
// When 同时读取任务列表与任务运行历史。
// Then 两者对同一 run 给出一致结论（列表 failed/已中断、历史 interrupted）——
// 归一判定与文案单源在引擎（History/LatestRun 内置），服务层列表用同一判定。
func TestHistoryMatchesListOnStaleRunningRow(t *testing.T) {
	newClusterTestService(t)
	alignMonitorEngineLocation(t)
	e := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	t.Cleanup(e.Stop)
	registerMonitorTestTask(t, e, "t-history-stale", func(taskengine.RunContext) error { return nil })

	startedAt := time.Now().In(CurrentLocation()).Add(-5 * time.Minute).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at)
		VALUES ('t-history-stale', 't', 'auto', 'running', ?)`, startedAt); err != nil {
		t.Fatal(err)
	}
	runs := e.History("t-history-stale", 10)
	if len(runs) != 1 {
		t.Fatalf("历史行数 %d, want 1", len(runs))
	}
	if runs[0].Status != "interrupted" {
		t.Fatalf("残留 running 行在历史里应归一为 interrupted, got %q", runs[0].Status)
	}
	if runs[0].Message != staleRunInterruptedMessage {
		t.Fatalf("归一须带与列表同源说明, got %q", runs[0].Message)
	}
	// 与列表对同一行的结论一致（单源判定的直接对照）。
	ti := findTaskInfo(t, collectEngineFamilies(e), "t-history-stale")
	if ti.Status != TaskStatusFailed || ti.LastRun == nil || ti.LastRun.Result != "interrupted" {
		t.Fatalf("列表侧结论=(%q,%+v)，与历史归一不一致", ti.Status, ti.LastRun)
	}
}
