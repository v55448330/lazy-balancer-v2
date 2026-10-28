package taskengine

// 残留 running 行的跨端点口径：task_runs 终态 UPDATE 失败只 WARN，行会留到
// 进程重启被 RecoverOrphans 回收——期间「库行 running 但进程内已无在途执行」
// 的行必须按中断呈现，且 History/LatestRun/任务列表共用同一判定（否则同一 run
// 在列表显示失败/已中断、点开历史却仍称运行中）。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// Given 终态 UPDATE 失败的残留行（库 running + 进程内无该任务在途执行）。
// When 读取任务历史与最近运行。
// Then 归一为 interrupted 并带说明（History 与 LatestRun 同源）。
func TestEngineHistory_normalizesStaleRunningRow(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	if err := e.Register(Descriptor{ID: "t-hist-stale", Family: "t", Name: "残留历史", Kind: KindOneshot,
		RunsOn: RoleAny, Run: func(RunContext) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now().In(engineLocPtr()).Add(-5 * time.Minute).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at)
		VALUES ('t-hist-stale', 't', 'auto', 'running', ?)`, startedAt); err != nil {
		t.Fatal(err)
	}

	runs := e.History("t-hist-stale", 10)
	if len(runs) != 1 {
		t.Fatalf("历史行数 %d, want 1", len(runs))
	}
	if runs[0].Status != "interrupted" {
		t.Fatalf("残留 running 行应归一为 interrupted, got %q", runs[0].Status)
	}
	if runs[0].Message != StaleRunInterruptedMessage {
		t.Fatalf("归一须带说明, got %q", runs[0].Message)
	}
	latest := e.LatestRun("t-hist-stale")
	if latest == nil || latest.Status != "interrupted" {
		t.Fatalf("LatestRun 必须与 History 同口径, got %+v", latest)
	}
}

// Given 宽限内的 running 行（刚写入，可能是两次快照之间的瞬态）。
// When 读取任务历史。
// Then 保持 running（不得因瞬态误报中断）。
func TestEngineHistory_keepsYoungRunningRow(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	if err := e.Register(Descriptor{ID: "t-hist-young", Family: "t", Name: "瞬态历史", Kind: KindOneshot,
		RunsOn: RoleAny, Run: func(RunContext) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now().In(engineLocPtr()).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at)
		VALUES ('t-hist-young', 't', 'auto', 'running', ?)`, startedAt); err != nil {
		t.Fatal(err)
	}
	runs := e.History("t-hist-young", 10)
	if len(runs) != 1 || runs[0].Status != "running" {
		t.Fatalf("宽限内的行必须保持 running, got %+v", runs)
	}
}

// Given 引擎确有在途执行（IsTaskInFlight=true）。
// When 读取任务历史。
// Then running 行原样保留（真实在途轮不得被归一为中断）。
func TestEngineHistory_keepsInFlightRow(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	if err := e.Register(Descriptor{ID: "t-hist-live", Family: "t", Name: "在途历史", Kind: KindOneshot,
		RunsOn: RoleAny,
		Run: func(rc RunContext) error {
			<-rc.Ctx.Done()
			return rc.Ctx.Err()
		}}); err != nil {
		t.Fatal(err)
	}
	if err := e.RunAsync("t-hist-live", "manual", ""); err != nil {
		t.Fatal(err)
	}
	waitForEngine(t, "在途占位", 2*time.Second, func() bool { return e.IsTaskInFlight("t-hist-live") })

	startedAt := time.Now().In(engineLocPtr()).Add(-5 * time.Minute).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at)
		VALUES ('t-hist-live', 't', 'manual', 'running', ?)`, startedAt); err != nil {
		t.Fatal(err)
	}
	runs := e.History("t-hist-live", 10)
	if len(runs) == 0 {
		t.Fatal("历史行不得为空")
	}
	for _, run := range runs {
		if run.Status != "running" {
			t.Fatalf("在途轮的 running 行不得归一为中断, got %+v", run)
		}
	}
}
