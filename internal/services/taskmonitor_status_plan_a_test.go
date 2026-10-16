package services

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// 方案 A（2026-10-12 用户裁定）：任务监控状态列只承载执行语义
// （运行中/空闲/失败/排队中；cert-job 退役行「已禁用」），调度语义
// （调度关/业务关）全部归开关列——状态列不再产出 stopped/disabled。

func TestCollectSystemTasks_statusColumnExecutionOnly(t *testing.T) {
	// 与 taskengine newTestEngine 同模式：临时目录全套库（task_runs 消费面）
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	e := taskengine.NewEngine(taskengine.Options{})
	// Given 常驻任务：调度关闭——修复前状态列=stopped
	e.Register(taskengine.Descriptor{
		ID: "t-svc", Family: "test", Name: "t-svc", Kind: taskengine.KindDaemon, RunsOn: taskengine.RoleAny,
		Run: func(taskengine.RunContext) error { return nil },
	})
	// Given 循环任务：调度开但业务开关关——修复前=disabled
	e.Register(taskengine.Descriptor{
		ID: "t-biz", Family: "test", Name: "t-biz", Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleAny,
		IntervalFn: func() time.Duration { return time.Hour },
		EnabledFn:  func() bool { return false },
		Run:        func(taskengine.RunContext) error { return nil },
	})
	e.StartLoop("t-biz")

	// When
	rows := collectEngineFamilies(e)

	status := map[string]string{}
	loopOn := map[string]bool{}
	for _, r := range rows {
		status[r.ID] = string(r.Status)
		loopOn[r.ID] = r.LoopOn
	}
	// Then 状态列=空闲（调度关/业务关由开关列表达）
	if status["t-svc"] != "idle" {
		t.Errorf("daemon 调度关: status=%q, want idle（调度语义归开关列）", status["t-svc"])
	}
	if status["t-biz"] != "idle" {
		t.Errorf("业务关: status=%q, want idle（开关列表达）", status["t-biz"])
	}
	// 任务视图只保留 loop_on 调度开关，不再暴露额外 enabled 字段。
	if !loopOn["t-biz"] {
		t.Errorf("业务关: LoopOn=%v, want true（loop_on 与业务字段独立表达调度状态）", loopOn["t-biz"])
	}
}

// cert-waiting-ca（Periodic）StatusFn 不再借用 stopped——无活跃证书任务时镜像=idle。
func TestCertWaitingCAStatusMirror_idleWhenNoActiveJobs(t *testing.T) {
	te := newWireTestEngine(t) // 装配 17 任务族（空库：无活跃证书任务）
	for _, m := range te.DescribeAll() {
		if m.ID != "cert-waiting-ca" {
			continue
		}
		if m.StatusMirror != "idle" {
			t.Fatalf("cert-waiting-ca StatusMirror=%q（空库无活跃任务应为 idle——stopped 仅常驻模型已废,方案 A 2026-10-12）", m.StatusMirror)
		}
		return
	}
	t.Fatal("cert-waiting-ca 未注册")
}
