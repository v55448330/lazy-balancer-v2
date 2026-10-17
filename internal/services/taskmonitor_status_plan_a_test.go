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

// cert-waiting-ca（Periodic）不再以业务活跃数生成 StatusMirror；空库由执行实态得 idle。
func TestCertWaitingCAStatus_usesExecutionStateWhenNoActiveJobs(t *testing.T) {
	te := newWireTestEngine(t)
	for _, m := range te.DescribeAll() {
		if m.ID != "cert-waiting-ca" {
			continue
		}
		if m.StatusMirror != "" {
			t.Fatalf("cert-waiting-ca 不得携带业务 StatusMirror，got %q", m.StatusMirror)
		}
	}
	for _, ti := range collectEngineFamilies(te) {
		if ti.ID == "cert-waiting-ca" && ti.Status != TaskStatusIdle {
			t.Fatalf("空库无活跃任务应为 idle，got %s", ti.Status)
		}
	}
}

func TestCertTasksStatus_businessActivityDoesNotOverrideStoppedExecution(t *testing.T) {
	// Given：有活跃 cert_jobs，但两个证书任务的调度均已停止。
	te := newWireTestEngine(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status) VALUES ('r1','a.test','pending')`); err != nil {
		t.Fatal(err)
	}
	te.StopLoop("cert-waiting-ca")
	te.StopLoop("cert-issuance")
	waitForCond(t, 2*time.Second, func() bool { return !te.IsRunning("cert-issuance") })

	// When/Then：状态列只承载执行实态，不得被业务活跃镜像覆盖为 running。
	for _, ti := range collectEngineFamilies(te) {
		if ti.ID != "cert-issuance" && ti.ID != "cert-waiting-ca" {
			continue
		}
		if ti.Status != TaskStatusIdle {
			t.Errorf("%s 调度已停但 status=%q，want idle（业务活跃≠任务执行中）", ti.ID, ti.Status)
		}
	}
}
