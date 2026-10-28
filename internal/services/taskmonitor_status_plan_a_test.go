package services

import (
	"errors"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// 方案 A（2026-10-12 用户裁定）：任务监控状态列只承载执行语义；2026-10-22
// 用户裁定进一步收敛为三态（运行中/空闲/失败）——调度语义（调度关/业务关）
// 全部归开关列，业务生命周期态（cert_jobs.status）只进业务文本位，不进状态列。

func TestCollectSystemTasks_statusColumnExecutionOnly(t *testing.T) {
	setupIsolatedDB(t)
	e := taskengine.NewEngine(taskengine.Options{})
	t.Cleanup(e.Stop)
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
	meta, ok := te.Lookup("cert-waiting-ca")
	if !ok {
		t.Fatal("cert-waiting-ca 未注册")
	}
	if meta.StatusMirror != "" {
		t.Fatalf("cert-waiting-ca 不得携带业务 StatusMirror，got %q", meta.StatusMirror)
	}
	ti := findTaskInfo(t, collectEngineFamilies(te), "cert-waiting-ca")
	if ti.Status != TaskStatusIdle {
		t.Fatalf("空库无活跃任务应为 idle，got %s", ti.Status)
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
	seen := map[string]bool{}
	for _, ti := range collectEngineFamilies(te) {
		if ti.ID != "cert-issuance" && ti.ID != "cert-waiting-ca" {
			continue
		}
		seen[ti.ID] = true
		if ti.Status != TaskStatusIdle {
			t.Errorf("%s 调度已停但 status=%q，want idle（业务活跃≠任务执行中）", ti.ID, ti.Status)
		}
	}
	for _, id := range []string{"cert-issuance", "cert-waiting-ca"} {
		if !seen[id] {
			t.Errorf("任务视图缺少 %s 行", id)
		}
	}
}

// 常驻任务自愈预算用尽后 loop_on=false（与用户主动停止同形），
// 修复前状态列回落 idle——采集/签发永久停摆与「用户主动停止」不可区分。
// 引擎以 RestartExhausted 标记暴露真实停摆来源，监控必须呈现 failed。
func TestCollectEngineFamilies_daemonRestartExhaustedShowsFailed(t *testing.T) {
	setupIsolatedDB(t)
	e := taskengine.NewEngine(taskengine.Options{
		TickInterval:        10 * time.Millisecond,
		DaemonRestartDelays: []time.Duration{time.Millisecond},
	})
	t.Cleanup(e.Stop)
	if err := e.Register(taskengine.Descriptor{
		ID: "self-heal-exhaust", Family: "test", Name: "自愈用尽探针",
		Kind: taskengine.KindDaemon, RunsOn: taskengine.RoleAny,
		Run: func(taskengine.RunContext) error { return errors.New("boom") },
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	e.StartLoop("self-heal-exhaust")
	waitForCond(t, 3*time.Second, func() bool {
		meta, ok := e.Lookup("self-heal-exhaust")
		return ok && meta.RestartExhausted
	})
	meta, _ := e.Lookup("self-heal-exhaust")
	if meta.LoopOn {
		t.Fatal("自愈用尽后 loop_on 必须为 false（与日志「已停止调度」一致）")
	}

	rows := collectEngineFamilies(e)
	for _, row := range rows {
		if row.ID != "self-heal-exhaust" {
			continue
		}
		if row.Status != TaskStatusFailed {
			t.Fatalf("自愈用尽 status=%q, want failed（修复前恒 idle，永久停摆无信号）", row.Status)
		}
		if row.LoopOn {
			t.Fatal("状态列判据不得改写调度开关（loop_on 仍由引擎唯一事实源）")
		}
		return
	}
	t.Fatal("任务视图缺少 self-heal-exhaust 行")
}
