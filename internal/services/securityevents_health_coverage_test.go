package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"lazy-balancer-v2/internal/taskengine"
)

// 采集健康位必须反映「任务已停」：任务已停用/未运行时，事件数据不再增长，
// 健康位不得继续显示 healthy（三处面板同源消费该快照）。
func TestSecurityEventsIngestionHealth_reflectsTaskState(t *testing.T) {
	previous := TaskEngine()
	te := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	SetTaskEngineForTest(te)
	t.Cleanup(func() {
		te.StopWithTimeout(time.Second)
		SetTaskEngineForTest(previous)
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})
	if err := te.Register(taskengine.Descriptor{
		ID: "security-events-ingestion", Family: "system", Name: "安全事件采集",
		Kind: taskengine.KindDaemon,
		Run: func(rc taskengine.RunContext) error {
			<-rc.Ctx.Done()
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{Observed: true, Healthy: true})

	// 任务未启动（调度关闭）：未采集 → 非 healthy，且任务态可区分。
	status := SecurityEventsIngestionHealthSnapshot()
	if status.TaskRunning {
		t.Fatalf("task_running=%v, want false before StartLoop", status.TaskRunning)
	}
	if status.TaskState != "stopped" {
		t.Fatalf("task_state=%q, want stopped", status.TaskState)
	}
	if status.Healthy {
		t.Fatalf("stopped task must not report healthy: %+v", status)
	}

	// 任务运行中：快照回归 tick 记账的 healthy。
	te.StartLoop("security-events-ingestion")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if meta, ok := te.Lookup("security-events-ingestion"); ok && meta.Running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon did not reach running state")
		}
		time.Sleep(10 * time.Millisecond)
	}
	status = SecurityEventsIngestionHealthSnapshot()
	if !status.TaskRunning || status.TaskState != "running" {
		t.Fatalf("running task state=%q running=%v, want running", status.TaskState, status.TaskRunning)
	}
	if !status.Healthy {
		t.Fatalf("running task with a clean poll must stay healthy: %+v", status)
	}
}

// 审计写侧失败/丢弃（插件侧车计数）必须进入采集健康位：累计达阈值即降级，
// 下阈只披露计数；恢复后状态位复位。
func TestSecurityEventsPollOnce_auditWriterFailuresDegradeHealth(t *testing.T) {
	logPath, offsetPath := stallSetup(t)
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	oldLogPath, oldOffsetPath := auditLogPath, securityEventsOffsetPath
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	resetSecurityEventsPollState(t)
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath = oldLogPath, oldOffsetPath
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})

	writeWriterStats := func(dropped, ioErrors uint64) {
		t.Helper()
		// written_at 为秒精度，而进程启动基线是纳秒时刻：单跑时同秒写入会被
		// 判为「上一代进程产物」并复位基线（WriterDropped 恒 0 假红）。
		// 夹具统一写 now+1s（与 sidecar_health 用例同法）。
		body := fmt.Sprintf(`{"dropped":%d,"io_errors":%d,"written_at":%q}`, dropped, ioErrors, time.Now().Add(time.Second).UTC().Format(time.RFC3339))
		if err := os.WriteFile(securityEventsAuditWriterStatsPath(), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// 下阈：1 条丢弃 → 计数披露，健康位保持。
	writeWriterStats(1, 0)
	if _, err := securityEventsPollOnce(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	status := SecurityEventsIngestionHealthSnapshot()
	if status.WriterDropped != 1 || status.WriterIOErrors != 0 {
		t.Fatalf("writer counters=%d/%d, want 1/0", status.WriterDropped, status.WriterIOErrors)
	}
	if status.WriterDegraded || !status.Healthy {
		t.Fatalf("below-threshold writer failures must not degrade: %+v", status)
	}

	// 达阈值：累计 3 条丢弃 → 降级（健康位与面板同一位）。
	writeWriterStats(3, 0)
	if _, err := securityEventsPollOnce(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	status = SecurityEventsIngestionHealthSnapshot()
	if status.WriterDropped != 3 || !status.WriterDegraded || status.Healthy {
		t.Fatalf("threshold writer failures must degrade health: %+v", status)
	}
	if status.WriterLastFailureAt == "" {
		t.Fatalf("writer_last_failure_at must be set: %+v", status)
	}

	// 插件进程重启（计数器回落）：按新基线继续累计，不产生负增量假告警。
	writeWriterStats(0, 0)
	if _, err := securityEventsPollOnce(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	status = SecurityEventsIngestionHealthSnapshot()
	if status.WriterDropped != 3 {
		t.Fatalf("counter reset must not lose accumulated failures: %+v", status)
	}
}

// 异常自愈退避期（LoopOn=true、Run 不在）不得被打成 stopped：引擎按 1s/5s/30s
// 有界重拉，每次短暂重拉都瞬时把三面健康位判「采集已停止」并触发 autoban
// feed_degraded，属自愈噪音。判据单源 securityEventsIngestionTaskState：
// 只有循环真停（用户停止/自愈预算用尽）才降级。
func TestSecurityEventsIngestionHealth_backoffRestartIsNotStopped(t *testing.T) {
	previous := TaskEngine()
	// 退避拉长到 1h：测试期间稳定停在「调度开、Run 不在」窗口。
	te := taskengine.NewEngine(taskengine.Options{
		TickInterval:        time.Hour,
		DaemonRestartDelays: []time.Duration{time.Hour},
	})
	SetTaskEngineForTest(te)
	t.Cleanup(func() {
		te.StopWithTimeout(time.Second)
		SetTaskEngineForTest(previous)
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})
	if err := te.Register(taskengine.Descriptor{
		ID: "security-events-ingestion", Family: "system", Name: "安全事件采集",
		Kind: taskengine.KindDaemon,
		Run:  func(rc taskengine.RunContext) error { return errors.New("simulated daemon fault") },
	}); err != nil {
		t.Fatal(err)
	}
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{Observed: true, Healthy: true})

	te.StartLoop("security-events-ingestion")
	deadline := time.Now().Add(2 * time.Second)
	for {
		meta, ok := te.Lookup("security-events-ingestion")
		if ok && !meta.Running && meta.LoopOn && !meta.RestartExhausted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon 未进入退避重拉窗口: %+v", meta)
		}
		time.Sleep(5 * time.Millisecond)
	}

	status := SecurityEventsIngestionHealthSnapshot()
	if status.TaskState != "restarting" {
		t.Fatalf("退避窗口 task_state=%q, want restarting", status.TaskState)
	}
	if status.TaskRunning {
		t.Fatalf("退避窗口 task_running 必须为 false: %+v", status)
	}
	if !status.Healthy {
		t.Fatalf("退避重拉窗口不得降级健康位（自愈通道仍在）: %+v", status)
	}
	if degraded, reason := AutobanFeedHealth(); degraded {
		t.Fatalf("退避窗口不得触发 autoban 数据源降级: %s", reason)
	}

	// 反向：真停（用户停止调度）仍必须降级，避免修复引入「停环仍显示健康」。
	te.StopLoop("security-events-ingestion")
	status = SecurityEventsIngestionHealthSnapshot()
	if status.TaskState != "stopped" || status.Healthy {
		t.Fatalf("调度停止后必须判 stopped 且非健康: %+v", status)
	}
	if degraded, reason := AutobanFeedHealth(); !degraded {
		t.Fatalf("调度停止后 autoban 喂入源必须降级（reason=%q）", reason)
	}
}
