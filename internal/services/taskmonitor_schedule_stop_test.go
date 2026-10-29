package services

// 引擎自行停调的来源必须透出到任务视图（与用户主动停止区分）：业务驱动任务
// 的调度开关在任务页只读，视图只有知道「引擎停调」才能指向业务页的恢复入口。

import (
	"errors"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// Given Scheduled 业务驱动任务（威胁库）自动轮连续失败且槽不推进。
// When 达到停调终点后读取任务视图。
// Then 视图携带 schedule_stopped_reason=fail-streak，且开关列为关、来源与用户
// 主动停止可区分，next_run_at 为空（引擎槽缓存残留过去槽——与 Periodic 兜底
// 推算同口径只在槽位于未来时下发，否则页面恒显已过去的「下次执行」）。
func TestCollectEngineFamilies_surfacesScheduleStoppedReason(t *testing.T) {
	setupIsolatedDB(t)
	// 恢复入口在业务页：业务开关仍为开启。
	if _, err := db.DB.Exec(`UPDATE global_config SET threat_auto_update=1 WHERE id=1`); err != nil {
		t.Fatalf("seed threat_auto_update: %v", err)
	}
	e := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	t.Cleanup(e.Stop)
	e.SetRole(true)
	pastSlot := time.Now().Add(-time.Minute)
	if err := e.Register(taskengine.Descriptor{
		ID: "threat", Family: "security", Name: "威胁情报库更新", Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleAny,
		NextSlotFn: func() time.Time { return pastSlot },
		Run:        func(taskengine.RunContext) error { return errors.New("boom") },
	}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("threat")
	// 由实际停调状态驱动，不把循环次数当同步条件；最终次数仍精确钉住阈值。
	attempts := 0
	for attempts < 10 {
		attempts++
		if _, err := e.RunSync("threat", "auto", ""); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("第 %d 轮 err=%v, want 注入的 boom", attempts, err)
		}
		if meta, ok := e.Lookup("threat"); ok && !meta.LoopOn {
			break
		}
	}
	if attempts != 5 {
		t.Fatalf("自动失败停调轮数=%d, want 5（首轮+4 次连续失败）", attempts)
	}

	rows := collectEngineFamilies(e)
	hit := findTaskInfo(t, rows, "threat")
	if hit.LoopOn {
		t.Fatal("停调后 LoopOn 应为 false")
	}
	if hit.ScheduleStoppedReason != taskengine.ScheduleStopReasonFailStreak {
		t.Fatalf("停调来源=%q, want %q（任务页据此提示引擎已停调与恢复入口）", hit.ScheduleStoppedReason, taskengine.ScheduleStopReasonFailStreak)
	}
	if !hit.BusinessDriven {
		t.Fatal("业务驱动标记丢失（恢复入口必须指向业务页）")
	}
	if hit.NextRunAt != "" {
		t.Fatalf("停调后 next_run_at=%q, want 空（过去槽直通会让页面恒显已过去的「下次执行」）", hit.NextRunAt)
	}

	// 重新开启调度后来源清空（视图不再提示引擎停调）。
	e.StartLoop("threat")
	if hit := findTaskInfo(t, collectEngineFamilies(e), "threat"); hit.ScheduleStoppedReason != "" {
		t.Fatalf("恢复调度后停调来源应清空, got %q", hit.ScheduleStoppedReason)
	}
}
