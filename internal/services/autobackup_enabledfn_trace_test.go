package services

// 自动备份 tick 侧 EnabledFn 的读失败留痕接线钉：引擎先求值 EnabledFn 再求值
// NextSlotFn，EnabledFn 读错即短路——nextAutoBackupSlot 里的
// schedule-read-auto-backup 告警永远不会被求值。EnabledFn 必须消费带留痕的
// 开关单源 AutoBackupEnabledState（首报 warn + 恢复 info），否则库故障窗口
// 自动备份「静默停摆」：零执行、零失败行、零日志，与用户关闭完全同形。
//
// 断言落在 InitTaskEngine 注册的真实 EnabledFn 上（经引擎 tick 驱动）——
// 直接调 AutoBackupEnabledState 只能证明单源自身留痕，删掉接线里的单源
// 消费改回裸 loadAutoBackupSettings 时那样的用例仍然绿。

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func TestAutoBackupEnabledFnWiring_logsReadFailureOnceAndRecovers(t *testing.T) {
	te := newWireTestEngine(t)
	isolateMetricsState(t)
	logs := captureLogf(t)
	// 业务开关开启 + 调度对齐（默认关闭，LoopOn=false 时 tick 不求值闭包）。
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	SyncBusinessTaskDrivers()
	// 其余业务驱动全部停调度：tick 每轮只消费 auto-backup 的闭包，
	// 避免同 key 的其它读失败路径污染计数。
	for _, id := range []string{"threat", "crs", "ip2region", "crawlerbot-update", AutobanTaskID} {
		te.StopLoop(id)
	}
	if !loopOnOf(t, te, "auto-backup") {
		t.Fatal("前置：auto-backup 必须处于调度开启态，避免 false 假绿")
	}
	// 槽求值地板拉到 tick 量级：故障窗口内 EnabledFn 每轮都被求值。
	oldFloor := taskengine.SchedSlotEvalFloorForTest(10 * time.Millisecond)
	t.Cleanup(func() { taskengine.SchedSlotEvalFloorForTest(oldFloor) })

	// Given：库查询恒失败（真实驱动级故障，非标志位模拟）。
	healthy, healthyCurrent := db.DB, db.GetDB()
	swapBrokenDB(t)

	// When：tick 持续求值 EnabledFn（故障窗口）。Then：首报恰一条。
	waitForAutoBackupEnabledFnTrace(t, logs, "读取配置失败（schedule-read-auto-backup-enabled）")
	// 状态转换去重：窗口内多轮求值不得刷屏。
	time.Sleep(80 * time.Millisecond)
	if count := strings.Count(logs.String(), "读取配置失败（schedule-read-auto-backup-enabled）"); count != 1 {
		t.Fatalf("故障窗口告警次数=%d, want 1（状态转换去重）: %s", count, logs.String())
	}

	// When：库恢复。Then：恢复 info 一条，且稳定期零噪音。
	db.DB = healthy
	db.SetDB(healthyCurrent)
	waitForAutoBackupEnabledFnTrace(t, logs, "读取配置已恢复（schedule-read-auto-backup-enabled）")
	time.Sleep(80 * time.Millisecond)
	if count := strings.Count(logs.String(), "读取配置已恢复（schedule-read-auto-backup-enabled）"); count != 1 {
		t.Fatalf("恢复日志次数=%d, want 1: %s", count, logs.String())
	}
}

// waitForAutoBackupEnabledFnTrace 等待 tick 驱动的 EnabledFn 留痕出现。
func waitForAutoBackupEnabledFnTrace(t *testing.T, logs *bytes.Buffer, substr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), substr) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待 EnabledFn 留痕超时（%s）——tick 侧读失败静默（接线绕过留痕单源）: %s", substr, logs.String())
}
