package services

// 看门狗两条「fail-visible 留痕」分支的回归钉：
//  ① 运行配置超解析上限（永久盲区，不会自愈）与瞬时读失败必须是两种文案——
//     若回归把超限并入通用文案，管理员会按「稍后自愈」处理，而漂移检测实际
//     已永久停摆；首报去重与恢复后复位同样要有断言。
//  ② 比对路径 panic 的兜底分支（任务日志「检查异常（panic 已拦）」+ 专用错误
//     文案）——引擎 runGuarded 另有兜底，本层独有价值是任务日志留痕，删掉不会
//     让进程崩，只能靠断言看守。

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 超限留痕：专用文案一次（不并入通用读失败），恢复后不再重复。
func TestConfigWatchdog_oversizeConfigUsesDedicatedWarningOnce(t *testing.T) {
	newClusterTestService(t)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := io.Copy(w, &spaceFillReader{remaining: caddyAdminConfigMaxBytes + 1}); err != nil {
			t.Errorf("stream oversized config: %v", err)
		}
	}))
	t.Cleanup(oversized.Close)
	recovered := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	oldURL := watchdogAdminURLValue
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })
	logs := captureStandardLog(t)

	// When：超限配置连续两轮
	watchdogAdminURLValue = oversized.URL
	for range 2 {
		err := WatchdogCheckOnce(context.Background())
		if err == nil {
			t.Fatal("超限配置必须让本轮返回错误（task_runs failed）")
		}
		if !errors.Is(err, errCaddyAdminConfigTooLarge) {
			t.Fatalf("err=%v, want 超限哨兵（不得与瞬时读失败同形）", err)
		}
	}
	// Then：恰一条专用文案，且没有通用文案。
	if got := strings.Count(logs.String(), "漂移检测无法进行"); got != 1 {
		t.Fatalf("超限专用留痕次数=%d, want 1（首报去重）: %s", got, logs.String())
	}
	if strings.Contains(logs.String(), "读取运行配置失败") {
		t.Fatalf("超限被并入通用读失败文案（永久盲区会被读成瞬时故障）: %s", logs.String())
	}

	// When：配置缩回上限内，检查恢复
	watchdogAdminURLValue = recovered.URL
	for range 2 {
		if err := WatchdogCheckOnce(context.Background()); err != nil {
			t.Fatalf("恢复后的检查失败: %v", err)
		}
	}
	// Then：恢复轮不重复打印超限/读失败文案（标志已复位）。
	if got := strings.Count(logs.String(), "漂移检测无法进行"); got != 1 {
		t.Fatalf("恢复后仍重复超限留痕 %d 次: %s", got, logs.String())
	}
}

// panic 兜底：错误文案 + 任务日志留痕 + 打断漂移连续窗口；恢复后不再出现该行。
func TestConfigWatchdog_panicIsWrappedLoggedAndBreaksDriftStreak(t *testing.T) {
	newClusterTestService(t)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	oldURL := watchdogAdminURLValue
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })
	watchdogAdminURLValue = fakeCaddyWithRoutes(t, emptyCaddyConfig).URL
	logs := captureStandardLog(t)

	configDriftMu.Lock()
	configDriftStreak = 1
	configDriftMu.Unlock()

	previousSeam := configDriftCheckForTest
	configDriftCheckForTest = func(string) (bool, *configDriftEvent, error) {
		panic("injected compare panic")
	}
	// When
	err := WatchdogCheckOnce(context.Background())
	configDriftCheckForTest = previousSeam
	t.Cleanup(func() { configDriftCheckForTest = previousSeam })

	// Then：专用错误文案（本轮按失败上报，task_runs 落 failed）。
	if err == nil || !strings.Contains(err.Error(), "配置一致性检查 panic") {
		t.Fatalf("err=%v, want 配置一致性检查 panic 包装", err)
	}
	if !strings.Contains(err.Error(), "injected compare panic") {
		t.Fatalf("err=%v, want 原始 panic 值（排障线索）", err)
	}
	if got := strings.Count(logs.String(), "检查 panic"); got != 1 {
		t.Fatalf("运行日志 panic 留痕=%d, want 1: %s", got, logs.String())
	}
	if logText := readTaskLog(t, "config-watchdog"); !strings.Contains(logText, "检查异常（panic 已拦") {
		t.Fatalf("任务日志缺少 panic 留痕行:\n%s", logText)
	}
	// And：panic 轮没有判定证据，必须打断连续窗口并计入跳过轮。
	configDriftMu.RLock()
	consistent, streak, cleanRounds, skipped := configDriftStatus.Consistent, configDriftStreak, configDriftCleanRounds, configDriftSkipped
	configDriftMu.RUnlock()
	if !consistent || streak != 0 || cleanRounds != 0 || skipped != 1 {
		t.Fatalf("panic 轮未按未判定簿记: consistent=%v streak=%d clean=%d skipped=%d, want streak=0 skipped=1", consistent, streak, cleanRounds, skipped)
	}

	// 回归形状：正常轮不再产生 panic 留痕。
	if err := WatchdogCheckOnce(context.Background()); err != nil {
		t.Fatalf("正常轮失败: %v", err)
	}
	if got := strings.Count(logs.String(), "检查 panic"); got != 1 {
		t.Fatalf("正常轮复用了 panic 留痕（次数=%d）: %s", got, logs.String())
	}
}

// 降级复位（代际自增）后，在途轮的快照回滚必须放弃整轮簿记——包括两枚
// 「首报留痕已发」标志：只清状态/计数会让复位后的下一次失败被当成「已报过」
// 而静默（首条诊断日志永不出现，唯一线索丢失）。
func TestRestoreConfigDriftSnapshot_generationMismatchClearsWarnedFlags(t *testing.T) {
	resetConfigWatchdogForTest(t)
	snapshot := snapshotConfigDrift()

	// Given 在途轮进行中发生降级复位（代际自增），复位后该轮仍继续执行并
	// 写出两条首报标志——它们属于已失效的主节点视角。
	ResetConfigDrift()
	configDriftMu.Lock()
	configDriftQueryWarned = true
	configDriftReadWarned = true
	configDriftMu.Unlock()

	// When 在途轮收尾回滚到降级前快照（代际不一致）。
	restoreConfigDriftSnapshot(snapshot)

	// Then 首报标志必须随复位一并丢弃（下一次失败重新首报）。
	configDriftMu.RLock()
	queryWarned, readWarned := configDriftQueryWarned, configDriftReadWarned
	configDriftMu.RUnlock()
	if queryWarned {
		t.Fatal("代际不一致回滚未清 configDriftQueryWarned：复位后的首个查询失败会被静默")
	}
	if readWarned {
		t.Fatal("代际不一致回滚未清 configDriftReadWarned：复位后的首个读取失败会被静默")
	}
}
