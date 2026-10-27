package services

// 看门狗两条「fail-visible 留痕」分支的回归钉：
//  ① 运行配置超解析上限（永久盲区，不会自愈）与瞬时读失败必须是两种文案——
//     若回归把超限并入通用文案，管理员会按「稍后自愈」处理，而漂移检测实际
//     已永久停摆；首报去重与恢复后复位同样要有断言。
//  ② 比对路径 panic 的兜底分支（任务日志「检查异常（panic 已拦）」+ 专用错误
//     文案）——引擎 runGuarded 另有兜底，本层独有价值是任务日志留痕，删掉不会
//     让进程崩，只能靠断言看守。

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
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
	originalWriter := log.Writer()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

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

// panic 兜底：错误文案 + 任务日志留痕 + 漂移簿记零改动；恢复后不再出现该行。
func TestConfigWatchdog_panicIsWrappedAndLoggedWithoutBookkeeping(t *testing.T) {
	newClusterTestService(t)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	oldURL := watchdogAdminURLValue
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })
	watchdogAdminURLValue = fakeCaddyWithRoutes(t, emptyCaddyConfig).URL
	originalWriter := log.Writer()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

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
	// And：漂移簿记零改动（panic 轮既不算一致也不推进 streak）。
	configDriftMu.RLock()
	consistent, streak, cleanRounds, skipped := configDriftStatus.Consistent, configDriftStreak, configDriftCleanRounds, configDriftSkipped
	configDriftMu.RUnlock()
	if !consistent || streak != 0 || cleanRounds != 0 || skipped != 0 {
		t.Fatalf("panic 轮改动了漂移簿记: consistent=%v streak=%d clean=%d skipped=%d", consistent, streak, cleanRounds, skipped)
	}

	// 回归形状：正常轮不再产生 panic 留痕。
	if err := WatchdogCheckOnce(context.Background()); err != nil {
		t.Fatalf("正常轮失败: %v", err)
	}
	if got := strings.Count(logs.String(), "检查 panic"); got != 1 {
		t.Fatalf("正常轮复用了 panic 留痕（次数=%d）: %s", got, logs.String())
	}
}
