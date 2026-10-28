package handlers

// 日志体量读取失败的可观测契约：目录枚举/Info 失败必须留痕（状态转换去重：
// 首报 warn、恢复 info、持续失败不刷屏），响应形状不变——「没有日志」与
// 「读不到日志」不得混为一谈。

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/services"
)

func captureHandlerLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	preserveApplicationLogLevel(t, "info")
	buffer := &bytes.Buffer{}
	oldWriter := log.Writer()
	log.SetOutput(buffer)
	t.Cleanup(func() { log.SetOutput(oldWriter) })
	return buffer
}

// preserveApplicationLogLevel 记录进程级应用日志级别并在用例结束时复位；
// force 非空时先切到该级别。
//
// 级别是进程级阈值（services.ConfigureLogLevel），而 PUT /config、
// 配置备份导入、配置写中间件都会经 services.ApplyLogLevel 把它改成载荷里的
// log_level——这些用例只改库不复位，阈值就泄漏给后续用例：断言「本用例是否
// 留痕」的 info 级用例会拿到空日志，失败文案却指向「实现没留痕」。捕获型用例
// 必须先固定级别；写 log_level 的用例必须快照复位。
func preserveApplicationLogLevel(t *testing.T, force string) {
	t.Helper()
	previous := services.CurrentLogLevel()
	if force != "" {
		if err := services.ConfigureLogLevel(force); err != nil {
			t.Fatalf("设置应用日志级别 %q 失败: %v", force, err)
		}
	}
	t.Cleanup(func() { _ = services.ConfigureLogLevel(previous) })
}

func countLogOccurrences(logs *bytes.Buffer, fragment string) int {
	return strings.Count(logs.String(), fragment)
}

func TestLogStatsVolume_dirReadFailureIsVisibleAndRecovers(t *testing.T) {
	resetLogStatsVolumeStateForTest()
	t.Cleanup(resetLogStatsVolumeStateForTest)
	dir := t.TempDir()
	match := func(name string) bool { return strings.HasSuffix(name, ".log") }

	origReadDir := logStatsReadDir
	logStatsReadDir = func(string) ([]os.DirEntry, error) { return nil, os.ErrPermission }
	t.Cleanup(func() { logStatsReadDir = origReadDir })
	logs := captureHandlerLog(t)

	// When：连续两轮枚举失败。
	for range 2 {
		if stats := aggregateDirStatsWithEntries(dir, nil, match); len(stats) != 0 {
			t.Fatalf("读取失败应返回空聚合, got %v", stats)
		}
	}
	// Then：恰一条 warn（状态转换去重），key 携带目录路径。
	if got := countLogOccurrences(logs, "日志体量读取失败（logstats-dir-"+dir+"）"); got != 1 {
		t.Fatalf("失败留痕 %d 条, want 1: %q", got, logs.String())
	}
	if strings.Contains(logs.String(), "ERROR:") {
		t.Fatalf("体量读取失败应记 warn: %q", logs.String())
	}

	// When：恢复（真实枚举），有文件的目录。
	if err := os.WriteFile(filepath.Join(dir, "app.log"), []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	logStatsReadDir = origReadDir
	if stats := aggregateDirStatsWithEntries(dir, nil, match); stats["app.log"].Active != 3 {
		t.Fatalf("恢复后聚合=%v, want app.log Active=3", stats)
	}
	// Then：恰一条恢复 info。
	if got := countLogOccurrences(logs, "日志体量读取已恢复（logstats-dir-"+dir+"）"); got != 1 {
		t.Fatalf("恢复留痕 %d 条, want 1: %q", got, logs.String())
	}
}

// 端点级：体量读取失败时响应保持 200 与单行形状（不新增错误面），失败由
// 日志留痕承担。
func TestGetLogStats_responseStaysOKOnVolumeReadFailure(t *testing.T) {
	h := newBackupTestHandlers(t)
	resetLogStatsVolumeStateForTest()
	t.Cleanup(resetLogStatsVolumeStateForTest)
	origReadDir := logStatsReadDir
	logStatsReadDir = func(string) ([]os.DirEntry, error) { return nil, os.ErrPermission }
	t.Cleanup(func() { logStatsReadDir = origReadDir })
	logs := captureHandlerLog(t)

	resp := fetchLogStatsRows(t, h.GetLogStats, "?keys=runtime")
	active, rotated, count, ok := logStatsRowByKey(resp, "runtime")
	if !ok || active != 0 || rotated != 0 || count != 0 {
		t.Fatalf("runtime row=(%d,%d,%d,found=%v), want 零值但存在", active, rotated, count, ok)
	}
	if got := countLogOccurrences(logs, "日志体量读取失败"); got == 0 {
		t.Fatalf("端点路径失败必须留痕: %q", logs.String())
	}
}

// ENOENT（日志尚未产生）是正常形态，不得留痕。
func TestLogStatsVolume_missingDirectoryIsNotLogged(t *testing.T) {
	resetLogStatsVolumeStateForTest()
	t.Cleanup(resetLogStatsVolumeStateForTest)
	logs := captureHandlerLog(t)
	missing := filepath.Join(t.TempDir(), "absent")
	resetLogStatsVolumeStateForTest()
	aggregateDirStatsWithEntries(missing, nil, func(name string) bool { return true })
	if strings.Contains(logs.String(), "日志体量读取失败") {
		t.Fatalf("目录不存在不得留痕: %q", logs.String())
	}
}

// 去重表触顶时逐出单个键而非整表清空：清空会让仍在失败的路径全部回到「首报」
// （一次性告警风暴），并丢掉失败→恢复的配对信息。
func TestLogStatsVolumeFailure_capEvictsSingleKey(t *testing.T) {
	resetLogStatsVolumeStateForTest()
	t.Cleanup(resetLogStatsVolumeStateForTest)
	logStatsVolumeState.Lock()
	logStatsVolumeState.failed = map[string]bool{}
	for i := range logStatsVolumeStateCap {
		logStatsVolumeState.failed["k"+strconv.Itoa(i)] = true
	}
	logStatsVolumeState.Unlock()

	logStatsVolumeReadFailure("new-key", os.ErrPermission)

	logStatsVolumeState.Lock()
	defer logStatsVolumeState.Unlock()
	if len(logStatsVolumeState.failed) != logStatsVolumeStateCap {
		t.Fatalf("触顶后键数=%d, want %d", len(logStatsVolumeState.failed), logStatsVolumeStateCap)
	}
	if !logStatsVolumeState.failed["new-key"] {
		t.Fatal("新失败键必须登记（触顶即拒登会让该路径的失败永久静默）")
	}
	kept := 0
	for i := range logStatsVolumeStateCap {
		if logStatsVolumeState.failed["k"+strconv.Itoa(i)] {
			kept++
		}
	}
	if kept != logStatsVolumeStateCap-1 {
		t.Fatalf("旧键保留 %d 个, want %d（清空整表会让全部旧键重新首报）", kept, logStatsVolumeStateCap-1)
	}
}
