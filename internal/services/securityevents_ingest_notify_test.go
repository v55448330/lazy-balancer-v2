package services

// v2.4.5 摄取健康降级/恢复通知：边沿判定与原因聚合；四库终态发布点守卫。

import (
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/notify"
)

func TestIngestionNotifyTrackerTransitions(t *testing.T) {
	var tr ingestionNotifyTracker
	// 未观测（进程刚起/首轮 tick 未记账）不判定。
	if ev := tr.observe(SecurityEventsIngestionStatus{}); ev != nil {
		t.Fatalf("未观测快照发布了事件: %+v", ev)
	}
	// 首次观测健康：无转换。
	if ev := tr.observe(SecurityEventsIngestionStatus{Observed: true, Healthy: true}); ev != nil {
		t.Fatalf("初始健康发布了事件: %+v", ev)
	}
	// 健康 → 降级：一条 degraded，原因聚合写侧/截断。
	degraded := SecurityEventsIngestionStatus{
		Observed: true, Healthy: false, TaskState: "stopped",
		WriterDegraded: true, WriterStatsUnavailable: true,
		SkippedRegions: 3, MessagesDropped: 7,
	}
	ev := tr.observe(degraded)
	if ev == nil || ev.Type != notify.EvtIngestDegraded {
		t.Fatalf("健康→降级未发 degraded: %+v", ev)
	}
	body := ev.Fields["1"]
	for _, want := range []string{"采集任务未运行", "审计写侧丢弃", "侧车不可读", "畸形区跳过", "命中明细被截断"} {
		if !strings.Contains(body, want) {
			t.Errorf("降级原因缺 %q: %q", want, body)
		}
	}
	// 持续降级：不重复（即使原因变化）。
	if ev := tr.observe(SecurityEventsIngestionStatus{Observed: true, Healthy: false, WriterDegraded: true}); ev != nil {
		t.Fatalf("持续降级重复发布: %+v", ev)
	}
	// 降级 → 恢复：一条 recovered，携带降级原因。
	ev = tr.observe(SecurityEventsIngestionStatus{Observed: true, Healthy: true})
	if ev == nil || ev.Type != notify.EvtIngestRecovered {
		t.Fatalf("降级→恢复未发 recovered: %+v", ev)
	}
	if !strings.Contains(ev.Fields["1"], "采集任务未运行") {
		t.Fatalf("恢复事件未携带降级原因: %q", ev.Fields["1"])
	}
	// 持续健康：不重复。
	if ev := tr.observe(SecurityEventsIngestionStatus{Observed: true, Healthy: true}); ev != nil {
		t.Fatalf("持续健康重复发布: %+v", ev)
	}
	// 未列出信号的降级不得空正文。
	ev = tr.observe(SecurityEventsIngestionStatus{Observed: true, Healthy: false})
	if ev == nil || strings.TrimSpace(ev.Fields["1"]) == "" {
		t.Fatalf("兜底降级原因缺失: %+v", ev)
	}
}

// TestLibUpdateTerminalPublishSites 四库 manager 终态收尾必须调用终态事件
// 发布函数（成功/失败各可达）——只在 notify 目录里定义不代表运行期会发。
func TestLibUpdateTerminalPublishSites(t *testing.T) {
	files := map[string][]string{
		"crsupdate.go":       {"PublishLibUpdateSucceeded", "PublishLibUpdateFailed"},
		"ip2regionupdate.go": {"PublishLibUpdateSucceeded", "PublishLibUpdateFailed"},
		"threatupdate.go":    {"PublishLibUpdateSucceeded", "PublishLibUpdateFailed"},
		"crawler_update.go":  {"PublishLibUpdateSucceeded", "PublishLibUpdateFailed"},
	}
	for file, wants := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		src := string(b)
		for _, want := range wants {
			if !strings.Contains(src, "notify."+want) {
				t.Errorf("%s 未调用 notify.%s（终态事件不可达）", file, want)
			}
		}
	}
}
