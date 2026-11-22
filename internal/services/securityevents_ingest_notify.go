package services

// 安全事件摄取健康降级/恢复通知：在 runIngestionLoop 的健康快照边沿发布
// （降级→恢复各一条，持续降级/持续健康不重复）。降级原因聚合自快照的
// 一等信号（跳过区/写侧丢弃/侧车不可读/截断/采集失败/spool 异常），恢复
// 事件携带上次降级原因便于闭环排障。

import (
	"fmt"
	"strings"

	"lazy-balancer-v2/internal/notify"
)

// ingestionNotifyTracker 摄取健康通知的边沿状态（进程内，随采集 daemon
// 生命周期）。
type ingestionNotifyTracker struct {
	initialized bool
	healthy     bool
	lastReasons string
}

// observe 按健康快照返回需要发布的事件（nil=无状态转换）。
// Observed=false（进程刚起、首轮 tick 尚未记账）不参与判定——否则初始零值
// 会被误判为「降级」。
func (t *ingestionNotifyTracker) observe(status SecurityEventsIngestionStatus) *notify.Event {
	if !status.Observed {
		return nil
	}
	prevInitialized, prevHealthy := t.initialized, t.healthy
	t.initialized, t.healthy = true, status.Healthy
	if status.Healthy {
		if !prevInitialized || prevHealthy {
			return nil
		}
		evt := notify.Event{Type: notify.EvtIngestRecovered, Fields: map[string]string{"1": t.lastReasons}}
		t.lastReasons = ""
		return &evt
	}
	if prevInitialized && !prevHealthy {
		return nil
	}
	t.lastReasons = ingestionDegradedReasons(status)
	return &notify.Event{Type: notify.EvtIngestDegraded, Fields: map[string]string{"1": t.lastReasons}}
}

// ingestionDegradedReasons 聚合当前降级原因（空=健康位由未列出的信号置降级，
// 给兜底文案而不是空正文）。
func ingestionDegradedReasons(status SecurityEventsIngestionStatus) string {
	reasons := make([]string, 0, 6)
	if status.TaskState == "stopped" {
		reasons = append(reasons, "采集任务未运行")
	}
	if status.ConsecutiveFailures >= securityEventsIngestionFailureThreshold {
		reasons = append(reasons, fmt.Sprintf("采集连续失败 %d 次", status.ConsecutiveFailures))
	}
	if status.WriterDegraded {
		reasons = append(reasons, "审计写侧丢弃/写盘失败")
	}
	if status.WriterStatsUnavailable {
		reasons = append(reasons, "写侧计数侧车不可读")
	}
	if status.SkippedRegions > 0 {
		reasons = append(reasons, fmt.Sprintf("审计日志畸形区跳过（累计 %d 段）", status.SkippedRegions))
	}
	if status.MessagesDropped > 0 {
		reasons = append(reasons, fmt.Sprintf("命中明细被截断（累计 %d 条）", status.MessagesDropped))
	}
	if status.SpoolSaturated {
		reasons = append(reasons, "待补采 spool 已达上限")
	}
	if status.SpoolUnavailable {
		reasons = append(reasons, "待补采目录不可读")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "健康检查未通过")
	}
	return strings.Join(reasons, "；")
}
