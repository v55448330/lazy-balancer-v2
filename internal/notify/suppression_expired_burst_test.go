package notify

import (
	"strconv"
	"testing"
)

// 自动解封通知的风暴上界：短窗口内大量 IP 同时到期时，逐 IP 发布会把总线
// 打满并挤掉同刻的其它关键事件。窗口内逐 IP 通知有上界（首次若干条），
// 超出部分静默（审计行仍逐条保留），总量与窗口复位后行为保持可预期。
func TestPublishAutobanExpired_boundedPerWindow(t *testing.T) {
	resetBlockedStateForTest(t)
	ensureBusStoppedForTest(t)
	before := DroppedCount()
	for i := range 2000 {
		PublishAutobanExpired("198.18." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256))
	}
	if got := DroppedCount() - before; got > int64(autobanExpiredBurstCap) {
		t.Fatalf("单窗口解封通知=%d 条，超过上界 %d（会挤占总线并丢弃其它事件）", got, autobanExpiredBurstCap)
	}

	// 回归：少量解封仍逐条发布；窗口复位后重新计数。
	resetBlockedStateForTest(t)
	ensureBusStoppedForTest(t)
	before = DroppedCount()
	for i := range 3 {
		PublishAutobanExpired("198.19.0." + strconv.Itoa(i))
	}
	if got := DroppedCount() - before; got != 3 {
		t.Fatalf("少量解封必须逐条发布：got %d want 3", got)
	}
}
