package services

import "testing"

// 健康位是一个整体：测试重置 helper 必须同时清空消息截断计数
// （securityEventsMessagesDropped），否则上一个用例留下的截断事实会让后续用例
// 在没有任何截断的情况下读出 MessagesDropped>0 与 DataLoss=true（顺序依赖/
// 随机红，且此前的用例只能各自手工清零）。
func TestSecurityEventsSetIngestionHealthForTest_clearsMessagesDropped(t *testing.T) {
	securityEventsMessagesDropped.Store(7)
	t.Cleanup(func() { securityEventsMessagesDropped.Store(0) })

	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})

	status := securityEventsOverlayIngestionHealth(SecurityEventsIngestionStatus{})
	if status.MessagesDropped != 0 {
		t.Fatalf("MessagesDropped=%d, want 0（重置必须清空截断计数）", status.MessagesDropped)
	}
	if status.DataLoss {
		t.Fatalf("未产生截断的用例不得继承 DataLoss=true")
	}
}
