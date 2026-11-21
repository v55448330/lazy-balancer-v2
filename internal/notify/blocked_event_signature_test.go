package notify

// 契约守卫：RecordBlockedEvent 不得再收「publish 回调」形参。
// 该形参从未参与渲染（首条告警与窗口 flush 恒走包级 Publish），却让调用侧
// 与测试误以为可以注入隔离的发布器——测试传 no-op 后仍观察到真实发布，
// 属于会误导断言语义的死缝。需要可观测断言时以「包级总线状态」为准
// （见 TestRecordBlockedEventFirstOnlyPublishPerWindow 的 DroppedCount 口径）。

import (
	"reflect"
	"testing"
)

func TestRecordBlockedEventExposesNoUnusedPublishSeam(t *testing.T) {
	fnType := reflect.TypeOf(RecordBlockedEvent)
	if fnType.Kind() != reflect.Func {
		t.Fatalf("RecordBlockedEvent 不是函数: %v", fnType.Kind())
	}
	if got := fnType.NumIn(); got != 1 {
		t.Fatalf("RecordBlockedEvent 形参数=%d, want 1（仅 ruleName；publish 死缝已删除，勿回流）", got)
	}
	if fnType.In(0).Kind() != reflect.String {
		t.Fatalf("RecordBlockedEvent 首参类型=%v, want string（ruleName）", fnType.In(0).Kind())
	}
}
