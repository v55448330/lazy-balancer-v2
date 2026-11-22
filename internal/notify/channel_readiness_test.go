package notify

// 通道就绪门（2026-11-22 用户裁定）：微信会话失效（iLink 上下文过期/
// 会话待刷新）后不再允许发送——派发侧跳过并留可见原因，直到用户重新
// 绑定且会话就绪。本文件钉派发守卫；写侧选择清洗与前端禁用由同批
// handlers/web 测试覆盖。

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fakeWxSender 记录是否被调用（不触网）。
type fakeWxSender struct{ calls int }

func (f *fakeWxSender) Send(ctx context.Context, targetJSON string, msg Message) error {
	f.calls++
	return nil
}

func (f *fakeWxSender) Test(ctx context.Context, targetJSON string) error { return nil }

func TestSendToChannels_skipsStaleWxSession(t *testing.T) {
	_ = newNotifySchemaDB(t) // subscriptionTemplateFor 需要 db.DB
	fake := &fakeWxSender{}
	RegisterSenderForTest(t, "wx_clawbot", fake)
	oldReady := wxSessionReadyForDelivery
	wxSessionReadyForDelivery = func(targetJSON string) bool { return false }
	t.Cleanup(func() { wxSessionReadyForDelivery = oldReady })

	// 凭据齐全（receiver+token）但会话未就绪：跳过原因=会话待刷新
	// （receiver/token 缺空的「凭据未配置」文案见 notify_semantics_hardening_test.go）。
	channels := []deliveryTarget{{ChannelID: 7, Name: "微信测试", Type: "wx_clawbot", Target: `{"receiver":"wxid-x","token":"tkn"}`}}
	errs, sent := sendToChannels(context.Background(), 0, 1, channels, nil, Message{EventType: "cfg.caddy_apply_failed", Level: "warn", Title: "T", Body: "B"})
	if fake.calls != 0 {
		t.Fatalf("会话未就绪仍调用了发送器：calls=%d", fake.calls)
	}
	if sent {
		t.Fatal("会话未就绪不得标记 sent")
	}
	if len(errs) == 0 || !strings.Contains(errs[0], "会话") {
		t.Fatalf("必须返回可见跳过原因（含「会话」）: %v", errs)
	}
	// 就绪后正常发送
	wxSessionReadyForDelivery = func(string) bool { return true }
	errs2, sent2 := sendToChannels(context.Background(), 0, 1, channels, nil, Message{EventType: "cfg.caddy_apply_failed", Level: "warn", Title: "T", Body: "B"})
	if fake.calls != 1 || !sent2 || len(errs2) != 0 {
		t.Fatalf("就绪后应正常发送: calls=%d sent=%v errs=%v", fake.calls, sent2, errs2)
	}
	_ = time.Now
}
