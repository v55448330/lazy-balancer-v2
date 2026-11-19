package notify

// 绑定会话状态机回归（弹框统一流程）：注册→待发送→入站「绑定测试」确认→
// 幂等不重复回复；per-bot per-scanner 隔离（多通道共存）；品牌确认文案。

import (
	"strings"
	"testing"
)

func clearBindSessions() {
	bindSessionMu.Lock()
	bindSessions = map[string]*BindSession{}
	bindSessionMu.Unlock()
}

func TestBindSessionFlow(t *testing.T) {
	clearBindSessions()
	t.Cleanup(clearBindSessions)
	// 注册会话→待发送
	StartBindSession(7, "wx_clawbot", "scanner1", "botA")
	if phase, _ := PollBindSession("wx_clawbot", "scanner1", "botA"); phase != "awaiting_message" {
		t.Fatalf("注册后应 awaiting_message, got %q", phase)
	}
	// 入站「绑定测试」确认
	if !ConfirmBindSessionByInbound("wx_clawbot", "scanner1", "botA", "scanner1", "ctx-1") {
		t.Fatalf("活跃会话应被确认")
	}
	phase, receiver := PollBindSession("wx_clawbot", "scanner1", "botA")
	if phase != "confirmed" || receiver != "scanner1" {
		t.Errorf("确认后 phase=%q receiver=%q, want confirmed/scanner1", phase, receiver)
	}
	// 幂等：已确认不重复回复
	if ConfirmBindSessionByInbound("wx_clawbot", "scanner1", "botA", "scanner1", "ctx-2") {
		t.Errorf("已确认会话不应重复确认")
	}
}

func TestBindSessionIsolation(t *testing.T) {
	clearBindSessions()
	t.Cleanup(clearBindSessions)
	StartBindSession(7, "wx_clawbot", "scanner1", "botA")
	// 不同 bot / 不同扫码者 / 不同类型均不匹配
	if ConfirmBindSessionByInbound("wx_clawbot", "scanner1", "botB", "scanner1", "") {
		t.Errorf("不同 bot 不应匹配")
	}
	if ConfirmBindSessionByInbound("wx_clawbot", "scanner2", "botA", "scanner2", "") {
		t.Errorf("不同扫码者不应匹配")
	}
	if ConfirmBindSessionByInbound("qq", "scanner1", "botA", "scanner1", "") {
		t.Errorf("不同类型不应匹配")
	}
	if phase, _ := PollBindSession("wx_clawbot", "scanner1", "botA"); phase != "awaiting_message" {
		t.Errorf("原会话应仍待发送, got %q", phase)
	}
	// 无会话=idle
	if phase, _ := PollBindSession("qq", "nobody", "botX"); phase != "idle" {
		t.Errorf("无会话应 idle, got %q", phase)
	}
}

func TestIsBindTestMessage(t *testing.T) {
	cases := map[string]bool{
		"绑定测试":      true,
		"  绑定测试  ":  true,
		"绑定 123456": false,
		"绑定":        false,
		"你好":        false,
		"":          false,
	}
	for text, want := range cases {
		if got := IsBindTestMessage(text); got != want {
			t.Errorf("IsBindTestMessage(%q)=%v, want %v", text, got, want)
		}
	}
}

func TestBindConfirmReplyBrand(t *testing.T) {
	reply := BindConfirmReply()
	// 无 branding 文件（测试库 DataDir 空）回退默认品牌名
	if !strings.Contains(reply, "Lazy Balancer") || !strings.Contains(reply, "绑定成功") {
		t.Errorf("确认文案应含品牌名+绑定成功, got %q", reply)
	}
}
