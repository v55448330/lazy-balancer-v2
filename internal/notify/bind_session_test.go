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
	// 排空残留唤醒：无 supervisor 消费时缓冲留存，会污染后续连接测试的对账时序。
	select {
	case <-qqWakeCh:
	default:
	}
	select {
	case <-wxWakeCh:
	default:
	}
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

// 破「连接测试↔保存门控」死锁回归：supervisor 枚举须含待绑定凭据（QQ 会话携带
// secret / wx 二登 pin），否则二登 bot 扫码后不建连（QQ 卡连接测试/wx 客户端网络错误）。
func TestEnumerateIncludesPendingBindCreds(t *testing.T) {
	newNotifyConnectorDB(t)
	clearBindSessions()
	t.Cleanup(func() {
		clearBindSessions()
		wxCtxMu.Lock()
		wxConfirmedPin = nil
		wxCtxMu.Unlock()
		// 排空残留唤醒（无 supervisor 消费时缓冲留存，污染后续连接测试对账时序）。
		select {
		case <-qqWakeCh:
		default:
		}
	})
	StartBindSessionWithCred(7, "qq", "scanner1", "APP_PENDING", "SEC_PENDING")
	foundQQ := false
	for _, b := range qqEnumerateBots() {
		if b.AppID == "APP_PENDING" && b.Secret == "SEC_PENDING" {
			foundQQ = true
		}
	}
	if !foundQQ {
		t.Errorf("qqEnumerateBots 应含待绑定凭据 APP_PENDING（破死锁）")
	}
	wxCtxMu.Lock()
	wxConfirmedPin = &wxBotCred{Token: "T_PIN", AccountID: "B_PIN", UserID: "U_PIN"}
	wxCtxMu.Unlock()
	foundWx := false
	for _, b := range wxEnumerateBots() {
		if wxCredKey(b) == "B_PIN" {
			foundWx = true
		}
	}
	if !foundWx {
		t.Errorf("wxEnumerateBots 应含二登 pin B_PIN（破死锁）")
	}
}

// 取消绑定清理回归：AbortBindSession 删会话+清 wx 匹配 pin+qq 待绑定凭据不再
// 枚举（防未保存通道 bot 的幽灵入站连接）。
func TestAbortBindSessionClearsGhost(t *testing.T) {
	newNotifyConnectorDB(t)
	clearBindSessions()
	t.Cleanup(func() {
		clearBindSessions()
		wxCtxMu.Lock()
		wxConfirmedPin = nil
		wxCtxMu.Unlock()
	})
	// wx：会话+pin 存在→取消后会话 idle、pin 清、不再枚举
	StartBindSessionWithCred(7, "wx_clawbot", "wxU", "B_GHOST", "")
	wxCtxMu.Lock()
	wxConfirmedPin = &wxBotCred{Token: "T_G", AccountID: "B_GHOST", UserID: "wxU"}
	wxCtxMu.Unlock()
	AbortBindSession("wx_clawbot", "wxU", "B_GHOST")
	if phase, _ := PollBindSession("wx_clawbot", "wxU", "B_GHOST"); phase != "idle" {
		t.Errorf("取消后 wx 会话应 idle, got %q", phase)
	}
	wxCtxMu.Lock()
	pin := wxConfirmedPin
	wxCtxMu.Unlock()
	if pin != nil {
		t.Errorf("取消应清 wx 匹配 pin")
	}
	for _, b := range wxEnumerateBots() {
		if wxCredKey(b) == "B_GHOST" {
			t.Errorf("取消后 wx 不应再枚举幽灵 bot")
		}
	}
	// qq：会话携带 secret→取消后不再枚举
	StartBindSessionWithCred(7, "qq", "oU", "APP_GHOST", "SEC_G")
	AbortBindSession("qq", "oU", "APP_GHOST")
	for _, b := range PendingBindQQCreds() {
		if b.AppID == "APP_GHOST" {
			t.Errorf("取消后 qq 不应再枚举幽灵凭据")
		}
	}
}

// 重扫同 bot 回归：待绑定新 secret 覆盖陈旧全局 secret（防旧 secret 掩蔽致
// 鉴权 100016），且保持全局在前的首 bot 序。
func TestEnumerateFreshBindSecretOverridesStaleGlobal(t *testing.T) {
	newNotifyConnectorDB(t)
	clearBindSessions()
	t.Cleanup(clearBindSessions)
	seedQQGlobalCred(t, "APP_SAME", "SECRET_OLD")
	StartBindSessionWithCred(7, "qq", "oSame", "APP_SAME", "SECRET_NEW")
	bots := qqEnumerateBots()
	if len(bots) == 0 || bots[0].AppID != "APP_SAME" {
		t.Fatalf("首 bot 应为全局 APP_SAME, got %+v", bots)
	}
	if bots[0].Secret != "SECRET_NEW" {
		t.Errorf("重扫同 bot 应用新 secret SECRET_NEW, got %q", bots[0].Secret)
	}
}
