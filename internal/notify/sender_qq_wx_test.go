package notify

// QQ/微信通道适配器错误路径测试（真 sqlite 表，零外呼）：目标校验、连接
// 离线明确报错、iLink context_token 缺失 fail-loud、绑定会话入站确认闭环。

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// newNotifyConnectorDB 通道/KV 两表齐全的测试库。
func newNotifyConnectorDB(t *testing.T) {
	t.Helper()
	old := db.DB
	database, err := sql.Open("sqlite", t.TempDir()+"/connector-test.db")
	if err != nil {
		t.Fatalf("测试库打开失败: %v", err)
	}
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS notify_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS notification_channels (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL, type TEXT NOT NULL, name TEXT NOT NULL,
			target TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
			last_test_at DATETIME, last_test_ok INTEGER,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, type, target))`,
	} {
		if _, err := database.Exec(ddl); err != nil {
			t.Fatalf("建表失败: %v", err)
		}
	}
	db.DB = database
	// 凭据静态加密测试接缝：临时主密钥文件（生产经 db.DataDir，测试库 sql.Open 不设）。
	oldKeyPath := secretKeyPath
	keyFile := t.TempDir() + "/.notify_secret_key"
	secretKeyPath = func() string { return keyFile }
	resetSecretKeyCache()
	t.Cleanup(func() {
		db.DB = old
		secretKeyPath = oldKeyPath
		resetSecretKeyCache()
		_ = database.Close()
		// per-bot 态隔离：登记表与 wx 会话路由态清零，防跨测试污染。
		qqLinks.mu.Lock()
		qqLinks.links = nil
		qqLinks.first = ""
		qqLinks.mu.Unlock()
		wxLinks.mu.Lock()
		wxLinks.links = nil
		wxLinks.first = ""
		wxLinks.mu.Unlock()
		wxCtxMu.Lock()
		wxContextTokens = map[string]map[string]string{}
		wxUpdatesBufs = map[string]string{}
		wxConfirmedPin = nil
		wxPendingQR = ""
		wxPendingInbound = wxInboundCapture{}
		wxCtxMu.Unlock()
	})
}

func TestSendQQC2CTargetValidation(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{"缺 openid", `{}`},
		{"非 JSON", `{bad`},
	}
	for _, tc := range cases {
		err := SendQQC2C(context.Background(), tc.target, "hello")
		if err == nil {
			t.Errorf("%s: 未返回错误", tc.name)
		}
	}
}

func TestQQSenderTestOfflineClearError(t *testing.T) {
	newNotifyConnectorDB(t)
	qqLinks.setFirst("APP_OFF")
	qqLinks.register("APP_OFF").set(false, "")
	err := qqSender{}.Test(context.Background(), `{"openid":"o123"}`)
	if err == nil || !strings.Contains(err.Error(), "离线") {
		t.Errorf("连接离线应明确报错含「离线」, got %v", err)
	}
}

func TestQQSenderSendMissingCredentials(t *testing.T) {
	newNotifyConnectorDB(t)
	// 凭据未配置：REST 发送在鉴权处 fail-loud（不外呼——凭据读取先于 token 请求）。
	err := SendQQC2C(context.Background(), `{"openid":"o123"}`, "hello")
	if err == nil || !strings.Contains(err.Error(), "凭据未配置") {
		t.Errorf("凭据未配置应明确报错, got %v", err)
	}
}

func TestWxSenderSendFailsLoudWithoutContextToken(t *testing.T) {
	newNotifyConnectorDB(t)
	// 登录态已配置但接收方从未发过消息：context_token 缺失必须 fail-loud。
	if err := SetSettings(map[string]string{
		KeyWxBotCred: `{"token":"test-token","baseUrl":"","accountId":"b@im.bot","userId":"u@im.wechat"}`,
	}); err != nil {
		t.Fatalf("写入登录态失败: %v", err)
	}
	t.Cleanup(func() {
		_ = SetSettings(map[string]string{KeyWxBotCred: ""})
	})
	err := SendWxText(context.Background(), `{"receiver":"fresh-wxid-`+t.Name()+`"}`, "hello")
	if err == nil || !strings.Contains(err.Error(), "会话上下文") {
		t.Errorf("缺 context_token 应明确报错, got %v", err)
	}
}

func TestWxSenderTestOfflineClearError(t *testing.T) {
	newNotifyConnectorDB(t)
	wxLinks.setFirst("B_OFF")
	wxLinks.register("B_OFF").set(false, "")
	err := wxSender{}.Test(context.Background(), `{"receiver":"wx1"}`)
	if err == nil || !strings.Contains(err.Error(), "离线") {
		t.Errorf("连接离线应明确报错, got %v", err)
	}
}

func TestWxSplitTextChunking(t *testing.T) {
	long := strings.Repeat("ab\n", 3000) // 9000 字符，含换行软边界
	chunks := splitWxText(long, 2000)
	if len(chunks) < 2 {
		t.Fatalf("长文本应分片, got %d 片", len(chunks))
	}
	total := 0
	for i, c := range chunks {
		if len([]rune(c)) > 2000 {
			t.Errorf("片 %d 超限: %d", i, len([]rune(c)))
		}
		total += len([]rune(c))
	}
	if total != len([]rune(long)) {
		t.Errorf("分片丢失内容: %d != %d", total, len([]rune(long)))
	}
	short := splitWxText("短消息", 2000)
	if len(short) != 1 || short[0] != "短消息" {
		t.Errorf("短文本不应分片: %v", short)
	}
}

// 入站「绑定测试」确认语义（替代旧绑定码落库闭环）：弹框注册会话→入站确认
// （捕获 receiver/context）→幂等不重复确认；无会话→不匹配。入站确认不建
// 通道（建通道交弹框保存路径）。
func TestConfirmBindSessionByInboundSemantics(t *testing.T) {
	newNotifyConnectorDB(t)
	clearBindSessions()
	t.Cleanup(clearBindSessions)
	// Given 弹框扫码注册会话（QQ 携带待绑定凭据）
	StartBindSessionWithCred(7, "qq", "o456", "APP_A", "SEC_A")
	if phase, _ := PollBindSession(7, "qq", "o456", "APP_A"); phase != "awaiting_message" {
		t.Fatalf("注册后应 awaiting_message, got %q", phase)
	}
	// When 入站确认
	if !ConfirmBindSessionByInbound("qq", "o456", "APP_A", "o456", "") {
		t.Fatal("活跃会话应被确认")
	}
	phase, receiver := PollBindSession(7, "qq", "o456", "APP_A")
	if phase != "confirmed" || receiver != "o456" {
		t.Errorf("确认后 phase=%q receiver=%q, want confirmed/o456", phase, receiver)
	}
	// Then 幂等：已确认不重复确认（不重复回执）
	if ConfirmBindSessionByInbound("qq", "o456", "APP_A", "o456", "") {
		t.Error("已确认会话不应重复确认")
	}
	// Then wx 会话捕获 context_token，二次确认不覆盖
	StartBindSession(7, "wx_clawbot", "wx1", "B1")
	if !ConfirmBindSessionByInbound("wx_clawbot", "wx1", "B1", "wx1", "ctx-1") {
		t.Fatal("wx 活跃会话应被确认")
	}
	if ConfirmBindSessionByInbound("wx_clawbot", "wx1", "B1", "wx1", "ctx-2") {
		t.Error("wx 已确认会话不应重复确认")
	}
	bindSessionMu.Lock()
	ctxTok := bindSessions[bindSessionKey("wx_clawbot", "wx1", "B1")].ContextToken
	bindSessionMu.Unlock()
	if ctxTok != "ctx-1" {
		t.Errorf("二次确认改写 context_token: %q, want ctx-1", ctxTok)
	}
	// Then 无会话→不匹配（旧「无活跃会话」兜底已移除）
	if ConfirmBindSessionByInbound("qq", "nobody", "APP_A", "nobody", "") {
		t.Error("无会话不应被确认")
	}
	// Then 旧「绑定 <验证码>」形态不再匹配（不向后兼容）
	if IsBindTestMessage("绑定 CODE1") {
		t.Error("旧绑定码指令不应匹配绑定测试")
	}
	// Then 入站确认不建通道（建通道交弹框保存）
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_channels`).Scan(&n); err != nil || n != 0 {
		t.Errorf("入站确认不应建通道: n=%d err=%v", n, err)
	}
}

// 停止语义回归（用户裁定+实测根因）：连接任务清洁停止必须置离线，且出站
// Send 因「服务未运行」直接失败（不静默滞留 pending）。此前早退路径不清
// per-bot 链接态，残留假在线使 Send/Test 门放行。
func TestQQConnectionStopClearsLinkAndBlocksSend(t *testing.T) {
	newNotifyConnectorDB(t)
	qqLinks.setFirst("APP_STOP")
	qqLinks.register("APP_STOP").set(true, "") // 模拟停止前在线
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = RunQQBotConnection(ctx) // 清洁停止（ctx 已取消）
	if connected, _, _ := QQLinkStatus(); connected {
		t.Fatal("连接任务停止后首 bot 应置离线（残留假在线=根因）")
	}
	err := qqSender{}.Send(context.Background(), `{"openid":"o123"}`, Message{Title: "t", Body: "b"})
	if err == nil || !strings.Contains(err.Error(), "服务未运行") {
		t.Errorf("停止后出站 Send 应失败含「服务未运行」, got %v", err)
	}
}

func TestWxConnectionStopClearsLinkAndBlocksSend(t *testing.T) {
	newNotifyConnectorDB(t)
	wxLinks.setFirst("B_STOP")
	wxLinks.register("B_STOP").set(true, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = RunWxBotConnection(ctx)
	if connected, _, _ := WxLinkStatus(); connected {
		t.Fatal("连接任务停止后首 bot 应置离线")
	}
	err := wxSender{}.Send(context.Background(), `{"receiver":"wxid_1"}`, Message{Title: "t", Body: "b"})
	if err == nil || !strings.Contains(err.Error(), "服务未运行") {
		t.Errorf("停止后出站 Send 应失败含「服务未运行」, got %v", err)
	}
}

// 发送闸门权威=调度器运行态（用户裁定）：探针优先于链接标志。探针 false
// 即使链接在线也拒发；探针 true 即使链接离线也放行过闸（后续凭据/目标校验
// 另行 fail-loud，不属于「服务未运行」）。
func TestBotSendGateUsesEngineRunningState(t *testing.T) {
	newNotifyConnectorDB(t)
	t.Cleanup(func() { SetTaskRunningProbe(nil) })
	gateLink := qqLinks.register("APP_GATE")
	qqLinks.setFirst("APP_GATE")
	gateLink.set(true, "")
	SetTaskRunningProbe(func(string) bool { return false })
	err := qqSender{}.Send(context.Background(), `{"openid":"o1"}`, Message{Title: "t"})
	if err == nil || !strings.Contains(err.Error(), "服务未运行") {
		t.Errorf("探针 false（任务停止）即使链接在线也应拒发, got %v", err)
	}
	gateLink.set(false, "")
	SetTaskRunningProbe(func(string) bool { return true })
	err = qqSender{}.Send(context.Background(), `{"openid":"o1"}`, Message{Title: "t"})
	if err != nil && strings.Contains(err.Error(), "服务未运行") {
		t.Errorf("探针 true（任务运行）不应以「服务未运行」拒发, got %v", err)
	}
}
