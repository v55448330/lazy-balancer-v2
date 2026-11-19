package notify

// QQ/微信通道适配器错误路径测试（真 sqlite 表，零外呼）：目标校验、连接
// 离线明确报错、iLink context_token 缺失 fail-loud、绑定码落库闭环。

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// newNotifyConnectorDB 通道/绑定码/KV 三表齐全的测试库。
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
		`CREATE TABLE IF NOT EXISTS qq_bind_codes (
			code TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at DATETIME NOT NULL)`,
	} {
		if _, err := database.Exec(ddl); err != nil {
			t.Fatalf("建表失败: %v", err)
		}
	}
	db.DB = database
	t.Cleanup(func() {
		db.DB = old
		_ = database.Close()
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
	qqLink.set(false, "")
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
	wxLink.set(false, "")
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

func TestBindBotChannelUpsert(t *testing.T) {
	newNotifyConnectorDB(t)
	if _, err := db.DB.Exec(`INSERT INTO qq_bind_codes (code, user_id, expires_at) VALUES ('CODE1', 7, datetime('now', '+1 hour'))`); err != nil {
		t.Fatalf("播种绑定码失败: %v", err)
	}
	var replies []string
	bindBotChannel("CODE1", "o456", "qq", "QQ 机器人", `{"openid":"o456"}`, func(reply string) {
		replies = append(replies, reply)
	})
	if len(replies) != 1 || replies[0] != "绑定成功" {
		t.Fatalf("绑定回执 = %v, want [绑定成功]", replies)
	}
	var target string
	var userID int64
	if err := db.DB.QueryRow(`SELECT user_id, target FROM notification_channels WHERE type='qq'`).Scan(&userID, &target); err != nil {
		t.Fatalf("通道行未落库: %v", err)
	}
	if userID != 7 || target != `{"openid":"o456"}` {
		t.Errorf("通道行 user_id=%d target=%s", userID, target)
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM qq_bind_codes WHERE code='CODE1'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("绑定码未消费: n=%d err=%v", n, err)
	}
	// 无效绑定码 → 明确回执。
	replies = nil
	bindBotChannel("GONE", "o789", "qq", "QQ 机器人", `{"openid":"o789"}`, func(reply string) {
		replies = append(replies, reply)
	})
	if len(replies) != 1 || !strings.Contains(replies[0], "无效或已过期") {
		t.Errorf("失效绑定码回执 = %v", replies)
	}
}

// 停止语义回归（用户裁定+实测根因）：连接任务清洁停止必须置离线，且出站
// Send 因「服务未运行」直接失败（不静默滞留 pending）。此前早退路径不清
// qqLink/wxLink，残留假在线使 Send/Test 门放行。
func TestQQConnectionStopClearsLinkAndBlocksSend(t *testing.T) {
	newNotifyConnectorDB(t)
	qqLink.set(true, "") // 模拟停止前在线
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = RunQQBotConnection(ctx) // 清洁停止（ctx 已取消）
	if connected, _, _ := QQLinkStatus(); connected {
		t.Fatal("连接任务停止后 qqLink 应置离线（残留假在线=根因）")
	}
	err := qqSender{}.Send(context.Background(), `{"openid":"o123"}`, Message{Title: "t", Body: "b"})
	if err == nil || !strings.Contains(err.Error(), "服务未运行") {
		t.Errorf("停止后出站 Send 应失败含「服务未运行」, got %v", err)
	}
}

func TestWxConnectionStopClearsLinkAndBlocksSend(t *testing.T) {
	newNotifyConnectorDB(t)
	wxLink.set(true, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = RunWxBotConnection(ctx)
	if connected, _, _ := WxLinkStatus(); connected {
		t.Fatal("连接任务停止后 wxLink 应置离线")
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
	qqLink.set(true, "")
	SetTaskRunningProbe(func(string) bool { return false })
	err := qqSender{}.Send(context.Background(), `{"openid":"o1"}`, Message{Title: "t"})
	if err == nil || !strings.Contains(err.Error(), "服务未运行") {
		t.Errorf("探针 false（任务停止）即使链接在线也应拒发, got %v", err)
	}
	qqLink.set(false, "")
	SetTaskRunningProbe(func(string) bool { return true })
	err = qqSender{}.Send(context.Background(), `{"openid":"o1"}`, Message{Title: "t"})
	if err != nil && strings.Contains(err.Error(), "服务未运行") {
		t.Errorf("探针 true（任务运行）不应以「服务未运行」拒发, got %v", err)
	}
}
