package notify

// QQ 多机器人入站会话回归（根因：入站只维护全局首 bot 的 WS，第二 bot 无
// 入站会话→客户端停留「连接中」）：①双 bot 各自独立 WS 会话/鉴权/在线态/
// 任务日志；②单 bot 断开不影响另一 bot，断线自动 Resume 重连；③入站绑定
// 钉住会话所属 bot 凭据；④清洁停止全部 bot 置离线；⑤单 bot 形态兼容
// （无参状态=首 bot）；⑥bot 枚举=全局+通道钉住按 appid 去重。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// qqWSMock mock QQ ws 事件网关：Hello→Identify/Resume→READY/RESUMED，
// 记录各 bot 的鉴权 token；支持注入 C2C 入站与单方断连。
type qqWSMock struct {
	mu       sync.Mutex
	identify map[string]string          // appid → 最近 Identify/Resume 的 token
	conns    map[string]*websocket.Conn // appid → 当前连接
	ready    chan string                // READY/RESUMED 已下发信号
	server   *httptest.Server
}

func setupQQWSMock(t *testing.T) *qqWSMock {
	t.Helper()
	m := &qqWSMock{
		identify: map[string]string{},
		conns:    map[string]*websocket.Conn{},
		ready:    make(chan string, 16),
	}
	up := websocket.Upgrader{}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]any{"op": 10, "d": map[string]any{"heartbeat_interval": 60000}})
		var frame struct {
			OP int `json:"op"`
			D  struct {
				Token string `json:"token"`
			} `json:"d"`
		}
		if err := conn.ReadJSON(&frame); err != nil {
			return
		}
		appid := strings.TrimPrefix(frame.D.Token, "QQBot token-")
		m.mu.Lock()
		m.identify[appid] = frame.D.Token
		m.conns[appid] = conn
		m.mu.Unlock()
		if frame.OP == 6 {
			_ = conn.WriteJSON(map[string]any{"op": 0, "s": 2, "t": "RESUMED", "d": map[string]any{}})
		} else {
			_ = conn.WriteJSON(map[string]any{"op": 0, "s": 1, "t": "READY", "d": map[string]any{"session_id": "sess-" + appid}})
		}
		m.ready <- appid
		for {
			var f struct {
				OP int `json:"op"`
			}
			if err := conn.ReadJSON(&f); err != nil {
				return
			}
			if f.OP == 1 {
				_ = conn.WriteJSON(map[string]any{"op": 11})
			}
		}
	}))
	old := qqWSGateway
	qqWSGateway = "ws" + strings.TrimPrefix(m.server.URL, "http") + "/websocket"
	t.Cleanup(func() {
		qqWSGateway = old
		m.server.Close()
	})
	return m
}

// waitReady 等待指定 bot 全部 READY/RESUMED（信号可乱序到达）。
func (m *qqWSMock) waitReady(t *testing.T, appids ...string) {
	t.Helper()
	pending := map[string]bool{}
	for _, id := range appids {
		pending[id] = true
	}
	deadline := time.After(5 * time.Second)
	for len(pending) > 0 {
		select {
		case got := <-m.ready:
			delete(pending, got)
		case <-deadline:
			t.Fatalf("bot %v 未在时限内 READY/RESUMED", pending)
		}
	}
}

func (m *qqWSMock) drop(appid string) {
	m.mu.Lock()
	conn := m.conns[appid]
	m.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (m *qqWSMock) sendC2C(appid, openid, content, msgID string) {
	m.mu.Lock()
	conn := m.conns[appid]
	m.mu.Unlock()
	if conn == nil {
		return
	}
	_ = conn.WriteJSON(map[string]any{"op": 0, "s": 3, "t": "C2C_MESSAGE_CREATE", "d": map[string]any{
		"content": content, "id": msgID, "author": map[string]any{"user_openid": openid},
	}})
}

// waitLinkConnected 轮询链接态收敛（会话建立/断开有毫秒级异步窗口）。
func waitLinkConnected(t *testing.T, get func() (bool, string, time.Time), want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, _, _ := get(); c == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	c, lastErr, _ := get()
	t.Fatalf("链接态未收敛: connected=%v want=%v lastErr=%s", c, want, lastErr)
}

// waitChannelTarget 轮询通道行落库（入站绑定异步处理）。
func waitChannelTarget(t *testing.T, typ, like string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var target string
		err := db.DB.QueryRow(`SELECT target FROM notification_channels WHERE type=? AND target LIKE ?`, typ, "%"+like+"%").Scan(&target)
		if err == nil {
			return target
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("通道行未落库: type=%s like=%s", typ, like)
	return ""
}

// 双 bot 入站：各自会话/鉴权/在线态/日志互不干扰；单 bot 断开另一 bot 不受
// 影响且自动重连；入站绑定钉住会话 bot；清洁停止全部离线。
func TestQQInboundMultiBotSessions(t *testing.T) {
	newNotifyConnectorDB(t)
	m := setupQQPlatformMock(t)
	ws := setupQQWSMock(t)
	seedQQGlobalCred(t, "APP_A", "SEC_A")
	// Given 第二 bot 经通道 target 钉住（全局仍是首 bot APP_A）
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target) VALUES (7, 'qq', 'botB', '{"openid":"oB","appid":"APP_B","secret":"SEC_B"}')`); err != nil {
		t.Fatalf("播种第二 bot 通道失败: %v", err)
	}
	logDir := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(logDir)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunQQBotConnection(ctx) }()

	// When 双 bot 各自建连
	ws.waitReady(t, "APP_A", "APP_B")
	// Then 各用所属凭据鉴权（互不顶掉）
	ws.mu.Lock()
	tokenA, tokenB := ws.identify["APP_A"], ws.identify["APP_B"]
	ws.mu.Unlock()
	if tokenA != "QQBot token-APP_A" || tokenB != "QQBot token-APP_B" {
		t.Errorf("入站鉴权 token: A=%q B=%q, want 各 bot 独立 token", tokenA, tokenB)
	}
	// Then per-bot 在线态独立；无参=首 bot（全局 APP_A）
	waitLinkConnected(t, func() (bool, string, time.Time) { return QQLinkStatusFor("APP_A") }, true)
	waitLinkConnected(t, func() (bool, string, time.Time) { return QQLinkStatusFor("APP_B") }, true)
	if c, _, _ := QQLinkStatus(); !c {
		t.Error("无参 QQLinkStatus 应为首 bot APP_A 在线")
	}
	// Then 任务日志 per-bot 可区分
	logRaw, err := os.ReadFile(filepath.Join(logDir, "qq-bot-connection.log"))
	if err != nil {
		t.Fatalf("任务日志未落盘: %v", err)
	}
	logText := string(logRaw)
	if !strings.Contains(logText, "bot=APP_A") || !strings.Contains(logText, "bot=APP_B") {
		t.Errorf("任务日志缺 per-bot 标识:\n%s", logText)
	}
	if !strings.Contains(logText, "READY") {
		t.Errorf("任务日志缺 READY 建连行:\n%s", logText)
	}

	// When 第二 bot 入站绑定指令
	if _, err := db.DB.Exec(`INSERT INTO qq_bind_codes (code, user_id, expires_at) VALUES ('CODE_B', 7, datetime('now', '+1 hour'))`); err != nil {
		t.Fatalf("播种绑定码失败: %v", err)
	}
	ws.sendC2C("APP_B", "oBind", "绑定 CODE_B", "MSG_B")
	// Then 通道 target 钉住会话所属 bot（APP_B），非全局首 bot
	target := waitChannelTarget(t, "qq", "oBind")
	var tm map[string]any
	if err := json.Unmarshal([]byte(target), &tm); err != nil {
		t.Fatalf("绑定 target 非 JSON: %v", err)
	}
	if tm["appid"] != "APP_B" || tm["secret"] != "SEC_B" || tm["openid"] != "oBind" {
		t.Errorf("入站绑定 target=%s, want 钉住会话 bot APP_B", target)
	}
	// Then 被动回执用会话 bot token
	m.mu.Lock()
	replyOK := false
	for _, a := range m.sentAuth {
		if a == "QQBot token-APP_B" {
			replyOK = true
		}
	}
	m.mu.Unlock()
	if !replyOK {
		t.Error("绑定回执未用会话 bot APP_B 的 token")
	}

	// When 第二 bot 单方断连
	ws.drop("APP_B")
	// Then 仅 APP_B 离线，APP_A 不受影响
	waitLinkConnected(t, func() (bool, string, time.Time) { return QQLinkStatusFor("APP_B") }, false)
	if c, _, _ := QQLinkStatusFor("APP_A"); !c {
		t.Error("APP_B 断连波及 APP_A 在线态")
	}
	// Then APP_B 退避后自动重连（Resume 续传），APP_A 始终在线
	ws.waitReady(t, "APP_B")
	waitLinkConnected(t, func() (bool, string, time.Time) { return QQLinkStatusFor("APP_B") }, true)
	if c, _, _ := QQLinkStatusFor("APP_A"); !c {
		t.Error("APP_B 重连后 APP_A 应仍在线")
	}

	// When 清洁停止
	cancel()
	// Then Run 同步收口返回，全部 bot 置离线（无假在线残留）
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("清洁停止 Run 应返回 nil, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("停止后 Run 未在时限内返回")
	}
	if c, _, _ := QQLinkStatus(); c {
		t.Error("停止后首 bot 应离线")
	}
	if c, _, _ := QQLinkStatusFor("APP_B"); c {
		t.Error("停止后第二 bot 应离线")
	}
}

// 单 bot 形态兼容：仅全局凭据时会话/在线态/日志与多 bot 口径一致，
// 无参状态=该 bot；未知 bot 查询离线。
func TestQQInboundSingleBotCompat(t *testing.T) {
	newNotifyConnectorDB(t)
	setupQQPlatformMock(t)
	ws := setupQQWSMock(t)
	seedQQGlobalCred(t, "APP_S", "SEC_S")
	logDir := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(logDir)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunQQBotConnection(ctx) }()

	ws.waitReady(t, "APP_S")
	waitLinkConnected(t, QQLinkStatus, true)
	if c, _, _ := QQLinkStatusFor("APP_S"); !c {
		t.Error("单 bot For(appid) 应与无参状态一致在线")
	}
	if c, _, _ := QQLinkStatusFor("APP_UNKNOWN"); c {
		t.Error("未知 bot 应离线")
	}
	logRaw, _ := os.ReadFile(filepath.Join(logDir, "qq-bot-connection.log"))
	if !strings.Contains(string(logRaw), "bot=APP_S") {
		t.Errorf("单 bot 日志缺 bot 标识:\n%s", logRaw)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("清洁停止 Run 应返回 nil, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("停止后 Run 未在时限内返回")
	}
	if c, _, _ := QQLinkStatus(); c {
		t.Error("停止后单 bot 应离线")
	}
}

// bot 枚举：全局首 bot + 通道钉住，按 appid 去重（全局优先）；缺凭据/坏
// JSON 的 target 跳过；无凭据源返回空。
func TestQQEnumerateBotsDistinct(t *testing.T) {
	newNotifyConnectorDB(t)
	if bots := qqEnumerateBots(); len(bots) != 0 {
		t.Fatalf("无凭据源应枚举空, got %+v", bots)
	}
	seedQQGlobalCred(t, "APP_A", "SEC_A")
	rows := []string{
		`{"openid":"o1","appid":"APP_B","secret":"SEC_B"}`,
		`{"openid":"o2","appid":"APP_A","secret":"SEC_OTHER"}`, // 同 appid 去重（全局优先）
		`{"openid":"o3","appid":"APP_C"}`,                      // 缺 secret 跳过
		`{bad`,                                                 // 坏 JSON 跳过
		`{"openid":"o4"}`,                                      // 无凭据跳过
	}
	for i, target := range rows {
		if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target) VALUES (7, 'qq', ?, ?)`, "ch"+string(rune('0'+i)), target); err != nil {
			t.Fatalf("播种通道失败: %v", err)
		}
	}
	bots := qqEnumerateBots()
	if len(bots) != 2 {
		t.Fatalf("枚举数=%d, want 2（APP_A 全局优先 + APP_B）: %+v", len(bots), bots)
	}
	if bots[0] != (qqBotCred{AppID: "APP_A", Secret: "SEC_A"}) || bots[1] != (qqBotCred{AppID: "APP_B", Secret: "SEC_B"}) {
		t.Errorf("枚举序/凭据=%+v, want [APP_A/SEC_A APP_B/SEC_B]（首 bot=全局）", bots)
	}
}

// drainNotifyEvents 非阻塞排空事件队列（测试直注 queue，不启分发循环）。
func drainNotifyEvents() []Event {
	var evts []Event
	for {
		select {
		case e := <-queue:
			evts = append(evts, e)
		default:
			return evts
		}
	}
}

// 计划内回收（凭据轮换/删通道）不得触发虚假「通知通道离线」告警：回收只
// 注销登记，不产生在线→离线沿；清洁停止仍对在线 bot 发一次掉线告警（自监控
// 闭环语义不变）。
func TestQQReclaimNoFalseChannelDown(t *testing.T) {
	newNotifyConnectorDB(t)
	setupQQPlatformMock(t)
	ws := setupQQWSMock(t)
	seedQQGlobalCred(t, "APP_A", "SEC_A")
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target) VALUES (7, 'qq', 'botB', '{"openid":"oB","appid":"APP_B","secret":"SEC_B"}')`); err != nil {
		t.Fatalf("播种第二 bot 通道失败: %v", err)
	}
	oldQueue := queue
	queue = make(chan Event, 64)
	t.Cleanup(func() { queue = oldQueue })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunQQBotConnection(ctx) }()
	ws.waitReady(t, "APP_A", "APP_B")
	waitLinkConnected(t, func() (bool, string, time.Time) { return QQLinkStatusFor("APP_A") }, true)
	waitLinkConnected(t, func() (bool, string, time.Time) { return QQLinkStatusFor("APP_B") }, true)
	drainNotifyEvents() // 建连期无离线沿，清空基线

	// When 凭据轮换：第二 bot 通道 target 改钉 APP_C（回收 APP_B + 新建 APP_C）
	if _, err := db.DB.Exec(`UPDATE notification_channels SET target='{"openid":"oB","appid":"APP_C","secret":"SEC_C"}' WHERE name='botB'`); err != nil {
		t.Fatalf("轮换通道凭据失败: %v", err)
	}
	ws.waitReady(t, "APP_C")
	waitLinkConnected(t, func() (bool, string, time.Time) { return QQLinkStatusFor("APP_C") }, true)
	// Then 回收 APP_B 无虚假掉线告警，首 bot 不受影响
	for _, e := range drainNotifyEvents() {
		if e.Type == EvtNotifyChannelDown {
			t.Errorf("凭据轮换回收触发虚假通道离线告警: %+v", e)
		}
	}
	if c, _, _ := QQLinkStatusFor("APP_A"); !c {
		t.Error("轮换第二 bot 波及首 bot 在线态")
	}

	// When 删除第二 bot 最后一条通道（回收 APP_C）
	if _, err := db.DB.Exec(`DELETE FROM notification_channels WHERE name='botB'`); err != nil {
		t.Fatalf("删除通道失败: %v", err)
	}
	waitLinkConnected(t, func() (bool, string, time.Time) { return QQLinkStatusFor("APP_C") }, false)
	// Then 回收无告警
	for _, e := range drainNotifyEvents() {
		if e.Type == EvtNotifyChannelDown {
			t.Errorf("删通道回收触发虚假通道离线告警: %+v", e)
		}
	}

	// When 清洁停止
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("清洁停止 Run 应返回 nil, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("停止后 Run 未在时限内返回")
	}
	// Then 停止语义保留：在线首 bot 一次掉线告警
	downs := 0
	for _, e := range drainNotifyEvents() {
		if e.Type == EvtNotifyChannelDown {
			downs++
		}
	}
	if downs != 1 {
		t.Errorf("清洁停止应对在线首 bot 发一次掉线告警, got %d", downs)
	}
}

// pinned-only 形态（全局凭据未配置，仅通道 target 带凭据——API 手工建通道
// 可达）：supervisor 枚举到钉住 bot 即启动入站会话，无参状态=该首 bot。
func TestQQInboundPinnedOnlyBot(t *testing.T) {
	newNotifyConnectorDB(t)
	setupQQPlatformMock(t)
	ws := setupQQWSMock(t)
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target) VALUES (7, 'qq', 'pinned', '{"openid":"oP","appid":"APP_P","secret":"SEC_P"}')`); err != nil {
		t.Fatalf("播种钉住通道失败: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunQQBotConnection(ctx) }()
	ws.waitReady(t, "APP_P")
	waitLinkConnected(t, QQLinkStatus, true)
	if c, _, _ := QQLinkStatusFor("APP_P"); !c {
		t.Error("pinned-only bot 应在线")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("清洁停止 Run 应返回 nil, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("停止后 Run 未在时限内返回")
	}
	if c, _, _ := QQLinkStatus(); c {
		t.Error("停止后 pinned-only bot 应离线")
	}
}

// 停机聚合回归（用户实测：重启时每机器人通道收 2 次「连接任务已停止」）：
// 2 个在线 bot 清洁停止只发布**一次**通道离线事件（而非每 bot 一次），
// 避免 N 在线 bot × N 订阅通道=每通道收 N 次。
func TestQQStopAggregatesSingleChannelDown(t *testing.T) {
	newNotifyConnectorDB(t)
	setupQQPlatformMock(t)
	ws := setupQQWSMock(t)
	seedQQGlobalCred(t, "APP_A", "SEC_A")
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target) VALUES (7, 'qq', 'botB', '{"openid":"oB","appid":"APP_B","secret":"SEC_B"}')`); err != nil {
		t.Fatalf("播种第二 bot 通道失败: %v", err)
	}
	oldQueue := queue
	queue = make(chan Event, 64)
	t.Cleanup(func() { queue = oldQueue })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunQQBotConnection(ctx) }()
	ws.waitReady(t, "APP_A", "APP_B")
	waitLinkConnected(t, func() (bool, string, time.Time) { return QQLinkStatusFor("APP_A") }, true)
	waitLinkConnected(t, func() (bool, string, time.Time) { return QQLinkStatusFor("APP_B") }, true)
	drainNotifyEvents() // 建连期基线清空

	cancel() // 两 bot 均在线时清洁停止
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("清洁停止 Run 应返回 nil, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("停止后 Run 未在时限内返回")
	}
	downs := 0
	for _, e := range drainNotifyEvents() {
		if e.Type == EvtNotifyChannelDown {
			downs++
		}
	}
	if downs != 1 {
		t.Errorf("2 在线 bot 停机应聚合为一次通道离线告警, got %d", downs)
	}
}
