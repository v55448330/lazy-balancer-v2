package notify

// 微信多机器人入站会话回归（对称 QQ 根因 + 现网 session timeout 重连循环）：
// ①双 bot 各自独立长轮询会话（游标/context_token per-bot 隔离）/在线态/日志；
// ②单 bot 登录态过期（-14）仅该 bot 终止，另一 bot 不受影响；③二登不重置
// 首 bot 会话，新凭据钉通道后第二 bot 入站自动上线；④清洁停止全部离线；
// ⑤bot 枚举=全局+通道钉住按 account_id/token 去重。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// wxPollMock mock iLink getupdates 长轮询：首批返回游标（+可选入站消息），
// 后续请求挂起（模拟服务端 ~35s 挂起）；记录各 token 的游标序列；支持
// 单方注入 -14 过期与唤醒挂起请求。sendmessage 记录出站 Authorization。
type wxPollMock struct {
	mu     sync.Mutex
	bufs   map[string][]string      // token → get_updates_buf 请求序列
	msgs   map[string]string        // token → 待交付入站消息 JSON（一次性）
	expire map[string]bool          // token → 下一轮返回 -14
	pokes  map[string]chan struct{} // token → 唤醒挂起长轮询（缓冲 1）
	auths  []string                 // sendmessage Authorization 序列
	server *httptest.Server
}

func setupWxPollMock(t *testing.T) *wxPollMock {
	t.Helper()
	m := &wxPollMock{
		bufs:   map[string][]string{},
		msgs:   map[string]string{},
		expire: map[string]bool{},
		pokes:  map[string]chan struct{}{},
	}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ilink/bot/getupdates":
			var body struct {
				Buf string `json:"get_updates_buf"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			m.mu.Lock()
			m.bufs[token] = append(m.bufs[token], body.Buf)
			n := len(m.bufs[token])
			msgs := m.msgs[token]
			delete(m.msgs, token)
			expire := m.expire[token]
			poke := m.pokes[token]
			if poke == nil {
				poke = make(chan struct{}, 1)
				m.pokes[token] = poke
			}
			m.mu.Unlock()
			if expire {
				_, _ = w.Write([]byte(`{"ret":-14,"errmsg":"session timeout"}`))
				return
			}
			resp := map[string]any{"ret": 0}
			if n == 1 {
				resp["get_updates_buf"] = "cursor-" + token
			}
			if msgs != "" {
				resp["msgs"] = json.RawMessage(msgs)
			}
			if n == 1 || msgs != "" {
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
			// 长轮询挂起：请求 ctx 取消（任务停止）或测试唤醒才返回。
			select {
			case <-r.Context().Done():
			case <-poke:
			}
			_, _ = w.Write([]byte(`{"ret":0}`))
		case "/ilink/bot/sendmessage":
			m.mu.Lock()
			m.auths = append(m.auths, r.Header.Get("Authorization"))
			m.mu.Unlock()
			_, _ = w.Write([]byte(`{"ret":0}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *wxPollMock) poke(token string) {
	m.mu.Lock()
	poke := m.pokes[token]
	m.mu.Unlock()
	if poke != nil {
		select {
		case poke <- struct{}{}:
		default:
		}
	}
}

func (m *wxPollMock) setMsgs(token, msgsJSON string) {
	m.mu.Lock()
	m.msgs[token] = msgsJSON
	m.mu.Unlock()
}

func (m *wxPollMock) setExpire(token string) {
	m.mu.Lock()
	m.expire[token] = true
	m.mu.Unlock()
}

// waitPollBufs 等待指定 token 的游标请求序列达到 n 条。
func (m *wxPollMock) waitPollBufs(t *testing.T, token string, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		bufs := append([]string(nil), m.bufs[token]...)
		m.mu.Unlock()
		if len(bufs) >= n {
			return bufs
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("token=%s 长轮询请求数未达 %d", token, n)
	return nil
}

func seedWxCred(t *testing.T, cred wxBotCred) {
	t.Helper()
	raw, _ := json.Marshal(cred)
	if err := SetSettings(map[string]string{KeyWxBotCred: string(raw)}); err != nil {
		t.Fatalf("写入全局登录态失败: %v", err)
	}
	t.Cleanup(func() { _ = SetSettings(map[string]string{KeyWxBotCred: ""}) })
}

// 双 bot 入站：各自长轮询会话/游标/context_token/在线态/日志隔离；第二 bot
// 登录态过期仅自身终止；清洁停止全部离线。
func TestWxInboundMultiBotSessions(t *testing.T) {
	newNotifyConnectorDB(t)
	clearBindSessions()
	t.Cleanup(clearBindSessions)
	m := setupWxPollMock(t)
	seedWxCred(t, wxBotCred{Token: "T1", BaseURL: m.server.URL, AccountID: "B1", UserID: "U1"})
	// Given 第二 bot 经通道 target 钉住
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target) VALUES (7, 'wx_clawbot', 'botB', '{"receiver":"rB","token":"T2","baseurl":"` + m.server.URL + `","account_id":"B2","user_id":"U2"}')`); err != nil {
		t.Fatalf("播种第二 bot 通道失败: %v", err)
	}
	logDir := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(logDir)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunWxBotConnection(ctx) }()

	// When 双 bot 各自建立长轮询
	waitLinkConnected(t, func() (bool, string, time.Time) { return WxLinkStatusFor("B1") }, true)
	waitLinkConnected(t, func() (bool, string, time.Time) { return WxLinkStatusFor("B2") }, true)
	if c, _, _ := WxLinkStatus(); !c {
		t.Error("无参 WxLinkStatus 应为首 bot B1 在线")
	}
	// Then 游标 per-bot 隔离：各 bot 后续请求携带自己的游标
	bufs1 := m.waitPollBufs(t, "T1", 2)
	bufs2 := m.waitPollBufs(t, "T2", 2)
	if bufs1[0] != "" || bufs1[1] != "cursor-T1" {
		t.Errorf("首 bot 游标序列=%v, want [空 cursor-T1]", bufs1)
	}
	if bufs2[0] != "" || bufs2[1] != "cursor-T2" {
		t.Errorf("第二 bot 游标序列=%v, want [空 cursor-T2]（不得共用首 bot 游标）", bufs2)
	}
	// Then 任务日志 per-bot 可区分
	logRaw, err := os.ReadFile(filepath.Join(logDir, "wx-bot-connection.log"))
	if err != nil {
		t.Fatalf("任务日志未落盘: %v", err)
	}
	logText := string(logRaw)
	if !strings.Contains(logText, "bot=B1") || !strings.Contains(logText, "bot=B2") {
		t.Errorf("任务日志缺 per-bot 标识:\n%s", logText)
	}
	if !strings.Contains(logText, "长轮询建立") {
		t.Errorf("任务日志缺长轮询建立行:\n%s", logText)
	}

	// When 第二 bot 入站「绑定测试」（弹框已注册会话；context_token 随会话隔离缓存）
	StartBindSession(7, "wx_clawbot", "wxU", "B2")
	m.setMsgs("T2", `[{"from_user_id":"wxU","context_token":"ctx-B2","item_list":[{"type":1,"text_item":{"text":"绑定测试"}}]}]`)
	m.poke("T2")
	// Then 会话确认且 receiver=扫码者；入站不建通道（建通道交弹框保存）
	if receiver := waitBindConfirmed(t, 7, "wx_clawbot", "wxU", "B2"); receiver != "wxU" {
		t.Errorf("绑定会话 receiver=%q, want wxU", receiver)
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_channels WHERE target LIKE '%wxU%'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("入站绑定测试不应建通道: n=%d err=%v", n, err)
	}
	// Then context_token 按 bot 隔离：B2 命名空间有，B1 命名空间不受影响
	if got := wxContextTokenFor("B2", "wxU"); got != "ctx-B2" {
		t.Errorf("B2 context_token=%q, want ctx-B2", got)
	}
	if got := wxContextTokenFor("B1", "wxU"); got != "" {
		t.Errorf("B1 命名空间被第二 bot 入站污染: %q", got)
	}
	// Then 会话捕获 context_token（保存路径凭据钉住后出站用）
	bindSessionMu.Lock()
	ctxTok := bindSessions[bindSessionKey("wx_clawbot", "wxU", "B2")].ContextToken
	bindSessionMu.Unlock()
	if ctxTok != "ctx-B2" {
		t.Errorf("会话 context_token=%q, want ctx-B2", ctxTok)
	}
	// Then 被动回执用会话 bot token（异步送达）
	deadline := time.Now().Add(5 * time.Second)
	replyOK := false
	for time.Now().Before(deadline) && !replyOK {
		m.mu.Lock()
		for _, a := range m.auths {
			if a == "Bearer T2" {
				replyOK = true
			}
		}
		m.mu.Unlock()
		if !replyOK {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !replyOK {
		t.Fatal("绑定回执未用会话 bot T2 的 token")
	}
	// Then 幂等：重复「绑定测试」不重复回执
	m.setMsgs("T2", `[{"from_user_id":"wxU","context_token":"ctx-B2","item_list":[{"type":1,"text_item":{"text":"绑定测试"}}]}]`)
	m.poke("T2")
	time.Sleep(300 * time.Millisecond)
	m.mu.Lock()
	nReply := len(m.auths)
	m.mu.Unlock()
	if nReply != 1 {
		t.Errorf("重复绑定测试回执数=%d, want 1（幂等）", nReply)
	}

	// When 第二 bot 登录态过期（-14 session timeout）
	m.setExpire("T2")
	m.poke("T2")
	// Then 仅 B2 离线（fail-loud 留痕），B1 长轮询不受影响，Run 不终止
	waitLinkConnected(t, func() (bool, string, time.Time) { return WxLinkStatusFor("B2") }, false)
	if _, lastErr, _ := WxLinkStatusFor("B2"); !strings.Contains(lastErr, "过期") {
		t.Errorf("B2 离线原因应含「过期」, got %q", lastErr)
	}
	if c, _, _ := WxLinkStatusFor("B1"); !c {
		t.Error("B2 登录态过期波及 B1 在线态")
	}
	select {
	case err := <-done:
		t.Fatalf("单 bot 过期不应终止连接任务, got %v", err)
	default:
	}

	// When 清洁停止
	cancel()
	// Then Run 同步收口返回，全部 bot 置离线
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("清洁停止 Run 应返回 nil, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("停止后 Run 未在时限内返回")
	}
	if c, _, _ := WxLinkStatus(); c {
		t.Error("停止后首 bot 应离线")
	}
	if c, lastErr, _ := WxLinkStatusFor("B2"); c {
		t.Error("停止后第二 bot 应离线")
	} else if !strings.Contains(lastErr, "过期") {
		t.Errorf("停止后 fatal bot 应保留「登录态过期」排障原因, got %q", lastErr)
	}
}

// 二登端到端：首 bot 会话在运行时第二次扫码登录不重置首 bot（全局/游标/
// 在线态不变）；新凭据经 WxPinChannelTarget 钉通道后第二 bot 入站自动上线。
func TestWxInboundSecondLoginOnboardsBot(t *testing.T) {
	newNotifyConnectorDB(t)
	m := setupWxPollMock(t)
	seedWxCred(t, wxBotCred{Token: "T1", BaseURL: m.server.URL, AccountID: "B1", UserID: "U1"})
	// 扫码端点 mock（二登 confirmed 下发 T2/B2）
	qrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ilink/bot/get_bot_qrcode":
			_, _ = w.Write([]byte(`{"qrcode":"QR1","qrcode_img_content":"img"}`))
		case "/ilink/bot/get_qrcode_status":
			_, _ = w.Write([]byte(`{"status":"confirmed","bot_token":"T2","ilink_bot_id":"B2","ilink_user_id":"U2","baseurl":"` + m.server.URL + `"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	oldCode, oldStatus := wxQRCodeURL, wxQRStatusURL
	wxQRCodeURL, wxQRStatusURL = qrSrv.URL+"/ilink/bot/get_bot_qrcode", qrSrv.URL+"/ilink/bot/get_qrcode_status"
	t.Cleanup(func() {
		wxQRCodeURL, wxQRStatusURL = oldCode, oldStatus
		qrSrv.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunWxBotConnection(ctx) }()
	waitLinkConnected(t, func() (bool, string, time.Time) { return WxLinkStatusFor("B1") }, true)
	m.waitPollBufs(t, "T1", 2)

	// When 首 bot 在线时第二次扫码登录
	if _, err := WxQRLoginStart(ctx); err != nil {
		t.Fatalf("二登产码失败: %v", err)
	}
	if _, confirmed, err := WxQRLoginPoll(ctx); err != nil || !confirmed {
		t.Fatalf("二登未确认: confirmed=%v err=%v", confirmed, err)
	}
	// Then 首 bot 会话态不被重置：全局仍 T1、游标不变、在线态不变
	if cred, ok := loadWxBotCred(); !ok || cred.Token != "T1" {
		t.Errorf("二登覆盖全局: %+v ok=%v, want T1", cred, ok)
	}
	wxCtxMu.Lock()
	cursor := wxUpdatesBufs["B1"]
	wxCtxMu.Unlock()
	if cursor != "cursor-T1" {
		t.Errorf("二登重置首 bot 游标: %q, want cursor-T1", cursor)
	}
	if c, _, _ := WxLinkStatusFor("B1"); !c {
		t.Error("二登致首 bot 掉线")
	}

	// When 新凭据钉入通道 target 并保存（WxPinChannelTarget 唤醒连接任务）
	pinned := WxPinChannelTarget(`{"receiver":"rB"}`)
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target) VALUES (7, 'wx_clawbot', 'botB', ?)`, pinned); err != nil {
		t.Fatalf("保存第二 bot 通道失败: %v", err)
	}
	// Then 第二 bot 入站会话自动上线（首批 getupdates 成功后置在线），首 bot 不受影响
	m.waitPollBufs(t, "T2", 1)
	waitLinkConnected(t, func() (bool, string, time.Time) { return WxLinkStatusFor("B2") }, true)
	if c, _, _ := WxLinkStatusFor("B1"); !c {
		t.Error("第二 bot 上线波及首 bot")
	}
	bufs2 := m.waitPollBufs(t, "T2", 2)
	if bufs2[1] != "cursor-T2" {
		t.Errorf("第二 bot 游标=%v, want 独立 cursor-T2", bufs2)
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
	if c, _, _ := WxLinkStatus(); c {
		t.Error("停止后首 bot 应离线")
	}
	if c, _, _ := WxLinkStatusFor("B2"); c {
		t.Error("停止后第二 bot 应离线")
	}
}

// bot 枚举：全局首 bot + 通道钉住，按 account_id 去重（缺 account_id 按
// token）；缺 token/坏 JSON 的 target 跳过；无凭据源返回空。
func TestWxEnumerateBotsDistinct(t *testing.T) {
	newNotifyConnectorDB(t)
	if bots := wxEnumerateBots(); len(bots) != 0 {
		t.Fatalf("无凭据源应枚举空, got %+v", bots)
	}
	seedWxCred(t, wxBotCred{Token: "T1", BaseURL: "http://b1", AccountID: "B1", UserID: "U1"})
	rows := []string{
		`{"receiver":"r1","token":"T2","baseurl":"http://b2","account_id":"B2","user_id":"U2"}`,
		`{"receiver":"r2","token":"T1-dup","baseurl":"http://b1","account_id":"B1","user_id":"U1"}`, // 同 account 去重（全局优先）
		`{"receiver":"r3","token":"T3"}`,      // 缺 account_id 按 token 键
		`{"receiver":"r4","account_id":"B4"}`, // 缺 token 跳过
		`{bad`,                                // 坏 JSON 跳过
	}
	for i, target := range rows {
		if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target) VALUES (7, 'wx_clawbot', ?, ?)`, fmt.Sprintf("ch%d", i), target); err != nil {
			t.Fatalf("播种通道失败: %v", err)
		}
	}
	bots := wxEnumerateBots()
	if len(bots) != 3 {
		t.Fatalf("枚举数=%d, want 3（B1 全局优先 + B2 + T3）: %+v", len(bots), bots)
	}
	if wxCredKey(bots[0]) != "B1" || bots[0].Token != "T1" {
		t.Errorf("首 bot=%+v, want 全局 B1/T1", bots[0])
	}
	if wxCredKey(bots[1]) != "B2" || wxCredKey(bots[2]) != "T3" {
		t.Errorf("枚举键序=%+v, want [B1 B2 T3]", bots)
	}
}

// 计划内回收无虚假告警；真实登录过期仍告警一次；fatal bot 凭据变更后重建
// 上线（恢复路径）；清洁停止对在线首 bot 告警一次。
func TestWxReclaimNoFalseChannelDown(t *testing.T) {
	newNotifyConnectorDB(t)
	m := setupWxPollMock(t)
	seedWxCred(t, wxBotCred{Token: "T1", BaseURL: m.server.URL, AccountID: "B1", UserID: "U1"})
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target) VALUES (7, 'wx_clawbot', 'botB', '{"receiver":"rB","token":"T2","baseurl":"` + m.server.URL + `","account_id":"B2","user_id":"U2"}')`); err != nil {
		t.Fatalf("播种第二 bot 通道失败: %v", err)
	}
	oldQueue := queue
	queue = make(chan Event, 64)
	t.Cleanup(func() { queue = oldQueue })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunWxBotConnection(ctx) }()
	waitLinkConnected(t, func() (bool, string, time.Time) { return WxLinkStatusFor("B1") }, true)
	waitLinkConnected(t, func() (bool, string, time.Time) { return WxLinkStatusFor("B2") }, true)
	drainNotifyEvents()

	// When 第二 bot 登录态过期（真实掉线）
	m.setExpire("T2")
	m.poke("T2")
	waitLinkConnected(t, func() (bool, string, time.Time) { return WxLinkStatusFor("B2") }, false)
	// Then 真实过期发一次掉线告警（自监控闭环保留）
	downs := 0
	for _, e := range drainNotifyEvents() {
		if e.Type == EvtNotifyChannelDown {
			downs++
		}
	}
	if downs != 1 {
		t.Errorf("真实登录过期应发一次掉线告警, got %d", downs)
	}

	// When 重新扫码后通道钉入新 token（同 account_id，凭据变更重建 fatal bot）
	if _, err := db.DB.Exec(`UPDATE notification_channels SET target='{"receiver":"rB","token":"T3","baseurl":"` + m.server.URL + `","account_id":"B2","user_id":"U2"}' WHERE name='botB'`); err != nil {
		t.Fatalf("更新通道凭据失败: %v", err)
	}
	waitLinkConnected(t, func() (bool, string, time.Time) { return WxLinkStatusFor("B2") }, true)
	bufs3 := m.waitPollBufs(t, "T3", 2)
	if bufs3[1] != "cursor-T3" {
		t.Errorf("重建 bot 游标=%v, want 独立 cursor-T3", bufs3)
	}
	// Then 重建无新增告警，首 bot 不受影响
	for _, e := range drainNotifyEvents() {
		if e.Type == EvtNotifyChannelDown {
			t.Errorf("fatal 重建触发虚假通道离线告警: %+v", e)
		}
	}
	if c, _, _ := WxLinkStatusFor("B1"); !c {
		t.Error("第二 bot 重建波及首 bot 在线态")
	}

	// When 删除第二 bot 最后一条通道（回收在线 worker）
	if _, err := db.DB.Exec(`DELETE FROM notification_channels WHERE name='botB'`); err != nil {
		t.Fatalf("删除通道失败: %v", err)
	}
	waitLinkConnected(t, func() (bool, string, time.Time) { return WxLinkStatusFor("B2") }, false)
	// Then 计划内回收无虚假告警
	for _, e := range drainNotifyEvents() {
		if e.Type == EvtNotifyChannelDown {
			t.Errorf("删通道回收触发虚假通道离线告警: %+v", e)
		}
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
	// Then 停止时在线首 bot 一次掉线告警
	downs = 0
	for _, e := range drainNotifyEvents() {
		if e.Type == EvtNotifyChannelDown {
			downs++
		}
	}
	if downs != 1 {
		t.Errorf("清洁停止应对在线首 bot 发一次掉线告警, got %d", downs)
	}
}

// pinned-only 形态（全局登录态未配置，仅通道 target 带凭据）：supervisor
// 枚举到钉住 bot 即启动长轮询，无参状态=该首 bot。
func TestWxInboundPinnedOnlyBot(t *testing.T) {
	newNotifyConnectorDB(t)
	m := setupWxPollMock(t)
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target) VALUES (7, 'wx_clawbot', 'pinned', '{"receiver":"rP","token":"TP","baseurl":"` + m.server.URL + `","account_id":"BP","user_id":"UP"}')`); err != nil {
		t.Fatalf("播种钉住通道失败: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunWxBotConnection(ctx) }()
	waitLinkConnected(t, WxLinkStatus, true)
	if c, _, _ := WxLinkStatusFor("BP"); !c {
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
	if c, _, _ := WxLinkStatus(); c {
		t.Error("停止后 pinned-only bot 应离线")
	}
}
