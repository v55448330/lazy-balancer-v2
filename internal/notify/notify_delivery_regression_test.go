package notify

// （回归） 通知域回归：日报默认配置与调度一致、7 参测试样例、目录分组/离线文案、
// 挑战原因标签归一、阈值下限、显式空选不落 pending、wx 会话/pin/二维码生命周期。

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// ---- （回归）：无 notification_daily 行=默认启用，调度必须覆盖 ----

func TestDailyDefaultConfigWithoutRowIsScheduled(t *testing.T) {
	newDailyTestDBs(t)
	mustExec(t, db.DB, `INSERT INTO users (id, username) VALUES (42, 'default-user')`)

	times, err := AllDailySendTimes()
	if err != nil {
		t.Fatalf("AllDailySendTimes: %v", err)
	}
	if len(times) != 1 || times[0] != "09:00" {
		t.Fatalf("无配置行用户的默认 09:00 槽缺失：%v（GET 显示启用而调度排除=永不发送）", times)
	}

	old := dailyDataCollector
	dailyDataCollector = func(context.Context, time.Time) (DailyData, error) {
		return DailyData{Date: "2026-11-22", Requests: 1}, nil
	}
	t.Cleanup(func() { dailyDataCollector = old })

	n, err := DeliverDailyForAll(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("DeliverDailyForAll: %v", err)
	}
	if n != 1 || dailyRows(t, 42) != 1 {
		t.Fatalf("默认启用用户未投递：rendered=%d rows=%d（want 1/1）", n, dailyRows(t, 42))
	}
}

// ---- （回归）：日报模板模式未显式 body_format 时按 HTML 发送，值必须转义 ----

func TestDailyEmailTemplateWithoutBodyFormatEscapesValues(t *testing.T) {
	newNotifySettingsDB(t)
	srv := newFakeSMTPServer(t)
	host, port, _ := net.SplitHostPort(srv.addr())
	if err := SetSettings(map[string]string{KeySMTPHost: host, KeySMTPPort: port, KeySMTPFrom: "lb@example.com"}); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"date": "2026-11-22", "items": []string{"top_paths"},
		"values":  map[string]string{"top_paths": "<img src=x onerror=alert(1)>"},
		"formats": map[string]string{},
	})
	msg := Message{EventType: EvtDailyReport, Level: "info", Title: "每日日报", Body: string(payload), ContentFormat: "html"}
	msg.Fields = DailyFieldsFromBody(msg.Body)
	// body_format 未设置：emailHTMLBody 仍按 ContentFormat=html 发 text/html，
	// 正文渲染必须同口径走 HTML 转义。
	target := `{"email":"ops@example.com","body_template":"<p>{{top_paths}}</p>"}`
	if err := sendToChannel(context.Background(), "email", target, msg); err != nil {
		t.Fatalf("sendToChannel: %v", err)
	}
	_, _, raw := srv.capture()
	body := decodeMailBody(t, raw)
	if strings.Contains(body, "<img src=x") || !strings.Contains(body, "&lt;img") {
		t.Fatalf("日报 HTML 上下文占位符未转义：%q", body)
	}
}

// ---- （回归）：7 参聚合事件测试样例不得 %!s(MISSING) ----

func TestEnqueueTestDeliverySevenArgSample(t *testing.T) {
	database := newNotifyTestDB(t)
	if _, err := database.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled)
		VALUES (301, 7, 'webhook', 'sample', '{"url":"http://127.0.0.1:1"}', 1)`); err != nil {
		t.Fatal(err)
	}
	if err := EnqueueTestDelivery(7, EvtBlockedAggregate); err != nil {
		t.Fatalf("EnqueueTestDelivery: %v", err)
	}
	var title, body string
	if err := database.QueryRow(`SELECT title, body FROM notification_deliveries WHERE user_id=7 AND event_type=?`, EvtBlockedAggregate).Scan(&title, &body); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(title, "%!s(MISSING)") || strings.Contains(body, "%!s(MISSING)") {
		t.Fatalf("7 参聚合事件样例缺参：title=%q body=%q", title, body)
	}
	if !strings.Contains(body, "TOP 路径：") {
		t.Fatalf("7 参样例第 7 位（TOP 路径）未渲染：%q", body)
	}
}

// ---- （回归）/（回归）：caddy 生命周期归「系统」；离线文案不再承诺暂存重投 ----

func TestCatalogCaddyLifecycleGroupAndOfflineWording(t *testing.T) {
	group := ""
	for _, e := range CatalogExport() {
		if e.ID == EvtCaddyLifecycle {
			group = e.Group
		}
	}
	if group != "系统" {
		t.Fatalf("cfg.caddy_lifecycle 分组=%q，want 系统（cfg. 前缀分支不得抢先）", group)
	}
	entry, ok := catalogByID(EvtNotifyChannelDown)
	if !ok {
		t.Fatal("目录缺少 notify.channel_down")
	}
	if strings.Contains(entry.BodyFormat, "暂存") || strings.Contains(catalogDescription(EvtNotifyChannelDown), "暂存") {
		t.Fatalf("离线文案仍承诺暂存重投：body=%q desc=%q", entry.BodyFormat, catalogDescription(EvtNotifyChannelDown))
	}
}

// ---- （回归）：挑战 TOP 原因机器 ID 归一为展示标签 ----

func TestChallengeReasonLabelsNormalized(t *testing.T) {
	resetBlockedStateForTest(t)
	t.Cleanup(func() { resetBlockedStateForTest(t) })
	RecordChallengeEvent("cc_rps_spike", "203.0.113.9")
	RecordChallengeEvent("突刺", "203.0.113.9")
	RecordChallengeEvent("911100", "203.0.113.9")
	challengeMu.Lock()
	reasons := map[string]int{}
	for k, v := range challengeCurrent.topReason {
		reasons[k] = v
	}
	challengeMu.Unlock()
	if _, ok := reasons["cc_rps_spike"]; ok {
		t.Fatalf("机器 ID cc_rps_spike 未归一：%v", reasons)
	}
	if reasons["突刺"] != 2 {
		t.Fatalf("机器 ID 与展示名未合并同一标签：%v", reasons)
	}
	if reasons["规则 911100"] != 1 {
		t.Fatalf("数字规则 ID 未加可读标签：%v", reasons)
	}
}

// ---- （回归）：warn 阈值不得低于 info 起点造成级别倒序 ----

func TestBlockedWarnThresholdNotBelowInfo(t *testing.T) {
	newNotifySettingsDB(t)
	if err := SetSettings(map[string]string{
		KeyAttackWarnAt: "5", KeyAttackCriticalAt: "20",
	}); err != nil {
		t.Fatal(err)
	}
	warnAt, criticalAt := BlockedThresholds()
	if warnAt < MinBlockedWarnAt {
		t.Fatalf("warn 阈值=%d < info 起点 %d（窗口会先 warn 后 info）", warnAt, MinBlockedWarnAt)
	}
	if criticalAt <= warnAt {
		t.Fatalf("critical=%d 不高于 warn=%d", criticalAt, warnAt)
	}
}

// ---- （回归）：显式空选不得落 pending→dead 稀释成功率 ----

func TestDispatchExplicitEmptySelectionDoesNotCreateDelivery(t *testing.T) {
	database := newNotifyTestDB(t)
	if _, err := database.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled)
		VALUES (401, 7, 'webhook', 'ok', '{"url":"http://127.0.0.1:1"}', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, channel_ids)
		VALUES (7, 'cert.failed', 'info', '[]')`); err != nil {
		t.Fatal(err)
	}
	dispatch(Event{Type: EvtCertFailed, Level: LevelCritical, Fields: map[string]string{"1": "a.example", "2": "x"}})
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE user_id=7`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("显式空选仍落 %d 条 pending（后续立即 dead 稀释成功率）", n)
	}
}

// ---- 附录 P3：wx 会话上下文清理同步内存；遗留无时间戳不算就绪 ----

func TestPruneWxContextTokensClearsMemory(t *testing.T) {
	newNotifyConnectorDB(t)
	t.Cleanup(clearWxContextMemory)
	if _, err := db.DB.Exec(`INSERT INTO notify_settings (key, value) VALUES (?, ?)`,
		wxContextKey("BOT_X", "u-old"), "token-old\x1f1"); err != nil {
		t.Fatal(err)
	}
	wxCtxMu.Lock()
	wxContextTokens["BOT_X"] = map[string]string{"u-old": "token-old"}
	wxCtxMu.Unlock()
	if _, err := PruneWxContextTokens(time.Hour); err != nil {
		t.Fatal(err)
	}
	wxCtxMu.Lock()
	_, still := wxContextTokens["BOT_X"]["u-old"]
	wxCtxMu.Unlock()
	if still {
		t.Fatal("PruneWxContextTokens 删除 DB 行后内存 token 仍残留（就绪判定反转）")
	}
}

func TestWxSessionReadyLegacyTokenWithoutTTLIsNotReady(t *testing.T) {
	newNotifyConnectorDB(t)
	t.Cleanup(clearWxContextMemory)
	if _, err := db.DB.Exec(`INSERT INTO notify_settings (key, value) VALUES (?, ?)`,
		wxContextKey("BOT_Y", "u-legacy"), "legacy-token"); err != nil {
		t.Fatal(err)
	}
	target := `{"receiver":"u-legacy","account_id":"BOT_Y","token":"T"}`
	if WxSessionReady(target) {
		t.Fatal("无时间戳的遗留上下文被判定就绪（TTL 无法生效）")
	}
}

// ---- 附录 P3：wxConfirmedPin 有 TTL；PruneBindSessions 同步清理 ----

func TestWxConfirmedPinExpiresWithBindSession(t *testing.T) {
	newNotifyConnectorDB(t)
	clearBindSessions()
	t.Cleanup(func() {
		clearBindSessions()
		wxCtxMu.Lock()
		wxConfirmedPin, wxConfirmedPinAt = nil, time.Time{}
		wxCtxMu.Unlock()
	})
	StartBindSessionWithCred(7, "wx_clawbot", "scanner", "BOT_PIN", "")
	wxCtxMu.Lock()
	wxConfirmedPin = &wxBotCred{Token: "T", AccountID: "BOT_PIN", UserID: "scanner"}
	wxConfirmedPinAt = time.Now().Add(-2 * wxConfirmedPinTTL)
	wxCtxMu.Unlock()
	if WxQRLoginActive() {
		t.Fatal("测试前置：不应有进行中二维码")
	}
	found := false
	for _, b := range wxEnumerateBots() {
		if wxCredKey(b) == "BOT_PIN" {
			found = true
		}
	}
	if found {
		t.Fatal("过期 pin 仍被枚举（幽灵 bot 建连）")
	}
}

func TestPruneBindSessionsClearsWxPin(t *testing.T) {
	newNotifyConnectorDB(t)
	clearBindSessions()
	t.Cleanup(func() {
		clearBindSessions()
		wxCtxMu.Lock()
		wxConfirmedPin, wxConfirmedPinAt = nil, time.Time{}
		wxCtxMu.Unlock()
	})
	StartBindSessionWithCred(7, "wx_clawbot", "scanner", "BOT_EXPIRE", "")
	wxCtxMu.Lock()
	wxConfirmedPin = &wxBotCred{Token: "T", AccountID: "BOT_EXPIRE", UserID: "scanner"}
	wxConfirmedPinAt = time.Now()
	wxCtxMu.Unlock()
	bindSessionMu.Lock()
	for _, s := range bindSessions {
		s.UpdatedAt = time.Now().Add(-time.Hour)
	}
	bindSessionMu.Unlock()
	if n := PruneBindSessions(10 * time.Minute); n != 1 {
		t.Fatalf("PruneBindSessions=%d, want 1", n)
	}
	wxCtxMu.Lock()
	pin := wxConfirmedPin
	wxCtxMu.Unlock()
	if pin != nil {
		t.Fatalf("绑定会话过期后 pin 未清：%+v", pin)
	}
}

// ---- 附录 P3：wxPendingQR 过期清除，WxQRLoginActive 不永久 true ----

func TestWxQRLoginActiveExpiresStaleQR(t *testing.T) {
	newNotifyConnectorDB(t)
	t.Cleanup(func() {
		wxCtxMu.Lock()
		wxPendingQR, wxPendingQRAt = "", time.Time{}
		wxCtxMu.Unlock()
	})
	wxCtxMu.Lock()
	wxPendingQR = "stale-qr"
	wxPendingQRAt = time.Now().Add(-2 * wxPendingQRTTL)
	wxCtxMu.Unlock()
	if WxQRLoginActive() {
		t.Fatal("过期二维码仍判定进行中（bind-state 永不复位）")
	}
	wxCtxMu.Lock()
	qr := wxPendingQR
	wxCtxMu.Unlock()
	if qr != "" {
		t.Fatalf("过期二维码未清除：%q", qr)
	}
}

// ---- 附录 P3：QQ 待绑定凭据不得在确认前覆盖同名在线全局 bot ----

func TestPendingQQCredDoesNotOverrideExistingBotBeforeConfirm(t *testing.T) {
	newNotifyConnectorDB(t)
	clearBindSessions()
	t.Cleanup(clearBindSessions)
	if err := SetSettings(map[string]string{KeyQQAppID: "APP_LIVE", KeyQQSecret: "SEC_LIVE"}); err != nil {
		t.Fatal(err)
	}
	StartBindSessionWithCred(7, "qq", "scanner", "APP_LIVE", "SEC_PENDING")
	bots := qqEnumerateBots()
	for _, b := range bots {
		if b.AppID == "APP_LIVE" && b.Secret != "SEC_LIVE" {
			t.Fatalf("未确认的待绑定凭据覆盖了在线全局 bot：secret=%q", b.Secret)
		}
	}
}

// 旧 secret 已失效时，同 appid 的待绑定新 secret 必须能用于连接测试。
func TestQQCredentialFallbackUsesPendingSecretOnInvalidOld(t *testing.T) {
	newNotifyConnectorDB(t)
	clearBindSessions()
	t.Cleanup(clearBindSessions)
	StartBindSessionWithCred(7, "qq", "scanner", "APP_SAME", "SEC_PENDING")

	next, ok := qqCredentialFallback(qqBotCred{AppID: "APP_SAME", Secret: "SEC_OLD"}, errors.New(`QQ 鉴权响应缺 access_token: {"code":100016,"message":"invalid appid or secret"}`))
	if !ok || next.Secret != "SEC_PENDING" {
		t.Fatalf("fallback ok=%v cred=%+v, want APP_SAME/SEC_PENDING", ok, next)
	}
	// 非鉴权错误不切换（回归：网络/协议错误不得误换凭据）。
	if _, ok := qqCredentialFallback(qqBotCred{AppID: "APP_SAME", Secret: "SEC_OLD"}, errors.New("connection reset")); ok {
		t.Fatal("非鉴权错误不得切换待绑定凭据")
	}
}

// ---- （回归）：落盘队列满时调用方必须非阻塞（异步有界） ----

func TestClusterForwardSpoolQueueFullDoesNotBlockCaller(t *testing.T) {
	ch := clusterForwardSpoolQueue()
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	clusterForwardSpoolMu.Lock()
	oldWriter := clusterForwardSpoolWriter
	clusterForwardSpoolWriter = func(Event) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
	}
	clusterForwardSpoolMu.Unlock()
	t.Cleanup(func() {
		close(release)
		clusterForwardSpoolMu.Lock()
		clusterForwardSpoolWriter = oldWriter
		clusterForwardSpoolMu.Unlock()
	})

	// 首个事件占住 worker（阻塞写），随后填满缓冲，再一次入队必须立即返回。
	enqueueClusterForwardSpool(Event{Type: EvtCertFailed})
	<-started
	for range cap(ch) {
		enqueueClusterForwardSpool(Event{Type: EvtCertFailed})
	}
	before := clusterForwardSpoolDropped.Load()
	done := make(chan struct{})
	go func() {
		enqueueClusterForwardSpool(Event{Type: EvtCertFailed})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("落盘队列满时调用方被阻塞（同步 fsync/spool 扫描仍在事件源线程）")
	}
	if clusterForwardSpoolDropped.Load() <= before {
		t.Fatal("队列满未计入丢弃计数（静默丢失）")
	}
}

// ---- 附录 P3：wx 重连失败不得在会话启动即置在线（否则每轮抖动发恢复沿） ----

func TestWxBotSessionOnlineOnlyAfterFirstSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	var link botLinkState
	if err := wxBotSession(context.Background(), wxBotCred{Token: "T", BaseURL: srv.URL, AccountID: "B_FAIL"}, &link, false); err == nil {
		t.Fatal("wxBotSession 预期失败")
	}
	link.mu.Lock()
	connected := link.connected
	link.mu.Unlock()
	if connected {
		t.Fatal("getupdates 首次成功前即置在线（重连失败每轮制造 recovered 沿）")
	}
}
