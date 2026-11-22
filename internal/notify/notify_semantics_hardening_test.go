package notify

// 通知语义回归钉测（RED→GREEN 覆盖）：任务角色、统计读写键、HTML 转义、
// 并发发送、spool 收敛与日报采集留痕。
// 命名按行为面而非轮次：本文件长期留存，作为上述语义的回归门。

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// ---- 读侧与生产写入键同形（SlaveNodeLabel）---------------

// TestCollectNodesSummary_readsProductionLabelKey 生产写入键=SlaveNodeLabel
// （「从节点 name(ip:port)」，services.RecordNodeDailyStats 的 NodeIdentity），
// 旧读侧按 nodes.name 裸名 LEFT JOIN → 永远「未上报」。
func TestCollectNodesSummary_readsProductionLabelKey(t *testing.T) {
	database := newNotifySchemaDB(t)
	if _, err := database.Exec(`INSERT INTO nodes (name, mode, ip_address, port, is_approved, status)
		VALUES ('slave-a','slave','10.0.0.2',8000,1,'online')`); err != nil {
		t.Fatal(err)
	}
	label := SlaveNodeLabel("slave-a", "10.0.0.2", 8000)
	st, _ := json.Marshal(ClusterNodeStats{Date: "2026-11-21", Requests: 1200, Blocked: 30, DistinctIPs: 9})
	if _, err := database.Exec(`INSERT INTO cluster_node_daily_stats (date,node,stats_json) VALUES ('2026-11-21',?,?)`, label, string(st)); err != nil {
		t.Fatal(err)
	}
	got := collectNodesSummary(t.Context(), "2026-11-21")
	if !strings.Contains(got, "请求 1200") {
		t.Fatalf("生产键（%s）未被读侧命中，摘要=%q（旧实现按裸名 LEFT JOIN 永远「未上报」）", label, got)
	}
}

// ---- 邮件 HTML 模板占位符转义 --------------------------------------

// resetSMTPCapture 清空共享假 SMTP 的已收内容（同一用例多次发送）。
func resetSMTPCapture(s *fakeSMTPServer) {
	s.mu.Lock()
	s.data.Reset()
	s.mailFrom, s.rcptTo = "", ""
	s.mu.Unlock()
}

// decodeMailBody 取 RFC822 base64 正文（首个空行之后）。
func decodeMailBody(t *testing.T, raw string) string {
	t.Helper()
	var b64 strings.Builder
	inBody := false
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		if inBody && line != "" {
			b64.WriteString(line)
		}
		if line == "" {
			inBody = true
		}
	}
	body, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		t.Fatalf("正文 base64 解码失败: %v（原始 %q）", err, b64.String())
	}
	return string(body)
}

func TestEmailHTMLTemplate_escapesPlaceholderValues(t *testing.T) {
	newNotifySettingsDB(t)
	srv := newFakeSMTPServer(t)
	host, port, _ := net.SplitHostPort(srv.addr())
	if err := SetSettings(map[string]string{KeySMTPHost: host, KeySMTPPort: port, KeySMTPFrom: "lb@example.com"}); err != nil {
		t.Fatal(err)
	}
	// 事件 HTML 模板：{{body}} 注入面必须转义。
	msg := Message{EventType: "cfg.caddy_apply_failed", Level: "warn", Title: "T", Body: "<img src=x onerror=alert(1)>"}
	target := `{"email":"ops@example.com","body_template":"<div>{{body}}</div>","body_format":"html"}`
	if err := sendToChannel(context.Background(), "email", target, msg); err != nil {
		t.Fatalf("sendToChannel: %v", err)
	}
	_, _, raw := srv.capture()
	body := decodeMailBody(t, raw)
	if !strings.Contains(body, "&lt;img") || strings.Contains(body, "<img src") {
		t.Fatalf("HTML 模板占位符值未转义（注入面）：%q", body)
	}

	// 非 HTML 模板（text）不得转义（保持纯文本原样）。
	resetSMTPCapture(srv)
	msg2 := Message{EventType: "cfg.caddy_apply_failed", Level: "warn", Title: "T", Body: "<b>raw</b>"}
	target2 := `{"email":"ops@example.com","body_template":"{{body}}","body_format":"text"}`
	if err := sendToChannel(context.Background(), "email", target2, msg2); err != nil {
		t.Fatalf("sendToChannel(text): %v", err)
	}
	_, _, raw = srv.capture()
	body = decodeMailBody(t, raw)
	if !strings.Contains(body, "<b>raw</b>") {
		t.Fatalf("text 模板不应转义占位符值：%q", body)
	}
}

// 日报变量同口径转义（body_format=html + body_template 生效）。
func TestEmailHTMLTemplate_escapesDailyVariables(t *testing.T) {
	newNotifySettingsDB(t)
	srv := newFakeSMTPServer(t)
	host, port, _ := net.SplitHostPort(srv.addr())
	if err := SetSettings(map[string]string{KeySMTPHost: host, KeySMTPPort: port, KeySMTPFrom: "lb@example.com"}); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"date": "2026-11-21", "items": []string{"requests"},
		"values":  map[string]string{"requests": "<img src=x>"},
		"formats": map[string]string{},
	})
	msg := Message{EventType: EvtDailyReport, Level: "info", Title: "每日日报", Body: string(payload)}
	msg.Fields = DailyFieldsFromBody(msg.Body) // deliverOne 的日报变量注入同源
	target := `{"email":"ops@example.com","body_template":"<p>{{requests}}</p><p>{{body}}</p>","body_format":"html"}`
	if err := sendToChannel(context.Background(), "email", target, msg); err != nil {
		t.Fatalf("sendToChannel(daily): %v", err)
	}
	_, _, raw := srv.capture()
	body := decodeMailBody(t, raw)
	if !strings.Contains(body, "&lt;img src=x&gt;") || strings.Contains(body, "<img src=x>") {
		t.Fatalf("日报变量未转义：%q", body)
	}
}

// ---- 通道名后缀仅非日报追加 ---------------------------------------

type titleCaptureSender struct {
	mu     sync.Mutex
	titles []string
}

func (s *titleCaptureSender) Send(_ context.Context, _ string, msg Message) error {
	s.mu.Lock()
	s.titles = append(s.titles, msg.Title)
	s.mu.Unlock()
	return nil
}
func (s *titleCaptureSender) Test(context.Context, string) error { return nil }

func TestSendToChannels_titleSuffixOnlyForEvents(t *testing.T) {
	_ = newNotifySchemaDB(t)
	cap := &titleCaptureSender{}
	RegisterSenderForTest(t, "test-title", cap)
	channels := []deliveryTarget{{ChannelID: 1, Name: "邮件", Type: "test-title", Target: "{}"}}

	if _, sent := sendToChannels(context.Background(), 0, 1, channels, nil,
		Message{EventType: "cfg.caddy_apply_failed", Level: "warn", Title: "T", Body: "B"}); !sent {
		t.Fatal("事件消息未发送")
	}
	if _, sent := sendToChannels(context.Background(), 0, 1, channels, nil,
		Message{EventType: EvtDailyReport, Level: "info", Title: "每日日报", Body: "{}"}); !sent {
		t.Fatal("日报消息未发送")
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if len(cap.titles) != 2 {
		t.Fatalf("标题采集=%v，want 2 条", cap.titles)
	}
	if cap.titles[0] != "T（邮件）" {
		t.Fatalf("事件标题=%q，want 通道名后缀", cap.titles[0])
	}
	if cap.titles[1] != "每日日报" {
		t.Fatalf("日报标题=%q，want 无通道名后缀（日报标题保持原样）", cap.titles[1])
	}
}

// ---- 微信跳过原因区分凭据未配置 / 会话待刷新 ----------------------

func TestSendToChannels_wxSkipReasonDistinguishesCredentials(t *testing.T) {
	_ = newNotifySchemaDB(t)
	fake := &fakeWxSender{}
	RegisterSenderForTest(t, "wx_clawbot", fake)
	oldReady := wxSessionReadyForDelivery
	wxSessionReadyForDelivery = func(string) bool { return false }
	t.Cleanup(func() { wxSessionReadyForDelivery = oldReady })

	msg := Message{EventType: "cfg.caddy_apply_failed", Level: "warn", Title: "T", Body: "B"}

	// receiver 空 → 凭据未配置
	errs, _ := sendToChannels(context.Background(), 0, 1,
		[]deliveryTarget{{ChannelID: 1, Type: "wx_clawbot", Target: `{"receiver":""}`}}, nil, msg)
	if len(errs) != 1 || !strings.Contains(errs[0], "微信凭据未配置") {
		t.Fatalf("receiver 空应报「微信凭据未配置」: %v", errs)
	}

	// receiver 有值、token/key 空（无全局凭据）→ 凭据未配置
	errs, _ = sendToChannels(context.Background(), 0, 1,
		[]deliveryTarget{{ChannelID: 2, Type: "wx_clawbot", Target: `{"receiver":"wxid-x"}`}}, nil, msg)
	if len(errs) != 1 || !strings.Contains(errs[0], "微信凭据未配置") {
		t.Fatalf("token/key 空应报「微信凭据未配置」: %v", errs)
	}

	// 凭据齐全但会话未就绪 → 会话待刷新
	errs, _ = sendToChannels(context.Background(), 0, 1,
		[]deliveryTarget{{ChannelID: 3, Type: "wx_clawbot", Target: `{"receiver":"wxid-x","token":"tkn"}`}}, nil, msg)
	if len(errs) != 1 || !strings.Contains(errs[0], "会话待刷新") {
		t.Fatalf("凭据齐全时应报会话待刷新: %v", errs)
	}
	if fake.calls != 0 {
		t.Fatalf("跳过路径不得调用发送器: calls=%d", fake.calls)
	}
}

// ---- sendToChannels 有界并发（≤3）且结果完整 ---------------------

type probeSender struct {
	mu       sync.Mutex
	inflight int
	peak     int
	calls    int
	fail     bool
}

func (s *probeSender) Send(context.Context, string, Message) error {
	s.mu.Lock()
	s.inflight++
	s.calls++
	if s.inflight > s.peak {
		s.peak = s.inflight
	}
	s.mu.Unlock()
	time.Sleep(25 * time.Millisecond)
	s.mu.Lock()
	s.inflight--
	s.mu.Unlock()
	if s.fail {
		return errors.New("boom")
	}
	return nil
}
func (s *probeSender) Test(context.Context, string) error { return nil }

func TestSendToChannels_boundedConcurrentResultsComplete(t *testing.T) {
	_ = newNotifySchemaDB(t)
	okS, failS := &probeSender{}, &probeSender{fail: true}
	RegisterSenderForTest(t, "test-ok", okS)
	RegisterSenderForTest(t, "test-fail", failS)

	channels := []deliveryTarget{
		{ChannelID: 1, Type: "test-ok", Target: "{}"},
		{ChannelID: 2, Type: "test-fail", Target: "{}"},
		{ChannelID: 3, Type: "test-ok", Target: "{}"},
		{ChannelID: 4, Type: "test-ok", Target: "{}"},
		{ChannelID: 5, Type: "test-ok", Target: "{}"},
	}
	errs, sent := sendToChannels(context.Background(), 0, 1, channels, nil,
		Message{EventType: "cfg.caddy_apply_failed", Level: "warn", Title: "T", Body: "B"})
	if !sent {
		t.Fatal("有成功通道时必须 sentAny=true")
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "boom") {
		t.Fatalf("失败通道结果不完整: %v", errs)
	}
	if okS.calls != 4 || failS.calls != 2 {
		// 失败通道保留既有「失败重试 1 次」语义 → 2 次调用；成功通道各 1 次。
		t.Fatalf("通道调用数 ok=%d fail=%d，want 4/2（结果完整且保留重试）", okS.calls, failS.calls)
	}
	if okS.peak < 2 {
		t.Fatalf("并发峰值=%d，want ≥2（逐通道串行发送是旧实现）", okS.peak)
	}
	if okS.peak > 3 || failS.peak > 3 {
		t.Fatalf("并发峰值 ok=%d fail=%d，want ≤3（有界并发）", okS.peak, failS.peak)
	}
}

// ---- 单次执行只发布一条（去重由主节点单点承担） ----------

func TestCheckAPIKeyExpiry_publishesOncePerRun(t *testing.T) {
	ensureBusStoppedForTest(t)
	newDailyTestDBs(t)
	now := time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)
	exp := now.Add(3 * 24 * time.Hour).Format("2006-01-02 15:04:05")
	mustExec(t, db.DB, `INSERT INTO api_keys (name, expires_at, is_enabled) VALUES ('k1', ?, 1), ('k-far', '2030-01-01 00:00:00', 1)`, exp)
	before := DroppedCount()
	if err := checkAPIKeyExpiryAt(now); err != nil {
		t.Fatalf("checkAPIKeyExpiryAt: %v", err)
	}
	if got := DroppedCount() - before; got != 1 {
		t.Fatalf("单次执行发布 %d 条，want 1（同轮不得重复发布；跨节点去重由主节点单点承担）", got)
	}
}

// ---- CollectDailyData 采集错误留痕（值保持零值） ------------------

func TestCollectDailyData_logsScanErrors(t *testing.T) {
	oldMain, oldMetrics, oldAudit := db.DB, db.MetricsDB, db.AuditDB
	dir := t.TempDir()
	mainDB, err := sql.Open("sqlite", dir+"/main.db")
	if err != nil {
		t.Fatal(err)
	}
	metricsDB, err := sql.Open("sqlite", dir+"/metrics.db")
	if err != nil {
		t.Fatal(err)
	}
	auditDB, err := sql.Open("sqlite", dir+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB, db.MetricsDB, db.AuditDB = mainDB, metricsDB, auditDB
	t.Cleanup(func() {
		db.DB, db.MetricsDB, db.AuditDB = oldMain, oldMetrics, oldAudit
		_ = mainDB.Close()
		_ = metricsDB.Close()
		_ = auditDB.Close()
	})

	var buf bytes.Buffer
	var mu sync.Mutex
	log.SetOutput(&lockedBuffer{mu: &mu, buf: &buf})
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	d, err := CollectDailyData(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("CollectDailyData: %v", err)
	}
	if d.Requests != 0 || d.Blocked != 0 || d.TaskOK != 0 {
		t.Fatalf("采集失败值应保持零值: requests=%d blocked=%d taskOK=%d", d.Requests, d.Blocked, d.TaskOK)
	}
	mu.Lock()
	out := buf.String()
	mu.Unlock()
	if n := strings.Count(out, "日报采集失败"); n < 10 {
		t.Fatalf("采集错误留痕 %d 条，want ≥10（15 处 `_ =` 静默吞错）：\n%s", n, out)
	}
}

type lockedBuffer struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// ---- DeliverDailyForAll 采集一次（用户无关数据） ------------------

func TestDeliverDailyForAll_collectsOnceForAllUsers(t *testing.T) {
	newDailyTestDBs(t)
	mustExec(t, db.DB, `INSERT INTO notification_daily (user_id, config) VALUES
		(1, '{"enabled":true,"send_time":"09:00","items":["requests"]}'),
		(2, '{"enabled":true,"send_time":"10:00","items":["requests"]}')`)

	var collects atomic.Int64
	old := dailyDataCollector
	dailyDataCollector = func(ctx context.Context, now time.Time) (DailyData, error) {
		collects.Add(1)
		return DailyData{Date: "2026-11-21", Requests: 1}, nil
	}
	t.Cleanup(func() { dailyDataCollector = old })

	n, err := DeliverDailyForAll(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("DeliverDailyForAll: %v", err)
	}
	if n != 2 {
		t.Fatalf("投递用户数=%d，want 2", n)
	}
	if got := collects.Load(); got != 1 {
		t.Fatalf("采集次数=%d，want 1（数据用户无关，应采集一次复用）", got)
	}
}

// ---- markDelivery 仅 sent/partial 写 sent_at ----------------------

func TestMarkDelivery_sentAtOnlyForSuccessStatuses(t *testing.T) {
	database := newNotifySchemaDB(t)
	insert := func() int64 {
		res, err := database.Exec(`INSERT INTO notification_deliveries
			(user_id,event_type,level,title,body,status,attempts,created_at) VALUES (1,'x','info','t','b','pending',0,'2026-11-21 00:00:00')`)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	sentAt := func(id int64) string {
		var v string
		if err := database.QueryRow(`SELECT COALESCE(sent_at,'') FROM notification_deliveries WHERE id=?`, id).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, tc := range []struct {
		status string
		wantTS bool
	}{
		{"sent", true}, {"partial", true}, {"failed", false}, {"dead", false},
	} {
		id := insert()
		markDelivery(id, tc.status, true, "e")
		got := sentAt(id)
		if tc.wantTS && got == "" {
			t.Fatalf("%s 应写 sent_at", tc.status)
		}
		if !tc.wantTS && got != "" {
			t.Fatalf("%s 不应写 sent_at（got %q）", tc.status, got)
		}
	}
}

// ---- certExpiringList 下界 + LIMIT 命中提示 -----------------------

func TestCertExpiringList_lowerBoundAndLimitNote(t *testing.T) {
	newDailyTestDBs(t)
	now := time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)
	ins := func(domain string, at time.Time) {
		mustExec(t, db.DB, `INSERT INTO cert_jobs (domain,status,expires_at) VALUES (?, 'issued', ?)`,
			domain, at.Format("2006-01-02 15:04:05"))
	}
	ins("expired.example", now.AddDate(0, 0, -10)) // 已过期：不在「临期」口径
	for i := 1; i <= 7; i++ {
		ins("soon-"+string(rune('a'+i-1))+".example", now.AddDate(0, 0, i))
	}
	got := certExpiringList(context.Background(), now)
	if strings.Contains(got, "expired.example") {
		t.Fatalf("已过期证书不应列入临期明细（缺下界）：%q", got)
	}
	if !strings.Contains(got, "（仅列前 5 条）") {
		t.Fatalf("超过 5 条未提示截断：%q", got)
	}
	if lines := len(strings.Split(got, "\n")); lines != 6 {
		t.Fatalf("行数=%d，want 5 条明细 + 1 条截断提示（got %q）", lines, got)
	}
}

// ---- 日报载荷解析失败回退可见占位 --------------------------------

func TestRenderDailyForChannel_payloadParseFailureVisiblePlaceholder(t *testing.T) {
	msg := Message{EventType: EvtDailyReport, Body: "not-json{{"}
	got, format := renderDailyForChannelFormat(msg, "webhook", "")
	if !strings.Contains(got, "日报数据解析失败（详见任务日志）") {
		t.Fatalf("坏载荷未回退可见占位: %q", got)
	}
	if strings.Contains(got, "not-json") {
		t.Fatalf("坏载荷原文不得直出（用户看到的是数据损坏细节）: %q", got)
	}
	if format != "" {
		t.Fatalf("解析失败格式=%q，want 空（未知=邮件按纯文本 fail-closed）", format)
	}
}

// ---- spool：永久 4xx 删除 / 未配置不落盘 / trim 跳过 .tmp --------

func writeSpoolReport(t *testing.T, dir, name string) string {
	t.Helper()
	report := ClusterEventReport{
		Node:    "slave-test",
		Events:  []ClusterEventOne{{Type: EvtCaddyApplyFailed, Fields: map[string]string{"1": "n", "2": "d"}}},
		Spooled: true,
		BatchID: "ev-test",
	}
	raw, _ := json.Marshal(report)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDrainClusterForwardSpool_permanent4xxDiscarded(t *testing.T) {
	flushClusterForwardQueue(t)
	dir := t.TempDir()
	overrideForwardSpoolDir(t, dir)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, false, srv.URL, "tok-1")
	path := writeSpoolReport(t, dir, "pending-1.json")

	DrainClusterForwardSpool(context.Background())
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("永久 4xx 的 spool 文件应删除（不再无限重试）: err=%v", err)
	}
}

func TestDrainClusterForwardSpool_transient5xxKeepsFile(t *testing.T) {
	flushClusterForwardQueue(t)
	dir := t.TempDir()
	overrideForwardSpoolDir(t, dir)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	overrideClusterForwardRole(t, false, srv.URL, "tok-1")
	path := writeSpoolReport(t, dir, "pending-1.json")

	DrainClusterForwardSpool(context.Background())
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("瞬时 5xx 必须保留 spool 待重传: %v", err)
	}
}

func TestSpoolClusterEvent_skipsWhenMasterNotConfigured(t *testing.T) {
	dir := t.TempDir()
	overrideForwardSpoolDir(t, dir)
	overrideClusterForwardRole(t, false, "", "")

	var buf bytes.Buffer
	var mu sync.Mutex
	log.SetOutput(&lockedBuffer{mu: &mu, buf: &buf})
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	spoolClusterEvent(Event{Type: EvtCaddyApplyFailed, Fields: map[string]string{"1": "n", "2": "d"}})
	if files := spoolJSONFiles(dir); len(files) != 0 {
		t.Fatalf("master_url/token 未配置时不得落盘（残留 %d 个文件）", len(files))
	}
	mu.Lock()
	out := buf.String()
	mu.Unlock()
	if !strings.Contains(out, "spool") || !strings.Contains(out, "丢弃") {
		t.Fatalf("未配置丢弃必须留痕: %q", out)
	}
}

func TestTrimClusterForwardSpool_skipsTmpFiles(t *testing.T) {
	dir := t.TempDir()
	for i := range clusterForwardSpoolMaxFiles + 2 {
		name := filepath.Join(dir, "pending-"+strconv.Itoa(i)+".json")
		if err := os.WriteFile(name, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tmp := filepath.Join(dir, "pending-999.tmp")
	if err := os.WriteFile(tmp, []byte(`half`), 0o600); err != nil {
		t.Fatal(err)
	}
	trimClusterForwardSpool(dir)
	if _, err := os.Stat(tmp); err != nil {
		t.Fatalf("trim 不得删除 .tmp 半成品: %v", err)
	}
	if n := len(spoolJSONFiles(dir)); n != clusterForwardSpoolMaxFiles {
		t.Fatalf("trim 后成品文件=%d，want %d", n, clusterForwardSpoolMaxFiles)
	}
}

// ---- Stop 幂等且可早于 Start ----------------------------

func TestNotifyStop_safeBeforeStartAndIdempotent(t *testing.T) {
	// 未启动（启动失败早退路径）即调用关停链：不得 close(nil) panic。
	started.Store(false)
	stopOnce = sync.Once{}
	stopCh = nil
	Stop()

	Start()
	Stop()
	Stop() // 幂等：第二次不得 panic、不得重复排空
	awaitLoopExit(t)

	started.Store(false)
	stopOnce = sync.Once{}
	stopCh = nil
	queue = nil
}

// 同族：通道测试留痕的 sent_at 与 markDelivery 同口径（成功才写）。
func TestRecordChannelTestDelivery_sentAtOnlyOnSuccess(t *testing.T) {
	old := db.DB
	database, err := sql.Open("sqlite", t.TempDir()+"/test-delivery.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB = database
	t.Cleanup(func() { db.DB = old; _ = database.Close() })
	if _, err := database.Exec(`
CREATE TABLE notification_deliveries (
	id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, event_type TEXT NOT NULL,
	level TEXT NOT NULL DEFAULT 'info', title TEXT NOT NULL, body TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
	error TEXT DEFAULT '', created_at TEXT NOT NULL, sent_at DATETIME,
	is_test INTEGER NOT NULL DEFAULT 0, retry_channel_ids TEXT NOT NULL DEFAULT '',
	node TEXT NOT NULL DEFAULT '');
CREATE TABLE notification_delivery_channels (
	id INTEGER PRIMARY KEY AUTOINCREMENT, delivery_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
	channel_id INTEGER NOT NULL, channel_name TEXT NOT NULL DEFAULT '', channel_type TEXT NOT NULL DEFAULT '',
	event_type TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '', error TEXT DEFAULT '',
	duration_ms INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);`); err != nil {
		t.Fatal(err)
	}
	if err := RecordChannelTestDelivery(1, 2, "webhook", "运维群", false, "dial timeout"); err != nil {
		t.Fatal(err)
	}
	if err := RecordChannelTestDelivery(1, 2, "webhook", "运维群", true, ""); err != nil {
		t.Fatal(err)
	}
	rows, err := database.Query(`SELECT status, COALESCE(sent_at,'') FROM notification_deliveries ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got [][2]string
	for rows.Next() {
		var st, ts string
		if err := rows.Scan(&st, &ts); err != nil {
			t.Fatal(err)
		}
		got = append(got, [2]string{st, ts})
	}
	if len(got) != 2 {
		t.Fatalf("留痕行数=%d，want 2", len(got))
	}
	if got[0][0] != "failed" || got[0][1] != "" {
		t.Fatalf("失败测试行 sent_at=%q，want 空", got[0][1])
	}
	if got[1][0] != "sent" || got[1][1] == "" {
		t.Fatalf("成功测试行应写 sent_at: %+v", got[1])
	}
}

// ---- 任务角色注册（services 侧见 notification_tasks_roles_test.go） --
// 本文件只覆盖 notify 包内可观测语义。

func TestSpoolClusterEvent_detectorErrorStillSpools(t *testing.T) {
	dir := t.TempDir()
	overrideForwardSpoolDir(t, dir)
	prev := clusterForwardRoleDetectorSnapshot()
	setClusterForwardRoleDetectorForTest(func() (bool, string, string, string, error) {
		return true, "", "", "", errors.New("db temporarily unavailable")
	})
	t.Cleanup(func() { setClusterForwardRoleDetectorForTest(prev) })

	spoolClusterEvent(Event{Type: EvtCaddyApplyFailed, Fields: map[string]string{"1": "n", "2": "d"}})
	if files := spoolJSONFiles(dir); len(files) != 1 {
		t.Fatalf("角色探测失败时必须落盘重试（误判丢弃=事件永久丢失），files=%d", len(files))
	}
}
