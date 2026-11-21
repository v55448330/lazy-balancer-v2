package notify

// email 通道适配器测试：本机起一个说真协议的简易 SMTP 服务（220/250/354
// 应答序列），net/smtp 客户端完整走 EHLO→MAIL→RCPT→DATA→QUIT 会话；
// 断言信封（MAIL FROM/RCPT TO）与 RFC822 正文（主题 Q 编码、正文 base64）。
// Send 级用例经 notify_settings KV（真 sqlite 表）提供凭据。

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/base64"
	"mime"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// fakeSMTPServer 简易 SMTP 服务（单进程真 socket；记录信封与 DATA 内容）。
type fakeSMTPServer struct {
	ln net.Listener

	mu       sync.Mutex
	mailFrom string
	rcptTo   string
	data     strings.Builder
}

func newFakeSMTPServer(t *testing.T) *fakeSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("SMTP 测试服务监听失败: %v", err)
	}
	s := &fakeSMTPServer{ln: ln}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeSMTPServer) addr() string { return s.ln.Addr().String() }

func (s *fakeSMTPServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTPServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	w := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	w("220 notify-test ESMTP")
	br := bufio.NewReader(conn)
	inData := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				w("250 OK")
			} else {
				s.mu.Lock()
				s.data.WriteString(line + "\n")
				s.mu.Unlock()
			}
			continue
		}
		u := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(u, "EHLO"):
			w("250-notify-test greets you")
			w("250 OK")
		case strings.HasPrefix(u, "MAIL FROM:"):
			s.mu.Lock()
			s.mailFrom = strings.TrimSpace(strings.TrimPrefix(line[len("MAIL FROM:"):], ""))
			s.mu.Unlock()
			w("250 OK")
		case strings.HasPrefix(u, "RCPT TO:"):
			s.mu.Lock()
			s.rcptTo = strings.TrimSpace(line[len("RCPT TO:"):])
			s.mu.Unlock()
			w("250 OK")
		case u == "DATA":
			w("354 end with <CR><LF>.<CR><LF>")
			inData = true
		case u == "QUIT":
			w("221 bye")
			return
		default:
			w("250 OK")
		}
	}
}

func (s *fakeSMTPServer) capture() (mailFrom, rcptTo, data string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mailFrom, s.rcptTo, s.data.String()
}

func TestSendSMTPMailRoundTrip(t *testing.T) {
	srv := newFakeSMTPServer(t)
	host, port, _ := net.SplitHostPort(srv.addr())
	err := sendSMTPMail(context.Background(), host, port, "", "",
		"lb@example.com", "ops@example.com", "证书续签失败", "第一行正文\n第二行正文", false, false, false)
	if err != nil {
		t.Fatalf("sendSMTPMail 返回错误: %v", err)
	}
	mailFrom, rcptTo, data := srv.capture()
	if mailFrom != "<lb@example.com>" && mailFrom != "lb@example.com" {
		t.Errorf("MAIL FROM = %q, want lb@example.com 形态", mailFrom)
	}
	if rcptTo != "<ops@example.com>" && rcptTo != "ops@example.com" {
		t.Errorf("RCPT TO = %q, want ops@example.com 形态", rcptTo)
	}
	for _, want := range []string{
		"From: lb@example.com",
		"To: ops@example.com",
		"Subject: " + mime.QEncoding.Encode("utf-8", "证书续签失败"),
		"Content-Type: text/plain; charset=UTF-8",
	} {
		if !strings.Contains(data, want) {
			t.Errorf("邮件缺少 %q\n完整内容:\n%s", want, data)
		}
	}
	// 正文 base64 解码还原。
	var b64 strings.Builder
	inBody := false
	for _, line := range strings.Split(data, "\n") {
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
	if string(body) != "第一行正文\n第二行正文" {
		t.Errorf("正文还原 = %q", string(body))
	}
}

// newNotifySettingsDB 通知 KV 测试库（真 sqlite；建 notify_settings 表，
// 驱动经 db 包注册）。
func newNotifySettingsDB(t *testing.T) {
	t.Helper()
	old := db.DB
	database, err := sql.Open("sqlite", t.TempDir()+"/notify-test.db")
	if err != nil {
		t.Fatalf("测试库打开失败: %v", err)
	}
	if _, err := database.Exec(`CREATE TABLE IF NOT EXISTS notify_settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		t.Fatalf("notify_settings 建表失败: %v", err)
	}
	db.DB = database
	t.Cleanup(func() {
		db.DB = old
		_ = database.Close()
	})
}

func TestEmailSenderSendViaSettings(t *testing.T) {
	newNotifySettingsDB(t)
	srv := newFakeSMTPServer(t)
	host, port, _ := net.SplitHostPort(srv.addr())
	if err := SetSettings(map[string]string{
		KeySMTPHost: host, KeySMTPPort: port, KeySMTPFrom: "lb@example.com",
	}); err != nil {
		t.Fatalf("写入 SMTP 设置失败: %v", err)
	}
	msg := Message{Level: "critical", Title: "集群节点离线", Body: "node-b 心跳超时"}
	if err := sendToChannel(context.Background(), "email", `{"email":"ops@example.com"}`, msg); err != nil {
		t.Fatalf("sendToChannel(email) 返回错误: %v", err)
	}
	mailFrom, rcptTo, data := srv.capture()
	if rcptTo != "<ops@example.com>" && rcptTo != "ops@example.com" {
		t.Errorf("收件人 = %q, want ops@example.com", rcptTo)
	}
	if !strings.Contains(data, "Subject: "+mime.QEncoding.Encode("utf-8", "集群节点离线")) {
		t.Errorf("主题未正确编码:\n%s", data)
	}
	if mailFrom != "<lb@example.com>" && mailFrom != "lb@example.com" {
		t.Errorf("发件人 = %q, want lb@example.com", mailFrom)
	}
}

func TestEmailSenderFailsLoudWithoutSettings(t *testing.T) {
	newNotifySettingsDB(t)
	err := sendToChannel(context.Background(), "email", `{"email":"ops@example.com"}`,
		Message{Level: "warn", Title: "t"})
	if err == nil || !strings.Contains(err.Error(), "SMTP 服务器未配置") {
		t.Errorf("未配置 SMTP 应明确报错, got %v", err)
	}
}

func TestEmailSenderTargetValidation(t *testing.T) {
	newNotifySettingsDB(t)
	_ = SetSettings(map[string]string{KeySMTPHost: "127.0.0.1", KeySMTPPort: "1"})
	cases := []struct {
		name   string
		target string
	}{
		{"缺 email", `{}`},
		{"非 JSON", `{bad`},
	}
	for _, tc := range cases {
		if err := (emailSender{}).Send(context.Background(), tc.target, Message{Title: "t"}); err == nil {
			t.Errorf("%s: 未返回错误", tc.name)
		}
	}
}

// NOTIF154-P2-01：事件模板已全量渲染（TemplateApplied）时，邮件主题模板
// 必须走窄渲染器——只替换元信息占位符，「[告警] {{title}}」组合不得被整篇
// markdown 正文顶替（此前 subject_template 复用正文渲染器，主题变成多行全文）。
func TestEmailSubjectTemplate_templateAppliedNarrowRender(t *testing.T) {
	newNotifySettingsDB(t)
	srv := newFakeSMTPServer(t)
	host, port, _ := net.SplitHostPort(srv.addr())
	if err := SetSettings(map[string]string{
		KeySMTPHost: host, KeySMTPPort: port, KeySMTPFrom: "lb@example.com",
	}); err != nil {
		t.Fatalf("写入 SMTP 设置失败: %v", err)
	}
	msg := Message{
		EventType: "cfg.caddy_apply_failed", Level: "warn", Title: "Caddy 重载失败",
		Body: "## 整篇正文第一行\n---\n**详情**", TemplateApplied: true,
		Time: time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC), Node: "slave-a",
	}
	target := `{"email":"ops@example.com","subject_template":"[告警] {{title}}"}`
	if err := sendToChannel(context.Background(), "email", target, msg); err != nil {
		t.Fatalf("sendToChannel(email) 返回错误: %v", err)
	}
	_, _, data := srv.capture()
	want := "Subject: " + mime.QEncoding.Encode("utf-8", "[告警] Caddy 重载失败")
	if !strings.Contains(data, want) {
		t.Fatalf("主题未按窄渲染器渲染（不得吞正文）:\n%s", data)
	}
	if strings.Contains(data, "整篇正文第一行") && strings.Index(data, "整篇正文第一行") < strings.Index(data, "Subject:") {
		t.Fatalf("主题被整篇正文顶替:\n%s", data)
	}
	// 正文仍是事件模板产物（原文直发，markdown 不进 HTML 卡片）。
	if !strings.Contains(data, "base64") && !strings.Contains(data, "整篇正文第一行") {
		t.Fatalf("正文丢失:\n%s", data)
	}

	// 窄渲染器本身：{{body}} 不展开（保留字面量，便于用户自查），元信息占位符生效。
	if got := renderSubjectTemplate("{{node}}/{{level}} {{body}}", msg, msg.Time); got != "slave-a/警告 {{body}}" {
		t.Fatalf("窄渲染器输出=%q, want 元信息替换且 {{body}} 保留", got)
	}
}

// emailHTMLBody 契约（2026-11-22 残留交互修复）：事件模板已全量渲染
// （TemplateApplied）的正文是 markdown 文本——邮件不得再包 HTML 卡片
// （卡片标题/徽章/元信息与模板自身布局视觉重复），也不得进 HTML 上下文
// （NOTIF153-02 同源纪律），一律 text/plain 原文直发，显式 html 格式不破例。
func TestEmailHTMLBody_templateAppliedPlainText(t *testing.T) {
	tplApplied := Message{EventType: "cfg.caddy_apply_failed", TemplateApplied: true,
		Body: "## 🔔 标题\n---\n**正文**"}
	if emailHTMLBody("", "", tplApplied) {
		t.Fatal("TemplateApplied 正文=markdown 文本，必须 text/plain 原文直发（不得包 HTML 卡片）")
	}
	if emailHTMLBody("", "html", tplApplied) {
		t.Fatal("TemplateApplied 显式 html 格式也不破例：模板产物不是 HTML，进 HTML 上下文即注入面")
	}
	// 回归：默认事件链（无事件模板、通道无正文模板）仍走 HTML 卡片
	if !emailHTMLBody("", "", Message{EventType: "cfg.caddy_apply_failed"}) {
		t.Fatal("默认事件链（无模板）应走 HTML 卡片")
	}
	if emailHTMLBody("", "text", Message{EventType: "cfg.caddy_apply_failed"}) {
		t.Fatal("显式纯文本格式须 text/plain")
	}
	// 回归：通道正文模板存在时跟随显式格式
	if !emailHTMLBody("<p>{{body}}</p>", "html", Message{EventType: "cfg.caddy_apply_failed"}) {
		t.Fatal("通道 HTML 正文模板应按 text/html 发送")
	}
	if emailHTMLBody("<p>{{body}}</p>", "", Message{EventType: "cfg.caddy_apply_failed"}) {
		t.Fatal("通道正文模板未显式 html 时不得进 HTML 上下文")
	}
	// 回归：日报跟随实际渲染格式（ContentFormat）
	if !emailHTMLBody("", "", Message{EventType: EvtDailyReport, ContentFormat: "html"}) {
		t.Fatal("日报 html 渲染应按 text/html 发送")
	}
	if emailHTMLBody("", "", Message{EventType: EvtDailyReport, ContentFormat: "text"}) {
		t.Fatal("日报 text 渲染必须 text/plain（fail-closed）")
	}
	// NOTIF154-P3-06：日报模板模式（有正文模板）Content-Type 纳入 body_format
	// ——显式 html 必须 text/html（旧实现只看模块渲染格式，HTML 模板被当
	// text/plain 发出）；显式 text 必须 text/plain。
	if !emailHTMLBody("<p>{{requests}}</p>", "html", Message{EventType: EvtDailyReport, ContentFormat: "text"}) {
		t.Fatal("日报 HTML 正文模板（body_format=html）必须按 text/html 发送")
	}
	if emailHTMLBody("<p>{{requests}}</p>", "text", Message{EventType: EvtDailyReport, ContentFormat: "html"}) {
		t.Fatal("日报正文模板显式 text 必须 text/plain")
	}
	// 模块拼装模式（模板被抑制）忽略 body_format，仍跟随实际渲染格式。
	if emailHTMLBody("<p>x</p>", "html", Message{EventType: EvtDailyReport, ContentFormat: "text", DailyModuleMode: true}) {
		t.Fatal("日报模块拼装模式不得因遗留 body_format=html 进 HTML 上下文")
	}
}
