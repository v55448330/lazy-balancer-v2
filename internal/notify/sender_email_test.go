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
		"lb@example.com", "ops@example.com", "证书续签失败", "第一行正文\n第二行正文", false)
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
