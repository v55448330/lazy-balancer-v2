package notify

// AUTH LOGIN 回归（Office365/Outlook 仅宣告 LOGIN，PLAIN 报 504 5.7.4
// Unrecognized authentication type——用户实测）。本机起仅宣告 AUTH LOGIN
// 的 SMTP 服务：AUTH PLAIN 一律 504 拒绝，AUTH LOGIN 走 Username/Password
// 挑战。断言 sendSMTPMail 在该服务器下认证+投递成功（loginAuth 生效）。

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type loginOnlySMTP struct {
	ln            net.Listener
	mu            sync.Mutex
	authOK        bool
	plainRejected bool
}

func newLoginOnlySMTP(t *testing.T) *loginOnlySMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &loginOnlySMTP{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *loginOnlySMTP) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	w := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	w("220 login-only ESMTP")
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
			}
			continue
		}
		u := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(u, "EHLO"):
			w("250-login-only greets you")
			w("250-AUTH LOGIN")
			w("250 OK")
		case strings.HasPrefix(u, "AUTH PLAIN"):
			s.mu.Lock()
			s.plainRejected = true
			s.mu.Unlock()
			w("504 5.7.4 Unrecognized authentication type")
		case strings.HasPrefix(u, "AUTH LOGIN"):
			w("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
			if _, err := br.ReadString('\n'); err != nil {
				return
			}
			w("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
			if _, err := br.ReadString('\n'); err != nil {
				return
			}
			s.mu.Lock()
			s.authOK = true
			s.mu.Unlock()
			w("235 authenticated")
		case strings.HasPrefix(u, "MAIL FROM:"), strings.HasPrefix(u, "RCPT TO:"):
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

func TestSendSMTPMailAuthLoginOnlyServer(t *testing.T) {
	srv := newLoginOnlySMTP(t)
	host, port, _ := net.SplitHostPort(srv.ln.Addr().String())
	err := sendSMTPMail(context.Background(), host, port, "noreply@xiaobao.cool", "secret",
		"noreply@xiaobao.cool", "ops@example.com", "SMTP LOGIN 测试", "正文", false, false, false)
	if err != nil {
		t.Fatalf("仅宣告 LOGIN 的服务器认证+投递应成功（Office365 形态），got: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !srv.authOK {
		t.Errorf("应走 AUTH LOGIN 挑战流程")
	}
	if srv.plainRejected {
		t.Errorf("不应尝试 AUTH PLAIN（该服务器拒绝 PLAIN）")
	}
}
