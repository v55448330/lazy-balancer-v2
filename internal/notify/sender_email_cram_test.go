package notify

// AUTH CRAM-MD5 回归（方案 A：部分企业/老旧服务器仅宣告 CRAM-MD5）。本机起
// 仅宣告 AUTH CRAM-MD5 的 SMTP 服务：AUTH PLAIN/LOGIN 一律 504 拒绝，AUTH
// CRAM-MD5 发挑战并校验 HMAC-MD5 响应。断言 sendSMTPMail 择优 CRAM-MD5
// 认证+投递成功（旧代码误发 PLAIN 会被拒→RED）。

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

const cramChallenge = "<12345.67890@notify-test>"

type cramOnlySMTP struct {
	ln            net.Listener
	mu            sync.Mutex
	authOK        bool
	otherRejected bool
}

func newCramOnlySMTP(t *testing.T) *cramOnlySMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &cramOnlySMTP{ln: ln}
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

func (s *cramOnlySMTP) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	w := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	w("220 cram-only ESMTP")
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
			w("250-cram-only greets you")
			w("250-AUTH CRAM-MD5")
			w("250 OK")
		case strings.HasPrefix(u, "AUTH PLAIN"), strings.HasPrefix(u, "AUTH LOGIN"):
			s.mu.Lock()
			s.otherRejected = true
			s.mu.Unlock()
			w("504 5.7.4 Unrecognized authentication type")
		case strings.HasPrefix(u, "AUTH CRAM-MD5"):
			w("334 " + base64.StdEncoding.EncodeToString([]byte(cramChallenge)))
			resp, err := br.ReadString('\n')
			if err != nil {
				return
			}
			raw, err := base64.StdEncoding.DecodeString(strings.TrimRight(resp, "\r\n"))
			if err != nil {
				w("535 decode failed")
				continue
			}
			// 响应形态：username SP hex(hmac-md5(challenge, secret))
			parts := strings.SplitN(string(raw), " ", 2)
			mac := hmac.New(md5.New, []byte("secret"))
			mac.Write([]byte(cramChallenge))
			want := hex.EncodeToString(mac.Sum(nil))
			if len(parts) == 2 && parts[0] == "noreply@xiaobao.cool" && hmac.Equal([]byte(parts[1]), []byte(want)) {
				s.mu.Lock()
				s.authOK = true
				s.mu.Unlock()
				w("235 authenticated")
			} else {
				w("535 5.7.8 authentication credentials invalid")
			}
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

func TestSendSMTPMailAuthCramMD5OnlyServer(t *testing.T) {
	srv := newCramOnlySMTP(t)
	host, port, _ := net.SplitHostPort(srv.ln.Addr().String())
	err := sendSMTPMail(context.Background(), host, port, "noreply@xiaobao.cool", "secret",
		"noreply@xiaobao.cool", "ops@example.com", "SMTP CRAM-MD5 测试", "正文", false, false, false)
	if err != nil {
		t.Fatalf("仅宣告 CRAM-MD5 的服务器认证+投递应成功，got: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !srv.authOK {
		t.Errorf("应走 AUTH CRAM-MD5 挑战响应（HMAC-MD5 校验通过）")
	}
	if srv.otherRejected {
		t.Errorf("不应尝试 AUTH PLAIN/LOGIN（该服务器仅宣告 CRAM-MD5）")
	}
}
