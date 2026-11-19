package notify

// SMTP OAuth2（XOAUTH2）回归：令牌刷新（缓存单飞/invalid_grant fail-loud/
// 未配置）+ 仅宣告 XOAUTH2 的 SMTP 服务器认证串形态校验（Bearer token）。
// 令牌端点经 oauthTokenEndpoint var 覆写为 httptest；OAuth 配置经 SetSettings
// （refresh_token 静态加密，newNotifyConnectorDB 提供密钥接缝）。

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// useOAuthTokenMock 覆写令牌端点为 mock（自动还原 + 清令牌缓存）。
func useOAuthTokenMock(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	old := oauthTokenEndpoint
	oauthTokenEndpoint = func(string) string { return srv.URL }
	invalidateOAuthToken()
	t.Cleanup(func() { oauthTokenEndpoint = old; srv.Close(); invalidateOAuthToken() })
	return srv
}

func seedOAuthConfig(t *testing.T) {
	t.Helper()
	if err := SetSettings(map[string]string{
		KeySMTPOAuthTenant:       "common",
		KeySMTPOAuthClientID:     "cid-test",
		KeySMTPOAuthRefreshToken: "rt-test",
	}); err != nil {
		t.Fatalf("播种 OAuth 配置: %v", err)
	}
}

func TestOAuthAccessToken_RefreshAndCache(t *testing.T) {
	newNotifyConnectorDB(t)
	var calls atomic.Int32
	useOAuthTokenMock(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "refresh_token" {
			t.Errorf("刷新请求 grant_type=%q, want refresh_token", r.PostForm.Get("grant_type"))
		}
		if r.PostForm.Get("refresh_token") != "rt-test" || r.PostForm.Get("client_id") != "cid-test" {
			t.Errorf("刷新凭据不符: %v", r.PostForm)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT_1","expires_in":3600}`))
	})
	seedOAuthConfig(t)
	// When 首次取令牌（刷新）
	tok, err := OAuthAccessToken(context.Background())
	if err != nil || tok != "AT_1" {
		t.Fatalf("OAuthAccessToken = %q, %v; want AT_1", tok, err)
	}
	// Then 二次取令牌命中缓存（不再刷新）
	tok2, err := OAuthAccessToken(context.Background())
	if err != nil || tok2 != "AT_1" {
		t.Fatalf("二次取令牌 = %q, %v", tok2, err)
	}
	if calls.Load() != 1 {
		t.Errorf("缓存命中应只刷新一次, got %d 次", calls.Load())
	}
}

func TestOAuthAccessToken_InvalidGrantFailLoud(t *testing.T) {
	newNotifyConnectorDB(t)
	useOAuthTokenMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token expired"}`))
	})
	seedOAuthConfig(t)
	// Then invalid_grant fail-loud（不静默回退）
	if _, err := OAuthAccessToken(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("invalid_grant 应 fail-loud, got %v", err)
	}
}

func TestOAuthAccessToken_NotConfigured(t *testing.T) {
	newNotifyConnectorDB(t)
	useOAuthTokenMock(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("未配置不应发起刷新")
	})
	if _, err := OAuthAccessToken(context.Background()); err == nil {
		t.Fatalf("未配置应返回错误")
	}
}

// xoauth2OnlySMTP 仅宣告 AUTH XOAUTH2 的 SMTP 服务：校验认证串形态+Bearer
// token；PLAIN/LOGIN/CRAM-MD5 一律 504 拒绝。
type xoauth2OnlySMTP struct {
	ln            net.Listener
	mu            sync.Mutex
	authOK        bool
	otherRejected bool
}

func newXOAuth2OnlySMTP(t *testing.T, wantToken string) *xoauth2OnlySMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &xoauth2OnlySMTP{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn, wantToken)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *xoauth2OnlySMTP) handle(conn net.Conn, wantToken string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	w := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	w("220 xoauth2-only ESMTP")
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
			w("250-xoauth2-only greets you")
			w("250-AUTH XOAUTH2")
			w("250 OK")
		case strings.HasPrefix(u, "AUTH PLAIN"), strings.HasPrefix(u, "AUTH LOGIN"), strings.HasPrefix(u, "AUTH CRAM-MD5"):
			s.mu.Lock()
			s.otherRejected = true
			s.mu.Unlock()
			w("504 5.7.4 Unrecognized authentication type")
		case strings.HasPrefix(u, "AUTH XOAUTH2"):
			payload := strings.TrimSpace(strings.TrimPrefix(line, "AUTH XOAUTH2"))
			var raw []byte
			if payload != "" {
				raw, _ = base64.StdEncoding.DecodeString(payload)
			} else {
				w("334 ")
				resp, err := br.ReadString('\n')
				if err != nil {
					return
				}
				raw, _ = base64.StdEncoding.DecodeString(strings.TrimRight(resp, "\r\n"))
			}
			want := "user=noreply@xiaobao.cool\x01auth=Bearer " + wantToken + "\x01\x01"
			if string(raw) == want {
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

func TestSendSMTPMailAuthXOAuth2OnlyServer(t *testing.T) {
	newNotifyConnectorDB(t)
	useOAuthTokenMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT_XO","expires_in":3600}`))
	})
	seedOAuthConfig(t)
	srv := newXOAuth2OnlySMTP(t, "AT_XO")
	host, port, _ := net.SplitHostPort(srv.ln.Addr().String())
	// When 配置 OAuth + 服务器仅宣告 XOAUTH2 → 走 XOAUTH2（Bearer AT_XO）
	err := sendSMTPMail(context.Background(), host, port, "noreply@xiaobao.cool", "",
		"noreply@xiaobao.cool", "ops@example.com", "SMTP XOAUTH2 测试", "正文", false, false, false)
	if err != nil {
		t.Fatalf("仅宣告 XOAUTH2 的服务器认证+投递应成功，got: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !srv.authOK {
		t.Errorf("应走 AUTH XOAUTH2（user+Bearer token 串形态校验通过）")
	}
	if srv.otherRejected {
		t.Errorf("不应尝试基本认证（该服务器仅宣告 XOAUTH2）")
	}
}
