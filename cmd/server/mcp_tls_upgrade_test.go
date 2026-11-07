package main

// 真实 TLS 升级链联测：明文 tools/call → 真实
// newHTTPRedirectMux 302（此前所有测试只 mock 301，给了假绿）→ MCP 内部
// 转发按原方法/原请求体重放 https。重放集合缺 302 时本测试拿到 {} 错误。
// 生产回环客户端（middleware.LoopbackAPIClient）必须信任面板自签证书，
// 否则该重放会以 x509 不受信任失败——测试只用生产客户端，不自注入旁路。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/mcpserver"
	"lazy-balancer-v2/internal/middleware"
)

// selfSignedTestCert 生成测试用自签证书：生产回环客户端显式豁免回环自签
// 证书校验，因此该证书不被任何公共根信任，正是面板 selfsigned 形态。
func selfSignedTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestMCPForwardFollowsRealMux302PreservingMethodBodyAndHeaders(t *testing.T) {
	// Given：真实 newHTTPRedirectMux + TLS 面板端点（生产 ServeTLS 同构）。
	wantBody := `{"caddy_id":"rule-1","domain":"example.com"}`
	var gotMethod, gotPath, gotBody, gotAPIKey, gotInternalAuth, gotClientIP string
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAPIKey = r.Header.Get("X-API-Key")
		gotInternalAuth = r.Header.Get(mcpserver.InternalAuthHeader)
		gotClientIP = r.Header.Get(mcpserver.InternalClientIPHeader)
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := newHTTPRedirectMux(listener)
	cert := selfSignedTestCert(t)
	server := &http.Server{
		Handler: api,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}
	tlsListener := tls.NewListener(mux, server.TLSConfig)
	go func() { _ = server.Serve(tlsListener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = mux.Close()
	})

	// 必须锚定生产回环客户端（middleware.LoopbackAPIClient，由 SetupRouter
	// 注入 MCP 转发链）——用测试自注入的「跳过校验」客户端只能证明重放逻辑，
	// 不能证明生产 TLS 行为（曾因此让自签 HTTPS 下的回环重放缺陷假绿）。
	handler := mcpserver.NewWithInternalAuth(fmt.Sprintf("http://%s/api/v1", listener.Addr().String()), middleware.LoopbackAPIClient(), "tls-upgrade-internal-secret", "")

	// When：经 MCP 信封调用 POST 工具——转发层先以 http 明文命中嗅探层 302。
	envelope := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_certificate","arguments":` + wantBody + `}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(envelope))
	request = request.WithContext(mcpserver.WithClientIP(request.Context(), "192.0.2.44"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-API-Key", "lb_sk_tls-upgrade-test")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	// Then：302 被按原方法/原请求体重放到 https，面板端点收到完整请求。
	if !strings.Contains(recorder.Body.String(), `\"ok\":true`) {
		t.Fatalf("result=%q（真实 mux 302 必须被跟随重放）", recorder.Body.String())
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/certificates/issue" || gotBody != wantBody {
		t.Fatalf("重放请求失真: method=%s path=%s body=%q", gotMethod, gotPath, gotBody)
	}
	if gotAPIKey != "lb_sk_tls-upgrade-test" || gotInternalAuth != "tls-upgrade-internal-secret" || gotClientIP != "192.0.2.44" {
		t.Fatalf("重放认证/审计头失真: api_key=%q internal_auth=%q client_ip=%q", gotAPIKey, gotInternalAuth, gotClientIP)
	}
}
