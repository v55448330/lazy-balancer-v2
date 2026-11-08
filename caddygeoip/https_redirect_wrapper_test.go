package caddygeoip

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// 同端口明文跳转包装器行为验收（引擎级 validate 由 services 引擎验收族
// 覆盖，运行时 E2E 由容器验证链覆盖）：
//   - TLS 首字节（0x16）连接：透传且首字节重放（握手完整性）
//   - 白名单 Host 明文 GET：301 → https://同域名:目标端口（保留 path+query）
//   - 白名单外 Host / 解析失败：Go 标准文案 400（fail-closed）

func newRedirectSplitListener(t *testing.T, httpsPort int, domains []string) net.Listener {
	t.Helper()
	p := &HTTPSRedirectSplitWrapper{HTTPSPort: httpsPort, Domains: domains}
	ctx, cancel := caddy.NewContextWithCause(caddy.Context{Context: context.Background()})
	t.Cleanup(func() { cancel(nil) })
	if err := p.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = base.Close() })
	return p.WrapListener(base)
}

// startAccept 启动包装器 Accept 循环：明文连接由包装器内部 goroutine 就地
// 应答（Accept 不返回），TLS 连接送入通道供断言。通道不 drain——Accept 依赖
// base.Close 退出，而 Cleanup 后进先出要求 base.Close 先于任何读取方收尾；
// 遗留 goroutine 随测试进程退出回收。
func startAccept(t *testing.T, ln net.Listener) <-chan net.Conn {
	t.Helper()
	tlsCh := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			tlsCh <- conn
		}
	}()
	return tlsCh
}

func dialRaw(t *testing.T, ln net.Listener) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func readResponse(t *testing.T, conn net.Conn) *http.Response {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

func TestHTTPSRedirectSplit_tlsHandshakeBytesPassThroughWithReplay(t *testing.T) {
	ln := newRedirectSplitListener(t, 666, []string{"shop.example.test"})
	tlsCh := startAccept(t, ln)

	client := dialRaw(t, ln)
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x2f}
	if _, err := client.Write(hello); err != nil {
		t.Fatal(err)
	}

	var conn net.Conn
	select {
	case conn = <-tlsCh:
	case <-time.After(3 * time.Second):
		t.Fatal("TLS 连接未在超时内透传")
	}
	got := make([]byte, len(hello))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("replay read: %v", err)
	}
	for i := range hello {
		if got[i] != hello[i] {
			t.Fatalf("首字节重放失真: got=%v want=%v", got, hello)
		}
	}
}

func TestHTTPSRedirectSplit_whitelistedHostRedirects301(t *testing.T) {
	ln := newRedirectSplitListener(t, 666, []string{"shop.example.test"})
	startAccept(t, ln)

	client := dialRaw(t, ln)
	req, _ := http.NewRequest(http.MethodGet, "http://shop.example.test:666/page?x=1", nil)
	req.Host = "shop.example.test:666"
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}
	resp := readResponse(t, client)
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status=%d, want 301", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://shop.example.test:666/page?x=1" {
		t.Fatalf("Location=%q, want https://shop.example.test:666/page?x=1（保留 path+query）", loc)
	}
}

func TestHTTPSRedirectSplit_nonWhitelistedHostRejects400(t *testing.T) {
	ln := newRedirectSplitListener(t, 666, []string{"shop.example.test"})
	startAccept(t, ln)

	client := dialRaw(t, ln)
	req, _ := http.NewRequest(http.MethodGet, "http://evil.example.test:666/", nil)
	req.Host = "evil.example.test:666"
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}
	resp := readResponse(t, client)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400（白名单外 Host 必须拒绝，不得反射开放重定向）", resp.StatusCode)
	}
}

// Host 未带端口（非浏览器客户端形态）：301 目标必须补 https 端口。
func TestHTTPSRedirectSplit_hostWithoutPortGetsPortAppended(t *testing.T) {
	ln := newRedirectSplitListener(t, 666, []string{"shop.example.test"})
	startAccept(t, ln)

	client := dialRaw(t, ln)
	req, _ := http.NewRequest(http.MethodGet, "http://shop.example.test/a", nil)
	req.Host = "shop.example.test"
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}
	resp := readResponse(t, client)
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status=%d, want 301", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://shop.example.test:666/a" {
		t.Fatalf("Location=%q, want https://shop.example.test:666/a（Host 缺端口时补目标端口）", loc)
	}
}
