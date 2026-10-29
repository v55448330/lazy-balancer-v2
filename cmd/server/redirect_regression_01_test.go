package main

// 缺失或畸形 Host 时不再回退监听地址（0.0.0.0 不可用），统一按 400 拒绝。

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// assertMalformedHostRejected 断言畸形/缺失 Host 的请求得到 400 且无 Location。
func assertMalformedHostRejected(t *testing.T, rawRequest string) {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		redirectHTTP(bufio.NewReader(server), server)
		close(done)
	}()
	if _, err := client.Write([]byte(rawRequest)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 (no valid Host must not reflect the bind address)", response.StatusCode)
	}
	if location := response.Header.Get("Location"); location != "" {
		t.Fatalf("Location=%q, want absent (must not reflect malformed/missing Host)", location)
	}
	_ = io.Closer(client).Close()
	<-done
}

func TestRedirectHTTP_hostWithBareCRRejected(t *testing.T) {
	assertMalformedHostRejected(t, "GET / HTTP/1.1\r\nHost: evil\rX-Injected: 1\r\n\r\n")
}

func TestRedirectHTTP_hostWithEmbeddedSpaceRejected(t *testing.T) {
	assertMalformedHostRejected(t, "GET / HTTP/1.1\r\nHost: evil .example.com\r\n\r\n")
}

// Location，跳转不可用；现按 400 拒绝。
func TestRedirectHTTP_missingHostRejected(t *testing.T) {
	assertMalformedHostRejected(t, "GET / HTTP/1.0\r\n\r\n")
}

// 回归形状：有效 Host 照常 302 到 https。
func TestRedirectHTTP_validHostStillRedirects(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		redirectHTTP(bufio.NewReader(server), server)
		close(done)
	}()
	if _, err := client.Write([]byte("GET /a?b=1 HTTP/1.1\r\nHost: public.example\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got := response.Header.Get("Location"); got != "https://public.example/a?b=1" {
		t.Fatalf("Location=%q", got)
	}
	if !strings.HasPrefix(response.Status, "302") {
		t.Fatalf("status=%q, want 302", response.Status)
	}
	_ = io.Closer(client).Close()
	<-done
}

type redirectMemoryConn struct {
	reader *strings.Reader
	output strings.Builder
}

func newRedirectMemoryConn(input string) *redirectMemoryConn {
	return &redirectMemoryConn{reader: strings.NewReader(input)}
}

func (c *redirectMemoryConn) Read(p []byte) (int, error)       { return c.reader.Read(p) }
func (c *redirectMemoryConn) Write(p []byte) (int, error)      { return c.output.Write(p) }
func (c *redirectMemoryConn) Close() error                     { return nil }
func (c *redirectMemoryConn) LocalAddr() net.Addr              { return nil }
func (c *redirectMemoryConn) RemoteAddr() net.Addr             { return nil }
func (c *redirectMemoryConn) SetDeadline(time.Time) error      { return nil }
func (c *redirectMemoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *redirectMemoryConn) SetWriteDeadline(time.Time) error { return nil }

func TestRedirectHTTPDrainsBoundedRequestBody(t *testing.T) {
	const bodySize = 8 * 1024
	request := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: public.example\r\nContent-Length: %d\r\n\r\n%s", bodySize, strings.Repeat("x", bodySize))
	connection := newRedirectMemoryConn(request)
	redirectHTTP(bufio.NewReader(connection), connection)
	if connection.reader.Len() != 0 {
		t.Fatalf("request body left unread: %d bytes", connection.reader.Len())
	}
	if !strings.HasPrefix(connection.output.String(), "HTTP/1.1 302 Found\r\n") {
		t.Fatalf("unexpected response: %q", connection.output.String())
	}
}

func TestRedirectHTTPEmptyBodyDoesNotWait(t *testing.T) {
	connection := newRedirectMemoryConn("GET / HTTP/1.1\r\nHost: public.example\r\n\r\n")
	redirectHTTP(bufio.NewReader(connection), connection)
	if !strings.HasPrefix(connection.output.String(), "HTTP/1.1 302 Found\r\n") {
		t.Fatalf("unexpected response: %q", connection.output.String())
	}
}
