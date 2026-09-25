package main

// 第 55 轮 P3-3 RED：redirectHTTP 提取的 Host 行内裸 CR（TrimSpace 剔不掉
// 中置控制字符）原样拼入 Location 响应头——Host: evil\rX-Injected: 1 会把
// 注入头带进 301 响应。修复后：Host 含控制字符（<0x20 或 0x7f）视为无效，
// 回退 connection 本地地址（无注入面）。

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestRedirectHTTP_hostWithBareCRFallsBackToLocalAddr(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		redirectHTTP(bufio.NewReader(server), server)
		close(done)
	}()
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: evil\rX-Injected: 1\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	location := response.Header.Get("Location")
	if strings.Contains(location, "\r") || strings.Contains(location, "\n") {
		t.Fatalf("Location=%q 携带控制字符（头注入面未闭合）", location)
	}
	if strings.Contains(location, "evil") || strings.Contains(location, "X-Injected") {
		t.Fatalf("Location=%q 反射了含控制字符的 Host", location)
	}
	if !strings.HasPrefix(location, "https://") {
		t.Fatalf("Location=%q, want https:// 前缀（回退本地地址形态）", location)
	}
	_ = io.Closer(client).Close()
	<-done
}
