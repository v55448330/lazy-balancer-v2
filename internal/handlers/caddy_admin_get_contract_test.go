package handlers

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// 非标准 Transport（测试注入/未来代理中间件）可能给出 200 + nil Body。
// caddyAdminGet 的成功响应契约必须单侧成立：要么返回非 nil Body，要么
// 调用方（caddyAdminReady / GetCaddyStatus / GetCaddyConfig）的无条件
// Close 会 nil 解引用 panic。统一收敛为 http.NoBody。
type nilBodyRoundTripper struct{}

func (nilBodyRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: nil}, nil
}

func TestCaddyAdminGetSuccessAlwaysHasCloseableBody(t *testing.T) {
	withIsolatedGlobal(t)
	previous := caddyAdminHTTPClient
	caddyAdminHTTPClient = &http.Client{Transport: nilBodyRoundTripper{}}
	t.Cleanup(func() { caddyAdminHTTPClient = previous })

	resp, err := caddyAdminGet(context.Background(), "http://127.0.0.1:2019", "/config/", time.Second)
	if err != nil {
		t.Fatalf("caddyAdminGet: %v", err)
	}
	if resp == nil {
		t.Fatal("caddyAdminGet 返回 nil 响应且 err=nil")
	}
	if resp.Body == nil {
		t.Fatal("成功响应 Body=nil——三个调用方无条件 Close 会 nil 解引用 panic")
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
