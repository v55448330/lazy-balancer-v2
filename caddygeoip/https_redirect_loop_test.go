package caddygeoip

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"testing"
)

// HTTP→HTTPS 跳转的两个运行时约束：
//   - 请求已经是 HTTPS（前置代理终止 TLS 后以明文回源）时不得再 301——同一
//     https 地址上的 301 就是浏览器里的无限跳转；改为 400 + 说明文字。
//   - 301 不得可缓存——跳转受规则开关控制，可缓存的 301 会让浏览器在开关
//     关闭后仍沿用旧跳转（「关了也没用」）。

func plainGet(t *testing.T, forwardedProto string) *http.Response {
	t.Helper()
	ln := newRedirectSplitListener(t, 666, []string{"shop.example.test"})
	startAccept(t, ln)

	client := dialRaw(t, ln)
	req, _ := http.NewRequest(http.MethodGet, "http://shop.example.test:666/page?x=1", nil)
	req.Host = "shop.example.test:666"
	if forwardedProto != "" {
		req.Header.Set("X-Forwarded-Proto", forwardedProto)
	}
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}
	return readResponse(t, client)
}

func TestHTTPSRedirectSplit_requestAlreadyHTTPSIsNotRedirectedAgain(t *testing.T) {
	resp := plainGet(t, "https")

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400（已是 HTTPS 的请求再 301 即无限跳转）", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("已是 HTTPS 的请求不得再下发 Location: %q", loc)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", cc)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("X-Forwarded-Proto")) {
		t.Fatalf("诊断页必须点明 X-Forwarded-Proto，实际: %q", body)
	}
}

func TestHTTPSRedirectSplit_plainHTTPStillRedirectsAndIsNotCacheable(t *testing.T) {
	for _, forwardedProto := range []string{"", "http", "http, https", "HTTP"} {
		resp := plainGet(t, forwardedProto)
		if resp.StatusCode != http.StatusMovedPermanently {
			t.Fatalf("X-Forwarded-Proto=%q: status=%d, want 301", forwardedProto, resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "https://shop.example.test:666/page?x=1" {
			t.Fatalf("X-Forwarded-Proto=%q: Location=%q", forwardedProto, loc)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("X-Forwarded-Proto=%q: Cache-Control=%q, want no-store", forwardedProto, cc)
		}
	}
}

func TestForwardedProtoIsHTTPS(t *testing.T) {
	// 以首个 token 为准：X-Forwarded-Proto 逐跳追加，首项是客户端实际协议。
	cases := map[string]bool{
		"":            false,
		"http":        false,
		"https":       true,
		"HTTPS":       true,
		"  https ":    true,
		"https, http": true,
		"https ,http": true,
		"http, https": false,
		"HTTP,https":  false,
		"ws":          false,
		",https":      false,
		"unlisted":    false,
	}
	for value, want := range cases {
		if got := ForwardedProtoIsHTTPS(value); got != want {
			t.Errorf("ForwardedProtoIsHTTPS(%q)=%v, want %v", value, got, want)
		}
	}
}

func TestForwardedProtoPatternMatchesGoJudgment(t *testing.T) {
	// 渲染层（services）用同一正则在路由匹配里判「已是 HTTPS」；这里的 Go 判据
	// 服务于监听包装器。两侧口径必须一致——逐 token 取值集合比对。
	pattern := regexp.MustCompile(forwardedHTTPSHeaderPattern)
	values := []string{"", "http", "https", "HTTPS", "  https ", "https, http", "https ,http",
		"http, https", "HTTP,https", "ws", ",https", "unlisted", "https,https"}
	for _, value := range values {
		want := ForwardedProtoIsHTTPS(value)
		if got := pattern.MatchString(value); got != want {
			t.Errorf("pattern/Go 判据不一致: %q pattern=%v go=%v", value, got, want)
		}
	}
}
