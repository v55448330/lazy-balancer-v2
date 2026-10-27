package accesslog

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
)

// 规范路径必须与引擎实际看到的键逐字符相等：Caddy 的 filter encoder 用
// http.Header 的原键做精确查表，任何拼写差一位就意味着删除规则永不命中。
func TestAPIKeyHeaderPath_matchesCanonicalHTTPHeaderKey(t *testing.T) {
	cases := []struct {
		name  string
		build func() http.Header
	}{
		{"set-uppercase", func() http.Header {
			h := http.Header{}
			h.Set("X-API-Key", "lb_sk_x")
			return h
		}},
		{"set-lowercase", func() http.Header {
			h := http.Header{}
			h.Set("x-api-key", "lb_sk_x")
			return h
		}},
		{"parsed-request", func() http.Header {
			req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
				"GET / HTTP/1.1\r\nHost: example.test\r\nX-API-Key: lb_sk_x\r\n\r\n")))
			if err != nil {
				t.Fatalf("ReadRequest: %v", err)
			}
			return req.Header
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := tc.build()
			if len(header) != 1 {
				t.Fatalf("expected exactly one header, got %v", header)
			}
			for key := range header {
				if got, want := headerPathPrefix+key, APIKeyHeaderPath(); got != want {
					t.Fatalf("redaction path %q does not match engine header key %q (want %q)", got, key, want)
				}
			}
		})
	}
}

func TestAPIKeyHeaderPathIsCanonicalMIME(t *testing.T) {
	if got, want := APIKeyHeaderPath(), "request>headers>X-Api-Key"; got != want {
		t.Fatalf("canonical redaction path = %q, want %q", got, want)
	}
}

func TestAPIKeyHeaderPaths_coversCanonicalAndLiteral(t *testing.T) {
	paths := APIKeyHeaderPaths()
	want := []string{"request>headers>X-Api-Key", "request>headers>X-API-Key"}
	if len(paths) != len(want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("paths[%d] = %q, want %q", i, paths[i], want[i])
		}
	}
}

func TestIsAPIKeyPath(t *testing.T) {
	yes := []string{
		"request>headers>X-API-Key",
		"request>headers>X-Api-Key",
		"request>headers>x-api-key",
		"  request>headers>X-API-Key  ",
	}
	for _, path := range yes {
		if !IsAPIKeyPath(path) {
			t.Fatalf("IsAPIKeyPath(%q) = false, want true", path)
		}
	}
	no := []string{
		"",
		"request>headers",
		"request>headers>",
		"request>headers>X-API-Key-Extra",
		"request>headers>Authorization",
		"request>headers>X-Forwarded-For",
		"request>remote_ip",
		"headers>X-API-Key",
	}
	for _, path := range no {
		if IsAPIKeyPath(path) {
			t.Fatalf("IsAPIKeyPath(%q) = true, want false", path)
		}
	}
}
