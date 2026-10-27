package services

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/accesslog"
)

// 引擎侧 pin：Caddy 的 filter encoder 对字段路径做精确字符串查表，而日志里的
// 请求头键取自 http.Header 的原始键（net/textproto 规范化的 MIME 形态）。
// 因此「encoder 的删除键集合」必须覆盖「真实请求产生的头键」——本用例直接从
// http.Header 生成期望路径，而不是复制一个手写字面量（复制字面量正是此前
// 脱敏恒定空转的根因）。
func TestBuildAccessLogEncoder_deleteKeysCoverRealHeaderKeys(t *testing.T) {
	headerShapes := []struct {
		name   string
		header func(t *testing.T) http.Header
	}{
		{"set-uppercase", func(t *testing.T) http.Header {
			h := http.Header{}
			h.Set("X-API-Key", "lb_sk_probe")
			return h
		}},
		{"set-lowercase", func(t *testing.T) http.Header {
			h := http.Header{}
			h.Set("x-api-key", "lb_sk_probe")
			return h
		}},
		{"parsed-request", func(t *testing.T) http.Header {
			req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
				"GET / HTTP/1.1\r\nHost: redact.example.test\r\nX-API-Key: lb_sk_probe\r\n\r\n")))
			if err != nil {
				t.Fatalf("ReadRequest: %v", err)
			}
			return req.Header
		}},
	}
	for _, shape := range headerShapes {
		t.Run(shape.name, func(t *testing.T) {
			header := shape.header(t)
			fields := encoderFields(t, buildAccessLogEncoder(true, "request>remote_ip -> src"))
			checked := 0
			for key := range header {
				path := "request>headers>" + key
				rule, ok := fields[path].(map[string]interface{})
				if !ok {
					t.Fatalf("fields 缺少真实头键的脱敏行 %q: %v", path, fields)
				}
				if rule["filter"] != "delete" {
					t.Fatalf("%q 动作=%v, want delete", path, rule["filter"])
				}
				checked++
			}
			if checked != 1 {
				t.Fatalf("header 键数=%d, want 1（夹具失效，断言面无意义）", checked)
			}
		})
	}
}

// 旧模板/手写格式的字面量拼写（X-API-Key）与规范拼写是同一个 HTTP 头：
// 两者都要发射 delete（filter 精确匹配，多发射一条没有任何副作用），这样任何
// 代理/引擎改写出的拼写形态都不会漏网。
func TestBuildAccessLogEncoder_emitsBothHeaderSpellings(t *testing.T) {
	fields := encoderFields(t, buildAccessLogEncoder(false, ""))
	for _, path := range []string{"request>headers>X-Api-Key", "request>headers>X-API-Key"} {
		rule, ok := fields[path].(map[string]interface{})
		if !ok || rule["filter"] != "delete" {
			t.Fatalf("fields 缺少 %q 的 delete 规则: %v", path, fields)
		}
	}
	// 单源口径：规范形态就是 APIKeyHeaderPath()，不得与这里的手写期望分叉。
	if got := accesslog.APIKeyHeaderPath(); got != "request>headers>X-Api-Key" {
		t.Fatalf("APIKeyHeaderPath()=%q, want 规范化键形态", got)
	}
}
