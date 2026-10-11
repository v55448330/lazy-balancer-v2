package handlers

// LBH-B-L1（第 69 轮 P2）：UA 改名保护门只认精确路径——祖先改名
//（request>headers->hdrs 整树带走 User-Agent，filterencoder.go:466-471 引擎实证）
// 绕过校验，UA 统计静默失效。钉三形状：祖先改名/根改名/精确改名全拒。
// 回归：合法改名（remote_ip→src）与无关改名放行。

import (
	"strings"
	"testing"
)

func TestValidateAccessLogFormat_rejectsUARenameIncludingAncestors(t *testing.T) {
	cases := []struct {
		name    string
		format  string
		wantErr string
	}{
		{"祖先 headers 整树改名", "request>headers -> hdrs", "User-Agent"},
		{"精确 UA 改名", "request>headers>User-Agent -> ua", "User-Agent"},
		{"根 request 整树改名", "request -> req", "统计"}, // 由 remote_ip 门先行拦截（文案不含 UA），拒绝即正确
		{"合法 remote_ip→src 放行", "request>remote_ip -> src", ""},
		{"合法 uri→uri_path 放行", "request>uri -> uri_path", ""},
		{"无关字段改名放行", "request>host -> h", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAccessLogFormat(tc.format)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("format %q must pass, got %v", tc.format, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("format %q must reject with %q, got %v", tc.format, tc.wantErr, err)
			}
		})
	}
}
