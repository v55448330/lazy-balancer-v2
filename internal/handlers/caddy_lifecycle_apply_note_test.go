package handlers

import (
	"strings"
	"testing"
)

func TestCaddyLifecycleApplyFailureMessage_reportsFailureOnce(t *testing.T) {
	note := "；但 Caddy 配置应用失败：dial tcp: connection refused"
	for _, action := range []string{"Caddy 已启动", "Caddy 已重启"} {
		message := caddyLifecycleApplyFailureMessage(action, note)
		if got := strings.Count(message, "Caddy 配置应用失败"); got != 1 {
			t.Fatalf("%s message=%q, 配置应用失败出现 %d 次, want 1", action, message, got)
		}
		if !strings.HasPrefix(message, action+"；但 Caddy 配置应用失败：") {
			t.Fatalf("message=%q, want 动作句首+统一失败后缀", message)
		}
	}
}
