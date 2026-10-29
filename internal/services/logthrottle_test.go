package services

import (
	"testing"
	"time"
)

// LogThrottle/LogEscalation 是日志节流与留痕分级的单源结构（OIDC 状态降级、
// MFA step-up 未来时间戳、last_login 记账、OIDC 显示名刷新共用）。窗口语义与
// 升级语义在此钉住；各留痕点自己的回归门（节流计数/首条 error）在 handlers。

func TestLogThrottle_windowAdmission(t *testing.T) {
	var lt LogThrottle
	const window = 40 * time.Millisecond
	if !lt.Allow(window) {
		t.Fatal("first call must be admitted")
	}
	if lt.Allow(window) {
		t.Fatal("second call within window must be throttled")
	}
	time.Sleep(window + 10*time.Millisecond)
	if !lt.Allow(window) {
		t.Fatal("call after window must be admitted again")
	}
}

func TestLogThrottle_resetStartsNewWindow(t *testing.T) {
	var lt LogThrottle
	if !lt.Allow(time.Minute) {
		t.Fatal("first call must be admitted")
	}
	lt.Reset()
	if !lt.Allow(time.Minute) {
		t.Fatal("reset must admit the next call immediately")
	}
}

func TestLogEscalation_firstErrorThenWarnAndReset(t *testing.T) {
	var le LogEscalation
	if got := le.Level(); got != "error" {
		t.Fatalf("first failure level=%q, want error", got)
	}
	if got := le.Level(); got != "warn" {
		t.Fatalf("subsequent failure level=%q, want warn", got)
	}
	le.Reset()
	if got := le.Level(); got != "error" {
		t.Fatalf("failure after success level=%q, want error again", got)
	}
}
