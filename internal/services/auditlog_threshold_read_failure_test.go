package services

// 审计日志轮转阈值读取失败的可观测契约：回退 10MB 当轮生效、失败值不进缓存
// （下一轮重试能拿到真实配置）、留痕按状态转换去重（连续失败只首报一条 warn，
// 恢复补一条 info）——此前读失败静默回退，面板配置长期形同虚设且零信号。

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// resetLogStateTransitionForTest 清空状态转换记录（同一 key 的状态跨用例共享）。
func resetLogStateTransitionForTest(key string) {
	metricsStateMu.Lock()
	delete(metricsStateFailed, key)
	metricsStateMu.Unlock()
}

func captureServiceLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buffer := &bytes.Buffer{}
	oldWriter := log.Writer()
	log.SetOutput(buffer)
	t.Cleanup(func() { log.SetOutput(oldWriter) })
	return buffer
}

func countLogLines(logs *bytes.Buffer, fragments ...string) int {
	count := 0
	for _, line := range strings.Split(logs.String(), "\n") {
		matched := true
		for _, fragment := range fragments {
			if !strings.Contains(line, fragment) {
				matched = false
				break
			}
		}
		if matched && strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func TestAuditLogThresholdReadFailure_fallsBackWithoutCachingAndWarnsOnce(t *testing.T) {
	initServicesDB(t)
	const cacheKey = "audit-log-size-refresh"
	resetLogStateTransitionForTest(cacheKey)
	auditLogSizeValueCache.invalidate()
	t.Cleanup(func() {
		auditLogSizeValueCache.invalidate()
		resetLogStateTransitionForTest(cacheKey)
	})
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_log_size_mb=42 WHERE id=1`); err != nil {
		t.Fatalf("seed audit log size: %v", err)
	}
	logs := captureServiceLog(t)

	// Given 配置读取失败（表不可见 = 库故障/迁移窗口形态）。
	if _, err := db.DB.Exec(`ALTER TABLE global_config RENAME TO global_config_unavailable`); err != nil {
		t.Fatalf("simulate read failure: %v", err)
	}

	// When 连续两轮读取阈值。
	first := getAuditLogSizeBytesContext(context.Background())
	second := getAuditLogSizeBytesContext(context.Background())

	// Then 两轮都回退默认 10MB，且只有一个状态转换 warn（持续失败不刷屏）。
	const fallback = 10 * 1024 * 1024
	if first != fallback || second != fallback {
		t.Fatalf("read failure fallback=(%d,%d), want 10MB each", first, second)
	}
	if warns := countLogLines(logs, "读取审计日志轮转阈值失败"); warns != 1 {
		t.Fatalf("read failure warn lines=%d, want 1（状态转换去重）; logs=%s", warns, logs.String())
	}

	// When 配置表恢复可读。
	if _, err := db.DB.Exec(`ALTER TABLE global_config_unavailable RENAME TO global_config`); err != nil {
		t.Fatalf("restore config table: %v", err)
	}

	// Then 下一轮读取直接得到配置值 42MB——失败回退值没有被缓存进 TTL 窗口。
	if got := getAuditLogSizeBytesContext(context.Background()); got != 42*1024*1024 {
		t.Fatalf("after recovery size=%d, want 42MB（失败值不得缓存，必须重试）", got)
	}
	if infos := countLogLines(logs, "读取审计日志轮转阈值已恢复"); infos != 1 {
		t.Fatalf("recovery info lines=%d, want 1; logs=%s", infos, logs.String())
	}

	// Then 恢复后的值进入缓存：再次读库失败也不应回退（60s 窗口内沿用有效值）。
	if _, err := db.DB.Exec(`ALTER TABLE global_config RENAME TO global_config_unavailable`); err != nil {
		t.Fatal(err)
	}
	if got := getAuditLogSizeBytesContext(context.Background()); got != 42*1024*1024 {
		t.Fatalf("cached value after successful load=%d, want 42MB", got)
	}
}
