package services

import (
	"os"
	"path/filepath"
	"testing"
)

// SECLB23-P1-1(第 23 轮审计):审计日志目录必须在首次 ApplyConfigOnStartup 前
// 保证存在——coraza v3.7.0 NewWAF→serialWriter.Init OpenFile 不建父目录,目录
// 缺失=Provision 致命=/load 拒收。导出 helper 供 main.go 启动早期调用。
func TestEnsureWafAuditDir_createsDirectory(t *testing.T) {
	// Given: 不存在的嵌套目录
	dir := filepath.Join(t.TempDir(), "logs", "waf-audit")
	oldPath := auditLogPath
	auditLogPath = filepath.Join(dir, "audit.log")
	t.Cleanup(func() { auditLogPath = oldPath })

	// When
	if err := EnsureWafAuditDir(); err != nil {
		t.Fatalf("EnsureWafAuditDir: %v", err)
	}

	// Then: 目录已创建
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("dir %s not created: %v", dir, err)
	}
	// 幂等:重复调用不报错
	if err := EnsureWafAuditDir(); err != nil {
		t.Fatalf("EnsureWafAuditDir second call: %v", err)
	}
}
