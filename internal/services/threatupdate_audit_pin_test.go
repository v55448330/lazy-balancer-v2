package services

// 历史 修复钉：更新族审计单记+操作者归人。
// threat 族零源路径（成功早退）为可测最小形：一次 run 恰一条审计、
// operator 经 RunContext 流入审计 username。
// 隔离：三源种子默认 update_enabled=1 且 URL 为外网——必须
// 显式禁用（零源早退语义）+ URL 指回环桩（双保险零外网）+ waf/日志目录
// 注入临时目录 + 重试等待桩化，否则真网络下载+真 /app 写+30s/60s 真睡。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func countThreatAudits(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE resource='威胁情报库'`).Scan(&n); err != nil {
		t.Fatalf("count audits: %v", err)
	}
	return n
}

// Given 零启用源的威胁库（run 走成功早退）。
// When 经 RunContext 带 operator 执行一次 RunUpdate("manual")。
// Then 恰落 1 条审计（曾 defer+端点补记 2-3 条），且
// username=operator（曾恒 system，手动操作无法追责）。
func TestThreatRunUpdate_SingleAuditWithOperator(t *testing.T) {
	overrideWafDirForTest(t)
	stubUpdateRetrySleep(t)
	setupIsolatedDB(t)
	// 三源 URL 指回环桩（双保险：即使误启用也不触外网），随后禁用全部源
	// ——「零启用源」非默认形态（种子默认 update_enabled=1），须显式落实。
	setupThreatTest(t, nil, nil, nil)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=0`); err != nil {
		t.Fatalf("disable threat sources: %v", err)
	}
	m := GetThreatUpdateManager()
	if err := m.RunUpdate("manual", &taskengine.RunContext{Operator: "alice"}); err != nil {
		t.Fatalf("RunUpdate: %v", err)
	}
	if got := countThreatAudits(t); got != 1 {
		t.Fatalf("一次 run 应恰 1 条审计（单记口径）, got %d", got)
	}
	var user string
	if err := db.AuditDB.QueryRow(`SELECT username FROM audit_log WHERE resource='威胁情报库'`).Scan(&user); err != nil {
		t.Fatal(err)
	}
	if user != "alice" {
		t.Fatalf("审计 username 应为 operator=alice, got %q", user)
	}
}
