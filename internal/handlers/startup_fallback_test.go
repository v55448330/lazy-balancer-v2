package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 2026-09-06 裁定 ③（last-known-good 启动兜底）：DB 渲染的配置在启动时被
// Caddy 拒绝（升级判定漂移、不变量破坏等残余场景）时，必须回退应用最后一
// 次成功下发的配置——负载均衡可用性优先，DB↔运行配置分叉仍由既有
// caddy_apply_error 标记与看门狗可见，等待人工修复。
func TestApplyConfigOnStartup_fallsBackToLastKnownGood(t *testing.T) {
	// Given：首次 /load 被拒（模拟 DB 渲染非法），落盘的 last-good 文件可用
	handler, loadCalls, lastLoad := newAuditRuleHandlers(t, 1)
	path := filepath.Join(t.TempDir(), "last_good.json")
	if err := os.WriteFile(path, []byte(`{"apps":{"fallback_marker":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	handler.caddyService.SetLastGoodPath(path)

	// When
	err := handler.ApplyConfigOnStartup()

	// Then：启动不报错，第二次 /load 收到的正是 last-good 文件内容
	if err != nil {
		t.Fatalf("startup should succeed via fallback, got: %v", err)
	}
	if n := loadCalls.Load(); n != 2 {
		t.Fatalf("loads=%d, want 2 (rejected DB render + fallback apply)", n)
	}
	if !strings.Contains(*lastLoad, "fallback_marker") {
		t.Fatalf("last load body=%s, want last-known-good content", *lastLoad)
	}
	var warns int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='启动警告' AND detail LIKE '%回退最后已知正确配置%'").Scan(&warns); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if warns != 1 {
		t.Fatalf("fallback warning audit rows=%d, want 1", warns)
	}
}
