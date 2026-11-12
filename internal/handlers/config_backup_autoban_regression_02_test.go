package handlers

// 对 security_ip_lists 全量替换（DELETE 全表+插备份行），但内存 autobanWindows
// 保留旧计数桶：还原旧备份后 ≤1 tick 内零新流量重封已被「替换掉」的 IP（与
// 「删除即解封」同型撤销，两接线点不覆盖导入面）。
//
// 修复口径（Ruling，2026-10-15 主审裁定）：导入 commit 成功后
// services.ResetAutobanCounters 整体清桶，而非按名单差集 AutobanForgetIPs——
// 导入是全量替换语义：导入后名单世界=备份行集合（预置名单可缺席/换 id/换条目），
// 旧计数桶的全部前提（窗口内累计行为对导入后名单仍构成候选）失效；差集方案需
// 跨事务快照旧条目+解析备份 entries+按值比对，且无法覆盖「预置名单随备份整体
// 消失」形态，复杂而不更正确。Reset 代价=未受导入影响的 IP 计数清零重新累计
// （观察态一个窗口内自愈，≤5min），正确性优先简单性。
//
// 门控：仅备份实际携带 security_ip_lists（全量替换发生）时清桶——迟到表
// 「缺席=保留本地」形态下本地名单未动，计数桶保留（对照组钉死，防过度清）。
// 预览端（ValidateConfigImport）零写入语义、不发生替换，不接清桶。

import (
	"encoding/json"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// completeBackupJSONOmit completeBackupJSON 的缺席表变体：omit 中的表不出现在
// 备份体（迟到表「缺席=保留本地」形态），校验和按实际表集合计算。
func completeBackupJSONOmit(t *testing.T, omit map[string]struct{}, tables map[string][]map[string]any) string {
	t.Helper()
	completeTables := make(map[string][]map[string]any, len(configBackupTables))
	for _, table := range configBackupTables {
		if _, skip := omit[table]; skip {
			continue
		}
		completeTables[table] = []map[string]any{}
	}
	completeTables["users"] = []map[string]any{{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	for table, rows := range tables {
		completeTables[table] = rows
	}
	cfg := map[string]any{}
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-08-19T00:00:00Z"},
		Config: cfg,
		Tables: completeTables,
	}
	backup.Meta.Checksum = checksumBackupPayload(t, completeTables, cfg)
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	return string(data)
}

func enableAutobanFormalMode(t *testing.T) {
	t.Helper()
	if err := services.SetAutobanConfig(services.AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked,logged", DryRun: false}); err != nil {
		t.Fatalf("enable autoban: %v", err)
	}
}

func presetListContains(t *testing.T, ip string) bool {
	t.Helper()
	entries, _, err := services.AutobanListEntries()
	if err != nil {
		t.Fatalf("read preset list: %v", err)
	}
	for _, e := range entries {
		if e.Value == ip {
			return true
		}
	}
	return false
}

// Given 自动封禁启用（正式模式、阈值 1），IP 已达阈值计数；备份携带
// security_ip_lists（预置名单行，条目不含该 IP）。
// When 导入 commit 成功。
// Then 计数桶必须清零（直接断言），且零新流量跑一轮不得把该 IP 重封（行为
// 断言——旧实现无导入面清桶，两断言皆红）。
func TestImportConfigBackup_resetsAutobanCountersOnListsReplacement(t *testing.T) {
	h := newBackupTestHandlers(t)
	enableAutobanFormalMode(t)
	services.AutobanSeedCounterForTest("203.0.113.77", 3, 1)
	if got := services.AutobanTrackedIPs(); got != 1 {
		t.Fatalf("前置计数桶=%d, want 1", got)
	}

	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_ip_lists": {
			{"id": 1, "name": services.AutobanPresetListName, "category": "自动封禁", "description": "自动封禁命中 IP", "entries": "[]", "system": 1},
		},
	})
	response := postBackupImport(t, h, backup)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	// 直接断言：导入 commit 后计数桶清零
	if got := services.AutobanTrackedIPs(); got != 0 {
		t.Fatalf("导入 commit 后 autoban 计数桶=%d, want 0（备份导入面未接清桶：还原旧备份后零新流量 ≤1 tick 重封）", got)
	}
	// 行为断言：零新流量跑一轮，该 IP 不得进预置名单
	if err := services.RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("autoban cycle: %v", err)
	}
	if presetListContains(t, "203.0.113.77") {
		t.Fatal("导入替换名单后零新流量一轮不得重封 203.0.113.77（旧计数桶未随导入清零）")
	}
}

// 对照组：备份未携带 security_ip_lists（迟到表「缺席=保留本地」）——本地名单
// 未发生替换，计数桶必须原样保留（防清桶门控过宽误清观察态）。
func TestImportConfigBackup_keepsAutobanCountersWhenListsNotCarried(t *testing.T) {
	h := newBackupTestHandlers(t)
	enableAutobanFormalMode(t)
	services.AutobanSeedCounterForTest("203.0.113.77", 3, 1)

	backup := completeBackupJSONOmit(t, map[string]struct{}{"security_ip_lists": {}}, nil)
	response := postBackupImport(t, h, backup)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if got := services.AutobanTrackedIPs(); got != 1 {
		t.Fatalf("缺席表导入不得清计数桶，tracked=%d, want 1（「缺席=保留本地」语义）", got)
	}
}
