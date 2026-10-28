package handlers

// 备份导入（含自动备份还原）用通用
// `UPDATE global_config SET …` 直接写 `autoban_*` 六列，绕过
// `services.SetAutobanConfig` 的运行期收敛不变量——
//   - 统计窗口/口径变更 → 清空固定窗口计数桶（旧计数不可与新口径混算）；
//   - 阈值变更 → 重算「已达阈值」标记；
//   - 禁用（enabled 1→0）→ 到期条目解封收尾 + 清桶（停用期无喂入，陈旧桶
//     会让重新启用后零新流量立即批量封禁）。
//
// 既有唯一清桶门只覆盖「备份携带 security_ip_lists（全量替换）」形态：
// 只导「系统数据」（备份含 global_config 而不含名单迟到表）时六列被改写、
// 计数桶原样保留 → ≤60s 后的评估轮把陈旧计数按新窗口整批并入封禁候选。
//
// 修复口径：提交成功后按「导入前后六列是否变化」执行与 SetAutobanConfig
// 同源的收敛（单源 services.ReconcileAutobanRuntimeAfterConfigReplace），
// 结论并入响应 warnings 与成功审计。

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// autobanRuntimeImportBackup 构造「分类导入」形态的备份：omit 中的表不出现在
// 备份体（迟到表「缺席=保留本地」），cfg 为 global_config 携带的键值。
func autobanRuntimeImportBackup(t *testing.T, omit map[string]struct{}, cfg map[string]any) string {
	t.Helper()
	tables := make(map[string][]map[string]any, len(configBackupTables))
	for _, table := range configBackupTables {
		if _, skip := omit[table]; skip {
			continue
		}
		tables[table] = []map[string]any{}
	}
	tables["users"] = []map[string]any{{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-10-27T00:00:00Z"},
		Config: cfg,
		Tables: tables,
	}
	backup.Meta.Checksum = checksumBackupPayload(t, tables, cfg)
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	return string(data)
}

// Given 自动封禁启用（正式模式、阈值 1、窗口 5 分钟）且已有计数桶。
// When 导入「系统数据」分类备份（含 global_config、不含 security_ip_lists），
// 备份把窗口改为 1 分钟。
// Then 提交后计数桶必须清零（旧计数不得按新窗口参与候选评估），且响应
// warnings 披露该收敛；对照组（六列未变化的导入）不得清桶。
func TestImportConfigBackup_resetsAutobanCountersOnConfigChange(t *testing.T) {
	h := newBackupTestHandlers(t)
	enableAutobanFormalMode(t) // enabled=true / threshold=1 / window=5 / all / 正式
	services.AutobanSeedCounterForTest("203.0.113.77", 3, 1)
	if got := services.AutobanTrackedIPs(); got != 1 {
		t.Fatalf("前置计数桶=%d, want 1", got)
	}

	backup := autobanRuntimeImportBackup(t, map[string]struct{}{"security_ip_lists": {}}, map[string]any{
		"autoban_enabled": true, "autoban_threshold": 1, "autoban_window_minutes": 1,
		"autoban_duration": "1h", "autoban_scope": "all", "autoban_dry_run": false,
	})
	response := postBackupImport(t, h, backup)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	var storedWindow int
	if err := db.DB.QueryRow(`SELECT COALESCE(autoban_window_minutes,0) FROM global_config WHERE id=1`).Scan(&storedWindow); err != nil {
		t.Fatalf("read autoban_window_minutes: %v", err)
	}
	if storedWindow != 1 {
		t.Fatalf("autoban_window_minutes=%d, want 1（前置：六列确实随导入落库）", storedWindow)
	}
	if got := services.AutobanTrackedIPs(); got != 0 {
		t.Fatalf("导入提交后 autoban 计数桶=%d, want 0（口径/窗口变更必须清桶：陈旧计数会被新窗口整批并入封禁候选）", got)
	}
	if body := response.Body.String(); !strings.Contains(body, "自动封禁") {
		t.Fatalf("响应体=%s, want 含自动封禁运行期收敛披露", body)
	}
}

// 对照组：备份携带的六列与当前运行值完全一致 → 运行期状态不得被清
// （防过度清桶把观察态证据无谓丢弃）。
func TestImportConfigBackup_keepsAutobanCountersWhenConfigUnchanged(t *testing.T) {
	h := newBackupTestHandlers(t)
	enableAutobanFormalMode(t)
	services.AutobanSeedCounterForTest("203.0.113.77", 3, 1)

	backup := autobanRuntimeImportBackup(t, map[string]struct{}{"security_ip_lists": {}}, map[string]any{
		"autoban_enabled": true, "autoban_threshold": 1, "autoban_window_minutes": 5,
		"autoban_duration": "1h", "autoban_scope": "all", "autoban_dry_run": false,
	})
	response := postBackupImport(t, h, backup)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if got := services.AutobanTrackedIPs(); got != 1 {
		t.Fatalf("六列未变化的导入不得清计数桶，tracked=%d, want 1", got)
	}
}

// 对照组：备份根本未携带 global_config（Config=nil）→ 六列不可能变化，
// 不得触碰运行期状态。
func TestImportConfigBackup_keepsAutobanCountersWhenConfigNotCarried(t *testing.T) {
	h := newBackupTestHandlers(t)
	enableAutobanFormalMode(t)
	services.AutobanSeedCounterForTest("203.0.113.77", 3, 1)

	backup := autobanRuntimeImportBackup(t, map[string]struct{}{"security_ip_lists": {}}, nil)
	response := postBackupImport(t, h, backup)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if got := services.AutobanTrackedIPs(); got != 1 {
		t.Fatalf("未携带全局配置的导入不得清计数桶，tracked=%d, want 1", got)
	}
}

// Given 自动封禁启用、计数桶非空、预置名单含已到期的自动条目。
// When 导入把 autoban_enabled 改为 false（其余五列不变）。
// Then 提交后执行禁用收尾：过期时间戳清空、计数桶清零、名单内到期条目解封
// ——停用数周后重新启用不得以陈旧计数/陈旧条目立即封禁。
func TestImportConfigBackup_disableThroughImportRunsDisableFlush(t *testing.T) {
	h := newBackupTestHandlers(t)
	enableAutobanFormalMode(t)
	services.AutobanSeedCounterForTest("203.0.113.77", 3, 1)

	expiredEntry := `[{"value":"198.51.100.9","remark":"自动封禁","created_at":"2026-10-01 00:00:00","expires_at":"2026-10-02 00:00:00"}]`
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=? WHERE name=?`, expiredEntry, services.AutobanPresetListName); err != nil {
		t.Fatalf("seed preset entries: %v", err)
	}

	backup := autobanRuntimeImportBackup(t, map[string]struct{}{"security_ip_lists": {}}, map[string]any{
		"autoban_enabled": false, "autoban_threshold": 1, "autoban_window_minutes": 5,
		"autoban_duration": "1h", "autoban_scope": "all", "autoban_dry_run": false,
	})
	response := postBackupImport(t, h, backup)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	var enabled int
	if err := db.DB.QueryRow(`SELECT COALESCE(autoban_enabled,1) FROM global_config WHERE id=1`).Scan(&enabled); err != nil {
		t.Fatalf("read autoban_enabled: %v", err)
	}
	if enabled != 0 {
		t.Fatalf("autoban_enabled=%d, want 0（前置：导入确实停用）", enabled)
	}
	if got := services.AutobanTrackedIPs(); got != 0 {
		t.Fatalf("导入停用后计数桶=%d, want 0（禁用收尾必须清桶）", got)
	}
	if presetListContains(t, "198.51.100.9") {
		t.Fatal("导入停用后已到期条目必须解封（AutobanDisableFlush 禁用收尾）")
	}
	if body := response.Body.String(); !strings.Contains(body, "自动封禁") {
		t.Fatalf("响应体=%s, want 含自动封禁停用收尾披露", body)
	}
}
