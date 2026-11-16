package handlers

//   受信代理导入门按「备份是否携带 security_ip_lists 表」分流
//     携带时 refs 存在性仅按备份行集合解析（全量替换先例：备份行才是
//     导入后的真实数据），指向库内但不在备份内的 id 导入后必然悬空 → 400；
//     未携带时照旧走库（迟到表 era 备份/「缺席=保留本地」语义不变）。
//   /security/autoban/status 响应补 is_master/role（从端卡片角色门
//     数据源）；list_entries 与渲染生效面同口径（剔除已到期未清理）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// noIPListsBackupJSON 构造不含 security_ip_lists 键的 Version=2
// 备份 JSON（迟到表 era 形态——夹具恒按 configBackupTables 补全表集，
// 「表未携带」形态须自组表集），users 恒含一个启用管理员（过管理员门）。
func noIPListsBackupJSON(t *testing.T, cfg map[string]any) string {
	t.Helper()
	return buildBackup(t, backupFixtureOptions{FillAll: true, Omit: map[string]struct{}{"security_ip_lists": {}}, Config: cfg})
}

// TestImportConfigBackup_trustedProxyRefsResolvedAgainstBackupRowsOnly
// 备份携带名单表时，refs 存在性仅按备份行集合解析——指向库内存量（导入后被
// 全量替换掉）的 id 必须 400 拒绝，不得借「备份∪库」通道放行为导入后悬空引用。
func TestImportConfigBackup_trustedProxyRefsResolvedAgainstBackupRowsOnly(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedCurrentAdminShared(t)
	// 库内存量名单 #7（不在备份内）；备份携带名单表（仅 #1）。
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id, name, entries) VALUES (7, 'db-only-list', '[]')`); err != nil {
		t.Fatal(err)
	}

	t.Run("携表备份 refs 指向库内不在备份内必须 400", func(t *testing.T) {
		backup := configBackupJSON(t, map[string][]map[string]any{
			"security_ip_lists": {{"id": 1, "name": "backup-list", "entries": `[{"value":"203.0.113.0/24","remark":""}]`}},
		}, map[string]any{
			"trusted_proxy_ranges":     `["198.51.100.0/24"]`,
			"trusted_proxy_range_refs": "[7]",
		})
		response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "不存在") {
			t.Fatalf("status=%d body=%s, want 400 不存在（名单表随备份全量替换，库内 #7 导入后必然悬空）", response.Code, response.Body.String())
		}
		var refs string
		if err := db.DB.QueryRow(`SELECT COALESCE(trusted_proxy_range_refs,'[]') FROM global_config WHERE id=1`).Scan(&refs); err != nil {
			t.Fatal(err)
		}
		if refs == "[7]" {
			t.Fatal("被拒导入不得落库悬空 refs")
		}
	})

	t.Run("携表备份 refs 指向备份内名单照常放行", func(t *testing.T) {
		backup := configBackupJSON(t, map[string][]map[string]any{
			"security_ip_lists": {{"id": 1, "name": "backup-list", "entries": `[{"value":"203.0.113.0/24","remark":""}]`}},
		}, map[string]any{
			"trusted_proxy_ranges":     `["198.51.100.0/24"]`,
			"trusted_proxy_range_refs": "[1]",
		})
		response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200（备份内名单可解析，跨节点还原不误拒）", response.Code, response.Body.String())
		}
	})

	t.Run("未携名单表 refs 走库（缺席=保留本地）", func(t *testing.T) {
		// 上一子用例的导入曾全量替换名单表——重种库内存量 #7。
		if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id, name, entries) VALUES (7, 'db-only-list', '[]')`); err != nil {
			t.Fatal(err)
		}
		// 表集不含 security_ip_lists（迟到表 era 形态——夹具恒补全表集，
		// 表缺失须自组表集构造）。
		backup := noIPListsBackupJSON(t, map[string]any{
			"trusted_proxy_ranges":     `["198.51.100.0/24"]`,
			"trusted_proxy_range_refs": "[7]",
		})
		response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200（表未携带=导入后名单表保持本地，库内 #7 仍存在）", response.Code, response.Body.String())
		}
	})
}

// TestGetAutobanStatus_roleFieldsAndActiveCaliber：status 响应
// 补 is_master/role（引擎未装配时保守判从——不提供会在从端 403 的写入口）；
// list_entries 剔除已到期未清理条目（与渲染生效面同口径）。
func TestGetAutobanStatus_roleFieldsAndActiveCaliber(t *testing.T) {
	router := newAutobanTestEnv(t)
	now := time.Now().UTC()
	seedAutobanListEntries(t, fmt.Sprintf(`[
		{"value":"203.0.113.1","remark":"自动封禁","created_at":"%s","expires_at":"%s"},
		{"value":"203.0.113.2","remark":"自动封禁","created_at":"%s","expires_at":"%s"},
		{"value":"198.51.100.1","remark":"","created_at":"%s"}
	]`,
		now.Add(-time.Hour).Format("2006-01-02 15:04:05"), now.Add(24*time.Hour).Format("2006-01-02 15:04:05"),
		now.Add(-2*time.Hour).Format("2006-01-02 15:04:05"), now.Add(-time.Hour).Format("2006-01-02 15:04:05"),
		now.Add(-3*time.Hour).Format("2006-01-02 15:04:05")))

	w := getRequest(t, router, "/security/autoban/status")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Code int            `json:"code"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v body=%s", err, w.Body.String())
	}
	data := payload.Data
	// 角色位在场且自洽（绝对值由 services 层缝钉测锁定——handlers
	// 全量跑位时其它用例会装配全局引擎，环境角色不可在此断言）。
	rawMaster, ok := data["is_master"]
	if !ok {
		t.Fatal("is_master 字段缺失（历史修复 从端角色门数据源）")
	}
	isMaster, ok := rawMaster.(bool)
	if !ok {
		t.Fatalf("is_master 必须为布尔, got %T", rawMaster)
	}
	wantRole := "slave"
	if isMaster {
		wantRole = "master"
	}
	if role, _ := data["role"].(string); role != wantRole {
		t.Fatalf("role=%v 与 is_master=%v 不自洽, want %q", data["role"], isMaster, wantRole)
	}
	// list_entries=2（生效条目；已到期未清理的 203.0.113.2 不计入）。
	if n, _ := data["list_entries"].(float64); n != 2 {
		t.Fatalf("list_entries=%v, want 2（已到期未清理条目不计入——与渲染生效面同口径）", data["list_entries"])
	}
}
