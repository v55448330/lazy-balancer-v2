package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 还原确认弹框此前只能拿到「备份名 + 范围」，跨版本告警与冲突置禁用清单要到
// 提交之后才出现（同族文件导入在预览阶段就展示）。本文件钉住只读预览端点：
// 返回跨版本告警/版本号/预计算的冲突禁用清单，且**零写入**（不改配置、不建
// 备份行、不落成功/失败终态审计）。

type autoBackupPreviewPayload struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		VersionWarning    string `json:"version_warning"`
		BackupVersion     string `json:"backup_version"`
		CurrentVersion    string `json:"current_version"`
		DisabledConflicts []struct {
			Name          string `json:"name"`
			CaddyID       string `json:"caddy_id"`
			Reason        string `json:"reason"`
			ConflictsWith []struct {
				Name    string `json:"name"`
				CaddyID string `json:"caddy_id"`
				Reason  string `json:"reason"`
			} `json:"conflicts_with"`
		} `json:"disabled_conflicts"`
		Warnings []string `json:"warnings"`
	} `json:"data"`
}

// writePreviewBackupFixture 落一份真实备份文件 + auto_backups 行，返回行 ID。
func writePreviewBackupFixture(t *testing.T, h *Handlers, backup configBackup, name string) int64 {
	t.Helper()
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal backup fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.cfg.BackupDir, name), data, 0o600); err != nil {
		t.Fatalf("write backup fixture: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type) VALUES (?, 'success', 'manual')`, name)
	if err != nil {
		t.Fatalf("seed auto_backups row: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("read auto_backups id: %v", err)
	}
	return id
}

// countRule 统计某规则在库内的行数（预览必须零写入，按 caddy_id 直查）。
func countRule(t *testing.T, caddyID string) int {
	t.Helper()
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id=?`, caddyID).Scan(&n); err != nil {
		t.Fatalf("count rule %s: %v", caddyID, err)
	}
	return n
}

func servePreview(t *testing.T, h *Handlers, id int64) *autoBackupPreviewPayload {
	t.Helper()
	response := serveAutoBackupJSON(t, h, http.MethodGet, "/auto-backup/:id/preview", fmt.Sprintf("/auto-backup/%d/preview", id), "", h.PreviewAutoBackup)
	if response.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var payload autoBackupPreviewPayload
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("parse preview response: %v (body=%s)", err, response.Body.String())
	}
	return &payload
}

// conflictingBackupFixture 返回一份含两条同端口同域名启用规则的跨版本备份。
func conflictingBackupFixture(t *testing.T) configBackup {
	t.Helper()
	conflictA := map[string]any{"caddy_id": "lb_preview_a", "name": "a", "protocol": "http", "domain": "dup.preview.test", "listen_port": 18443, "enabled": 1}
	conflictB := map[string]any{"caddy_id": "lb_preview_b", "name": "b", "protocol": "http", "domain": "dup.preview.test", "listen_port": 18443, "enabled": 1}
	backup := buildBackupStruct(t, backupFixtureOptions{
		Tables: map[string][]map[string]any{
			"lb_rules":  {conflictA, conflictB},
			"upstreams": {{"rule_id": "lb_preview_a", "host": "127.0.0.1", "port": 9101, "weight": 1, "enabled": 1}, {"rule_id": "lb_preview_b", "host": "127.0.0.1", "port": 9102, "weight": 1, "enabled": 1}},
		},
		Sections: []string{"rules"},
	})
	backup.Meta.AppVersion = "v0.0.1"
	return backup
}

// Given 一份跨版本、含冲突规则的备份文件。
// When GET /auto-backup/:id/preview。
// Then 返回版本号/跨版本告警/预计算的冲突禁用清单，且 DB 与备份列表零新增。
func TestPreviewAutoBackup_returnsVersionAndConflictsWithoutWriting(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	h.cfg.Version = "v2.9.9"
	id := writePreviewBackupFixture(t, h, conflictingBackupFixture(t), "lbbak-manual-preview.lbbak")
	auditBefore := countAutoBackupAudit(t, "还原")
	backupRowsBefore := len(autoBackupRows(t, ""))

	payload := servePreview(t, h, id)

	if payload.Data.BackupVersion != "v0.0.1" {
		t.Fatalf("backup_version=%q, want v0.0.1", payload.Data.BackupVersion)
	}
	if payload.Data.CurrentVersion != "v2.9.9" {
		t.Fatalf("current_version=%q, want v2.9.9", payload.Data.CurrentVersion)
	}
	if payload.Data.VersionWarning == "" || !containsAll(payload.Data.VersionWarning, "v0.0.1", "v2.9.9") {
		t.Fatalf("version_warning=%q, want 含导出与当前版本号", payload.Data.VersionWarning)
	}
	if len(payload.Data.DisabledConflicts) != 2 {
		t.Fatalf("disabled_conflicts=%d, want 2（两侧同端口同域名）", len(payload.Data.DisabledConflicts))
	}
	if payload.Data.DisabledConflicts[0].CaddyID == "" || payload.Data.DisabledConflicts[0].Reason == "" {
		t.Fatalf("disabled_conflicts 条目缺 caddy_id/reason（与导入 data.disabled_conflicts 同形）: %+v", payload.Data.DisabledConflicts[0])
	}
	if len(payload.Data.DisabledConflicts[0].ConflictsWith) == 0 {
		t.Fatal("disabled_conflicts 条目缺少 conflicts_with 对手清单")
	}

	// 零写入：不建备份行、不改配置、不落还原审计。
	if rows := autoBackupRows(t, ""); len(rows) != backupRowsBefore {
		t.Fatalf("预览新增了备份行: before=%d after=%d", backupRowsBefore, len(rows))
	}
	if got := countAutoBackupAudit(t, "还原"); got != auditBefore {
		t.Fatalf("预览落了还原审计: %d → %d", auditBefore, got)
	}
	if countRule(t, "lb_preview_a") != 0 || countRule(t, "lb_preview_b") != 0 {
		t.Fatal("预览写入了配置（禁止）")
	}
}

// Given 备份文件不是有效备份（内容损坏）。
// When 预览。
// Then 400 且零写入（不建备份行、不改配置）。
func TestPreviewAutoBackup_invalidFileReturns400WithoutWriting(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	name := "lbbak-manual-preview-bad.lbbak"
	if err := os.WriteFile(filepath.Join(h.cfg.BackupDir, name), []byte("not-a-backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type) VALUES (?, 'success', 'manual')`, name)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	response := serveAutoBackupJSON(t, h, http.MethodGet, "/auto-backup/:id/preview", fmt.Sprintf("/auto-backup/%d/preview", id), "", h.PreviewAutoBackup)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if rows := autoBackupRows(t, ""); len(rows) != 1 {
		t.Fatalf("预览失败新增了备份行: %d", len(rows))
	}
}

// Given 备份行在而文件已被外部清理。
// When 预览。
// Then 404（与还原的文件面归因一致）。
func TestPreviewAutoBackup_missingFileReturns404(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	res, err := db.DB.Exec(`INSERT INTO auto_backups (filename, status, trigger_type) VALUES ('lbbak-manual-preview-gone.lbbak', 'success', 'manual')`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	response := serveAutoBackupJSON(t, h, http.MethodGet, "/auto-backup/:id/preview", fmt.Sprintf("/auto-backup/%d/preview", id), "", h.PreviewAutoBackup)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", response.Code, response.Body.String())
	}
}

// Given 从节点。
// When 预览。
// Then 403（与同族端点同一主节点门）。
func TestPreviewAutoBackup_rejectsSlaveNode(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	response := serveAutoBackupJSON(t, h, http.MethodGet, "/auto-backup/:id/preview", "/auto-backup/1/preview", "", h.PreviewAutoBackup)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403", response.Code, response.Body.String())
	}
}

func containsAll(value string, fragments ...string) bool {
	for _, fragment := range fragments {
		if !strings.Contains(value, fragment) {
			return false
		}
	}
	return true
}
