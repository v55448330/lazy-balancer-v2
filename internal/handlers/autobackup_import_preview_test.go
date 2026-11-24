package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 备份历史的「还原」复用文件导入弹框：预览走 POST /config/import/validate?
// backup_id=<行 ID>——按备份历史行读服务器上的文件，再走文件导入预览同一条
// 校验链；确认走 POST /auto-backup/:id/restore?sections=<所选分类>。

// seedServerBackupRow 把备份字节落成一份服务器备份（文件 + auto_backups 行），返回行 ID。
func seedServerBackupRow(t *testing.T, h *Handlers, name string, data []byte) int64 {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.cfg.BackupDir, name), data, 0o600); err != nil {
		t.Fatalf("write backup file: %v", err)
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

// postImportValidateQuery 以给定 query 与请求体调用导入预览端点，返回原始响应。
func postImportValidateQuery(t *testing.T, h *Handlers, query, body string) *httptest.ResponseRecorder {
	t.Helper()
	return serveAutoBackupJSON(t, h, http.MethodPost, "/config/import/validate", "/config/import/validate"+query, body, h.ValidateConfigImport)
}

// decodeImportValidateEnvelope 解出预览响应的 data。
func decodeImportValidateEnvelope(t *testing.T, response *httptest.ResponseRecorder) importValidateResponse {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var envelope struct {
		Data importValidateResponse `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode validate response: %v (body=%s)", err, response.Body.String())
	}
	return envelope.Data
}

// countRowsForImportPreview 统计某表满足条件的行数（预览必须零写入）。
func countRowsForImportPreview(t *testing.T, query string, args ...any) int {
	t.Helper()
	var count int
	if err := db.DB.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatalf("count rows (%s): %v", query, err)
	}
	return count
}

// conflictingPreviewBackupFixture 返回一份跨版本、含两条同端口同域名启用规则的备份字节。
func conflictingPreviewBackupFixture(t *testing.T) []byte {
	t.Helper()
	backup := buildBackupStruct(t, backupFixtureOptions{
		Tables: map[string][]map[string]any{
			"lb_rules": {
				{"caddy_id": "lb_preview_a", "name": "a", "protocol": "http", "domain": "dup.preview.test", "listen_port": 18443, "enabled": 1},
				{"caddy_id": "lb_preview_b", "name": "b", "protocol": "http", "domain": "dup.preview.test", "listen_port": 18443, "enabled": 1},
			},
			"upstreams": {
				{"rule_id": "lb_preview_a", "host": "127.0.0.1", "port": 9101, "weight": 1, "enabled": 1},
				{"rule_id": "lb_preview_b", "host": "127.0.0.1", "port": 9102, "weight": 1, "enabled": 1},
			},
		},
		Sections: []string{"rules"},
	})
	backup.Meta.AppVersion = "v0.0.1"
	return []byte(marshalJSONForTest(t, backup))
}

// assertPreviewIsCrossVersionConflictReport 断言预览非空：跨版本告警 + 两条冲突置禁用。
func assertPreviewIsCrossVersionConflictReport(t *testing.T, preview importValidateResponse) {
	t.Helper()
	if !preview.Valid || preview.Type != "v2" {
		t.Fatalf("preview=%+v, want valid v2", preview)
	}
	if len(preview.DisabledConflicts) != 2 {
		t.Fatalf("disabled_conflicts=%d, want 2（两侧同端口同域名）", len(preview.DisabledConflicts))
	}
	if preview.Summary["lb_rules"] != 2 {
		t.Fatalf("summary[lb_rules]=%d, want 2（summary=%v）", preview.Summary["lb_rules"], preview.Summary)
	}
	if !warningsContainOneOf(preview.Warnings, "v0.0.1", "v2.9.9") {
		t.Fatalf("warnings=%v, want 含导出与当前版本号的跨版本告警", preview.Warnings)
	}
}

// warningsContainOneOf 报告 warnings 中是否有同一条同时包含全部片段。
func warningsContainOneOf(warnings []string, fragments ...string) bool {
	for _, warning := range warnings {
		all := true
		for _, fragment := range fragments {
			if !strings.Contains(warning, fragment) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// sortedSummaryKeys 返回预览 summary 的表名键（排序后），用于核对分类过滤后的表集。
func sortedSummaryKeys(summary map[string]int) []string {
	keys := make([]string, 0, len(summary))
	for key := range summary {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// Given 一份跨版本、含冲突规则的纯 JSON 备份。
// When 同一份字节分别走文件导入预览（请求体）与服务器备份预览（backup_id）。
// Then 两次响应 data 逐字段一致，且服务器备份预览零写入。
func TestValidateConfigImport_backupIdMatchesFileImportPreview(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	h.cfg.Version = "v2.9.9"
	data := conflictingPreviewBackupFixture(t)
	id := seedServerBackupRow(t, h, "lbbak-manual-import-preview.lbbak", data)
	backupRowsBefore := len(autoBackupRows(t, ""))

	fromFile := decodeImportValidateEnvelope(t, postImportValidateQuery(t, h, "", string(data)))
	fromServer := decodeImportValidateEnvelope(t, postImportValidateQuery(t, h, fmt.Sprintf("?backup_id=%d", id), ""))

	assertPreviewIsCrossVersionConflictReport(t, fromFile)
	if !reflect.DeepEqual(fromServer, fromFile) {
		t.Fatalf("backup_id 预览与文件导入预览不一致:\n server=%+v\n file=%+v", fromServer, fromFile)
	}

	// 零写入：不建备份行、不改配置、不落还原审计。
	if rows := autoBackupRows(t, ""); len(rows) != backupRowsBefore {
		t.Fatalf("预览新增了备份行: before=%d after=%d", backupRowsBefore, len(rows))
	}
	if countRowsForImportPreview(t, `SELECT COUNT(*) FROM lb_rules WHERE caddy_id IN ('lb_preview_a','lb_preview_b')`) != 0 {
		t.Fatal("预览写入了配置（禁止）")
	}
	if countAutoBackupAudit(t, "还原") != 0 {
		t.Fatal("预览落了还原审计")
	}
}

// Given 服务器上的真实 lbbak 备份（导出自当前库，含冲突规则），导出后库内规则已删除。
// When 同一份 lbbak 字节分别走文件导入预览与 backup_id 预览。
// Then 逐字段一致——backup_id 路径同样完成 lbbak 解包，且不读请求体。
func TestValidateConfigImport_backupIdUnpacksServerLbbak(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	h.cfg.Version = "v0.0.1"
	for _, rule := range []string{"lb_preview_a", "lb_preview_b"} {
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES (?,?,'http','dup.preview.test',18443,1)`, rule, rule); err != nil {
			t.Fatalf("seed rule %s: %v", rule, err)
		}
	}
	payload, _, _, _, err := h.buildLbbakExport(context.Background(), []string{"rules"})
	if err != nil {
		t.Fatalf("buildLbbakExport: %v", err)
	}
	if _, err := db.DB.Exec(`DELETE FROM lb_rules WHERE caddy_id IN ('lb_preview_a','lb_preview_b')`); err != nil {
		t.Fatal(err)
	}
	h.cfg.Version = "v2.9.9"
	id := seedServerBackupRow(t, h, "lbbak-auto-20261125-030000.lbbak", payload)

	fromFile := decodeImportValidateEnvelope(t, postImportValidateQuery(t, h, "", string(payload)))
	fromServer := decodeImportValidateEnvelope(t, postImportValidateQuery(t, h, fmt.Sprintf("?backup_id=%d", id), "not-a-backup"))

	if !fromServer.Valid || fromServer.Type != "v2" || fromServer.Summary["lb_rules"] != 2 {
		t.Fatalf("server preview=%+v, want valid v2 with 2 rules", fromServer)
	}
	if !reflect.DeepEqual(fromServer, fromFile) {
		t.Fatalf("backup_id 预览与文件导入预览不一致:\n server=%+v\n file=%+v", fromServer, fromFile)
	}
}

// Given 备份体内分类为「系统数据 + 负载规则」。
// When backup_id 预览带 sections / 不带 / 选到备份未含的分类。
// Then sections 照常生效：只缩不扩，无交集时 valid=false。
func TestValidateConfigImport_backupIdHonorsSectionsQuery(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	data := []byte(buildBackup(t, backupFixtureOptions{FillAll: true, EmptyConfigIfNil: true, Sections: []string{"users", "rules"}}))
	id := seedServerBackupRow(t, h, "lbbak-manual-import-sections.lbbak", data)
	query := fmt.Sprintf("?backup_id=%d", id)

	all := decodeImportValidateEnvelope(t, postImportValidateQuery(t, h, query, ""))
	if got, want := strings.Join(sortedSummaryKeys(all.Summary), ","), "api_keys,ca_providers,cert_jobs,certificate_configs,lb_rules,path_rules,upstreams,users"; got != want {
		t.Fatalf("不带 sections 的 summary 键=%s, want %s", got, want)
	}

	rulesOnly := decodeImportValidateEnvelope(t, postImportValidateQuery(t, h, query+"&sections=rules", ""))
	if !rulesOnly.Valid {
		t.Fatalf("sections=rules preview=%+v, want valid", rulesOnly)
	}
	if got, want := strings.Join(sortedSummaryKeys(rulesOnly.Summary), ","), "cert_jobs,lb_rules,path_rules,upstreams"; got != want {
		t.Fatalf("sections=rules 的 summary 键=%s, want %s", got, want)
	}

	disjoint := decodeImportValidateEnvelope(t, postImportValidateQuery(t, h, query+"&sections=cluster", ""))
	if disjoint.Valid || !strings.Contains(disjoint.Error, "无交集") {
		t.Fatalf("sections=cluster preview=%+v, want valid=false 无交集", disjoint)
	}
}

// Given 备份行在而文件已被外部清理 / 行不存在 / ID 非法 / 文件内容损坏。
// When backup_id 预览。
// Then 文件缺失 404、行不存在 404、ID 非法 400（三者均落「预览失败」审计）；
// 内容损坏与文件导入预览同口径：200 + valid=false，零写入。
func TestValidateConfigImport_backupIdMissingBackupReturns404(t *testing.T) {
	h := newAutoBackupTestHandlers(t)

	goneID := seedServerBackupRow(t, h, "lbbak-manual-preview-gone.lbbak", []byte("{}"))
	if err := os.Remove(filepath.Join(h.cfg.BackupDir, "lbbak-manual-preview-gone.lbbak")); err != nil {
		t.Fatal(err)
	}
	response := postImportValidateQuery(t, h, fmt.Sprintf("?backup_id=%d", goneID), "")
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "备份文件已不存在") {
		t.Fatalf("status=%d body=%s, want 404 备份文件已不存在", response.Code, response.Body.String())
	}

	response = postImportValidateQuery(t, h, "?backup_id=999999", "")
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "备份不存在") {
		t.Fatalf("status=%d body=%s, want 404 备份不存在", response.Code, response.Body.String())
	}

	response = postImportValidateQuery(t, h, "?backup_id=abc", "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if got := countAutoBackupAudit(t, "预览失败"); got != 3 {
		t.Fatalf("预览失败 审计行=%d, want 3（文件缺失/行不存在/ID 非法各一条）", got)
	}

	badID := seedServerBackupRow(t, h, "lbbak-manual-preview-bad.lbbak", []byte("not-a-backup"))
	broken := decodeImportValidateEnvelope(t, postImportValidateQuery(t, h, fmt.Sprintf("?backup_id=%d", badID), ""))
	if broken.Valid || broken.Error == "" {
		t.Fatalf("损坏备份 preview=%+v, want valid=false 并给出原因", broken)
	}
	if rows := autoBackupRows(t, ""); len(rows) != 2 {
		t.Fatalf("预览新增了备份行: %d", len(rows))
	}
	if countAutoBackupAudit(t, "还原") != 0 {
		t.Fatal("预览落了还原审计")
	}
}

// Given 从节点。
// When backup_id 预览。
// Then 403（权限门与文件导入预览一致）。
func TestValidateConfigImport_backupIdRejectsSlaveNode(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	response := postImportValidateQuery(t, h, "?backup_id=1", "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403", response.Code, response.Body.String())
	}
}

// restoreSectionsBackupBytes 返回一份含单条启用规则的备份字节，分类范围由 sections 给出。
func restoreSectionsBackupBytes(t *testing.T, sections []string) []byte {
	t.Helper()
	return []byte(buildBackup(t, backupFixtureOptions{
		FillAll:          len(sections) == 0,
		EmptyConfigIfNil: true,
		Sections:         sections,
		Tables: map[string][]map[string]any{
			"lb_rules":  {{"caddy_id": "lb_from_backup", "name": "from-backup", "protocol": "http", "domain": "restore.example.test", "listen_port": 8081, "enabled": 1}},
			"upstreams": {{"rule_id": "lb_from_backup", "host": "127.0.0.1", "port": 9101, "weight": 1, "enabled": 1}},
		},
	}))
}

// seedLocalStateOutsideBackup 在本地放入备份外的用户与规则。
func seedLocalStateOutsideBackup(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (5,'local-keeper','x','admin',1)`); err != nil {
		t.Fatalf("seed local user: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_local','local','http','local.example.test',8082,1)`); err != nil {
		t.Fatalf("seed local rule: %v", err)
	}
}

// assertRestoredState 核对还原后的规则与用户（备份内规则 / 本地规则 / 本地用户 / 备份内管理员）。
func assertRestoredState(t *testing.T, wantBackupRule, wantLocalRule, wantLocalUser, wantBackupAdmin int) {
	t.Helper()
	cases := []struct {
		name  string
		query string
		want  int
	}{
		{"备份内规则", `SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_from_backup'`, wantBackupRule},
		{"本地规则", `SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_local'`, wantLocalRule},
		{"本地用户", `SELECT COUNT(*) FROM users WHERE username='local-keeper'`, wantLocalUser},
		{"备份内管理员", `SELECT COUNT(*) FROM users WHERE username='backup-admin'`, wantBackupAdmin},
	}
	for _, tc := range cases {
		if got := countRowsForImportPreview(t, tc.query); got != tc.want {
			t.Errorf("%s 还原后=%d, want %d", tc.name, got, tc.want)
		}
	}
}

// restoreServerBackup 调用还原端点并断言 200 + 还原成功文案。
func restoreServerBackup(t *testing.T, h *Handlers, id int64, query string) {
	t.Helper()
	response := serveAutoBackupJSON(t, h, http.MethodPost, "/auto-backup/:id/restore", fmt.Sprintf("/auto-backup/%d/restore%s", id, query), "", h.RestoreAutoBackup)
	if response.Code != http.StatusOK {
		t.Fatalf("restore status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode restore response: %v", err)
	}
	if !strings.Contains(envelope.Message, "配置还原成功") {
		t.Fatalf("restore message=%q, want 配置还原成功", envelope.Message)
	}
}

// Given 一份完整备份（全部分类）；本地有备份外的用户与规则。
// When POST /auto-backup/:id/restore?sections=rules。
// Then 只还原所选分类：负载规则被替换，本地用户保留。
func TestRestoreAutoBackup_sectionsRestoresOnlySelected(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	id := seedServerBackupRow(t, h, "lbbak-manual-restore-sections.lbbak", restoreSectionsBackupBytes(t, nil))
	seedLocalStateOutsideBackup(t)

	restoreServerBackup(t, h, id, "?sections=rules")

	assertRestoredState(t, 1, 0, 1, 0)
}

// Given 备份体内分类即还原范围（完整备份 / 仅负载规则）；本地有备份外的用户与规则。
// When POST /auto-backup/:id/restore（不带 sections）。
// Then 按备份体内分类还原：完整备份替换系统数据，仅规则的备份不动本地用户。
func TestRestoreAutoBackup_withoutSectionsRestoresBackupScope(t *testing.T) {
	t.Run("完整备份", func(t *testing.T) {
		h := newAutoBackupTestHandlers(t)
		id := seedServerBackupRow(t, h, "lbbak-manual-restore-full.lbbak", restoreSectionsBackupBytes(t, nil))
		seedLocalStateOutsideBackup(t)

		restoreServerBackup(t, h, id, "")

		assertRestoredState(t, 1, 0, 0, 1)
	})
	t.Run("仅负载规则的备份", func(t *testing.T) {
		h := newAutoBackupTestHandlers(t)
		id := seedServerBackupRow(t, h, "lbbak-manual-restore-rules-only.lbbak", restoreSectionsBackupBytes(t, []string{"rules"}))
		seedLocalStateOutsideBackup(t)

		restoreServerBackup(t, h, id, "")

		assertRestoredState(t, 1, 0, 1, 0)
	})
}
