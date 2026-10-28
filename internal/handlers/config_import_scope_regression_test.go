package handlers

// 覆盖导入/预览的单源判据与行级「可登录凭据」门：
//   - 预览与导入共用分类交集/零导入判据（同一文案，不再出现「预览可导入、
//     导入 400」或「软跳过清空后仍报成功」）；
//   - users 行级门（空哈希/缺 OIDC 身份/空 MFA 密钥）与管理员「可登录」门；
//   - 校验和覆盖 meta（篡改 sections 改变还原范围必须被拒）；
//   - 唯一键预检以 400 点名表/行/键（而非事务内 500）；
//   - global_config 写者在导入窗口 409 fast-fail；
//   - 既有备份目录权限收敛到 0700。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func importScopeRuleFixture() map[string][]map[string]any {
	return map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "imp1", "name": "imp", "protocol": "http", "domain": "a.example.com", "listen_port": 80, "enabled": 1}},
	}
}

// 预览与导入对 lbbak 的 query×body 分类选择必须同源：交集为空两边都拒绝且
// 文案一致；交集非空预览照常可导入。
func TestLbbakSectionsPreviewMirrorsImportIntersection(t *testing.T) {
	h := newBackupTestHandlers(t)
	backupJSON := buildBackup(t, backupFixtureOptions{
		Sections:         []string{"rules"},
		Tables:           importScopeRuleFixture(),
		EmptyConfigIfNil: true,
	})
	body := buildTestLbbak(t, backupJSON, nil)

	// Given 备份记录的分类是 rules，请求却只选 security（交集为空）。
	// Then 预览 valid=false 且文案点名「无交集」（修复前预览会把 sections
	// 替换为 security 后返回 valid=true）。
	preview := postLbbakValidate(t, h, body, "?sections=security")
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	previewData := decodeValidateResponse(t, preview)
	if previewData.Valid {
		t.Fatalf("交集为空的 lbbak 预览不得 valid=true: %+v", previewData)
	}
	if !strings.Contains(previewData.Error, "无交集") {
		t.Fatalf("预览错误文案应与导入同源（无交集），got=%q", previewData.Error)
	}

	// Then 同参数导入 400，同一文案。
	importRec := postLbbakImport(newBackupSectionRouter(h), t, body, "?sections=security")
	if importRec.Code != http.StatusBadRequest {
		t.Fatalf("import status=%d body=%s, want 400", importRec.Code, importRec.Body.String())
	}
	if !strings.Contains(importRec.Body.String(), "无交集") {
		t.Fatalf("导入错误应点名无交集: %s", importRec.Body.String())
	}

	// 对照：交集非空（query=rules）预览可导入且摘要含规则表。
	okPreview := postLbbakValidate(t, h, body, "?sections=rules")
	okData := decodeValidateResponse(t, okPreview)
	if !okData.Valid {
		t.Fatalf("交集非空应可导入: %+v", okData)
	}
	if _, carried := okData.Summary["lb_rules"]; !carried {
		t.Fatalf("交集非空时规则表应计入摘要: %+v", okData.Summary)
	}
}

// 纯 JSON 备份的唯一内容在软跳过中被保留本地（威胁源表）时，导入必须 400
// 而不是 200「成功」；预览同形态 valid=false 且文案一致。
func TestPureJSONZeroImportAfterSoftSkipRejected(t *testing.T) {
	h := newBackupTestHandlers(t)
	backupJSON := buildBackup(t, backupFixtureOptions{
		Sections: []string{"security"},
		Tables: map[string][]map[string]any{
			"security_threat_sources": {{"name": "ustc"}},
		},
	})

	preview := postValidateString(t, h, backupJSON)
	if preview.Valid {
		t.Fatalf("软跳过清空后预览不得 valid=true: %+v", preview)
	}
	if !strings.Contains(preview.Error, "均被跳过") {
		t.Fatalf("预览错误文案应点名「均被跳过」，got=%q", preview.Error)
	}

	rec := postJSONImport(t, newBackupSectionRouter(h), backupJSON)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（零导入）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "均被跳过") {
		t.Fatalf("导入错误文案应点名「均被跳过」: %s", rec.Body.String())
	}
}

// users 行级门：本地空哈希 / OIDC 身份缺字段 / 启用 MFA 空密钥均 400 点名，
// 预览与导入同判据；管理员可用性门要求「可登录」。
func TestUsersLoginCredentialGates(t *testing.T) {
	validAdmin := map[string]any{"id": 1, "username": "ok-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}

	cases := []struct {
		name        string
		rows        []map[string]any
		wantIn      []string
		validBackup bool
	}{
		{
			name:   "本地用户空哈希",
			rows:   []map[string]any{validAdmin, {"id": 2, "username": "no-pass", "password_hash": "", "role": "user", "is_enabled": 1}},
			wantIn: []string{"users 第 2 行", "password_hash"},
		},
		{
			name:   "OIDC 用户缺 issuer",
			rows:   []map[string]any{validAdmin, {"id": 3, "username": "oidc-user", "password_hash": "", "role": "user", "is_enabled": 1, "auth_provider": "oidc", "oidc_subject": "sub-1", "oidc_issuer": ""}},
			wantIn: []string{"users 第 2 行", "oidc_issuer"},
		},
		{
			name:   "启用 MFA 但密钥为空",
			rows:   []map[string]any{validAdmin, {"id": 4, "username": "mfa-user", "password_hash": "hash", "role": "user", "is_enabled": 1, "mfa_enabled": 1, "mfa_secret": ""}},
			wantIn: []string{"users 第 2 行", "mfa_secret"},
		},
		{
			name:   "启用管理员空哈希（管理员可用性门）",
			rows:   []map[string]any{{"id": 5, "username": "locked-out", "password_hash": "", "role": "admin", "is_enabled": 1}},
			wantIn: []string{"可用登录凭据"},
		},
		{
			name:        "OIDC 管理员身份完整即可用",
			rows:        []map[string]any{{"id": 6, "username": "oidc-admin", "password_hash": "", "role": "admin", "is_enabled": 1, "auth_provider": "oidc", "oidc_subject": "sub-6", "oidc_issuer": "https://idp.example.com"}},
			validBackup: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			body := buildBackup(t, backupFixtureOptions{
				Sections:         []string{"users"},
				Tables:           map[string][]map[string]any{"users": tc.rows},
				EmptyConfigIfNil: true,
			})

			preview := postValidateString(t, h, body)
			rec := postJSONImport(t, newBackupSectionRouter(h), body)

			if tc.validBackup {
				if !preview.Valid {
					t.Fatalf("预览应可导入: %+v", preview)
				}
				if rec.Code != http.StatusOK {
					t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
				}
				return
			}
			if preview.Valid {
				t.Fatalf("预览不得 valid=true: %+v", preview)
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(preview.Error, want) {
					t.Fatalf("预览错误缺 %q: %q", want, preview.Error)
				}
				if !strings.Contains(rec.Body.String(), want) {
					t.Fatalf("导入错误缺 %q: %s", want, rec.Body.String())
				}
			}
		})
	}
}

// 校验和覆盖 meta：改体内 sections（改变还原范围）必须触发「已篡改」。
func TestBackupChecksumCoversMetaSections(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 导入提交前要求库内仍有启用管理员（分类导出不含 users 表时不替换用户）。
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'current-admin','hash','admin',1)`); err != nil {
		t.Fatalf("seed current admin: %v", err)
	}
	payload, _, _, includesWafFiles, err := h.buildLbbakExport(context.Background(), []string{"rules"})
	if err != nil {
		t.Fatalf("buildLbbakExport: %v", err)
	}
	if includesWafFiles {
		t.Fatalf("rules 分类导出不应携带规则库文件")
	}
	parsed, err := parseLbbak(payload)
	if err != nil {
		t.Fatalf("parseLbbak: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(parsed.ConfigJSON, &envelope); err != nil {
		t.Fatalf("decode exported config.json: %v", err)
	}
	meta, _ := envelope["meta"].(map[string]any)
	if version, _ := meta["version"].(float64); version != 3 {
		t.Fatalf("导出 meta.version=%v, want 3（校验和需覆盖 meta）", meta["version"])
	}

	// 对照：未篡改的原始导出可导入。
	router := newBackupSectionRouter(h)
	if rec := postLbbakImport(router, t, payload, ""); rec.Code != http.StatusOK {
		t.Fatalf("原始导出导入 status=%d body=%s", rec.Code, rec.Body.String())
	}

	// When 把 sections 从 rules 改成 security（还原范围被悄悄扩大）。
	envelope["sections"] = []any{"security"}
	mutatedJSON, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	mutatedPayload, err := buildLbbakPayload(mutatedJSON, nil)
	if err != nil {
		t.Fatalf("repack lbbak: %v", err)
	}

	// Then 预览与导入都以「篡改」拒绝（v3 校验和覆盖 sections）。
	preview := postLbbakValidate(t, h, mutatedPayload, "")
	previewData := decodeValidateResponse(t, preview)
	if previewData.Valid || !strings.Contains(previewData.Error, "篡改") {
		t.Fatalf("篡改 sections 后预览应报篡改: %+v", previewData)
	}
	rec := postLbbakImport(newBackupSectionRouter(h), t, mutatedPayload, "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "篡改") {
		t.Fatalf("status=%d body=%s, want 400 篡改", rec.Code, rec.Body.String())
	}
}

// 唯一键/主键重复必须以 400 点名表/键退出，而不是事务内 500「写入表 …」。
func TestImportRejectsDuplicateUniqueKeys(t *testing.T) {
	validAdmin := map[string]any{"id": 1, "username": "ok-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}
	systemListName := db.ThreatSystemLists()[0].Name

	cases := []struct {
		name     string
		sections []string
		tables   map[string][]map[string]any
		wantIn   []string
	}{
		{
			name:     "users.username 重复",
			sections: []string{"users"},
			tables: map[string][]map[string]any{"users": {
				validAdmin,
				{"id": 2, "username": "ok-admin", "password_hash": "hash", "role": "user", "is_enabled": 1},
			}},
			wantIn: []string{"users", "唯一键 username"},
		},
		{
			name:     "users 主键重复",
			sections: []string{"users"},
			tables: map[string][]map[string]any{"users": {
				validAdmin,
				{"id": 1, "username": "another", "password_hash": "hash", "role": "user", "is_enabled": 1},
			}},
			wantIn: []string{"users", "主键 id"},
		},
		{
			// 布尔与整数在恢复侧同一落库形态（INTEGER 1/0）：唯一键预检必须
			// 同域判重，否则冲突漏成事务内 500。
			name:     "users 主键 true 与 1 同域重复",
			sections: []string{"users"},
			tables: map[string][]map[string]any{"users": {
				{"id": true, "username": "bool-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1},
				{"id": 1, "username": "int-admin", "password_hash": "hash", "role": "user", "is_enabled": 1},
			}},
			wantIn: []string{"users", "主键 id"},
		},
		{
			name:     "users 主键 false 与 0 同域重复",
			sections: []string{"users"},
			tables: map[string][]map[string]any{"users": {
				{"id": false, "username": "false-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1},
				{"id": 0, "username": "zero-admin", "password_hash": "hash", "role": "user", "is_enabled": 1},
			}},
			wantIn: []string{"users", "主键 id"},
		},
		{
			name:     "users 主键 true 与整数形字符串 1 同域重复",
			sections: []string{"users"},
			tables: map[string][]map[string]any{"users": {
				{"id": true, "username": "bool-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1},
				{"id": "1", "username": "text-admin", "password_hash": "hash", "role": "user", "is_enabled": 1},
			}},
			wantIn: []string{"users", "主键 id"},
		},
		{
			name:     "system 名单同名重复",
			sections: []string{"security"},
			tables: map[string][]map[string]any{"security_ip_lists": {
				{"id": 101, "name": systemListName, "system": 1, "entries": "[]"},
				{"id": 102, "name": systemListName, "system": 1, "entries": "[]"},
			}},
			wantIn: []string{"security_ip_lists", "唯一键 name"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			body := buildBackup(t, backupFixtureOptions{
				Sections:         tc.sections,
				Tables:           tc.tables,
				EmptyConfigIfNil: true,
			})
			rec := postJSONImport(t, newBackupSectionRouter(h), body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400（不是 500）", rec.Code, rec.Body.String())
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(rec.Body.String(), want) {
					t.Fatalf("错误缺 %q: %s", want, rec.Body.String())
				}
			}
		})
	}
}

// 唯一键预检的布尔同域归一不得产生假阳性：true/false 在库中是 1/0 两个不同
// 值，只有与同一数值（1/0 或整数形字符串）重复才拒绝。
func TestImportUniqueKeyPrecheck_booleanSharesNumericDomainWithoutFalsePositive(t *testing.T) {
	newBackupTestHandlers(t)
	row := func(id any, username string) map[string]any {
		return map[string]any{"id": id, "username": username, "password_hash": "hash", "role": "user", "is_enabled": 1}
	}
	distinct := map[string][]map[string]any{"users": {row(true, "bool-true"), row(false, "bool-false"), row(int64(2), "int-two")}}
	if err := validateBackupUniqueKeys(distinct); err != nil {
		t.Fatalf("true/false/2 三行不得判为重复: %v", err)
	}
	for _, tt := range []struct {
		name        string
		left, right any
	}{
		{"true 与 1", true, int64(1)},
		{"false 与 0", false, int64(0)},
		{"true 与整数形字符串 1", true, "1"},
	} {
		tables := map[string][]map[string]any{"users": {row(tt.left, "left"), row(tt.right, "right")}}
		err := validateBackupUniqueKeys(tables)
		if err == nil || !strings.Contains(err.Error(), "主键 id") {
			t.Fatalf("%s: err=%v, want 点名 users 主键 id 的重复", tt.name, err)
		}
	}
}

func TestImportUniqueKeyPrecheck_canonicalizesCertJobDomains(t *testing.T) {
	newBackupTestHandlers(t)
	job := func(id int, domain string) map[string]any {
		return map[string]any{"id": id, "rule_id": "lb_acme", "domain": domain, "status": "pending"}
	}
	duplicates := map[string][]map[string]any{"cert_jobs": {job(1, "A.com"), job(2, "a.com")}}
	if err := validateBackupUniqueKeys(duplicates); err == nil || !strings.Contains(err.Error(), "rule_id+domain") {
		t.Fatalf("规范化后相同域名的 cert_jobs 必须在预检 400 点名唯一键，err=%v", err)
	}
	distinct := map[string][]map[string]any{"cert_jobs": {job(1, "a.com"), job(2, "b.com")}}
	if err := validateBackupUniqueKeys(distinct); err != nil {
		t.Fatalf("规范化后仍不同的域名不得误判重复: %v", err)
	}
}

// global_config 写者在导入窗口内 409 fast-fail（不再排队至导入结束后落库）。
func TestGlobalConfigWritersRejectWriteDuringImport(t *testing.T) {
	beginImportWindowForTest(t)

	gin.SetMode(gin.TestMode)
	h := &Handlers{}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/config", nil)
	h.UpdateConfig(ctx)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("UpdateConfig during import = %d body=%s, want 409", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/admin-tls", nil)
	h.UpdateAdminTLS(ctx)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("UpdateAdminTLS during import = %d body=%s, want 409", recorder.Code, recorder.Body.String())
	}
}

// 已存在的宽权限备份目录（旧版本/手工 mkdir 产物）在下次备份时收敛为 0700。
func TestRunAutoBackupOnce_convergesExistingDirPermissions(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	dir := filepath.Join(t.TempDir(), "backup-existing")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	h.cfg.BackupDir = dir

	if _, err := h.RunAutoBackupOnce(context.Background(), "manual", "system", 0); err != nil {
		t.Fatalf("RunAutoBackupOnce: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("既有备份目录 perm=%o, want 700", perm)
	}
}
