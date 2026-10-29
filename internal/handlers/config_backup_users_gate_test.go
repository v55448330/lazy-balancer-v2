package handlers

// （v2 备份 users 键存在但空数组→校验期硬拒，
// 键缺席的分类导出形态不受影响）与 （预览端镜像导入侧单侧 WAF
// 文件缺失建模：剔对应版本表+告警）。

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// ── 回归钉 ──

// Given v2 备份 users 键存在但为空数组（合法导出永不产出该形态，仅手造/损坏）。
// When 导入。
// Then 校验期 400 且错误文案点名「users 表为空，导入将清空全部账户」。
func TestImportConfigBackup_rejects_empty_users_array_with_dedicated_message(t *testing.T) {
	h := newBackupTestHandlers(t)
	body := buildBackup(t, backupFixtureOptions{Sections: nil, Tables: map[string][]map[string]any{
		"users": {},
	}, Config: nil})

	response := postImportShared(t, h.ImportConfigBackup, "/config/import", body)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "users 表为空") {
		t.Fatalf("应在校验期点名 users 空表拒绝: %s", response.Body.String())
	}
}

// Given 同形态备份投递预览端点。
// When 预览。
// Then valid=false 且错误文案与导入一致（此前预览显示「用户 0 个」仍 valid=true）。
func TestValidateConfigImport_rejects_empty_users_array(t *testing.T) {
	h := newBackupTestHandlers(t)
	body := buildBackup(t, backupFixtureOptions{Sections: nil, Tables: map[string][]map[string]any{
		"users": {},
	}, Config: nil})

	got := postValidateString(t, h, body)

	if got.Valid {
		t.Fatalf("users 空表备份预览必须 valid=false，got %+v", got)
	}
	if !strings.Contains(got.Error, "users 表为空") {
		t.Fatalf("预览错误文案应与导入一致: %q", got.Error)
	}
}

// 回归形状：users 键缺席（分类导出/系统数据未选）照常导入，本地用户不动。
func TestImportConfigBackup_users_key_absent_still_imports(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (9,'local-keeper','hash','admin',1)`); err != nil {
		t.Fatalf("seed local keeper: %v", err)
	}
	body := buildBackup(t, backupFixtureOptions{Sections: nil, Tables: map[string][]map[string]any{
		"lb_rules":  {{"caddy_id": "lb_nousers", "name": "no-users", "protocol": "http", "domain": "nousers.example.test", "listen_port": 8081, "enabled": 1}},
		"upstreams": {{"rule_id": "lb_nousers", "host": "127.0.0.1", "port": 9001, "weight": 1, "enabled": 1}},
	}, Config: nil})

	response := postImportShared(t, h.ImportConfigBackup, "/config/import", body)

	if response.Code != http.StatusOK {
		t.Fatalf("users 键缺席（分类导出）必须照常导入: %d %s", response.Code, response.Body.String())
	}
	var keeper int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username='local-keeper'`).Scan(&keeper); err != nil {
		t.Fatalf("read keeper: %v", err)
	}
	if keeper != 1 {
		t.Fatalf("本地用户不得被触碰，keeper=%d", keeper)
	}
}

// 预览镜像导入侧单侧 WAF 文件缺失建模

// Given lbbak 备份只携带 xdb（无 CRS 文件），config.json 含两个版本表。
// When 预览。
// Then security_crs_version 不得计入 summary 且响应携带 CRS 侧跳过警告
// （此前预览计数含两表且无警告，与导入侧实际落库分叉）。
func TestValidateConfigImport_single_side_missing_crs_skips_table_and_warns(t *testing.T) {
	h := newBackupTestHandlers(t)
	backupJSON := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: nil, EmptyConfigIfNil: true})
	body := buildTestLbbak(t, backupJSON, []byte("XDB-ONLY-PAYLOAD"))

	rec := postLbbakValidate(t, h, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", rec.Code, rec.Body.String())
	}
	got := decodeValidateResponse(t, rec)
	if !got.Valid {
		t.Fatalf("单侧缺失不应阻断预览: %+v", got)
	}
	if _, present := got.Summary["security_crs_version"]; present {
		t.Fatalf("CRS 文件缺失时 security_crs_version 不得计入预览 summary: %+v", got.Summary)
	}
	if _, present := got.Summary["security_ip2region_version"]; !present {
		t.Fatalf("xdb 在场时 security_ip2region_version 应保留在 summary: %+v", got.Summary)
	}
	found := false
	for _, warning := range got.Warnings {
		if strings.Contains(warning, warningWafCRSMetadataSkipped) {
			found = true
		}
	}
	if !found {
		t.Fatalf("预览应携带 CRS 侧跳过警告: %+v", got.Warnings)
	}
}

// 对称形状：只携带 CRS（无 xdb）→ security_ip2region_version 剔除+xdb 侧警告。
func TestValidateConfigImport_single_side_missing_xdb_skips_table_and_warns(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 种 CRS 活动树（canonical 内容），经 BuildWafFileBundle 得到内容与声明
	// 哈希天然配对的仅 CRS bundle；xdb 路径无文件 → Xdb 缺席。
	crsDir, _ := overrideTestWafPaths(t) // xdb 路径无文件 → bundle 仅 CRS
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "VERSION"), []byte("v4.29.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "REQUEST-901.conf"), []byte("SecRule a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bundle := services.BuildWafFileBundle()
	if bundle == nil || len(bundle.CRSTarGz) == 0 || bundle.Xdb != nil {
		t.Fatalf("仅 CRS bundle 构建失败: %+v", bundle)
	}
	backupJSON := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: nil, EmptyConfigIfNil: true})
	body, err := buildLbbakPayload([]byte(backupJSON), bundle)
	if err != nil {
		t.Fatalf("buildLbbakPayload: %v", err)
	}

	rec := postLbbakValidate(t, h, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", rec.Code, rec.Body.String())
	}
	got := decodeValidateResponse(t, rec)
	if !got.Valid {
		t.Fatalf("单侧缺失不应阻断预览: %+v", got)
	}
	if _, present := got.Summary["security_ip2region_version"]; present {
		t.Fatalf("xdb 缺失时 security_ip2region_version 不得计入预览 summary: %+v", got.Summary)
	}
	if _, present := got.Summary["security_crs_version"]; !present {
		t.Fatalf("CRS 在场时 security_crs_version 应保留在 summary: %+v", got.Summary)
	}
	found := false
	for _, warning := range got.Warnings {
		if strings.Contains(warning, warningWafXdbMetadataSkipped) {
			found = true
		}
	}
	if !found {
		t.Fatalf("预览应携带 xdb 侧跳过警告: %+v", got.Warnings)
	}
}
