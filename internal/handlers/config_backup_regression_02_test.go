package handlers

//
// 覆盖：
//   布尔列枚举补 5 项 + PRAGMA/语义列对照钉测
//   导出包体携带 sections，还原按包体分类过滤
//   auto backup 设置组导入门（frequency/HH:MM/day/keep/sections）
//   校验顺序=完整性→sections 过滤→行级门
//   冲突矩阵分桶预计算等价性
//   legacy（v1 仅 tables 校验和）早退改为标志位，后置门照常执行
//   /03 lbbak 文件落盘失败/坏 xdb → 版本记录丢弃 + 响应明示
//   commit 后 ApplyLogLevel + admin TLS 重启提示
//   运行期设置门（timezone/坐标/枚举/超时/default_ca）
//   导入 off→on 水位线
//   sections 并集 == configBackupTables
//   cert_renewal_days 导入保留 0（0=默认 30，不再钳到 1）

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// legacyBackupJSON 构造 v2 备份体（可注入 sections），checksum 按 {tables,config}。
func legacyBackupJSON(t *testing.T, tables map[string][]map[string]any, cfg map[string]any, sections []string) string {
	t.Helper()
	completeTables := map[string][]map[string]any{}
	for _, table := range configBackupTables {
		completeTables[table] = []map[string]any{}
	}
	completeTables["users"] = []map[string]any{{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	for table, rows := range tables {
		completeTables[table] = rows
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	backup := configBackup{
		Meta:     configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-10-18T00:00:00Z"},
		Config:   cfg,
		Tables:   completeTables,
		Sections: sections,
	}
	backup.Meta.Checksum = checksumBackupPayload(t, completeTables, cfg)
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	return string(data)
}

// 布尔列枚举补项 + PRAGMA/语义列对照

// 语义 0/1 列（PRAGMA 声明为 INTEGER，无法按 BOOLEAN 类型识别）——新增列须
// 同步本清单与 backupBooleanTableColumns（本测试即两处漂移的机械拦截点）。
var backupSemanticBoolColumns = map[string][]string{
	"lb_rules":                   {"ntlm_compatible", "upstream_force_http1"},
	"security_block_pages":       {"is_builtin"},
	"security_ip_lists":          {"system"},
	"security_policies":          {"ip_whitelist_enabled", "trust_detection", "geoip_crawler_exempt"},
	"api_keys":                   {"mcp_enabled", "read_only"},
	"security_crs_version":       {"auto_update"},
	"security_ip2region_version": {"auto_update"},
}

// 复核豁免（携裁定）：声明为 INTEGER 0/1（或 BOOLEAN）但非布尔语义/无需类型门
// 的列。
var backupSemanticBoolExemptions = map[string]string{
	"lb_rules.server_tokens_hidden": "三态 0/1/2（rules.go 保存侧允许 2），非布尔列",
	"global_config.is_master":       "受保护配置键（configBackupProtectedConfigKeys）——导入跳过该键，布尔类型门无消费点",
}

func TestBackupBooleanEnumeration_coversSchemaBooleanColumns(t *testing.T) {
	newBackupTestHandlers(t)
	check := func(table, column, where string) {
		t.Helper()
		if _, exempt := backupSemanticBoolExemptions[table+"."+column]; exempt {
			return
		}
		if isBackupBooleanColumn(table, column) {
			return
		}
		t.Errorf("%s 列 %s.%s 未登记进 backupBooleanTableColumns（布尔门洞）", where, table, column)
	}
	for _, table := range configBackupTables {
		rows, err := db.DB.Query("PRAGMA table_info(" + table + ")")
		if err != nil {
			t.Fatalf("pragma %s: %v", table, err)
		}
		for rows.Next() {
			var cid, notNull, pk int
			var name, declType string
			var dflt any
			if err := rows.Scan(&cid, &name, &declType, &notNull, &dflt, &pk); err != nil {
				rows.Close()
				t.Fatalf("scan pragma %s: %v", table, err)
			}
			if strings.Contains(strings.ToUpper(declType), "BOOLEAN") {
				check(table, name, "PRAGMA BOOLEAN")
			}
		}
		rows.Close()
		for _, column := range backupSemanticBoolColumns[table] {
			check(table, column, "语义 0/1")
		}
		// 枚举项必须是真实存在的列（防拼写漂移/死条目）。
		for _, column := range backupBooleanTableColumns[table] {
			var exists int
			if err := db.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?", table, column).Scan(&exists); err != nil {
				t.Fatalf("pragma lookup %s.%s: %v", table, column, err)
			}
			if exists == 0 {
				t.Errorf("backupBooleanTableColumns 含不存在的列 %s.%s", table, column)
			}
		}
	}
	// global_config 的 BOOLEAN 声明列同样必须入配置键枚举。
	rows, err := db.DB.Query("PRAGMA table_info(global_config)")
	if err != nil {
		t.Fatalf("pragma global_config: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, pk int
		var name, declType string
		var dflt any
		if err := rows.Scan(&cid, &name, &declType, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan pragma global_config: %v", err)
		}
		if strings.Contains(strings.ToUpper(declType), "BOOLEAN") && !isBackupBooleanConfigKey(name) {
			if _, exempt := backupSemanticBoolExemptions["global_config."+name]; exempt {
				continue
			}
			t.Errorf("global_config.%s 为 BOOLEAN 列但未登记进 backupBooleanConfigKeys", name)
		}
	}
	if !isBackupBooleanConfigKey("auto_backup_enabled") {
		t.Error("auto_backup_enabled 必须入 backupBooleanConfigKeys（历史修复）")
	}
}

func TestValidateV2Backup_newlyEnumeratedBooleanColumnsRejectStrings(t *testing.T) {
	cases := []struct {
		table  string
		column string
		row    map[string]any
	}{
		{"lb_rules", "ntlm_compatible", map[string]any{"name": "r", "protocol": "http", "domain": "a.com", "listen_port": 80}},
		{"lb_rules", "upstream_force_http1", map[string]any{"name": "r", "protocol": "http", "domain": "a.com", "listen_port": 80}},
		{"security_block_pages", "is_builtin", map[string]any{"name": "p", "content": "x"}},
		{"security_ip_lists", "system", map[string]any{"name": "l", "entries": "[]"}},
	}
	for _, tc := range cases {
		t.Run(tc.table+"."+tc.column, func(t *testing.T) {
			row := map[string]any{}
			for k, v := range tc.row {
				row[k] = v
			}
			row[tc.column] = "true"
			var backup configBackup
			if err := json.Unmarshal([]byte(legacyBackupJSON(t, map[string][]map[string]any{tc.table: {row}}, nil, nil)), &backup); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			_, err := validateImportBackupChain(context.Background(), importValidationDeps{}, &backup, importValidationOptions{})
			if err == nil || !strings.Contains(err.Error(), tc.column) {
				t.Fatalf("err=%v, want 点名 %s", err, tc.column)
			}
		})
	}
	t.Run("global_config.auto_backup_enabled", func(t *testing.T) {
		var backup configBackup
		if err := json.Unmarshal([]byte(legacyBackupJSON(t, nil, map[string]any{"auto_backup_enabled": "true"}, nil)), &backup); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		_, err := validateImportBackupChain(context.Background(), importValidationDeps{}, &backup, importValidationOptions{})
		if err == nil || !strings.Contains(err.Error(), "auto_backup_enabled") {
			t.Fatalf("err=%v, want 点名 auto_backup_enabled", err)
		}
	})
}

// 导出包体携带 sections；还原按包体过滤

func TestBuildLbbakExport_writesSectionsAndScopedRestore(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,enabled) VALUES (9,'local-policy','off',0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (9,'local-admin','x','admin',1)`); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/export?sections=rules", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", rec.Code, rec.Body.String())
	}
	payload, err := parseLbbak(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse export: %v", err)
	}
	var exported configBackup
	if err := json.Unmarshal(payload.ConfigJSON, &exported); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	if len(exported.Sections) != 1 || exported.Sections[0] != "rules" {
		t.Fatalf("包体 sections=%v, want [rules]（还原据此过滤，不需 query）", exported.Sections)
	}

	// 导入同一 lbbak（不带 ?sections=）→ 仅按包体分类覆盖，安全策略保持不动
	rec = postLbbakImport(g, t, rec.Body.Bytes(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("restore status=%d body=%s", rec.Code, rec.Body.String())
	}
	var policyCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE id=9 AND name='local-policy'`).Scan(&policyCount); err != nil || policyCount != 1 {
		t.Fatalf("sections=rules 备份还原不得触碰安全策略, count=%d err=%v", policyCount, err)
	}
	var body struct {
		Data struct {
			Warnings []string `json:"warnings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	for _, warning := range body.Data.Warnings {
		if strings.Contains(warning, "证书") || strings.Contains(warning, "提供商") || strings.Contains(warning, "拦截页") {
			t.Fatalf("未选分类不得产生对应警告: %s", warning)
		}
	}
}

// auto backup 设置组导入门

func TestImportAutoBackupSettings_gatePreviewAndImport(t *testing.T) {
	type tc struct {
		name       string
		cfg        map[string]any
		previewOK  bool
		code       int
		errContain string
	}
	cases := []tc{
		{name: "非法频率", cfg: map[string]any{"auto_backup_frequency": "hourly"}, previewOK: false, code: 400, errContain: "auto_backup_frequency"},
		{name: "非法时间", cfg: map[string]any{"auto_backup_time": "25:61"}, previewOK: false, code: 400, errContain: "auto_backup_time"},
		{name: "weekly 日期越界", cfg: map[string]any{"auto_backup_frequency": "weekly", "auto_backup_day": 9}, previewOK: false, code: 400, errContain: "auto_backup_day"},
		{name: "未知分类", cfg: map[string]any{"auto_backup_sections": `["bogus"]`}, previewOK: false, code: 400, errContain: "auto_backup_sections"},
		// 否则落库 "[]" 让自动备份任务每轮 fail-closed。
		{name: "空分类数组", cfg: map[string]any{"auto_backup_sections": `[]`}, previewOK: false, code: 400, errContain: "备份范围不能为空"},
		{name: "空串分类", cfg: map[string]any{"auto_backup_sections": ""}, previewOK: false, code: 400, errContain: "备份范围不能为空"},
		{name: "null 分类", cfg: map[string]any{"auto_backup_sections": `null`}, previewOK: false, code: 400, errContain: "备份范围不能为空"},
		{name: "合法值回归", cfg: map[string]any{"auto_backup_frequency": "weekly", "auto_backup_time": "04:30", "auto_backup_day": 3, "auto_backup_keep": 12, "auto_backup_sections": `["users","rules"]`}, previewOK: true, code: 200},
		{name: "keep 越界钳制", cfg: map[string]any{"auto_backup_keep": 100, "auto_backup_frequency": "daily", "auto_backup_time": "03:00", "auto_backup_day": 1}, previewOK: true, code: 200},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			body := legacyBackupJSON(t, nil, tt.cfg, nil)
			preview := validateResponseShared(t, h, body)
			if preview.Valid != tt.previewOK {
				t.Fatalf("preview.Valid=%v err=%q, want %v", preview.Valid, preview.Error, tt.previewOK)
			}
			if !tt.previewOK && !strings.Contains(preview.Error, tt.errContain) {
				t.Fatalf("preview error=%q, want contains %q", preview.Error, tt.errContain)
			}
			rec := importBackupShared(h, t, body)
			if rec.Code != tt.code {
				t.Fatalf("import status=%d body=%s, want %d", rec.Code, rec.Body.String(), tt.code)
			}
			if tt.code != 200 {
				return
			}
			var keep int
			if err := db.DB.QueryRow(`SELECT COALESCE(auto_backup_keep,7) FROM global_config WHERE id=1`).Scan(&keep); err != nil {
				t.Fatalf("read auto_backup_keep: %v", err)
			}
			if _, hasKeep := tt.cfg["auto_backup_keep"]; hasKeep && keep > 30 {
				t.Fatalf("auto_backup_keep=%d, want 钳制到 ≤30", keep)
			}
		})
	}
}

// 完整性 → sections 过滤 → 行级门

func TestBackupValidationOrder_sectionsBeforeRowGates(t *testing.T) {
	badSecurity := map[string][]map[string]any{
		"security_ip_lists": {{"name": "bad-list", "entries": "[]", "system": "true"}},
	}
	t.Run("未选分类携带畸形布尔：预览/导入放行", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		body := legacyBackupJSON(t, badSecurity, nil, []string{"rules"})
		if preview := validateResponseShared(t, h, body); !preview.Valid {
			t.Fatalf("preview.Valid=false err=%q, want true（未选分类行不参与行级门）", preview.Error)
		}
		h2 := newBackupTestHandlers(t)
		if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (9,'local-admin','x','admin',1)`); err != nil {
			t.Fatal(err)
		}
		if rec := importBackupShared(h2, t, body); rec.Code != http.StatusOK {
			t.Fatalf("import status=%d body=%s, want 200", rec.Code, rec.Body.String())
		}
	})
	t.Run("选中的分类仍受行级门约束", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		badRules := map[string][]map[string]any{
			"lb_rules": {{"name": "r", "protocol": "http", "domain": "a.com", "listen_port": 80, "ntlm_compatible": "true"}},
		}
		body := legacyBackupJSON(t, badRules, nil, []string{"rules"})
		if preview := validateResponseShared(t, h, body); preview.Valid {
			t.Fatal("preview.Valid=true, want false（选中分类的畸形布尔必须拒绝）")
		}
		h2 := newBackupTestHandlers(t)
		if rec := importBackupShared(h2, t, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("import status=%d body=%s, want 400", rec.Code, rec.Body.String())
		}
	})
	t.Run("checksum 仍对全量计算：篡改未选分类也拒绝", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		body := legacyBackupJSON(t, badSecurity, nil, []string{"rules"})
		var tampered map[string]any
		if err := json.Unmarshal([]byte(body), &tampered); err != nil {
			t.Fatal(err)
		}
		tables := tampered["tables"].(map[string]any)
		tables["security_ip_lists"] = []any{map[string]any{"name": "tampered", "entries": "[]"}}
		mutated, _ := json.Marshal(tampered)
		if preview := validateResponseShared(t, h, string(mutated)); preview.Valid || !strings.Contains(preview.Error, "校验和不匹配") {
			t.Fatalf("preview valid=%v err=%q, want 校验和不匹配", preview.Valid, preview.Error)
		}
		h2 := newBackupTestHandlers(t)
		if rec := importBackupShared(h2, t, string(mutated)); rec.Code != http.StatusBadRequest {
			t.Fatalf("import status=%d body=%s, want 400", rec.Code, rec.Body.String())
		}
	})
}

// 冲突矩阵分桶预计算等价性

func TestValidateRuleConflictMatrix_bucketedEquivalence(t *testing.T) {
	candidates := []ruleConflictCandidate{
		newRuleConflictCandidate("a", "id-a", "http", "Example.COM", 443, true, false, false),
		newRuleConflictCandidate("b", "id-b", "http", "example.com", 443, true, false, false),
		newRuleConflictCandidate("c", "id-c", "http", "c.example.com", 80, true, false, false),
		newRuleConflictCandidate("d", "id-d", "http", "c.example.com", 8080, true, true, true),
		newRuleConflictCandidate("e", "id-e", "http", "x.example.com", 80, false, false, false),
		newRuleConflictCandidate("f", "id-f", "http", "x.example.com", 80, true, false, false),
		newRuleConflictCandidate("g", "id-g", "tcp", "", 9000, true, false, false),
		newRuleConflictCandidate("h", "id-h", "http", "h.example.com", 9000, true, false, false),
		newRuleConflictCandidate("i", "id-i", "tcp", "", 9001, true, false, false),
		newRuleConflictCandidate("j", "id-j", "tcp", "", 9001, true, false, false),
	}
	conflicts := validateRuleConflictMatrix(candidates)
	got := map[string]string{}
	for _, conflict := range conflicts {
		got[conflict.Name] = conflict.Reason
	}
	want := map[string]string{
		"a": "HTTP 域名", "b": "HTTP 域名",
		"c": "被 HTTPS 跳转遮蔽", "d": "被 HTTPS 跳转遮蔽",
		"g": "TCP 与 HTTP", "h": "TCP 与 HTTP",
		"i": "TCP 监听端口", "j": "TCP 监听端口",
	}
	for name, fragment := range want {
		reason, ok := got[name]
		if !ok {
			t.Fatalf("规则 %s 未判定冲突（got=%v）", name, got)
		}
		if !strings.Contains(reason, fragment) {
			t.Fatalf("规则 %s reason=%q, want contains %q", name, reason, fragment)
		}
	}
	for _, name := range []string{"e", "f"} {
		if _, ok := got[name]; ok {
			t.Fatalf("禁用行参与冲突或同端口不同域名被误判: %s reason=%q", name, got[name])
		}
	}
	if len(conflicts) != len(want) {
		t.Fatalf("conflicts=%d, want %d（%v）", len(conflicts), len(want), got)
	}
}

func BenchmarkValidateRuleConflictMatrix_500UniqueDomains(b *testing.B) {
	candidates := make([]ruleConflictCandidate, 0, 500)
	for i := range 500 {
		candidates = append(candidates, newRuleConflictCandidate(
			"rule", "id", "http", "host"+strconv.Itoa(i)+".example.com", 443, true, false, false))
	}
	b.ResetTimer()
	for b.Loop() {
		if conflicts := validateRuleConflictMatrix(candidates); len(conflicts) != 0 {
			b.Fatalf("unique domains must not conflict: %v", conflicts[0].Reason)
		}
	}
}

// legacy 仅 tables 校验和路径继续执行后置门

func legacyBackupShared(t *testing.T, mutate func(tables map[string][]map[string]any)) string {
	t.Helper()
	tables := map[string][]map[string]any{}
	for _, table := range configBackupV1Tables {
		tables[table] = []map[string]any{}
	}
	for _, table := range configBackupTables {
		if _, ok := tables[table]; !ok {
			tables[table] = []map[string]any{}
		}
	}
	tables["users"] = []map[string]any{{"id": 1, "username": "legacy-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	if mutate != nil {
		mutate(tables)
	}
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 1},
		Tables: tables,
	}
	backup.Meta.Checksum = checksumTablesOnly(t, tables)
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal legacy backup: %v", err)
	}
	return string(data)
}

func TestValidateV2Backup_legacyStillRunsPostGates(t *testing.T) {
	parse := func(t *testing.T, body string) configBackup {
		t.Helper()
		var backup configBackup
		if err := json.Unmarshal([]byte(body), &backup); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return backup
	}
	t.Run("合法 legacy 仍通过并标记旧校验和", func(t *testing.T) {
		candidate := parse(t, legacyBackupShared(t, nil))
		result, err := validateImportBackupChain(context.Background(), importValidationDeps{}, &candidate, importValidationOptions{})
		usedLegacy := result.UsedLegacyChecksum
		if err != nil {
			t.Fatalf("合法 legacy 备份不得拒绝: %v", err)
		}
		if !usedLegacy {
			t.Fatal("legacy 仅 tables 校验和应标记 usedLegacyChecksum")
		}
	})
	t.Run("白名单外 CA provider 拒绝", func(t *testing.T) {
		body := legacyBackupShared(t, func(tables map[string][]map[string]any) {
			tables["ca_providers"] = []map[string]any{{"id": 1, "provider": "evil-ca", "credentials": "{}"}}
		})
		candidate := parse(t, body)
		if _, err := validateImportBackupChain(context.Background(), importValidationDeps{}, &candidate, importValidationOptions{}); err == nil || !strings.Contains(err.Error(), "无效的 CA 提供商") {
			t.Fatalf("err=%v, want CA provider 白名单拒绝", err)
		}
	})
	t.Run("自定义 directory_url 被官方常量覆写", func(t *testing.T) {
		body := legacyBackupShared(t, func(tables map[string][]map[string]any) {
			tables["ca_providers"] = []map[string]any{{"id": 1, "provider": "letsencrypt", "credentials": "{}", "directory_url": "https://evil.example/acme"}}
		})
		backup := parse(t, body)
		if _, err := validateImportBackupChain(context.Background(), importValidationDeps{}, &backup, importValidationOptions{}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := backup.Tables["ca_providers"][0]["directory_url"]; got != services.LetsEncryptDirectoryURL {
			t.Fatalf("directory_url=%v, want 官方常量覆写", got)
		}
	})
	t.Run("非法凭证拒绝", func(t *testing.T) {
		body := legacyBackupShared(t, func(tables map[string][]map[string]any) {
			tables["ca_providers"] = []map[string]any{{"id": 1, "provider": "letsencrypt", "credentials": "not-json"}}
		})
		candidate := parse(t, body)
		if _, err := validateImportBackupChain(context.Background(), importValidationDeps{}, &candidate, importValidationOptions{}); err == nil || !strings.Contains(err.Error(), "凭证格式") {
			t.Fatalf("err=%v, want 凭证格式拒绝", err)
		}
	})
	t.Run("非法证书任务状态拒绝", func(t *testing.T) {
		body := legacyBackupShared(t, func(tables map[string][]map[string]any) {
			tables["cert_jobs"] = []map[string]any{{"rule_id": "x", "status": "bogus"}}
		})
		candidate := parse(t, body)
		if _, err := validateImportBackupChain(context.Background(), importValidationDeps{}, &candidate, importValidationOptions{}); err == nil || !strings.Contains(err.Error(), "无效的证书任务状态") {
			t.Fatalf("err=%v, want 证书任务状态拒绝", err)
		}
	})
	t.Run("字符串布尔拒绝", func(t *testing.T) {
		body := legacyBackupShared(t, func(tables map[string][]map[string]any) {
			tables["users"] = []map[string]any{{"id": 1, "username": "legacy-admin", "password_hash": "hash", "role": "admin", "is_enabled": "1"}}
		})
		candidate := parse(t, body)
		if _, err := validateImportBackupChain(context.Background(), importValidationDeps{}, &candidate, importValidationOptions{}); err == nil || !strings.Contains(err.Error(), "is_enabled") {
			t.Fatalf("err=%v, want 布尔类型门拒绝", err)
		}
	})
	t.Run("无启用管理员拒绝", func(t *testing.T) {
		body := legacyBackupShared(t, func(tables map[string][]map[string]any) {
			tables["users"] = []map[string]any{{"id": 1, "username": "legacy-admin", "password_hash": "hash", "role": "admin", "is_enabled": 0}}
		})
		candidate := parse(t, body)
		if _, err := validateImportBackupChain(context.Background(), importValidationDeps{}, &candidate, importValidationOptions{}); err == nil || !strings.Contains(err.Error(), "管理员") {
			t.Fatalf("err=%v, want 管理员门拒绝", err)
		}
	})
}

// ── /03/08：waf 文件失败 → 版本记录丢弃 + 响应明示 ──

func TestLbbakImport_badXdbRejectedKeepsLocal(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	_, xdbPath := overrideTestWafPaths(t)
	local := []byte("LOCAL-XDB-BYTES")
	if err := os.WriteFile(xdbPath, local, 0o644); err != nil {
		t.Fatal(err)
	}
	body := buildTestLbbak(t, completeBackupJSON(t, map[string][]map[string]any{
		"security_ip2region_version": {{"id": 1, "version": "bad-xdb", "auto_update": 1}},
	}), []byte(strings.Repeat("\xab", 4096)))

	rec := postLbbakImport(g, t, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("bad xdb 应拒绝该文件而非整包失败, status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "IP2Region") || !strings.Contains(rec.Body.String(), "版本记录已丢弃") {
		t.Fatalf("响应必须明示坏 xdb 与版本记录丢弃: %s", rec.Body.String())
	}
	got, err := os.ReadFile(xdbPath)
	if err != nil || string(got) != string(local) {
		t.Fatalf("坏 xdb 不得覆盖本地文件: err=%v content=%q", err, string(got))
	}
	// 备份携带的版本记录必须被丢弃；导入后的首槽武装可能重播种本地默认行
	// （version=unknown），但其内容不得是备份版本。
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip2region_version WHERE version='bad-xdb'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("备份的 security_ip2region_version 记录仍在（文件未落盘，版本记录必须丢弃）")
	}
}

// CRS 落盘失败只能丢弃备份版本行，不得抹掉导入前的本地版本/排程；
// rearm 也不得用默认种子覆盖恢复后的本地行。
func TestLbbakImport_crsFailureRestoresLocalVersionRow(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	overrideTestWafPaths(t)
	if _, err := db.DB.Exec(`INSERT INTO security_crs_version
		(id,version,auto_update,next_update,update_status,updated_at) VALUES (1,'v-local',0,'2026-12-01 03:00:00','idle','2026-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_crs_version": {{"id": 1, "version": "v-backup", "auto_update": 1}},
	})
	payload, err := buildLbbakPayload([]byte(backup), &services.WafFileBundle{
		CRSVersion: "v-backup", CRSSha256: "deadbeef", CRSTarGz: []byte("dummy-crs-tar"),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := postLbbakImport(g, t, payload, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 with CRS failure warning", rec.Code, rec.Body.String())
	}
	var version, nextUpdate, status string
	var autoUpdate int
	if err := db.DB.QueryRow(`SELECT version,COALESCE(auto_update,0),COALESCE(next_update,''),COALESCE(update_status,'') FROM security_crs_version WHERE id=1`).Scan(&version, &autoUpdate, &nextUpdate, &status); err != nil {
		t.Fatalf("read restored version: %v", err)
	}
	// 行的身份/开关/状态必须原样保留（备份的 v-backup/auto_update=1 不得落库）；
	// 恢复行的时间列以驱动串形态写回（"…+00:00"），导入后重排按「不可解析即
	// 跳过」保持原值——与补跑/自愈语义同口径。
	if version != "v-local" || autoUpdate != 0 || !strings.HasPrefix(nextUpdate, "2026-12-01 03:00:00") || status != "idle" {
		t.Fatalf("restored version=(%q,%d,%q,%q), want local row unchanged", version, autoUpdate, nextUpdate, status)
	}
}

// 必须回到 live 索引校验并显性拒绝不兼容策略。
func TestLbbakImport_crsFailureRevalidatesPoliciesAgainstLiveTree(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	overrideTestWafPaths(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_crs_version": {{"id": 1, "version": "v-backup", "auto_update": 1}},
		"security_policies":    {{"id": 1, "name": "new-tree-only", "mode": "blocking", "enabled": 1, "crs_rule_groups": `["42"]`}},
	})
	payload, err := buildLbbakPayload([]byte(backup), &services.WafFileBundle{
		CRSVersion: "v-backup", CRSSha256: "deadbeef", CRSTarGz: []byte("dummy-crs-tar"),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := postLbbakImport(g, t, payload, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400 after CRS failure exposes live-tree incompatibility", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "规则组") && !strings.Contains(rec.Body.String(), "CRS") {
		t.Fatalf("body=%s, want explicit CRS/policy incompatibility", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "备份同时替换 CRS 规则树") {
		t.Fatalf("failed CRS replacement must not claim tree was replaced: %s", rec.Body.String())
	}
}

func TestLbbakImport_validXdbLands(t *testing.T) {
	h := newBackupTestHandlers(t)
	t.Cleanup(services.ResetIP2RegionSearcherForTest)
	g := newBackupSectionRouter(h)
	_, xdbPath := overrideTestWafPaths(t)
	xdb := validXdbBytes(t)
	body := buildTestLbbak(t, completeBackupJSON(t, map[string][]map[string]any{
		"security_ip2region_version": {{"id": 1, "version": "good-xdb", "auto_update": 1}},
	}), xdb)

	rec := postLbbakImport(g, t, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "版本记录已丢弃") {
		t.Fatalf("合法 xdb 不得报版本记录丢弃: %s", rec.Body.String())
	}
	got, err := os.ReadFile(xdbPath)
	if err != nil || len(got) != len(xdb) {
		t.Fatalf("合法 xdb 必须落盘: err=%v len=%d", err, len(got))
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip2region_version`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("security_ip2region_version rows=%d err=%v, want 1", rows, err)
	}
}

func TestLbbakImport_threatSourceFailureWarnsAndKeepsLocal(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	overrideTestWafPaths(t)
	// 威胁库落盘目标不是目录（root 下 chmod 不生效，改用形态错误稳定失败）
	wafDir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(wafDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := services.OverrideThreatWafDirForTest(wafDir)
	defer restore()

	// 本地快照基线：先写可判别的旧值（updated_at 为 schema 既有列，不依赖
	// last_updated 的可选性），失败源回滚后必须仍等于该快照。
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET updated_at='2020-01-01 00:00:00' WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}
	var beforeRow string
	if err := db.DB.QueryRow(`SELECT COALESCE(updated_at,'') FROM security_threat_sources WHERE name='ustc'`).Scan(&beforeRow); err != nil {
		t.Fatalf("读取本地快照: %v", err)
	}
	if beforeRow != "2020-01-01 00:00:00" {
		t.Fatalf("本地快照播种失败: updated_at=%q", beforeRow)
	}

	body := buildLbbakWithExtraThreatEntry(t, completeBackupJSON(t, map[string][]map[string]any{
		"security_threat_sources": {{"name": "ustc", "display_name": "USTC", "url": "https://x", "update_enabled": 1, "apply_enabled": 1, "updated_at": "2030-01-01 00:00:00"}},
	}), []byte("1.2.3.4\n"))
	rec := postLbbakImport(g, t, body, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "威胁库") || !strings.Contains(rec.Body.String(), "ustc") {
		t.Fatalf("逐源失败必须进 responseWarnings: %s", rec.Body.String())
	}
	var afterRow string
	if err := db.DB.QueryRow(`SELECT COALESCE(updated_at,'') FROM security_threat_sources WHERE name='ustc'`).Scan(&afterRow); err != nil {
		t.Fatalf("失败源行必须仍在（未被删除成缺行）: %v", err)
	}
	// 失败源：整行回滚为本地快照——以「同一天同一时刻」比较（SQLite 回写
	// 快照会带 +00:00 后缀，逐字比较会假红；afterRow=="" 则会把本地空串
	// 误判为失败态），并额外排除备份值。
	if !strings.HasPrefix(afterRow, "2020-01-01 00:00:00") {
		t.Fatalf("失败源必须整行回滚为本地快照: updated_at=%q（本地=%q）", afterRow, beforeRow)
	}
	if afterRow == "2030-01-01 00:00:00" {
		t.Fatalf("失败源不得被备份值覆盖: updated_at=%q", afterRow)
	}
}

// commit 后应用日志级别 + admin TLS 重启提示

func TestImportConfigBackup_appliesLogLevelAndAdminTLSTip(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.RecordRuntimeAdminTLS(services.AdminTLSConfig{Enabled: false, Mode: "selfsigned"})
	t.Cleanup(func() { _ = services.ConfigureLogLevel("info") })

	body := legacyBackupJSON(t, nil, map[string]any{"log_level": "debug", "admin_tls_enabled": 1, "admin_tls_mode": "selfsigned"}, nil)
	rec := importBackupShared(h, t, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := services.CurrentLogLevel(); got != "debug" {
		t.Fatalf("CurrentLogLevel()=%q, want debug（导入后立即生效）", got)
	}
	if !strings.Contains(rec.Body.String(), "重启后生效") {
		t.Fatalf("admin TLS 变更必须提示重启: %s", rec.Body.String())
	}
}

// 运行期设置门

func TestImportRuntimeSettings_gate(t *testing.T) {
	cases := []struct {
		name       string
		cfg        map[string]any
		ok         bool
		errContain string
	}{
		{name: "非数值纬度", cfg: map[string]any{"server_map_lat": "north"}, errContain: "纬度"},
		{name: "纬度越界", cfg: map[string]any{"server_map_lat": 91}, errContain: "纬度"},
		{name: "经度越界", cfg: map[string]any{"server_map_lon": -181}, errContain: "经度"},
		{name: "非法时区", cfg: map[string]any{"timezone": "Mars/Olympus"}, errContain: "时区"},
		{name: "非法大屏模式", cfg: map[string]any{"threat_screen_mode": "3d"}, errContain: "威胁大屏"},
		{name: "非法 Caddy 日志级别", cfg: map[string]any{"caddy_log_level": "verbose"}, errContain: "Caddy 日志级别"},
		{name: "负代理超时", cfg: map[string]any{"proxy_dial_timeout": -1}, errContain: "超时"},
		{name: "default_ca 不存在", cfg: map[string]any{"default_ca_provider_id": 99}, errContain: "默认 CA"},
		{name: "同步间隔低于下限", cfg: map[string]any{"sync_interval": 9}, errContain: "sync_interval"},
		{name: "同步间隔高于上限", cfg: map[string]any{"sync_interval": 86401}, errContain: "sync_interval"},
		{name: "同步间隔非整数", cfg: map[string]any{"sync_interval": 1.5}, errContain: "sync_interval"},
		{name: "同步间隔下限", cfg: map[string]any{"sync_interval": 10}, ok: true},
		{name: "同步间隔上限", cfg: map[string]any{"sync_interval": 86400}, ok: true},
		{name: "合法组合", cfg: map[string]any{
			"timezone": "Asia/Shanghai", "server_map_lat": 31.2, "server_map_lon": 121.5,
			"threat_screen_mode": "globe", "caddy_log_level": "warn", "proxy_dial_timeout": 0,
			"default_ca_provider_id": 0,
		}, ok: true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			body := legacyBackupJSON(t, nil, tt.cfg, nil)
			preview := validateResponseShared(t, h, body)
			if preview.Valid != tt.ok {
				t.Fatalf("preview.Valid=%v err=%q, want %v", preview.Valid, preview.Error, tt.ok)
			}
			rec := importBackupShared(h, t, body)
			if tt.ok {
				if rec.Code != http.StatusOK {
					t.Fatalf("合法设置导入 status=%d body=%s", rec.Code, rec.Body.String())
				}
				return
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("import status=%d body=%s, want 400", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.errContain) {
				t.Fatalf("err body=%s, want contains %q", rec.Body.String(), tt.errContain)
			}
		})
	}
}

// 导入 off→on 水位线

func TestImportConfigBackup_autobackupWatermarkOnEnable(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=0, auto_backup_last_run='2020-01-01T00:00:00Z' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	body := legacyBackupJSON(t, nil, map[string]any{"auto_backup_enabled": 1}, nil)
	rec := importBackupShared(h, t, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var enabled int
	var lastRun string
	if err := db.DB.QueryRow(`SELECT COALESCE(auto_backup_enabled,0), COALESCE(auto_backup_last_run,'') FROM global_config WHERE id=1`).Scan(&enabled, &lastRun); err != nil {
		t.Fatal(err)
	}
	if enabled != 1 {
		t.Fatalf("auto_backup_enabled=%d, want 1", enabled)
	}
	parsed, err := time.Parse(time.RFC3339, lastRun)
	if err != nil {
		t.Fatalf("auto_backup_last_run=%q 非 RFC3339: %v", lastRun, err)
	}
	if time.Since(parsed) > time.Minute {
		t.Fatalf("off→on 导入必须重置水位线（now），got %s（陈旧水位会立即补跑首轮）", lastRun)
	}
}

// sections 并集 == configBackupTables 且无重复

func TestConfigBackupSections_unionMatchesTables(t *testing.T) {
	seen := map[string]string{}
	for _, section := range configBackupSections {
		for _, table := range section.Tables {
			if previous, dup := seen[table]; dup {
				t.Fatalf("表 %s 同时出现在分类 %s 与 %s", table, previous, section.Key)
			}
			seen[table] = section.Key
		}
	}
	for _, table := range configBackupTables {
		if _, ok := seen[table]; !ok {
			t.Fatalf("configBackupTables 的表 %s 未归入任何分类", table)
		}
	}
	if len(seen) != len(configBackupTables) {
		t.Fatalf("sections 并集=%d 表, configBackupTables=%d 表", len(seen), len(configBackupTables))
	}
}

// cert_renewal_days 导入保留 0（0=默认 30；钳到 1 是保存侧下界，不适用于导入
// ——导入是存量行还原，钳制会静默改变用户配置）。

func TestImportConfigBackup_keepsZeroCertRenewalDays(t *testing.T) {
	h := newBackupTestHandlers(t)
	body := legacyBackupJSON(t, nil, map[string]any{"cert_renewal_days": 0}, nil)
	rec := importBackupShared(h, t, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var stored int
	if err := db.DB.QueryRow(`SELECT COALESCE(cert_renewal_days,30) FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Fatalf("cert_renewal_days=%d, want 0（0=默认 30，导入不再钳到 1）", stored)
	}
}

// 导入后四族规则库首槽武装（DescribeAll NextSlot 非空的行为侧）

func TestImportConfigBackup_rearmsSecurityLibrarySlots(t *testing.T) {
	h := newBackupTestHandlers(t)
	t.Cleanup(services.ResetIP2RegionSearcherForTest)
	g := newBackupSectionRouter(h)
	crsDir, xdbPath := overrideTestWafPaths(t)
	if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "VERSION"), []byte("v4.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crsDir, "rules", "crs-setup.conf"), []byte("# crs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(xdbPath, validXdbBytes(t), 0o644); err != nil {
		t.Fatal(err)
	}
	restoreThreat := services.OverrideThreatWafDirForTest(t.TempDir())
	defer restoreThreat()

	// 真实 lbbak 形态（CRS/xdb 文件在场）——版本表才会随导入保留。
	bundle := services.BuildWafFileBundle()
	if bundle == nil || len(bundle.CRSTarGz) == 0 {
		t.Fatal("test fixture: BuildWafFileBundle 未产出 CRS 包")
	}
	backupJSON := completeBackupJSON(t, map[string][]map[string]any{
		"security_crs_version":       {{"id": 1, "version": "v4.0.0", "auto_update": 1, "next_update": ""}},
		"security_ip2region_version": {{"id": 1, "version": "v1", "auto_update": 1, "next_update": ""}},
		"security_threat_sources":    {{"name": "ustc", "display_name": "USTC", "url": "https://x", "update_enabled": 1, "apply_enabled": 1, "next_update": ""}},
	})
	payload, err := buildLbbakPayload([]byte(backupJSON), bundle)
	if err != nil {
		t.Fatalf("build lbbak: %v", err)
	}
	rec := postLbbakImport(g, t, payload, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	// 四族首槽武装：CRS/IP2Region 版本表 + 威胁源族 + 爬虫源族（后两族由
	// services 种子行/ensureCrawlerSources 提供）。
	for _, query := range []string{
		`SELECT COALESCE(next_update,'') FROM security_crs_version WHERE id=1`,
		`SELECT COALESCE(next_update,'') FROM security_ip2region_version WHERE id=1`,
		`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE update_enabled=1 LIMIT 1`,
		`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE update_enabled=1 LIMIT 1`,
	} {
		var next string
		if err := db.DB.QueryRow(query).Scan(&next); err != nil {
			t.Fatalf("query %q: %v", query, err)
		}
		if next == "" {
			t.Fatalf("%s 为空——导入后必须重新武装首槽（无需重启）", query)
		}
	}
}

// 证书队列未排空 → 导入 409

func TestImportConfigBackup_rejectsWhenCertDrainIncomplete(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	// 登记一个「执行中」条目（不响应取消的 issuer 形态）：PauseAndDrain 退役
	// 该队列后 active 仍非空 → 返回 false。
	services.GetCAQueueManager().MarkJobRunningForTest("rule-drain", 4242)

	rec := importBackupShared(h, t, legacyBackupJSON(t, nil, nil, nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（证书任务执行中）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "证书任务执行中") {
		t.Fatalf("body=%s, want 排空未完成提示", rec.Body.String())
	}

	// 正常排干（无在途任务）→ 导入成功。
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	services.GetCAQueueManager().Start()
	h2 := newBackupTestHandlers(t)
	if rec := importBackupShared(h2, t, legacyBackupJSON(t, nil, nil, nil)); rec.Code != http.StatusOK {
		t.Fatalf("drained import status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
}

// 必须在 begin 后的事务/锁内视图复核并拒绝，不能落库悬挂引用。
func TestImportConfigBackup_rechecksACMEReferencesAfterLock(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin','hash','admin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES (1,'live','dnspod','{"mode":"tencent","secret_id":"id","secret_key":"key"}',1)`); err != nil {
		t.Fatal(err)
	}
	body := legacyBackupJSON(t, map[string][]map[string]any{
		"lb_rules":  {{"caddy_id": "lb_ref_toctou", "name": "toctou", "protocol": "http", "domain": "toctou.example.test", "listen_port": 18551, "enabled": 1, "enable_tls": 1, "tls_source": "acme_dns", "acme_config_id": 1}},
		"cert_jobs": {{"rule_id": "lb_ref_toctou", "domain": "toctou.example.test", "status": "issued", "cert_pem": "CERT", "key_pem": "KEY"}},
	}, nil, []string{"rules"})
	oldHook := configImportBeforeLock
	configImportBeforeLock = func() {
		if _, err := db.DB.Exec(`DELETE FROM certificate_configs WHERE id=1`); err != nil {
			t.Errorf("delete referenced config: %v", err)
		}
	}
	t.Cleanup(func() { configImportBeforeLock = oldHook })

	rec := importBackupShared(h, t, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400 after referenced DNS config disappeared before lock", rec.Code, rec.Body.String())
	}
	var rules int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_ref_toctou'`).Scan(&rules); err != nil {
		t.Fatal(err)
	}
	if rules != 0 {
		t.Fatalf("dangling ACME rule was imported: %d", rules)
	}
}

func TestImportConfigBackup_liveACMEPrecheckUsesLockedView(t *testing.T) {
	// Given a live enabled ACME rule that no longer exists as ACME by import time.
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,acme_config_id)
		VALUES ('lb_prelock','prelock','http','prelock.example.test',18550,1,1,'acme_dns',999)`); err != nil {
		t.Fatal(err)
	}
	body := legacyBackupJSON(t, map[string][]map[string]any{
		"users":               {{"id": 1, "username": "admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}},
		"certificate_configs": {},
	}, nil, []string{"users"})
	oldHook := configImportBeforeLock
	configImportBeforeLock = func() {
		if _, err := db.DB.Exec(`UPDATE lb_rules SET enable_tls=0, tls_source='manual', acme_config_id=0 WHERE caddy_id='lb_prelock'`); err != nil {
			t.Errorf("mutate live rule: %v", err)
		}
	}
	t.Cleanup(func() { configImportBeforeLock = oldHook })

	// When importing system data after that live transition.
	rec := importBackupShared(h, t, body)

	// Then the dangling-reference warning reflects the locked import-time view.
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "提供商配置悬挂") {
		t.Fatalf("stale pre-lock ACME reference count leaked into response: %s", rec.Body.String())
	}
}

func TestImportConfigBackup_versionSeedCleanupUsesLockedSnapshot(t *testing.T) {
	// Given a CRS version row removed between the old pre-lock read and import.
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin','hash','admin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO security_crs_version (id, version, auto_update) VALUES (1, 'v4.0.0', 1)`); err != nil {
		t.Fatal(err)
	}
	body := legacyBackupJSON(t, map[string][]map[string]any{
		"security_threat_sources": {{"name": "ustc", "display_name": "USTC", "url": "https://example.test/list", "update_enabled": 1, "apply_enabled": 1, "next_update": ""}},
	}, nil, []string{"security"})
	oldHook := configImportBeforeLock
	configImportBeforeLock = func() {
		if _, err := db.DB.Exec(`DELETE FROM security_crs_version WHERE id=1`); err != nil {
			t.Errorf("delete version row: %v", err)
		}
	}
	t.Cleanup(func() { configImportBeforeLock = oldHook })

	// When importing another security table (which rearms the version slots).
	rec := importBackupShared(h, t, body)

	// Then the absent unimported version row is not resurrected by rearm.
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_crs_version WHERE id=1`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("unimported CRS version seed rows=%d, want 0", count)
	}
}

func TestImportConfigBackup_globalConfigRearmsSecuritySlots(t *testing.T) {
	// Given a pure global-config import that enables threat auto-update.
	h := newBackupTestHandlers(t)
	body := legacyBackupJSON(t, map[string][]map[string]any{
		"users": {{"id": 1, "username": "admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}},
	}, map[string]any{"threat_auto_update": 1}, []string{"users"})

	// When importing only users/global config (no security-library tables).
	rec := importBackupShared(h, t, body)

	// Then enabled threat sources receive a first slot and absent version rows stay absent.
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var armed int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_threat_sources WHERE update_enabled=1 AND COALESCE(next_update,'')<>''`).Scan(&armed); err != nil {
		t.Fatal(err)
	}
	if armed == 0 {
		t.Fatal("global-config import did not rearm threat first slots")
	}
	var crsRows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_crs_version WHERE id=1`).Scan(&crsRows); err != nil {
		t.Fatal(err)
	}
	if crsRows != 0 {
		t.Fatalf("unimported CRS version row was seeded by rearm: %d", crsRows)
	}
}

// 归一 NULL，空串落库后 users/lb_rules/cert_jobs/path_rules 的 raw time 扫描
// 每次 500。预览与导入共用同一行级门，故两侧必须同判。
func TestValidateV2Backup_rejectsMalformedTimestamps(t *testing.T) {
	h := newBackupTestHandlers(t)
	adminRow := func(created any) map[string]any {
		return map[string]any{
			"id": 1, "username": "backup-admin", "password_hash": "hash",
			"role": "admin", "is_enabled": 1, "created_at": created,
		}
	}
	for _, bad := range []any{"", "   ", "not-a-time", int64(12345)} {
		body := legacyBackupJSON(t, map[string][]map[string]any{"users": {adminRow(bad)}}, nil, nil)
		var backup configBackup
		if err := json.Unmarshal([]byte(body), &backup); err != nil {
			t.Fatalf("unmarshal (%v): %v", bad, err)
		}
		if _, err := validateImportBackupChain(context.Background(), importValidationDeps{DB: db.DB}, &backup, importValidationOptions{}); err == nil || !strings.Contains(err.Error(), "created_at") {
			t.Fatalf("created_at=%#v err=%v, want 点名 created_at 拒绝", bad, err)
		}
		response := postValidateBytes(t, h, []byte(body))
		if response.Valid || !strings.Contains(response.Error, "created_at") {
			t.Fatalf("created_at=%#v preview valid=%v error=%q, want invalid 且点名 created_at", bad, response.Valid, response.Error)
		}
	}
	// 合法形态（NULL 由写入侧归一；flat/RFC3339/带毫秒）不得误拒。
	for _, good := range []any{nil, "1970-01-01 00:00:00", "2026-10-18T00:00:00Z", "2026-10-18 00:00:00.123"} {
		body := legacyBackupJSON(t, map[string][]map[string]any{"users": {adminRow(good)}}, nil, nil)
		var backup configBackup
		if err := json.Unmarshal([]byte(body), &backup); err != nil {
			t.Fatalf("unmarshal (%v): %v", good, err)
		}
		if _, err := validateImportBackupChain(context.Background(), importValidationDeps{DB: db.DB}, &backup, importValidationOptions{}); err != nil {
			t.Fatalf("created_at=%#v err=%v, want accepted", good, err)
		}
		if response := postValidateBytes(t, h, []byte(body)); !response.Valid {
			t.Fatalf("created_at=%#v preview valid=false error=%q, want valid", good, response.Error)
		}
	}
}

// system 名单——旧备份含同名 system=0 用户列表时，启动播种按名跳过会让
// system=1 预置行永久缺失（自动封禁任务每轮失败）。
func TestImportConfigBackup_replaysSystemIPListSeeds(t *testing.T) {
	h := newBackupTestHandlers(t)
	rows := []map[string]any{{
		"id": 5, "name": "自动封禁名单", "description": "用户自建同名列表",
		"category": "自定义", "entries": "[]", "system": 0,
	}}
	// 导入后必须有启用管理员：随包携带 users 分类（legacyBackupJSON 的默认管理员行）。
	body := legacyBackupJSON(t, map[string][]map[string]any{"security_ip_lists": rows}, nil, []string{"security", "users"})
	rec := importBackupShared(h, t, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var systemRows, userRows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='自动封禁名单' AND COALESCE(system,0)=1`).Scan(&systemRows); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='自动封禁名单' AND COALESCE(system,0)=0`).Scan(&userRows); err != nil {
		t.Fatal(err)
	}
	if systemRows != 1 {
		t.Fatalf("system=1 预置行=%d, want 1（提交后补播）", systemRows)
	}
	if userRows != 1 {
		t.Fatalf("system=0 用户行=%d, want 1（同名用户列表不得被合并/删除）", userRows)
	}
}
