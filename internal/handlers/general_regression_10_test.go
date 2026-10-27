package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 公共夹具：构造带有效校验和的 configBackup 结构体（直测
// 校验链（validateImportBackupChain），不走 HTTP 反序列化，布尔值可按任意
// Go 类型注入）。
func ruleTableBuildBackup(t *testing.T, tables map[string][]map[string]any, cfg map[string]any) configBackup {
	t.Helper()
	completeTables := make(map[string][]map[string]any, len(configBackupTables))
	for _, table := range configBackupTables {
		completeTables[table] = []map[string]any{}
	}
	if _, hasUsers := tables["users"]; !hasUsers {
		completeTables["users"] = []map[string]any{{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	}
	for table, rows := range tables {
		completeTables[table] = rows
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-08-21T00:00:00Z"},
		Config: cfg,
		Tables: completeTables,
	}
	backup.Meta.Checksum = checksumBackupPayload(t, completeTables, cfg)
	return backup
}

// 布尔列类型门——备份中布尔列的 JSON 值只能是布尔或 0/1 数值。
// 字符串 "1" 在校验期被 backupBooleanEnabled 读为 false，而 SQLite 亲和性在
// 恢复期把同一文本转存为 INTEGER 1（同一值两期含义相反），全部门
// 被击穿（admin_tls 崩溃循环、TLSShape 白名单绕过、冲突矩阵漏判）。校验必须
func TestValidateV2Backup_rejects_non_boolean_typed_boolean_columns(t *testing.T) {
	tests := []struct {
		name      string
		tables    map[string][]map[string]any
		config    map[string]any
		wantParts []string
	}{
		{
			name:      "lb_rules.enabled 字符串被拒绝",
			tables:    map[string][]map[string]any{"lb_rules": {{"caddy_id": "lb_enabled_probe", "name": "enabled-probe", "protocol": "http", "domain": "probe.test", "listen_port": 8481, "enabled": "1"}}},
			wantParts: []string{"lb_rules", "第 1 行", "enabled"},
		},
		{
			name:      "lb_rules.enable_tls 字符串被拒绝",
			tables:    map[string][]map[string]any{"lb_rules": {{"caddy_id": "lb_enabled_probe", "name": "enabled-probe", "protocol": "http", "domain": "probe.test", "listen_port": 8481, "enabled": 1, "enable_tls": "true"}}},
			wantParts: []string{"lb_rules", "enable_tls"},
		},
		{
			name:      "lb_rules 布尔列数值 2 被拒绝",
			tables:    map[string][]map[string]any{"lb_rules": {{"caddy_id": "lb_enabled_probe", "name": "enabled-probe", "protocol": "http", "domain": "probe.test", "listen_port": 8481, "enabled": 2}}},
			wantParts: []string{"lb_rules", "enabled"},
		},
		{
			name:      "users.is_enabled 字符串被拒绝",
			tables:    map[string][]map[string]any{"users": {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": "1"}}},
			wantParts: []string{"users", "is_enabled"},
		},
		{
			name:      "upstreams.enabled 字符串被拒绝",
			tables:    map[string][]map[string]any{"lb_rules": {{"caddy_id": "lb_enabled_probe", "name": "enabled-probe", "protocol": "http", "domain": "probe.test", "listen_port": 8481, "enabled": 1}}, "upstreams": {{"rule_id": "lb_enabled_probe", "host": "127.0.0.1", "port": 9001, "enabled": "0"}}},
			wantParts: []string{"upstreams", "enabled"},
		},
		{
			name:      "security_policies.enabled 字符串被拒绝",
			tables:    map[string][]map[string]any{"security_policies": {{"id": 1, "name": "p", "enabled": "1"}}},
			wantParts: []string{"security_policies", "enabled"},
		},
		{
			name:      "admin_tls_enabled 字符串被拒绝",
			config:    map[string]any{"admin_tls_enabled": "1"},
			wantParts: []string{"admin_tls_enabled"},
		},
		{
			name:      "access_log_json 非布尔字符串被拒绝",
			config:    map[string]any{"access_log_json": "yes"},
			wantParts: []string{"access_log_json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			newBackupTestHandlers(t)
			backup := ruleTableBuildBackup(t, tt.tables, tt.config)

			// When
			_, err := validateImportBackupChain(context.Background(), importValidationDeps{DB: db.DB}, &backup, importValidationOptions{})

			// Then
			if err == nil {
				t.Fatalf("校验链放行了非布尔类型的布尔列（want 拒绝并点名 %v）", tt.wantParts)
			}
			for _, part := range tt.wantParts {
				if !strings.Contains(err.Error(), part) {
					t.Fatalf("拒绝必须点名 %q，实际: %v", part, err)
				}
			}
		})
	}
}

// 对照组：规范形态（JSON 布尔、0/1 数值、NULL）必须放行——
// 真实导出/旧版备份的合法形态不得被类型门误伤。
func TestValidateV2Backup_accepts_canonical_boolean_values(t *testing.T) {
	tests := []struct {
		name   string
		tables map[string][]map[string]any
		config map[string]any
	}{
		{
			name:   "JSON 布尔 true/false 放行",
			tables: map[string][]map[string]any{"lb_rules": {{"caddy_id": "lb_enabled_probe", "name": "enabled-probe", "protocol": "http", "domain": "probe.test", "listen_port": 8481, "enabled": true, "enable_tls": false, "custom_routes_enabled": true}}, "upstreams": {{"rule_id": "lb_enabled_probe", "host": "127.0.0.1", "port": 9001, "enabled": 1}}},
			config: map[string]any{"admin_tls_enabled": false, "access_log_json": true},
		},
		{
			name:   "0/1 数值放行",
			tables: map[string][]map[string]any{"lb_rules": {{"caddy_id": "lb_enabled_probe", "name": "enabled-probe", "protocol": "http", "domain": "probe.test", "listen_port": 8481, "enabled": 1, "enable_tls": 0}}, "upstreams": {{"rule_id": "lb_enabled_probe", "host": "127.0.0.1", "port": 9001, "enabled": 1}}},
			config: map[string]any{"admin_tls_enabled": 0},
		},
		{
			name:   "float64 0/1（JSON 反序列化形态）放行",
			tables: map[string][]map[string]any{"lb_rules": {{"caddy_id": "lb_enabled_probe", "name": "enabled-probe", "protocol": "http", "domain": "probe.test", "listen_port": 8481, "enabled": float64(1)}}, "upstreams": {{"rule_id": "lb_enabled_probe", "host": "127.0.0.1", "port": 9001, "enabled": 1}}},
		},
		{
			name:   "NULL 放行（由 normalizeBackupBooleanNulls 归一）",
			tables: map[string][]map[string]any{"lb_rules": {{"caddy_id": "lb_enabled_probe", "name": "enabled-probe", "protocol": "http", "domain": "probe.test", "listen_port": 8481, "enabled": nil}}, "upstreams": {{"rule_id": "lb_enabled_probe", "host": "127.0.0.1", "port": 9001, "enabled": 1}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newBackupTestHandlers(t)
			backup := ruleTableBuildBackup(t, tt.tables, tt.config)
			if _, err := validateImportBackupChain(context.Background(), importValidationDeps{DB: db.DB}, &backup, importValidationOptions{}); err != nil {
				t.Fatalf("校验链误伤规范布尔形态: %v", err)
			}
		})
	}
}

// admin_tls_enabled:"1"（字符串）
// + upload + 空证书——校验期被读为 disabled 放行、恢复期落库为 INTEGER 1，
// 下次启动 ResolveCertificate 失败即进程退出。类型门必须 400 点名字段且零写入。
func TestImportConfigBackup_rejects_string_typed_admin_tls_enabled(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	seedCurrentAdminShared(t)
	backup := configBackupJSON(t, map[string][]map[string]any{},
		map[string]any{"admin_tls_enabled": "1", "admin_tls_mode": "upload", "admin_tls_cert": "", "admin_tls_key": ""})

	// When
	response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("import status=%d body=%s, want 400（字符串型 admin_tls_enabled 必须整包拒绝）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "admin_tls_enabled") {
		t.Fatalf("拒绝必须点名字段 admin_tls_enabled，实际: %s", response.Body.String())
	}
	assertZeroWriteShared(t)
}

// TLSShape 白名单绕过封堵：enable_tls:"1"（字符串）+ 垃圾
// tls_source——校验期 enable_tls 被读为 false 跳过白名单、恢复期规则实际启用
// TLS 且无证书（TLS 端口明文服务）。类型门必须 400 点名字段且零写入。
func TestImportConfigBackup_rejects_string_typed_enable_tls(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	seedCurrentAdminShared(t)
	rule := backupTLSRuleShared("garbage")
	rule["enable_tls"] = "1"
	backup := completeBackupJSON(t, map[string][]map[string]any{"lb_rules": {rule}})

	// When
	response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("import status=%d body=%s, want 400（字符串型 enable_tls 必须整包拒绝）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "enable_tls") {
		t.Fatalf("拒绝必须点名字段 enable_tls，实际: %s", response.Body.String())
	}
	assertZeroWriteShared(t)
}

// 恢复侧规范化：导入携带 JSON 布尔值的备份后，落库值必须是
// 规范 INTEGER 0/1（存储期与校验期含义一致）；restoreTable 对幸存的字符串
// 形态（legacy 校验和路径跳过类型门）做 "1"/"true"→1、"0"/"false"→0 归一。
func TestImportConfigBackup_restores_canonical_boolean_integers(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	seedCurrentAdminShared(t)
	backup := configBackupJSON(t, map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "lb_enabled_probe_bool", "name": "bool-flag", "protocol": "http", "domain": "bool-flag.example.test", "listen_port": 8482, "enabled": true, "enable_tls": false, "custom_routes_enabled": true}},
	}, map[string]any{"access_log_json": true})

	// When
	response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200（JSON 布尔为规范形态）", response.Code, response.Body.String())
	}
	assertIntegerBoolean := func(query string, want int, args ...any) {
		t.Helper()
		var value int
		var valueType string
		if err := db.DB.QueryRow(query, args...).Scan(&value, &valueType); err != nil {
			t.Fatalf("query %s: %v", query, err)
		}
		if value != want || valueType != "integer" {
			t.Fatalf("%s = (%d, %s), want (%d, integer)", query, value, valueType, want)
		}
	}
	assertIntegerBoolean("SELECT enabled, typeof(enabled) FROM lb_rules WHERE caddy_id='lb_enabled_probe_bool'", 1)
	assertIntegerBoolean("SELECT enable_tls, typeof(enable_tls) FROM lb_rules WHERE caddy_id='lb_enabled_probe_bool'", 0)
	assertIntegerBoolean("SELECT custom_routes_enabled, typeof(custom_routes_enabled) FROM lb_rules WHERE caddy_id='lb_enabled_probe_bool'", 1)
	assertIntegerBoolean("SELECT access_log_json, typeof(access_log_json) FROM global_config WHERE id=1", 1)
}

// belt-and-braces：restoreTable 直接调用时，合法布尔与
// 0/1 数值仍统一落为 INTEGER；字符串由导入行级门拒绝，不在写入侧另造语义。
func TestRestoreTable_normalizes_canonical_boolean_values(t *testing.T) {
	// Given
	newBackupTestHandlers(t)
	ctx := context.Background()
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows := []map[string]any{{
		"caddy_id": "lb_enabled_probe_str", "name": "str-flag", "protocol": "http", "listen_port": 8483,
		"enabled": true, "enable_tls": float64(0), "custom_routes_enabled": int64(1),
	}}

	// When
	if err := restoreTable(ctx, tx, db.DB, "lb_rules", rows); err != nil {
		t.Fatalf("restoreTable: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Then
	for column, want := range map[string]int{"enabled": 1, "enable_tls": 0, "custom_routes_enabled": 1} {
		var value int
		var valueType string
		if err := db.DB.QueryRow(fmt.Sprintf("SELECT %s, typeof(%s) FROM lb_rules WHERE caddy_id='lb_enabled_probe_str'", column, column)).Scan(&value, &valueType); err != nil {
			t.Fatalf("query %s: %v", column, err)
		}
		if value != want || valueType != "integer" {
			t.Fatalf("%s = (%d, %s), want (%d, integer)", column, value, valueType, want)
		}
	}
}

// 备份未携带任何 admin_tls_* 键时不得合并校验 live 值——live
// 证书运行期自然过期后，无关导入不得被误拒（该键组不受导入影响）。
func TestImportConfigBackup_skips_admin_tls_validation_when_backup_omits_keys(t *testing.T) {
	// Given：live 启用 upload + 已过期证书（UpdateAdminTLS 保存期验期，运行期自然过期）
	expiredCert, expiredKey, err := generateTestCert("expired.example.com", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("generate expired cert: %v", err)
	}
	h := newBackupTestHandlers(t)
	seedCurrentAdminShared(t)
	if _, err := db.DB.Exec("UPDATE global_config SET admin_tls_enabled=1, admin_tls_mode='upload', admin_tls_cert=?, admin_tls_key=? WHERE id=1", expiredCert, expiredKey); err != nil {
		t.Fatalf("seed expired live admin tls: %v", err)
	}
	backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{"log_level": "debug"})

	// When
	response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200（备份未携带 admin_tls_* 键，不得校验 live 值）", response.Code, response.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT COALESCE(admin_tls_enabled,0) FROM global_config WHERE id=1").Scan(&enabled); err != nil {
		t.Fatalf("read admin_tls_enabled: %v", err)
	}
	if !enabled {
		t.Fatal("备份未携带 admin_tls_* 键时 live admin_tls 配置不应被改写")
	}
}

// 预览路径同序：备份未携带 admin_tls_* 键时预览同样不得校验
// live 过期证书——预览与实际导入口径必须一致。
func TestValidateConfigImport_skips_admin_tls_validation_when_backup_omits_keys(t *testing.T) {
	// Given
	expiredCert, expiredKey, err := generateTestCert("expired.example.com", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("generate expired cert: %v", err)
	}
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("UPDATE global_config SET admin_tls_enabled=1, admin_tls_mode='upload', admin_tls_cert=?, admin_tls_key=? WHERE id=1", expiredCert, expiredKey); err != nil {
		t.Fatalf("seed expired live admin tls: %v", err)
	}
	backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{"log_level": "debug"})

	// When
	response := postImportShared(t, h.ValidateConfigImport, "/config/import/validate", backup)

	// Then
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `"valid":true`) {
		t.Fatalf("validate status=%d body=%s, want valid=true", response.Code, body)
	}
}

// 对照组：备份携带 admin_tls_* 键时合并校验仍须生效——
// live 有效配置 + 备份携带垃圾 mode → 合并态非法，整包 400。
func TestImportConfigBackup_validates_admin_tls_when_backup_carries_keys(t *testing.T) {
	// Given
	validCert, validKey, err := generateTestCert("admin.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate valid cert: %v", err)
	}
	h := newBackupTestHandlers(t)
	seedCurrentAdminShared(t)
	if _, err := db.DB.Exec("UPDATE global_config SET admin_tls_enabled=1, admin_tls_mode='upload', admin_tls_cert=?, admin_tls_key=? WHERE id=1", validCert, validKey); err != nil {
		t.Fatalf("seed valid live admin tls: %v", err)
	}
	backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{"admin_tls_mode": "garbage"})

	// When
	response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("import status=%d body=%s, want 400（携带 admin_tls_* 键时合并态必须校验）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "无效的证书来源") {
		t.Fatalf("body must contain 无效的证书来源，实际: %s", response.Body.String())
	}
	assertZeroWriteShared(t)
}

// 导入路径对 audit_retention_months 复用启动钳位同边界：高于上限钳到 12；
// 旧备份的 0/负值必须回退运行期默认 3，不能绕过默认被钳成 1。
func TestImportConfigBackup_clamps_audit_retention_months(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  int
	}{
		{name: "999 钳位到 12", value: 999, want: 12},
		{name: "13 钳位到 12", value: 13, want: 12},
		{name: "0 回退默认 3", value: 0, want: 3},
		{name: "负值回退默认 3", value: -3, want: 3},
		{name: "合法值保持不变", value: 6, want: 6},
		{name: "边界 1 保持不变", value: 1, want: 1},
		{name: "边界 12 保持不变", value: 12, want: 12},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			seedCurrentAdminShared(t)
			backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{"audit_retention_months": tt.value})

			// When
			response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)

			// Then
			if response.Code != http.StatusOK {
				t.Fatalf("import status=%d body=%s, want 200（越界值钳位放行而非整包拒绝）", response.Code, response.Body.String())
			}
			var stored int
			if err := db.DB.QueryRow("SELECT COALESCE(audit_retention_months,3) FROM global_config WHERE id=1").Scan(&stored); err != nil {
				t.Fatalf("read audit_retention_months: %v", err)
			}
			if stored != tt.want {
				t.Fatalf("audit_retention_months=%d, want %d", stored, tt.want)
			}
		})
	}
}

// jwt_expire_minutes 同样保留旧备份 0/负值的默认语义（20 分钟）；合法值、
// 上下边界与超上限形状继续沿用原有导入钳制契约。
func TestImportConfigBackup_preservesJWTDefaultForNonPositiveValues(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  int
	}{
		{name: "0 回退默认 20", value: 0, want: 20},
		{name: "负值回退默认 20", value: -1, want: 20},
		{name: "合法值保持不变", value: 30, want: 30},
		{name: "下边界保持不变", value: 1, want: 1},
		{name: "上边界保持不变", value: 1440, want: 1440},
		{name: "超上限回退默认 20", value: 1441, want: 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedCurrentAdminShared(t)
			backup := configBackupJSON(t, map[string][]map[string]any{}, map[string]any{"jwt_expire_minutes": tt.value})

			response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)

			if response.Code != http.StatusOK {
				t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var stored int
			if err := db.DB.QueryRow(`SELECT COALESCE(jwt_expire_minutes,20) FROM global_config WHERE id=1`).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if stored != tt.want {
				t.Fatalf("jwt_expire_minutes=%d, want %d", stored, tt.want)
			}
		})
	}
}

// 爬虫豁免两列必须与保存侧同门：NULL 走 schema 默认值，布尔列拒绝字符串/
// 非 0/1 整数，engines 拒绝畸形 JSON 与未注册 ID，geoip off 不得开启豁免。
func TestImportConfigBackup_validatesCrawlerExemptionColumns(t *testing.T) {
	cases := []struct {
		name         string
		exempt       any
		engines      any
		geoipMode    string
		wantStatus   int
		wantExempt   int
		wantEngines  string
		wantFragment string
	}{
		{name: "NULL 归一默认值", exempt: nil, engines: nil, geoipMode: "off", wantStatus: http.StatusOK, wantExempt: 0, wantEngines: "[]"},
		{name: "字符串 true 拒绝", exempt: "true", engines: `["googlebot"]`, geoipMode: "deny", wantStatus: http.StatusBadRequest},
		{name: "整数 2 拒绝", exempt: 2, engines: `["googlebot"]`, geoipMode: "deny", wantStatus: http.StatusBadRequest},
		{name: "合法 1 往返", exempt: 1, engines: `["googlebot"]`, geoipMode: "deny", wantStatus: http.StatusOK, wantExempt: 1, wantEngines: `["googlebot"]`},
		{name: "非法引擎 ID 拒绝", exempt: 1, engines: `["not-registered"]`, geoipMode: "deny", wantStatus: http.StatusBadRequest, wantFragment: "未知爬虫引擎 ID"},
		{name: "畸形 engines 拒绝", exempt: 1, engines: "not-json", geoipMode: "deny", wantStatus: http.StatusBadRequest, wantFragment: "引擎 ID 数组"},
		{name: "geoip off 开启豁免拒绝", exempt: 1, engines: `["googlebot"]`, geoipMode: "off", wantStatus: http.StatusBadRequest, wantFragment: "开启爬虫豁免要求地域拦截"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedCurrentAdminShared(t)
			policy := map[string]any{
				"id": 1, "name": "crawler-backup", "mode": "off", "enabled": 0,
				"geoip_mode": tt.geoipMode, "geoip_countries": "[]",
				"geoip_crawler_exempt": tt.exempt, "geoip_crawler_engines": tt.engines,
			}
			backup := configBackupJSON(t, map[string][]map[string]any{"security_policies": {policy}}, map[string]any{})

			response := postImportShared(t, h.ImportConfigBackup, "/config/import", backup)

			if response.Code != tt.wantStatus {
				t.Fatalf("import status=%d body=%s, want %d", response.Code, response.Body.String(), tt.wantStatus)
			}
			if tt.wantFragment != "" && !strings.Contains(response.Body.String(), tt.wantFragment) {
				t.Fatalf("body=%s, want containing %q", response.Body.String(), tt.wantFragment)
			}
			if tt.wantStatus != http.StatusOK {
				assertZeroWriteShared(t)
				return
			}
			var exempt int
			var engines string
			if err := db.DB.QueryRow(`SELECT geoip_crawler_exempt, geoip_crawler_engines FROM security_policies WHERE name='crawler-backup'`).Scan(&exempt, &engines); err != nil {
				t.Fatal(err)
			}
			if exempt != tt.wantExempt || engines != tt.wantEngines {
				t.Fatalf("crawler columns=(%d,%q), want (%d,%q)", exempt, engines, tt.wantExempt, tt.wantEngines)
			}
		})
	}
}
