package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// R43 F-B: protocol 无白名单时 "https" 可落库并被渲染为 TCP（域名匹配静默丢失），
// 而保存校验把 https 当 HTTP 通过——校验与生成发散。Create/Update 必须 400。
func TestCreateRule_rejects_unknown_protocol(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{
		"name":"https-proto","protocol":"https","domain":"https.example.test","listen_port":8443,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]
	}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "协议仅支持 http 或 tcp") {
		t.Fatalf("create https protocol status=%d body=%s, want 400 协议白名单", response.Code, response.Body.String())
	}
}

func TestUpdateRule_rejects_unknown_protocol(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress) VALUES ('lb_proto','proto','','http','proto.example.test',8080,'weighted_round_robin',1,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_proto','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_proto", strings.NewReader(`{"protocol":"https"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "协议仅支持 http 或 tcp") {
		t.Fatalf("update to https protocol status=%d body=%s, want 400 协议白名单", response.Code, response.Body.String())
	}
}

// R43 F-C（v2 备份）: 启用的手动 TLS 规则证书/私钥为空时导入必须整包拒绝
// （镜像 rule_features.go:648-651 保存/启用侧口径）；禁用行或 acme_dns 行放行。
func TestValidateV2BackupRules_rejects_enabled_manual_tls_without_cert(t *testing.T) {
	tests := []struct {
		name        string
		rule        map[string]any
		extraTables map[string][]map[string]any
		wantErrText string
	}{
		{
			name:        "启用手动 TLS 缺证书被拒绝",
			rule:        map[string]any{"caddy_id": "lb_nocert", "name": "nocert", "protocol": "http", "domain": "nocert.example.test", "listen_port": 8443, "enabled": 1, "enable_tls": 1, "tls_source": "manual"},
			wantErrText: "手动证书模式下必须提供 TLS 证书和私钥",
		},
		{
			name:        "启用手动 TLS 证书为空白被拒绝",
			rule:        map[string]any{"caddy_id": "lb_blankcert", "name": "blankcert", "protocol": "http", "domain": "blank.example.test", "listen_port": 8444, "enabled": 1, "enable_tls": 1, "tls_source": "manual", "tls_cert": "  ", "tls_key": ""},
			wantErrText: "手动证书模式下必须提供 TLS 证书和私钥",
		},
		{
			name: "禁用手动 TLS 缺证书可导入（不参与渲染）",
			rule: map[string]any{"caddy_id": "lb_disabled_nocert", "name": "disabled", "protocol": "http", "domain": "disabled.example.test", "listen_port": 8445, "enabled": 0, "enable_tls": 1, "tls_source": "manual"},
		},
		{
			// R53 发现2/A-2 起启用 acme_dns 行须引用备份内有效配置且携带证书
			// 任务行；本用例的原始意图（无需内联 tls_cert/tls_key）保持不变。
			name: "启用 acme_dns 无内联证书可导入（证书由 cert_jobs 管理）",
			rule: map[string]any{"caddy_id": "lb_acme", "name": "acme", "protocol": "http", "domain": "acme.example.test", "listen_port": 8446, "enabled": 1, "enable_tls": 1, "tls_source": "acme_dns", "acme_config_id": 7},
			extraTables: map[string][]map[string]any{
				"certificate_configs": {{"id": 7, "name": "dns", "enabled": 1}},
				"cert_jobs":           {{"rule_id": "lb_acme", "domain": "acme.example.test", "status": "issued"}},
			},
		},
		{
			name: "启用手动 TLS 证书齐全正常",
			rule: map[string]any{"caddy_id": "lb_withcert", "name": "withcert", "protocol": "http", "domain": "withcert.example.test", "listen_port": 8447, "enabled": 1, "enable_tls": 1, "tls_source": "manual", "tls_cert": "cert", "tls_key": "key"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tables := map[string][]map[string]any{"lb_rules": {tt.rule}}
			for table, rows := range tt.extraTables {
				tables[table] = rows
			}
			err := validateV2BackupRules(tables)
			if tt.wantErrText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("validateV2BackupRules err=%v, want contains %q", err, tt.wantErrText)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateV2BackupRules unexpected error: %v", err)
			}
		})
	}
}

// R43 F-C（v1 备份）: 启用的 SSL 规则证书/私钥为空时按 v1 风格软跳过并警告；
// 禁用的 SSL 规则无证书仍导入（不参与渲染，可后续补证书再启用）。
func TestImportV1Config_skips_enabled_ssl_rule_without_cert(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := `{
		"proxy_config":{"config":[
			{"pk":1,"fields":{"proxy_name":"ssl-no-cert","protocol":true,"listen":8451,"server_name":"ssl-nocert.example.test","status":true,"ssl":true,"upstream_list":[1]}},
			{"pk":2,"fields":{"proxy_name":"ssl-disabled","protocol":true,"listen":8452,"server_name":"ssl-disabled.example.test","status":false,"ssl":true,"upstream_list":[2]}}
		]},
		"upstream_config":{"config":[
			{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9001,"weight":100}},
			{"pk":2,"fields":{"status":true,"address":"127.0.0.1","port":9002,"weight":100}}
		]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "启用 TLS 但证书或私钥为空") {
		t.Fatalf("import response missing soft-skip warning: %s", response.Body.String())
	}
	var skippedRules, keptRules int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE name='ssl-no-cert'").Scan(&skippedRules); err != nil {
		t.Fatalf("count skipped rules: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE name='ssl-disabled' AND enabled=0").Scan(&keptRules); err != nil {
		t.Fatalf("count kept rules: %v", err)
	}
	if skippedRules != 0 || keptRules != 1 {
		t.Fatalf("after import: skipped=%d kept-disabled=%d, want 0/1", skippedRules, keptRules)
	}
}

// R43 F-D: 旧格式（仅 tables）校验和回退仅限无 exported_at 的旧格式标记；
// 新格式文件（带 exported_at）只篡改 Config 区时校验和不匹配必须直接拒绝。
func checksumBackupPayload(t *testing.T, tables map[string][]map[string]any, config map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(struct {
		Tables map[string][]map[string]any `json:"tables"`
		Config map[string]any              `json:"config"`
	}{tables, config})
	if err != nil {
		t.Fatalf("marshal checksum payload: %v", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func checksumTablesOnly(t *testing.T, tables map[string][]map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(tables)
	if err != nil {
		t.Fatalf("marshal tables: %v", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func legacyChecksummedBackup(t *testing.T, version int, exportedAt string, legacySum bool) string {
	t.Helper()
	tables := map[string][]map[string]any{}
	for _, table := range configBackupTables {
		tables[table] = []map[string]any{}
	}
	tables["users"] = []map[string]any{{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	cfg := map[string]any{"acme_email": "admin@example.test"}
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: version, ExportedAt: exportedAt},
		Config: cfg,
		Tables: tables,
	}
	if legacySum {
		backup.Meta.Checksum = checksumTablesOnly(t, tables)
	} else {
		backup.Meta.Checksum = checksumBackupPayload(t, tables, cfg)
	}
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	return string(data)
}

func TestValidateV2Backup_legacyChecksumFallback_gatedOnLegacyMarker(t *testing.T) {
	t.Run("v2.1.1 形态（带 exported_at + tables 校验和）报兼容性提示而非篡改", func(t *testing.T) {
		var b configBackup
		if err := json.Unmarshal([]byte(legacyChecksummedBackup(t, 2, "2026-08-19T00:00:00Z", true)), &b); err != nil {
			t.Fatalf("unmarshal backup: %v", err)
		}
		usedLegacy, err := validateV2Backup(b)
		if err == nil || !strings.Contains(err.Error(), "v2.1.1 或更早版本导出") {
			t.Fatalf("validateV2Backup err=%v, want v2.1.1 兼容性提示", err)
		}
		if strings.Contains(err.Error(), "篡改") {
			t.Fatalf("v2.1.1 合法备份不得误报篡改: %v", err)
		}
		if usedLegacy {
			t.Fatal("新格式文件不得标记为旧格式校验和路径")
		}
	})

	t.Run("旧格式标记（Version==1 且无 exported_at）+ tables 校验和放行并标记", func(t *testing.T) {
		var b configBackup
		if err := json.Unmarshal([]byte(legacyChecksummedBackup(t, 1, "", true)), &b); err != nil {
			t.Fatalf("unmarshal backup: %v", err)
		}
		usedLegacy, err := validateV2Backup(b)
		if err != nil {
			t.Fatalf("validateV2Backup unexpected error: %v", err)
		}
		if !usedLegacy {
			t.Fatal("旧格式 tables 校验和命中时 usedLegacyChecksum 应为 true")
		}
	})

	t.Run("新格式完整校验和匹配通过且不标记", func(t *testing.T) {
		var b configBackup
		if err := json.Unmarshal([]byte(legacyChecksummedBackup(t, 2, "2026-08-19T00:00:00Z", false)), &b); err != nil {
			t.Fatalf("unmarshal backup: %v", err)
		}
		usedLegacy, err := validateV2Backup(b)
		if err != nil {
			t.Fatalf("validateV2Backup unexpected error: %v", err)
		}
		if usedLegacy {
			t.Fatal("新格式校验和匹配时 usedLegacyChecksum 应为 false")
		}
	})
}

// R43 F-D: 走旧格式校验和回退的导入必须记「使用旧格式校验和」审计警告。
func TestImportConfigBackup_legacyChecksum_recordsAuditWarning(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(legacyChecksummedBackup(t, 1, "", true)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var warnings int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='导入警告' AND detail LIKE '%使用旧格式校验和%'").Scan(&warnings); err != nil {
		t.Fatalf("count audit warnings: %v", err)
	}
	if warnings != 1 {
		t.Fatalf("旧格式校验和警告数=%d, want 1", warnings)
	}
}

// R43 B43-1: 单默认页（库存内容）+ 自定义非默认页的备份未发生降级，提升不得
// 执行——默认页内容不得被静默改写为自定义页内容。
func TestImportConfigBackup_doesNotPromoteCustomPageWhenNoDemotion(t *testing.T) {
	h := newBackupTestHandlers(t)
	stock := renderDefaultBlockPage(loadBrandingConfig(h.cfg.DataDir))
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users": {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": true}},
		"security_block_pages": {
			{"id": 1, "name": "默认拦截页面", "description": "sys", "content": stock, "is_default": true},
			{"id": 2, "name": "自定义页", "description": "custom", "content": "<html>自定义拦截页</html>", "is_default": false},
		},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var keptContent string
	if err := db.DB.QueryRow("SELECT content FROM security_block_pages WHERE id=1").Scan(&keptContent); err != nil {
		t.Fatalf("read kept page content: %v", err)
	}
	if keptContent != stock {
		t.Fatalf("未发生降级时默认页内容被改写为 %q, want 保持库存内容", keptContent)
	}
	var defaultCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE is_default=1").Scan(&defaultCount); err != nil {
		t.Fatalf("count default pages: %v", err)
	}
	if defaultCount != 1 {
		t.Fatalf("default page count=%d, want 1", defaultCount)
	}
}
