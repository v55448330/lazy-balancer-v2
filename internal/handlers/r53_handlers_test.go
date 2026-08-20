package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// R53 发现1：EnableRule 不得把 acme_config_id 悬挂（配置行已删除）的存量
// acme_dns 规则投入运行——R52 F-3 存在性门此前只组合进 Create/Update，
// EnableRule 的唯一预校验 validateStoredRuleConfig 只有 0 值门，悬挂 id
// 放行后 TLS 端口明文服务且签发期单任务失败，无自愈。
func TestEnableRule_rejects_dangling_acme_config_id(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_enable_dangling_cfg", "enable-dangling", "enable-dangling.example.test", 8080, false, "acme_dns", true)
	seedAuditUpstream(t, "lb_enable_dangling_cfg")
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=999 WHERE caddy_id='lb_enable_dangling_cfg'"); err != nil {
		t.Fatalf("bind dangling ACME config: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_enable_dangling_cfg/enable", nil))

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "DNS 提供商配置") {
		t.Fatalf("enable status=%d body=%s, want 400 点名 DNS 提供商配置", response.Code, response.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_enable_dangling_cfg'").Scan(&enabled); err != nil {
		t.Fatalf("read enabled state: %v", err)
	}
	if enabled {
		t.Fatal("rejected rule stayed enabled")
	}
}

// R53 发现1+发现4：EnableRule 不得把引用已禁用（enabled=0）DNS 提供商配置的
// 规则投入运行——签发侧 certissuer.go 按 AND enabled=1 查空即单任务失败。
func TestEnableRule_rejects_disabled_certificate_config(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_enable_disabled_cfg", "enable-disabled-cfg", "enable-disabled-cfg.example.test", 8080, false, "acme_dns", true)
	seedAuditUpstream(t, "lb_enable_disabled_cfg")
	result, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('r53-disabled-dns','dnspod','{"token":"x"}',0)`)
	if err != nil {
		t.Fatalf("seed disabled certificate config: %v", err)
	}
	configID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read disabled config ID: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=? WHERE caddy_id='lb_enable_disabled_cfg'", configID); err != nil {
		t.Fatalf("bind disabled ACME config: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_enable_disabled_cfg/enable", nil))

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "DNS 提供商配置") {
		t.Fatalf("enable status=%d body=%s, want 400 点名 DNS 提供商配置", response.Code, response.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_enable_disabled_cfg'").Scan(&enabled); err != nil {
		t.Fatalf("read enabled state: %v", err)
	}
	if enabled {
		t.Fatal("rejected rule stayed enabled")
	}
}

// R53 发现1：EnableRule 不得把 ca_provider_id 悬挂（提供商已删除）的存量
// acme_dns 规则投入运行——与 R52 F-1 写侧 400 口径对齐。
func TestEnableRule_rejects_dangling_ca_provider_id(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_enable_dangling_ca", "enable-dangling-ca", "enable-dangling-ca.example.test", 8080, false, "acme_dns", true)
	seedAuditUpstream(t, "lb_enable_dangling_ca")
	dnsConfigID := seedR52CertificateConfig(t)
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=?,ca_provider_id=999 WHERE caddy_id='lb_enable_dangling_ca'", dnsConfigID); err != nil {
		t.Fatalf("bind dangling CA provider: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_enable_dangling_ca/enable", nil))

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "CA 提供商") {
		t.Fatalf("enable status=%d body=%s, want 400 点名 CA 提供商", response.Code, response.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_enable_dangling_ca'").Scan(&enabled); err != nil {
		t.Fatalf("read enabled state: %v", err)
	}
	if enabled {
		t.Fatal("rejected rule stayed enabled")
	}
}

// R53 发现4：CreateRule 引用已禁用（enabled=0）的 certificate_configs 行必须
// 400——同函数 ca_provider 检查与签发侧均按 AND enabled=1 口径，存在性检查
// 不得只查 id。
func TestCreateRule_rejects_disabled_certificate_config(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	result, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('r53-create-disabled','dnspod','{"token":"x"}',0)`)
	if err != nil {
		t.Fatalf("seed disabled certificate config: %v", err)
	}
	configID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read disabled config ID: %v", err)
	}
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := fmt.Sprintf(`{"name":"disabled-cfg","protocol":"http","domain":"disabled-cfg.example.test","listen_port":8080,"enable_tls":true,"tls_source":"acme_dns","acme_config_id":%d,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, configID)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "DNS 提供商配置") {
		t.Fatalf("create status=%d body=%s, want 400 点名 DNS 提供商配置", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE domain='disabled-cfg.example.test'").Scan(&count); err != nil {
		t.Fatalf("read rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("rejected rule persisted, count=%d", count)
	}
}

// R53 发现5+发现6：DuplicateRule 复制源规则的 acme_config_id/ca_provider_id
// 原值且不跑存在性校验——源规则携带悬挂 id 时必须 400 并点名源规则，副本不得落库。
func TestDuplicateRule_rejects_dangling_acme_config_id(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_dup_dangling", "dup-source", "dup-source.example.test", 8080, false, "acme_dns", true)
	seedAuditUpstream(t, "lb_dup_dangling")
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=999 WHERE caddy_id='lb_dup_dangling'"); err != nil {
		t.Fatalf("bind dangling ACME config: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_dup_dangling/duplicate", nil))

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "dup-source") {
		t.Fatalf("duplicate status=%d body=%s, want 400 点名源规则", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE name='dup-source（副本）'").Scan(&count); err != nil {
		t.Fatalf("read duplicated rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("dangling copy persisted, count=%d", count)
	}
}

// R53 发现6：validateEnabledStoredRuleConfigs（启动 + UpdateConfig 聚合校验）
// 必须点名 acme_config_id 悬挂的启用规则——存量/导入坏规则不得静默通过。
func TestValidateEnabledStoredRuleConfigs_flags_dangling_acme_config(t *testing.T) {
	// Given
	newBackupTestHandlers(t)
	seedAuditRule(t, "lb_startup_dangling", "startup-dangling", "startup-dangling.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_startup_dangling")
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=999 WHERE caddy_id='lb_startup_dangling'"); err != nil {
		t.Fatalf("bind dangling ACME config: %v", err)
	}

	// When
	err := validateEnabledStoredRuleConfigs(context.Background())

	// Then
	if err == nil {
		t.Fatal("validateEnabledStoredRuleConfigs 接受了 acme_config_id 悬挂的启用规则")
	}
	for _, want := range []string{"startup-dangling", "lb_startup_dangling", "DNS 提供商配置"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("错误信息必须包含 %q，实际: %s", want, err.Error())
		}
	}
}

// R53 发现6 对照组：引用存在且启用的配置时聚合校验不得误伤合法启用规则。
func TestValidateEnabledStoredRuleConfigs_accepts_valid_acme_config(t *testing.T) {
	// Given
	newBackupTestHandlers(t)
	seedAuditRule(t, "lb_startup_valid", "startup-valid", "startup-valid.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_startup_valid")
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=? WHERE caddy_id='lb_startup_valid'", seedR52CertificateConfig(t)); err != nil {
		t.Fatalf("bind valid ACME config: %v", err)
	}

	// When
	err := validateEnabledStoredRuleConfigs(context.Background())

	// Then
	if err != nil {
		t.Fatalf("validateEnabledStoredRuleConfigs unexpected error: %v", err)
	}
}

// R53 发现2 公共夹具：备份内一条启用的 acme_dns 规则行。
func r53BackupACMERule(acmeConfigID int) map[string]any {
	return map[string]any{
		"caddy_id": "lb_bak_acme", "name": "bak-acme", "protocol": "http",
		"domain": "bak-acme.example.test", "listen_port": 8470,
		"enabled": 1, "enable_tls": 1, "tls_source": "acme_dns",
		"acme_config_id": acmeConfigID,
	}
}

// R53 发现2：v2 备份携带 enabled + acme_dns + acme_config_id=0（或悬挂）的
// 规则行时校验必须整包拒绝——导入为全量替换，坏行会绕过 R52 F-2 门直接
// 投入运行（TLS 端口明文服务，无自愈）。引用优先在备份自带表解析
// （deleteOrder 会清光 live 表），与 validateBackupRuleReferences 同哲学。
func TestValidateV2BackupRules_rejects_bad_acme_rows(t *testing.T) {
	tests := []struct {
		name        string
		tables      map[string][]map[string]any
		wantErrText string
	}{
		{
			name:        "启用 acme_dns 且 acme_config_id=0 被拒绝",
			tables:      map[string][]map[string]any{"lb_rules": {r53BackupACMERule(0)}},
			wantErrText: "使用 ACME 签发时必须选择 DNS 提供商配置",
		},
		{
			name: "启用 acme_dns 引用备份内不存在的配置被拒绝",
			tables: map[string][]map[string]any{
				"lb_rules":            {r53BackupACMERule(7)},
				"certificate_configs": {},
			},
			wantErrText: "选择的 DNS 提供商配置不存在或已禁用",
		},
		{
			name: "启用 acme_dns 引用备份内已禁用的配置被拒绝",
			tables: map[string][]map[string]any{
				"lb_rules":            {r53BackupACMERule(7)},
				"certificate_configs": {{"id": 7, "name": "dns", "enabled": 0}},
			},
			wantErrText: "选择的 DNS 提供商配置不存在或已禁用",
		},
		{
			name: "引用有效配置但缺少证书任务行被拒绝（R53-A-2）",
			tables: map[string][]map[string]any{
				"lb_rules":            {r53BackupACMERule(7)},
				"certificate_configs": {{"id": 7, "name": "dns", "enabled": 1}},
				"cert_jobs":           {},
			},
			wantErrText: "证书签发任务",
		},
		{
			name: "证书任务行全部为 disabled 同样被拒绝（R53-A-2）",
			tables: map[string][]map[string]any{
				"lb_rules":            {r53BackupACMERule(7)},
				"certificate_configs": {{"id": 7, "name": "dns", "enabled": 1}},
				"cert_jobs":           {{"rule_id": "lb_bak_acme", "domain": "bak-acme.example.test", "status": "disabled"}},
			},
			wantErrText: "证书签发任务",
		},
		{
			name: "引用有效且携带 queued 任务行放行",
			tables: map[string][]map[string]any{
				"lb_rules":            {r53BackupACMERule(7)},
				"certificate_configs": {{"id": 7, "name": "dns", "enabled": 1}},
				"cert_jobs":           {{"rule_id": "lb_bak_acme", "domain": "bak-acme.example.test", "status": "queued"}},
			},
		},
		{
			name: "禁用的 acme_dns 坏行不阻断导入（不参与渲染）",
			tables: map[string][]map[string]any{
				"lb_rules": {func() map[string]any {
					rule := r53BackupACMERule(0)
					rule["enabled"] = 0
					return rule
				}()},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newBackupTestHandlers(t)
			err := validateV2BackupRules(tt.tables)
			if tt.wantErrText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("validateV2BackupRules err=%v, want contains %q", err, tt.wantErrText)
				}
				if !strings.Contains(err.Error(), "bak-acme") {
					t.Fatalf("拒绝必须点名规则，实际: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateV2BackupRules unexpected error: %v", err)
			}
		})
	}
}

// R53-A-2（handler 级）：备份携带 enabled acme_dns 规则但 cert_jobs 缺行时
// 导入必须 400 且零写入——deleteOrder 全量清库后无周期路径重建任务行，
// 续签永久断链且无信号。
func TestImportConfigBackup_rejects_acme_rule_without_cert_job(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'current-admin','hash','admin',1)"); err != nil {
		t.Fatalf("seed current admin: %v", err)
	}
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules":            {r53BackupACMERule(7)},
		"certificate_configs": {{"id": 7, "name": "dns", "dns_provider": "dnspod", "dns_credentials": "{}", "enabled": 1}},
		"cert_jobs":           {},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "bak-acme") {
		t.Fatalf("import status=%d body=%s, want 400 点名规则", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_bak_acme'").Scan(&count); err != nil {
		t.Fatalf("read imported rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("rejected backup wrote rules, count=%d", count)
	}
	var admins int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='current-admin' AND is_enabled=1").Scan(&admins); err != nil {
		t.Fatalf("read current admin: %v", err)
	}
	if admins != 1 {
		t.Fatalf("current admin wiped by rejected import, count=%d", admins)
	}
}
