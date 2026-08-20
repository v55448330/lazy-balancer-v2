package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// R55 公共夹具：与 completeBackupJSON 同构，但允许注入全局配置区（Config）。
func r55BackupJSONWithConfig(t *testing.T, tables map[string][]map[string]any, cfg map[string]any) string {
	t.Helper()
	completeTables := make(map[string][]map[string]any, len(configBackupTables))
	for _, table := range configBackupTables {
		completeTables[table] = []map[string]any{}
	}
	completeTables["users"] = []map[string]any{{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	for table, rows := range tables {
		completeTables[table] = rows
	}
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-08-21T00:00:00Z"},
		Config: cfg,
		Tables: completeTables,
	}
	backup.Meta.Checksum = checksumBackupPayload(t, completeTables, cfg)
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	return string(data)
}

func r55Post(t *testing.T, handler gin.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST(path, handler)
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func r55SeedCurrentAdmin(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'current-admin','hash','admin',1)"); err != nil {
		t.Fatalf("seed current admin: %v", err)
	}
}

func r55AssertZeroWrite(t *testing.T) {
	t.Helper()
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='backup-admin'").Scan(&count); err != nil {
		t.Fatalf("query users: %v", err)
	}
	if count != 0 {
		t.Fatal("拒绝的备份必须零写入，backup-admin 不应落库")
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='current-admin'").Scan(&count); err != nil {
		t.Fatalf("query users: %v", err)
	}
	if count != 1 {
		t.Fatal("拒绝的备份必须零写入，current-admin 不应被清除")
	}
}

// R55 C-2：手造备份 enabled+acme_dns+domain="a.com,b.org"（两个合法单域但非
// root+www）+ 同形 cert_jobs 行——此前导入侧无 ACME 域名合法性门、cert_jobs
// 不变量回退原串假放行，导入后运行期 certJobRuleApplicable 严格规范化失败 →
// 任务置 disabled、续签永久断链、TLS 端口明文服务。保存侧（rules.go）与启用侧
// 均强制单域名或根域+www，导入不得更宽：必须 400 点名规则且零写入。
func TestImportConfigBackup_rejects_illegal_acme_domain_shape(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	r55SeedCurrentAdmin(t)
	rule := r53BackupACMERule(7)
	rule["domain"] = "a.com,b.org"
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules":            {rule},
		"certificate_configs": {{"id": 7, "name": "dns", "dns_provider": "dnspod", "dns_credentials": "{}", "enabled": 1}},
		"cert_jobs":           {{"rule_id": "lb_bak_acme", "domain": "a.com,b.org", "status": "queued"}},
	})

	// When
	response := r55Post(t, h.ImportConfigBackup, "/config/import", backup)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("import status=%d body=%s, want 400（非法 ACME 域名形态必须整包拒绝）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "bak-acme") {
		t.Fatalf("拒绝必须点名规则，实际: %s", response.Body.String())
	}
	r55AssertZeroWrite(t)
}

// R55 C-2（不变量严格化）：validateV2BackupCertJobs 的域比较两侧均须可规范化——
// canonicalACMEDomainForJobLookup 的原串回退是查询侧良性 miss 语义，用于校验侧
// 会把不可规范化的域名假放行（与运行期 certJobRuleApplicable 严格语义对齐）。
func TestValidateV2BackupCertJobs_rejects_uncanonicalizable_domains(t *testing.T) {
	tests := []struct {
		name       string
		ruleDomain string
		jobDomain  string
	}{
		{name: "规则域名非 root+www 双域", ruleDomain: "a.com,b.org", jobDomain: "a.com,b.org"},
		{name: "规则域名三域集", ruleDomain: "a.com,www.a.com,b.com", jobDomain: "a.com,www.a.com,b.com"},
		{name: "任务域名非 root+www 双域", ruleDomain: "a.com", jobDomain: "a.com,b.org"},
		{name: "任务域名三域集", ruleDomain: "a.com", jobDomain: "a.com,www.a.com,b.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newBackupTestHandlers(t)
			rule := r53BackupACMERule(7)
			rule["domain"] = tt.ruleDomain
			tables := map[string][]map[string]any{
				"lb_rules":            {rule},
				"certificate_configs": {{"id": 7, "name": "dns", "enabled": 1}},
				"cert_jobs":           {{"rule_id": "lb_bak_acme", "domain": tt.jobDomain, "status": "queued"}},
			}
			err := validateV2BackupCertJobs(tables)
			if err == nil {
				t.Fatalf("validateV2BackupCertJobs 放行了不可规范化域名（rule=%q job=%q）", tt.ruleDomain, tt.jobDomain)
			}
			if !strings.Contains(err.Error(), "bak-acme") {
				t.Fatalf("拒绝必须点名规则，实际: %v", err)
			}
		})
	}
}

// R55 C-2（校验门函数级）：acme_dns 分支对启用行强制 ValidateACMEDomains
// （与保存/启用侧同口径）——双非 root+www 域名与三域集拒绝并点名规则；
// 合法 root+www（含用户输入顺序变体）放行。
func TestValidateV2BackupTLSShape_acme_domain_legality(t *testing.T) {
	tests := []struct {
		name        string
		domain      string
		wantErrText string
	}{
		{name: "双非 root+www 域名被拒绝", domain: "a.com,b.org", wantErrText: "ACME证书仅支持单域名或根域+www二级域名"},
		{name: "三域名集被拒绝", domain: "a.com,www.a.com,b.com", wantErrText: "ACME证书仅支持单域名或根域+www二级域名"},
		{name: "单域名放行", domain: "bak-acme.example.test"},
		{name: "root+www 放行", domain: "bak-acme.example.test,www.bak-acme.example.test"},
		{name: "www+root 用户输入顺序放行", domain: "www.bak-acme.example.test,bak-acme.example.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newBackupTestHandlers(t)
			rule := r53BackupACMERule(7)
			rule["domain"] = tt.domain
			tables := map[string][]map[string]any{
				"lb_rules":            {rule},
				"certificate_configs": {{"id": 7, "name": "dns", "enabled": 1}},
			}
			err := validateV2BackupTLSShape(tables)
			if tt.wantErrText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("validateV2BackupTLSShape err=%v, want contains %q", err, tt.wantErrText)
				}
				if !strings.Contains(err.Error(), "bak-acme") {
					t.Fatalf("拒绝必须点名规则，实际: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateV2BackupTLSShape unexpected error: %v", err)
			}
		})
	}
}

// R55 C-2（合法 root+www 形态双门放行）：TLS 形态校验与 cert_jobs 不变量
// 均不得误伤合法 root+www 备份（含顺序变体）。
func TestValidateV2Backup_accepts_legal_root_www_acme_shape(t *testing.T) {
	newBackupTestHandlers(t)
	rule := r53BackupACMERule(7)
	rule["domain"] = "www.bak-acme.example.test,bak-acme.example.test"
	tables := map[string][]map[string]any{
		"lb_rules":            {rule},
		"certificate_configs": {{"id": 7, "name": "dns", "enabled": 1}},
		"cert_jobs":           {{"rule_id": "lb_bak_acme", "domain": "bak-acme.example.test,www.bak-acme.example.test", "status": "queued"}},
	}
	if err := validateV2BackupTLSShape(tables); err != nil {
		t.Fatalf("validateV2BackupTLSShape unexpected error: %v", err)
	}
	if err := validateV2BackupCertJobs(tables); err != nil {
		t.Fatalf("validateV2BackupCertJobs unexpected error: %v", err)
	}
}

// R55 C-1：将被 disableV2RuleConflicts 自动置禁用的冲突规则不参与运行态 TLS
// 形态校验——冲突集内一方携带垃圾 tls_source（不渲染、无风险），整包不得 400；
// 与 cert_jobs 不变量的豁免哲学同序（TLS 形态检查移到冲突置禁用之后）。
func TestImportConfigBackup_conflict_disabled_rule_with_garbage_tls_source(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	r55SeedCurrentAdmin(t)
	ruleA := r53BackupACMERule(7)
	ruleA["caddy_id"] = "lb_bak_tls_conflict_a"
	ruleA["name"] = "bak-tls-conflict-a"
	ruleA["domain"] = "bak-tls-conflict.example.test"
	ruleA["listen_port"] = 8475
	ruleB := r54BackupTLSRule("")
	ruleB["caddy_id"] = "lb_bak_tls_conflict_b"
	ruleB["name"] = "bak-tls-conflict-b"
	ruleB["domain"] = "bak-tls-conflict.example.test"
	ruleB["listen_port"] = 8475
	// 不带内联证书材料——避免提交期证书物化干扰（本用例针对 TLS 形态校验豁免）
	ruleB["tls_cert"] = ""
	ruleB["tls_key"] = ""
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules":            {ruleA, ruleB},
		"certificate_configs": {{"id": 7, "name": "dns", "dns_provider": "dnspod", "dns_credentials": "{}", "enabled": 1}},
		"cert_jobs":           {},
	})

	// When
	response := r55Post(t, h.ImportConfigBackup, "/config/import", backup)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200（冲突规则自动置禁用后不参与 TLS 形态校验）", response.Code, response.Body.String())
	}
	for _, ruleID := range []string{"lb_bak_tls_conflict_a", "lb_bak_tls_conflict_b"} {
		var enabled bool
		if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id=?", ruleID).Scan(&enabled); err != nil {
			t.Fatalf("read imported rule %s: %v", ruleID, err)
		}
		if enabled {
			t.Fatalf("冲突规则 %s 导入后应为禁用态", ruleID)
		}
	}
}

// R55 C-1（预览路径）：ValidateConfigImport 必须与 ImportConfigBackup 同序——
// 冲突置禁用后的垃圾 tls_source 规则不阻断预览，预览显示可导入且携带
// disabled_conflicts。
func TestValidateConfigImport_conflict_disabled_rule_with_garbage_tls_source(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	ruleA := r53BackupACMERule(7)
	ruleA["caddy_id"] = "lb_bak_tls_conflict_a"
	ruleA["name"] = "bak-tls-conflict-a"
	ruleA["domain"] = "bak-tls-conflict.example.test"
	ruleA["listen_port"] = 8475
	ruleB := r54BackupTLSRule("")
	ruleB["caddy_id"] = "lb_bak_tls_conflict_b"
	ruleB["name"] = "bak-tls-conflict-b"
	ruleB["domain"] = "bak-tls-conflict.example.test"
	ruleB["listen_port"] = 8475
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules":            {ruleA, ruleB},
		"certificate_configs": {{"id": 7, "name": "dns", "dns_provider": "dnspod", "dns_credentials": "{}", "enabled": 1}},
		"cert_jobs":           {},
	})

	// When
	response := r55Post(t, h.ValidateConfigImport, "/config/import/validate", backup)

	// Then
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `"valid":true`) {
		t.Fatalf("validate status=%d body=%s, want valid=true", response.Code, body)
	}
	if !strings.Contains(body, "disabled_conflicts") {
		t.Fatalf("预览必须携带 disabled_conflicts，实际: %s", body)
	}
}

// R55 C-3：UpdateConfig 聚合校验须点名 enabled+http+enable_tls 但 tls_source
// 为垃圾值的存量/篡改规则——渲染侧 availableCerts 仅认 manual/acme_dns，
// 该规则 TLS 端口明文服务；与 validateStoredRuleConfig:697-699 同口径白名单。
func TestUpdateConfig_flags_enabled_rule_with_unknown_tls_source(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	seedAuditRule(t, "lb_startup_garbage_tls", "startup-garbage-tls", "startup-garbage.example.test", 8080, true, "garbage", true)
	seedAuditUpstream(t, "lb_startup_garbage_tls")
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"source":"basic","log_level":"debug"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（垃圾 tls_source 启用规则必须点名）", response.Code, response.Body.String())
	}
	for _, want := range []string{"startup-garbage-tls", "lb_startup_garbage_tls", "启用 TLS 时必须选择证书来源（manual 或 acme_dns）"} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("body must contain %q，实际: %s", want, response.Body.String())
		}
	}
}

// R55 C-4：v2 导入写 admin_tls_* 前必须按 UpdateAdminTLS 同口径校验——
// enabled+upload+空证书（或过期证书）落库后下次启动 ResolveCertificate 失败
// 即进程退出（崩溃循环）；坏形态整包 400 零写入，合法形态放行。
func TestImportConfigBackup_rejects_bad_admin_tls_config(t *testing.T) {
	expiredCert, expiredKey, err := generateTestCert("expired.example.com", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("generate expired cert: %v", err)
	}
	validCert, validKey, err := generateTestCert("admin.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate valid cert: %v", err)
	}
	tests := []struct {
		name        string
		config      map[string]any
		wantStatus  int
		wantErrText string
	}{
		{
			name:        "enabled+upload+空证书被拒绝",
			config:      map[string]any{"admin_tls_enabled": 1, "admin_tls_mode": "upload", "admin_tls_cert": "", "admin_tls_key": ""},
			wantStatus:  http.StatusBadRequest,
			wantErrText: "管理面板 HTTPS",
		},
		{
			name:        "enabled+upload+过期证书被拒绝",
			config:      map[string]any{"admin_tls_enabled": 1, "admin_tls_mode": "upload", "admin_tls_cert": expiredCert, "admin_tls_key": expiredKey},
			wantStatus:  http.StatusBadRequest,
			wantErrText: "证书已过期",
		},
		{
			name:        "enabled+非法 mode 被拒绝",
			config:      map[string]any{"admin_tls_enabled": 1, "admin_tls_mode": "garbage"},
			wantStatus:  http.StatusBadRequest,
			wantErrText: "无效的证书来源",
		},
		{
			name:       "enabled+selfsigned 放行",
			config:     map[string]any{"admin_tls_enabled": 1, "admin_tls_mode": "selfsigned"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "enabled+upload+有效证书放行",
			config:     map[string]any{"admin_tls_enabled": 1, "admin_tls_mode": "upload", "admin_tls_cert": validCert, "admin_tls_key": validKey},
			wantStatus: http.StatusOK,
		},
		{
			name:       "disabled 携带垃圾材料放行（不投入运行）",
			config:     map[string]any{"admin_tls_enabled": 0, "admin_tls_mode": "upload", "admin_tls_cert": "", "admin_tls_key": ""},
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			r55SeedCurrentAdmin(t)
			backup := r55BackupJSONWithConfig(t, map[string][]map[string]any{}, tt.config)

			// When
			response := r55Post(t, h.ImportConfigBackup, "/config/import", backup)

			// Then
			if response.Code != tt.wantStatus {
				t.Fatalf("import status=%d body=%s, want %d", response.Code, response.Body.String(), tt.wantStatus)
			}
			if tt.wantErrText != "" {
				if !strings.Contains(response.Body.String(), tt.wantErrText) {
					t.Fatalf("body must contain %q，实际: %s", tt.wantErrText, response.Body.String())
				}
				r55AssertZeroWrite(t)
				return
			}
			var enabled bool
			if err := db.DB.QueryRow("SELECT COALESCE(admin_tls_enabled,0) FROM global_config WHERE id=1").Scan(&enabled); err != nil {
				t.Fatalf("read admin_tls_enabled: %v", err)
			}
			wantEnabled := tt.config["admin_tls_enabled"] == 1
			if enabled != wantEnabled {
				t.Fatalf("admin_tls_enabled=%v, want %v", enabled, wantEnabled)
			}
		})
	}
}

// R55 C-4（预览路径）：ValidateConfigImport 必须与 ImportConfigBackup 同序——
// 坏 admin_tls_* 形态预览即报不可导入，不得预览通过、导入才 400。
func TestValidateConfigImport_rejects_bad_admin_tls_config(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := r55BackupJSONWithConfig(t, map[string][]map[string]any{},
		map[string]any{"admin_tls_enabled": 1, "admin_tls_mode": "upload", "admin_tls_cert": "", "admin_tls_key": ""})

	// When
	response := r55Post(t, h.ValidateConfigImport, "/config/import/validate", backup)

	// Then
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `"valid":false`) {
		t.Fatalf("validate status=%d body=%s, want valid=false", response.Code, body)
	}
	if !strings.Contains(body, "管理面板 HTTPS") {
		t.Fatalf("预览错误必须说明管理面板 HTTPS 配置不可用，实际: %s", body)
	}
}

// R55 F3：audit_retention_months 写侧范围校验（UI 口径 1-12）——超大值使年龄
// 裁剪的 datetime('now', '-N days') 越出 SQLite 年份范围返回 NULL，年龄 DELETE
// 恒假静默失效（仅剩条数兜底）；越界值必须 400。
func TestUpdateConfig_rejects_audit_retention_months_out_of_range(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)

	for _, body := range []string{
		`{"source":"basic","audit_retention_months":0}`,
		`{"source":"basic","audit_retention_months":-5}`,
		`{"source":"basic","audit_retention_months":13}`,
		`{"source":"basic","audit_retention_months":1000000}`,
	} {
		// When
		request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)

		// Then
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d, want 400", body, response.Code)
		}
		if !strings.Contains(response.Body.String(), "1-12") {
			t.Fatalf("body=%s, want 范围提示（1-12），实际: %s", body, response.Body.String())
		}
	}
}

// R55 F3 对照组：边界值 1 与 12 必须放行。
func TestUpdateConfig_accepts_audit_retention_months_bounds(t *testing.T) {
	for _, months := range []int{1, 12} {
		t.Run(fmt.Sprintf("边界 %d 放行", months), func(t *testing.T) {
			handler := newBackupTestHandlers(t)
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.PUT("/config", handler.UpdateConfig)
			body := fmt.Sprintf(`{"source":"basic","audit_retention_months":%d}`, months)
			request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("body=%s status=%d body=%s, want 200", body, response.Code, response.Body.String())
			}
			var stored int
			if err := db.DB.QueryRow("SELECT COALESCE(audit_retention_months,3) FROM global_config WHERE id=1").Scan(&stored); err != nil {
				t.Fatalf("read audit_retention_months: %v", err)
			}
			if stored != months {
				t.Fatalf("audit_retention_months=%d, want %d", stored, months)
			}
		})
	}
}

// R55 F3：存量越界值启动钳位——写侧加范围校验后，历史越界值（含使年龄裁剪
// 静默失效的超大值）在启动时钳位到最近边界并记日志。
func TestClampAuditRetentionMonthsOnStartup(t *testing.T) {
	tests := []struct {
		name string
		seed int
		want int
	}{
		{name: "超大值钳位到 12", seed: 1000000, want: 12},
		{name: "13 钳位到 12", seed: 13, want: 12},
		{name: "0 钳位到 1", seed: 0, want: 1},
		{name: "负值钳位到 1", seed: -3, want: 1},
		{name: "合法值保持不变", seed: 6, want: 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newBackupTestHandlers(t)
			if _, err := db.DB.Exec("UPDATE global_config SET audit_retention_months=? WHERE id=1", tt.seed); err != nil {
				t.Fatalf("seed audit_retention_months: %v", err)
			}

			clampAuditRetentionMonthsOnStartup()

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
