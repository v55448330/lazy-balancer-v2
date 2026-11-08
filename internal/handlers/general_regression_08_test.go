package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 公共夹具：备份内一条启用 TLS 的 http 规则行，tls_source 由用例注入。
func backupTLSRuleShared(tlsSource any) map[string]any {
	return map[string]any{
		"caddy_id": "lb_bak_tls", "name": "bak-tls", "protocol": "http",
		"domain": "bak-tls.example.test", "listen_port": 8472,
		"enabled": 1, "enable_tls": 1, "tls_source": tlsSource,
		"tls_cert": "cert", "tls_key": "key",
	}
}

// v2 备份校验必须对 enabled+http+enable_tls 行的 tls_source 做白名单
// （manual/acme_dns）——空串/垃圾值（如 'https'）此前两个分支都不命中、整包放行，
// 导入后渲染侧 availableCerts 仅认 manual/acme_dns，该规则无证书 → TLS 端口明文服务。
// 保存侧（rules.go）与启用侧（rule_features.go:697-699）均 400 此形态，导入不得更宽。
// TLS 形态校验迁至 validateV2BackupTLSShape（冲突置禁用之后执行）。
func TestValidateV2BackupTLSShape_rejects_unknown_tls_source(t *testing.T) {
	tests := []struct {
		name        string
		tlsSource   any
		injectKey   bool
		wantErrText string
	}{
		{name: "空串 tls_source 被拒绝", tlsSource: "", injectKey: true, wantErrText: "启用 TLS 时必须选择证书来源（manual 或 acme_dns）"},
		{name: "垃圾值 https 被拒绝", tlsSource: "https", injectKey: true, wantErrText: "启用 TLS 时必须选择证书来源（manual 或 acme_dns）"},
		{name: "任意未知值被拒绝", tlsSource: "auto", injectKey: true, wantErrText: "启用 TLS 时必须选择证书来源（manual 或 acme_dns）"},
		{name: "非字符串值（数字）被拒绝", tlsSource: 1, injectKey: true, wantErrText: "启用 TLS 时必须选择证书来源（manual 或 acme_dns）"},
		{name: "缺失 tls_source 键被拒绝", tlsSource: nil, injectKey: false, wantErrText: "启用 TLS 时必须选择证书来源（manual 或 acme_dns）"},
		{name: "manual 携带证书材料放行", tlsSource: "manual", injectKey: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newBackupTestHandlers(t)
			rule := backupTLSRuleShared(tt.tlsSource)
			if !tt.injectKey {
				delete(rule, "tls_source")
			}
			err := validateV2BackupTLSShape(map[string][]map[string]any{"lb_rules": {rule}})
			if tt.wantErrText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("validateV2BackupTLSShape err=%v, want contains %q", err, tt.wantErrText)
				}
				if !strings.Contains(err.Error(), "bak-tls") {
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

// 对照组：禁用行 tls_source 为垃圾值不阻断导入（不参与渲染），
// 与矩阵「禁用的 acme_dns 坏行不阻断导入」同口径。
// TLS 形态校验迁至 validateV2BackupTLSShape（冲突置禁用之后执行）。
func TestValidateV2BackupTLSShape_allows_disabled_rule_with_unknown_tls_source(t *testing.T) {
	newBackupTestHandlers(t)
	rule := backupTLSRuleShared("")
	rule["enabled"] = 0
	if err := validateV2BackupTLSShape(map[string][]map[string]any{"lb_rules": {rule}}); err != nil {
		t.Fatalf("validateV2BackupTLSShape unexpected error: %v", err)
	}
}

// （acme_dns 合法值仍走原有校验）：合法 acme_dns 行不因白名单误伤。
// TLS 形态校验迁至 validateV2BackupTLSShape（冲突置禁用之后执行）。
func TestValidateV2BackupTLSShape_allows_valid_acme_dns_row(t *testing.T) {
	newBackupTestHandlers(t)
	tables := map[string][]map[string]any{
		"lb_rules":            {backupACMERuleShared(7)},
		"certificate_configs": {{"id": 7, "name": "dns", "enabled": 1}},
		"cert_jobs":           {{"rule_id": "lb_bak_acme", "domain": "bak-acme.example.test", "status": "queued"}},
	}
	if err := validateV2BackupTLSShape(tables); err != nil {
		t.Fatalf("validateV2BackupTLSShape unexpected error: %v", err)
	}
	if _, err := validateV2BackupCertJobs(tables); err != nil {
		t.Fatalf("validateV2BackupCertJobs unexpected error: %v", err)
	}
}

// 公共夹具：合法引用 + 可注入任务行的备份表。
func acmeJobTablesShared(jobDomain, jobStatus string) map[string][]map[string]any {
	jobs := []map[string]any{}
	if jobStatus != "" {
		jobs = append(jobs, map[string]any{"rule_id": "lb_bak_acme", "domain": jobDomain, "status": jobStatus})
	}
	return map[string][]map[string]any{
		"lb_rules":            {backupACMERuleShared(7)},
		"certificate_configs": {{"id": 7, "name": "dns", "enabled": 1}},
		"cert_jobs":           jobs,
	}
}

// cert_jobs 不变量必须校验 job.domain 与规则域名一致（canonical 或
// reversed 双形式）——错域残留行此前只凭存在性放行，导入后续签扫描按
// rule_id+domain 精确匹配永不命中，续签断链与「无任务行」同果。
func TestValidateV2BackupCertJobs_domain_matching(t *testing.T) {
	tests := []struct {
		name        string
		tables      map[string][]map[string]any
		wantErrText string
	}{
		{
			name:        "缺少任务行被拒绝（迁入）",
			tables:      acmeJobTablesShared("", ""),
			wantErrText: "缺少证书签发任务",
		},
		{
			name:        "任务行全部 disabled 被拒绝（迁入）",
			tables:      acmeJobTablesShared("bak-acme.example.test", "disabled"),
			wantErrText: "缺少证书签发任务",
		},
		{
			name:        "错域任务行被拒绝",
			tables:      acmeJobTablesShared("other.example.test", "queued"),
			wantErrText: "域名",
		},
		{
			name:   "规范域名任务行放行",
			tables: acmeJobTablesShared("bak-acme.example.test", "queued"),
		},
		{
			name:   "大小写/空白变体任务行放行（与续签扫描 lower+replace 口径一致）",
			tables: acmeJobTablesShared("BAK-ACME.example.test ", "queued"),
		},
		{
			name: "错域行 + 匹配行并存被拒绝",
			tables: func() map[string][]map[string]any {
				tables := acmeJobTablesShared("other.example.test", "queued")
				tables["cert_jobs"] = append(tables["cert_jobs"], map[string]any{"rule_id": "lb_bak_acme", "domain": "bak-acme.example.test", "status": "issued", "cert_pem": "CERT", "key_pem": "KEY"})
				return tables
			}(),
			wantErrText: "旧域",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newBackupTestHandlers(t)
			_, err := validateV2BackupCertJobs(tt.tables)
			if tt.wantErrText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("validateV2BackupCertJobs err=%v, want contains %q", err, tt.wantErrText)
				}
				if !strings.Contains(err.Error(), "bak-acme") {
					t.Fatalf("拒绝必须点名规则，实际: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateV2BackupCertJobs unexpected error: %v", err)
			}
		})
	}
}

// （双形式）：规则域名为用户输入顺序、任务行存排序规范形式（或反之）
// 时，canonical/reversed 双形式匹配必须放行——与 certjobs.go 规则侧
// joined+reversed 双形式匹配同型。
func TestValidateV2BackupCertJobs_accepts_reversed_dual_domain(t *testing.T) {
	newBackupTestHandlers(t)
	rule := backupACMERuleShared(7)
	rule["domain"] = "www.bak-acme.example.test,bak-acme.example.test"
	tables := map[string][]map[string]any{
		"lb_rules":            {rule},
		"certificate_configs": {{"id": 7, "name": "dns", "enabled": 1}},
		// cert_jobs.domain 按排序规范形式存储
		"cert_jobs": {{"rule_id": "lb_bak_acme", "domain": "bak-acme.example.test,www.bak-acme.example.test", "status": "queued"}},
	}
	if _, err := validateV2BackupCertJobs(tables); err != nil {
		t.Fatalf("validateV2BackupCertJobs unexpected error: %v", err)
	}
}

// 将被 disableV2RuleConflicts 自动置禁用的冲突规则不参与运行态
// 不变量——冲突集内规则导入后处于禁用态，「带入运行态」前提不成立，缺任务行
// 不得整包 400。
func TestValidateV2BackupCertJobs_skips_conflict_disabled_rules(t *testing.T) {
	newBackupTestHandlers(t)
	ruleA := backupACMERuleShared(7)
	ruleA["caddy_id"] = "lb_bak_conflict_a"
	ruleA["name"] = "bak-conflict-a"
	ruleA["domain"] = "bak-conflict.example.test"
	ruleA["listen_port"] = 8473
	ruleB := backupACMERuleShared(7)
	ruleB["caddy_id"] = "lb_bak_conflict_b"
	ruleB["name"] = "bak-conflict-b"
	ruleB["domain"] = "bak-conflict.example.test"
	ruleB["listen_port"] = 8473
	tables := map[string][]map[string]any{
		"lb_rules":            {ruleA, ruleB},
		"certificate_configs": {{"id": 7, "name": "dns", "enabled": 1}},
		"cert_jobs":           {},
	}
	conflicts := disableV2RuleConflicts(tables["lb_rules"])
	if len(conflicts) == 0 {
		t.Fatal("fixture 未构造出冲突，前置条件不成立")
	}
	if _, err := validateV2BackupCertJobs(tables); err != nil {
		t.Fatalf("冲突置禁用规则不得参与运行态不变量: %v", err)
	}
}

// （handler 级）：冲突将被自动置禁用的启用 acme_dns 规则即使无
// cert_jobs 行，导入也必须成功且规则落库为禁用——此前不变量先于冲突置禁用
// 执行，整包 400 过严拒绝可自愈备份。
func TestImportConfigBackup_conflict_disabled_acme_rule_without_cert_job(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'current-admin','hash','admin',1)"); err != nil {
		t.Fatalf("seed current admin: %v", err)
	}
	ruleA := backupACMERuleShared(7)
	ruleA["caddy_id"] = "lb_bak_conflict_a"
	ruleA["name"] = "bak-conflict-a"
	ruleA["domain"] = "bak-conflict.example.test"
	ruleA["listen_port"] = 8473
	ruleB := backupACMERuleShared(7)
	ruleB["caddy_id"] = "lb_bak_conflict_b"
	ruleB["name"] = "bak-conflict-b"
	ruleB["domain"] = "bak-conflict.example.test"
	ruleB["listen_port"] = 8473
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules":            {ruleA, ruleB},
		"certificate_configs": {{"id": 7, "name": "dns", "dns_provider": "dnspod", "dns_credentials": "", "enabled": 1}},
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
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200（冲突规则自动置禁用后放行）", response.Code, response.Body.String())
	}
	for _, ruleID := range []string{"lb_bak_conflict_a", "lb_bak_conflict_b"} {
		var enabled bool
		if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id=?", ruleID).Scan(&enabled); err != nil {
			t.Fatalf("read imported rule %s: %v", ruleID, err)
		}
		if enabled {
			t.Fatalf("冲突规则 %s 导入后应为禁用态", ruleID)
		}
	}
}

// （预览路径）：ValidateConfigImport 必须与 ImportConfigBackup 同序——
// 冲突置禁用后的规则不参与任务不变量，预览显示可导入且携带 disabled_conflicts。
func TestValidateConfigImport_conflict_disabled_acme_rule_without_cert_job(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	ruleA := backupACMERuleShared(7)
	ruleA["caddy_id"] = "lb_bak_conflict_a"
	ruleA["name"] = "bak-conflict-a"
	ruleA["domain"] = "bak-conflict.example.test"
	ruleA["listen_port"] = 8473
	ruleB := backupACMERuleShared(7)
	ruleB["caddy_id"] = "lb_bak_conflict_b"
	ruleB["name"] = "bak-conflict-b"
	ruleB["domain"] = "bak-conflict.example.test"
	ruleB["listen_port"] = 8473
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules":            {ruleA, ruleB},
		"certificate_configs": {{"id": 7, "name": "dns", "dns_provider": "dnspod", "dns_credentials": "", "enabled": 1}},
		"cert_jobs":           {},
	})
	router := gin.New()
	router.POST("/config/import/validate", h.ValidateConfigImport)
	request := httptest.NewRequest(http.MethodPost, "/config/import/validate", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `"valid":true`) {
		t.Fatalf("validate status=%d body=%s, want valid=true", response.Code, body)
	}
	if !strings.Contains(body, "disabled_conflicts") {
		t.Fatalf("预览必须携带 disabled_conflicts，实际: %s", body)
	}
}

// 聚合校验错误映射——纯 configValidationError 聚合保持 400 且
// 展示全部规则问题；混入普通错误（DB 故障等）时必须映射 500 通用文案并
// 不外泄底层错误文本，避免客户端把服务端故障误判为配置问题。
func TestWriteConfigValidationFailure_status_mapping(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		wantStatus      int
		wantContains    []string
		wantNotContains []string
	}{
		{
			name: "纯配置错误聚合返回 400 含全部问题",
			err: errors.Join(
				&configValidationError{message: "规则 a（lb_a）80 端口开启 TLS 跳转无意义"},
				&configValidationError{message: "规则 b（lb_b）选择的 DNS 提供商配置不存在或已禁用"},
			),
			wantStatus:   http.StatusBadRequest,
			wantContains: []string{"规则 a（lb_a）", "规则 b（lb_b）"},
		},
		{
			name:         "单个配置错误返回 400",
			err:          &configValidationError{message: "规则 a（lb_a）80 端口开启 TLS 跳转无意义"},
			wantStatus:   http.StatusBadRequest,
			wantContains: []string{"规则 a（lb_a）"},
		},
		{
			name: "配置错误混入 DB 故障返回 500 通用文案",
			err: errors.Join(
				&configValidationError{message: "规则 a（lb_a）80 端口开启 TLS 跳转无意义"},
				fmt.Errorf("规则 b（lb_b）ACME 引用校验失败：%w", errors.New("connection reset by peer")),
			),
			wantStatus:      http.StatusInternalServerError,
			wantContains:    []string{"预校验规则配置失败"},
			wantNotContains: []string{"connection reset by peer"},
		},
		{
			name:         "纯 DB 故障返回 500",
			err:          errors.New("读取待验证规则: database is locked"),
			wantStatus:   http.StatusInternalServerError,
			wantContains: []string{"预校验规则配置失败"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			writeConfigValidationFailure(ctx, tt.err, false)
			if recorder.Code != tt.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), tt.wantStatus)
			}
			for _, want := range tt.wantContains {
				if !strings.Contains(recorder.Body.String(), want) {
					t.Fatalf("body=%s, want contains %q", recorder.Body.String(), want)
				}
			}
			for _, unwanted := range tt.wantNotContains {
				if strings.Contains(recorder.Body.String(), unwanted) {
					t.Fatalf("body=%s, must not contain %q", recorder.Body.String(), unwanted)
				}
			}
		})
	}
}

// PUT /config 是 Explicit 审计策略（中间件不为失败兜底）：保存链预校验的 5xx
// 必须留痕，而 4xx 载荷/配置状态错误仍不审计（既定政策）；预览路由是
// AuditPolicySkip，同一分类器必须不产生虚假留痕。
func TestWriteConfigValidationFailure_auditOnlyOnExplicitServerErrors(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	const resource = "全局配置"
	mixed := errors.Join(
		&configValidationError{message: "规则 a（lb_a）80 端口开启 TLS 跳转无意义"},
		fmt.Errorf("规则 b（lb_b）ACME 引用校验失败：%w", errors.New("connection reset by peer")),
	)
	tests := []struct {
		name       string
		err        error
		audit      bool
		wantStatus int
		wantAudits int
	}{
		{name: "保存路径纯 DB 故障留痕", err: errors.New("读取待验证规则: database is locked"), audit: true, wantStatus: http.StatusInternalServerError, wantAudits: 1},
		{name: "保存路径混合错误留痕", err: mixed, audit: true, wantStatus: http.StatusInternalServerError, wantAudits: 1},
		{name: "保存路径纯配置错误不审计", err: &configValidationError{message: "规则 a（lb_a）端口无效"}, audit: true, wantStatus: http.StatusBadRequest, wantAudits: 0},
		{name: "预览路径服务端错误不审计", err: errors.New("读取待验证规则: database is locked"), audit: false, wantStatus: http.StatusInternalServerError, wantAudits: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPut, "/config", nil)
			before := auditCountFor(t, "更新失败", resource)

			writeConfigValidationFailure(ctx, tt.err, tt.audit)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), tt.wantStatus)
			}
			if got := auditCountFor(t, "更新失败", resource) - before; got != tt.wantAudits {
				t.Fatalf("失败审计条数=%d, want %d（audit=%v）", got, tt.wantAudits, tt.audit)
			}
		})
	}
	// 两条 5xx 留痕都必须带相位与底层错误（可追溯），且各恰一条。
	for _, underlying := range []string{"database is locked", "connection reset by peer"} {
		var audited int
		if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log
			WHERE action='更新失败' AND resource=? AND detail LIKE '%预校验规则配置失败%' AND detail LIKE ?`,
			resource, "%"+underlying+"%").Scan(&audited); err != nil {
			t.Fatalf("count audit rows for %q: %v", underlying, err)
		}
		if audited != 1 {
			t.Fatalf("底层错误 %q 的失败审计条数=%d, want 1（相位+底层错误可追溯）", underlying, audited)
		}
	}
}

// 存量聚合门镜像（用户裁定）：443 端口 + 明文 HTTP 的启用存量规则在启动/
// UpdateConfig 聚合校验必须点名（与 80 端口 + HTTPS 同族镜像）。
func TestValidateEnabledStoredRuleConfigs_rejectsPlainHTTPOn443(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_plain443','plain443','http','plain443.example.test',443,1)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	err := validateEnabledStoredRuleConfigs(context.Background())
	if err == nil {
		t.Fatal("aggregate validation must reject enabled plain-HTTP rule on port 443")
	}
	if !strings.Contains(err.Error(), "443 端口是 HTTPS 默认端口") || !strings.Contains(err.Error(), "lb_plain443") {
		t.Fatalf("aggregate error must name the rule and the default-port rationale, got: %v", err)
	}
}
