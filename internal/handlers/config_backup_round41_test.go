package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// r41BackupJSON 构造「精确表集」备份——与三分类导出同形态:只含给定表,
// 不做 15 表回填(completeBackupJSON 的全量回填无法模拟分类导出/规则库
// 单独导出的缺表形态)。sections 为调用方分类选择(空=全选默认)。
func r41BackupJSON(t *testing.T, sections []string, tables map[string][]map[string]any, cfg map[string]any) string {
	t.Helper()
	backup := configBackup{
		Sections: sections,
		Meta:     configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-09-19T00:00:00Z"},
		Config:   cfg,
		Tables:   tables,
	}
	backup.Meta.Checksum = checksumBackupPayload(t, tables, cfg)
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal r41 backup: %v", err)
	}
	return string(data)
}

// r41PostValidate 走预览端点并解码响应(导入/预览双路径同序钉板)。
func r41PostValidate(t *testing.T, h *Handlers, body string) importValidateResponse {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/validate", h.ValidateConfigImport)
	request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	var envelope struct {
		Data importValidateResponse `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode validate response: %v (body=%s)", err, response.Body.String())
	}
	return envelope.Data
}

// r41BadPortRuleRow 监听端口越界的坏规则行(validateV2BackupRules 必拒)。
func r41BadPortRuleRow() map[string]any {
	return map[string]any{
		"caddy_id": "lb_r41_bad", "name": "r41-bad", "protocol": "http",
		"domain": "r41-bad.example.test", "listen_port": 70000, "enabled": 1,
	}
}

// r41AdminUserRow 备份内一名启用管理员(满足管理员门)。
func r41AdminUserRow() map[string]any {
	return map[string]any{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}
}

// r41ACMEJobRow 与 r53BackupACMERule 域名匹配的终态任务行(避开重排队列)。
func r41ACMEJobRow() map[string]any {
	return map[string]any{"rule_id": "lb_bak_acme", "domain": "bak-acme.example.test", "status": "issued"}
}

// CERT41-1 形状①:坏行在未选分类——sections 过滤前置后,未选「负载规则」
// 分类的端口坏行不得误拒整包,且不得落库。
func TestImportConfigBackup_sectionsUnselectedBadRowsDoNotReject(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := r41BackupJSON(t, []string{"users", "security"}, map[string][]map[string]any{
		"users":    {r41AdminUserRow()},
		"lb_rules": {r41BadPortRuleRow()},
	}, nil)

	// When
	response := postBackupImport(t, h, backup)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（未选分类的坏行不得误拒）", response.Code, response.Body.String())
	}
	var badRules int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_r41_bad'`).Scan(&badRules); err != nil || badRules != 0 {
		t.Fatalf("unselected-section bad rule imported, count=%d err=%v", badRules, err)
	}
	var admins int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username='backup-admin'`).Scan(&admins); err != nil || admins != 1 {
		t.Fatalf("selected users section must import, admins=%d err=%v", admins, err)
	}
}

// CERT41-1 形状②:坏行在已选分类——勾选「负载规则」后同一坏行仍整包 400。
func TestImportConfigBackup_sectionsSelectedBadRowsStillReject(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := r41BackupJSON(t, []string{"rules"}, map[string][]map[string]any{
		"users":    {r41AdminUserRow()},
		"lb_rules": {r41BadPortRuleRow()},
	}, nil)

	// When
	response := postBackupImport(t, h, backup)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（已选分类的坏行必须拒绝）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "规则 #1") {
		t.Fatalf("body=%s, want rule-positioned validation error", response.Body.String())
	}
}

// r41FullBackupWithACMEPair 携带 certificate_configs(id 7 启用) + 启用
// acme_dns 规则(引用 7) + 任务行的全量形态备份。
func r41FullBackupWithACMEPair(t *testing.T, sections []string) string {
	return r41BackupJSON(t, sections, map[string][]map[string]any{
		"users":               {r41AdminUserRow()},
		"lb_rules":            {r53BackupACMERule(7)},
		"cert_jobs":           {r41ACMEJobRow()},
		"certificate_configs": {{"id": 7, "name": "dns", "dns_provider": "dnspod", "dns_credentials": "{}", "enabled": 1}},
		"ca_providers":        {},
	}, nil)
}

// CERT41-1 形状③:备份带 cert 配置但用户未勾系统数据——过滤后引用按 live
// 解析(live 缺引用)必须 400,不得按将被丢弃的备份行误放行。
func TestImportConfigBackup_sectionsUnselectedUsersDanglingACMERejected(t *testing.T) {
	// Given:live 无 certificate_configs id 7
	h := newBackupTestHandlers(t)
	backup := r41FullBackupWithACMEPair(t, []string{"rules"})

	// When
	response := postBackupImport(t, h, backup)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（误放行关闭）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "选择的 DNS 提供商配置不存在或已禁用") {
		t.Fatalf("body=%s, want ACME dangling message", response.Body.String())
	}
}

// CERT41-1 形状④:备份带 cert 配置且已选系统数据——按备份行解析(原语义),
// 与 live 无关,导入成功且配置落库。
func TestImportConfigBackup_sectionsSelectedUsersResolvesAgainstBackupRows(t *testing.T) {
	// Given:live 无 certificate_configs id 7(解析必须命中备份行)
	h := newBackupTestHandlers(t)
	backup := r41FullBackupWithACMEPair(t, []string{"rules", "users"})

	// When
	response := postBackupImport(t, h, backup)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var configs int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM certificate_configs WHERE id=7`).Scan(&configs); err != nil || configs != 1 {
		t.Fatalf("certificate_configs id 7 must be imported, count=%d err=%v", configs, err)
	}
}

// CERT41-1 形状⑤:规则库单独备份(从未携带 cert 表)+选 rules 未选 users——
// live 配置保留,启用 ACME 规则引用 live 缺失→降级警告(与 R39-14 预检
// 对称),导入成功且警告进响应。
func TestImportConfigBackup_rulesOnlyBackupLiveDanglingACMEWarns(t *testing.T) {
	// Given:live 有本地管理员(rules 分类不触碰 users),无 certificate_configs id 7
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (5,'local-keeper','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	backup := r41BackupJSON(t, []string{"rules"}, map[string][]map[string]any{
		"lb_rules":  {r53BackupACMERule(7)},
		"cert_jobs": {r41ACMEJobRow()},
	}, nil)

	// When
	response := postBackupImport(t, h, backup)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（反向悬挂降级警告）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "悬挂") {
		t.Fatalf("body=%s, want dangling warning in response", response.Body.String())
	}
	var keeper int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username='local-keeper'`).Scan(&keeper); err != nil || keeper != 1 {
		t.Fatalf("rules-only import must not touch users, count=%d err=%v", keeper, err)
	}
	var rules int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_bak_acme'`).Scan(&rules); err != nil || rules != 1 {
		t.Fatalf("rules-only import must apply rules, count=%d err=%v", rules, err)
	}
}

// CERT41-1 回归钉:规则库单独备份 + 未显式分类(默认全选) + live 缺引用——
// 默认全选语义下 cert 表「被选但缺席备份」,维持 live 硬解析 400(不降级)。
func TestImportConfigBackup_rulesOnlyBackupDefaultSectionsLiveDanglingRejected(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (5,'local-keeper','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	backup := r41BackupJSON(t, nil, map[string][]map[string]any{
		"lb_rules":  {r53BackupACMERule(7)},
		"cert_jobs": {r41ACMEJobRow()},
	}, nil)

	// When
	response := postBackupImport(t, h, backup)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（默认全选不降级）", response.Code, response.Body.String())
	}
}

// CERT41-1 形状⑥a:预览与导入同序——未选分类的坏行不得误报不可导入。
func TestValidateConfigImport_sectionsUnselectedBadRowsStayValid(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := r41BackupJSON(t, []string{"users"}, map[string][]map[string]any{
		"users":    {r41AdminUserRow()},
		"lb_rules": {r41BadPortRuleRow()},
	}, nil)

	// When
	result := r41PostValidate(t, h, backup)

	// Then
	if !result.Valid {
		t.Fatalf("valid=%v error=%q, want valid（预览同序:未选分类坏行不误拒）", result.Valid, result.Error)
	}
}

// CERT41-1 形状⑥b:预览与导入同序——已选分类的坏行预览即报不可导入。
func TestValidateConfigImport_sectionsSelectedBadRowsInvalid(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := r41BackupJSON(t, []string{"rules"}, map[string][]map[string]any{
		"users":    {r41AdminUserRow()},
		"lb_rules": {r41BadPortRuleRow()},
	}, nil)

	// When
	result := r41PostValidate(t, h, backup)

	// Then
	if result.Valid {
		t.Fatalf("valid=true, want invalid（预览同序:已选分类坏行必拒）warnings=%v", result.Warnings)
	}
	if !strings.Contains(result.Error, "规则 #1") {
		t.Fatalf("error=%q, want rule-positioned validation error", result.Error)
	}
}

// CERT41-1 形状⑥c:预览与导入同序——备份带 cert 配置但未勾系统数据,引用
// 按 live 解析失败,预览即报不可导入(误放行关闭)。
func TestValidateConfigImport_sectionsUnselectedUsersDanglingACMEInvalid(t *testing.T) {
	// Given:live 无 certificate_configs id 7
	h := newBackupTestHandlers(t)
	backup := r41FullBackupWithACMEPair(t, []string{"rules"})

	// When
	result := r41PostValidate(t, h, backup)

	// Then
	if result.Valid {
		t.Fatalf("valid=true, want invalid（预览同序:误放行关闭）warnings=%v", result.Warnings)
	}
	if !strings.Contains(result.Error, "选择的 DNS 提供商配置不存在或已禁用") {
		t.Fatalf("error=%q, want ACME dangling message", result.Error)
	}
}

// CERT41-1 形状⑥d:预览与导入同序——规则库单独备份+选 rules 未选 users,
// live 缺引用→预览可导入并携带悬挂警告(降级对称)。
func TestValidateConfigImport_rulesOnlyBackupLiveDanglingACMEWarns(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := r41BackupJSON(t, []string{"rules"}, map[string][]map[string]any{
		"lb_rules":  {r53BackupACMERule(7)},
		"cert_jobs": {r41ACMEJobRow()},
	}, nil)

	// When
	result := r41PostValidate(t, h, backup)

	// Then
	if !result.Valid {
		t.Fatalf("valid=%v error=%q, want valid（预览同序:反向悬挂降级）", result.Valid, result.Error)
	}
	if !strings.Contains(strings.Join(result.Warnings, "；"), "悬挂") {
		t.Fatalf("warnings=%v, want dangling warning", result.Warnings)
	}
}

// R41 追加(用户生产观察):导入/导出汇总 labels 覆盖安全域用户内容表——
// 安全策略/自定义规则/拦截页必须进 counts(绑定表为派生数据不加)。
func TestImportCountsDetail_includesSecurityUserContentTables(t *testing.T) {
	// Given
	tables := map[string][]map[string]any{
		"security_policies":     {{}, {}, {}},
		"security_custom_rules": {{}, {}},
		"security_block_pages":  {{}},
		"security_ip_lists":     {{}},
	}

	// When
	got := importCountsDetail(tables)

	// Then
	for _, want := range []string{"安全策略 3 条", "自定义规则 2 条", "拦截页 1 个", "IP 地址列表 1 个"} {
		if !strings.Contains(got, want) {
			t.Fatalf("importCountsDetail=%q, want contains %q", got, want)
		}
	}
	// 绑定表为派生数据,不得进汇总
	if strings.Contains(got, "绑定") {
		t.Fatalf("importCountsDetail=%q, must not include bindings", got)
	}
}

// CERT41-4 导入侧接线:手动证书规则的链不完整/域名不匹配警告并入导入
// responseWarnings(不阻断);配对合法性仍由 materializeImportCertificates 硬校验。
func TestImportConfigBackup_warnsManualCertChainAndDomainMismatch(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	restoreCertDir := services.SetCertDirForTest(t.TempDir())
	t.Cleanup(restoreCertDir)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (5,'local-keeper','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := generateTestCert("other.example.test", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	rule := map[string]any{
		"caddy_id": "lb_r41_cert", "name": "r41-cert", "protocol": "http",
		"domain": "r41-cert.example.test", "listen_port": 8443,
		"enabled": 1, "enable_tls": 1, "tls_source": "manual",
		"tls_cert": certPEM, "tls_key": keyPEM,
	}
	backup := r41BackupJSON(t, []string{"rules"}, map[string][]map[string]any{"lb_rules": {rule}}, nil)

	// When
	response := postBackupImport(t, h, backup)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（证书警告不阻断）", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "证书链可能不完整") {
		t.Fatalf("body=%s, want incomplete-chain warning", body)
	}
	if !strings.Contains(body, "证书域名与规则域名不匹配") {
		t.Fatalf("body=%s, want domain-mismatch warning", body)
	}
}

// CERT41-4 接线对照:证书域名覆盖规则域名时不得产生域名不匹配警告
// (自签单张的链警告仍出现)。
func TestImportConfigBackup_certWarningsSkipCoveredDomain(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	restoreCertDir := services.SetCertDirForTest(t.TempDir())
	t.Cleanup(restoreCertDir)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (5,'local-keeper','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := generateTestCert("r41-cert.example.test", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	rule := map[string]any{
		"caddy_id": "lb_r41_cert2", "name": "r41-cert2", "protocol": "http",
		"domain": "r41-cert.example.test", "listen_port": 8444,
		"enabled": 1, "enable_tls": 1, "tls_source": "manual",
		"tls_cert": certPEM, "tls_key": keyPEM,
	}
	backup := r41BackupJSON(t, []string{"rules"}, map[string][]map[string]any{"lb_rules": {rule}}, nil)

	// When
	response := postBackupImport(t, h, backup)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "证书链可能不完整") {
		t.Fatalf("body=%s, want incomplete-chain warning", body)
	}
	if strings.Contains(body, "证书域名与规则域名不匹配") {
		t.Fatalf("body=%s, must not warn domain mismatch for covered domain", body)
	}
}
