package handlers

// 证书域错误响应契约：
//   - business 组 5xx 只回固定中文文案，SQL/列名/驱动文本只进运行日志；
//   - 只读白名单端点的 400 不得直出 gin 校验器/Go 结构体名、tls/x509 英文错误；
//   - 库内凭证不是合法 JSON 属存储损坏（500），不是「凭证字段不能为掩码占位符」
//     之类的请求错误；
//   - 入队族错误（队列暂停/规则屏障）映射 409，不得折成 500。

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func assertBodyHides(t *testing.T, body string, leaks ...string) {
	t.Helper()
	for _, leak := range leaks {
		if strings.Contains(body, leak) {
			t.Fatalf("响应体泄露 %q: %s", leak, body)
		}
	}
}

// Given 证书配置表出现 NULL created_at（带外改库；导入通道按 epoch 归一）。
// When 任意登录用户读取配置列表。
// Then 500 只回固定文案，不直出 SQL/列名/驱动文本。
func TestListCertificateConfigs_500BodyHidesScanDetails(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled,created_at)
		VALUES ('broken','dnspod','{"auth_mode":"dnspod"}',1,NULL)`); err != nil {
		t.Fatalf("seed broken config: %v", err)
	}
	router := gin.New()
	router.GET("/certificate-configs", h.ListCertificateConfigs)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/certificate-configs", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "读取证书配置失败") {
		t.Fatalf("body=%s, want 固定中文归因", body)
	}
	assertBodyHides(t, body, "sql:", "created_at", "converting NULL", "Scan error")
}

// Given 证书任务表出现 NULL created_at。
// When 读取任务列表。
// Then 500 只回固定文案，不直出 SQL/列名。
func TestListCertJobs_500BodyHidesScanDetails(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,created_at)
		VALUES ('lb_broken','broken.example.com','issued',NULL)`); err != nil {
		t.Fatalf("seed broken job: %v", err)
	}
	router := gin.New()
	router.GET("/certificates/jobs", h.ListCertJobs)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/certificates/jobs", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "读取证书任务失败") {
		t.Fatalf("body=%s, want 固定中文归因", body)
	}
	assertBodyHides(t, body, "sql:", "created_at", "converting NULL", "Scan error")
}

// Given 只读白名单端点收到畸形证书 PEM。
// When 调用 /certificates/parse。
// Then 400 只回固定中文文案，不直出 tls/x509 英文错误。
func TestParseCertificate_400BodyHidesInternalParseText(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/certificates/parse", h.ParseCertificate)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/certificates/parse",
		strings.NewReader(`{"cert_pem":"not-a-cert","key_pem":"not-a-key"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "证书或私钥格式无效") {
		t.Fatalf("body=%s, want 固定中文文案", body)
	}
	assertBodyHides(t, body, "tls:", "x509:", "asn1", "private key does not match", "failed to parse")
}

// Given 只读白名单端点收到缺失必填字段的请求体。
// When 调用 /rules/cert-info。
// Then 400 不直出 gin 校验器文本与 Go 结构体/字段名。
func TestGetRulesCertInfo_400BodyHidesValidatorText(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/rules/cert-info", h.GetRulesCertInfo)
	for _, body := range []string{`{}`, `{"caddy_ids":"not-an-array"}`} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/rules/cert-info", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d, want 400", body, response.Code)
		}
		respBody := response.Body.String()
		if !strings.Contains(respBody, "请求参数无效") {
			t.Fatalf("request=%s body=%s, want 固定中文文案", body, respBody)
		}
		assertBodyHides(t, respBody, "CertInfoBatchRequest", "Key:", "Field validation", "cannot unmarshal", "json:")
	}
}

// Given /certificates/jobs/current 收到类型错误的 rule_ids。
// When 调用只读白名单端点。
// Then 400 不直出 encoding/json 解析文本与 Go 字段名。
func TestGetCurrentCertJobs_400BodyHidesJSONParserText(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/certificates/jobs/current", h.GetCurrentCertJobs)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/certificates/jobs/current", strings.NewReader(`{"rule_ids":123}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "请求格式错误") {
		t.Fatalf("body=%s, want 固定中文文案", body)
	}
	assertBodyHides(t, body, "json:", "RuleIDs", "cannot unmarshal", "struct field")
}

// Given 库内 dns_credentials 不是合法 JSON（带外改库/旧版本遗留）。
// When 非 admin 表单部分掩码回传（触发合并分支）或未提交凭证仅改名。
// Then 500「存储的 DNS 凭证已损坏，请重新填写完整凭证后保存」+ storage_corrupted 审计，
// 不得报 400「凭证字段不能为掩码占位符」/「Invalid stored DNS credentials」。
func TestUpdateCertificateConfig_corruptedStoredCredentialsReturns500(t *testing.T) {
	put := func(t *testing.T, h *Handlers, id int64, body string) *httptest.ResponseRecorder {
		t.Helper()
		router := gin.New()
		router.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPut, "/certificate-configs/"+strconv.FormatInt(id, 10), strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, request)
		return response
	}
	for _, tc := range []struct {
		name string
		body string
	}{
		{"partial mask merges against corrupt storage", `{"dns_credentials":{"auth_mode":"dnspod","app_token":"***"}}`},
		{"omitted credentials", `{"name":"renamed"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			result, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled)
				VALUES ('legacy','dnspod','not-json',1)`)
			if err != nil {
				t.Fatalf("seed corrupt config: %v", err)
			}
			id, err := result.LastInsertId()
			if err != nil {
				t.Fatal(err)
			}
			response := put(t, h, id, tc.body)
			if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "存储的 DNS 凭证已损坏") {
				t.Fatalf("status=%d body=%s, want 500 存储损坏文案", response.Code, response.Body.String())
			}
			detail := latestAuditDetail(t, "更新失败", "DNS配置")
			if !strings.Contains(detail, "存储数据损坏") {
				t.Fatalf("audit detail=%q, want 存储数据损坏 结果码", detail)
			}
		})
	}
}

// Given 服务层返回入队族错误（队列已停用）。
// When 定向签发。
// Then 409 并点名可操作原因（审计结果 skipped），不得折成 500。
func TestIssueCertificate_directedEnqueueConflictReturns409(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_enq_conflict", "enq-conflict.example.com")
	old := createOrRequeueCertJob
	createOrRequeueCertJob = func(string, string, int, *services.CAQueueManager) (int, bool, error) {
		return 0, false, fmt.Errorf("%w（任务未入队）", services.ErrCertificateQueueInactive)
	}
	t.Cleanup(func() { createOrRequeueCertJob = old })

	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_enq_conflict"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（入队族错误是可行动冲突）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "证书签发任务已停止") {
		t.Fatalf("body=%s, want 点名队列停用", response.Body.String())
	}
	if detail := latestAuditDetail(t, "触发签发", "证书"); !strings.Contains(detail, "已跳过") {
		t.Fatalf("audit detail=%q, want 结果：已跳过", detail)
	}
}

// Given 服务层返回真正的内部错误。
// When 定向签发。
// Then 500 只回固定前缀，底层文本只进运行日志。
func TestIssueCertificate_directedInternalFailureHidesCause(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_enq_internal", "enq-internal.example.com")
	old := createOrRequeueCertJob
	createOrRequeueCertJob = func(string, string, int, *services.CAQueueManager) (int, bool, error) {
		return 0, false, errors.New("sql: database is locked: INSERT INTO cert_jobs")
	}
	t.Cleanup(func() { createOrRequeueCertJob = old })

	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_enq_internal"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "创建签发任务失败") {
		t.Fatalf("body=%s, want 固定前缀", response.Body.String())
	}
	assertBodyHides(t, response.Body.String(), "sql:", "database is locked", "INSERT INTO")
}

// Given 批量签发中每个目标都命中入队族冲突（规则屏障）。
// When {"all":true}。
// Then 整批 409（不得 500），文案点名可操作原因。
func TestIssueCertificate_batchEnqueueConflictReturns409(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_batch_busy_a", "batch-busy-a.example.com")
	seedIssueRule(t, "lb_batch_busy_b", "batch-busy-b.example.com")
	old := createOrRequeueCertJob
	createOrRequeueCertJob = func(string, string, int, *services.CAQueueManager) (int, bool, error) {
		return 0, false, fmt.Errorf("create or enqueue cert job: %w", services.ErrCertRuleBusy)
	}
	t.Cleanup(func() { createOrRequeueCertJob = old })

	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（全部目标为入队族冲突）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), services.ErrCertRuleBusy.Error()) {
		t.Fatalf("body=%s, want 点名规则屏障", response.Body.String())
	}
}

// Given 批量签发中每个目标都命中真正的内部错误。
// When {"all":true}。
// Then 500 只回固定文案，失败明细（SQL 片段）只进运行日志。
func TestIssueCertificate_batchInternalFailureHidesCause(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_batch_int_a", "batch-int-a.example.com")
	old := createOrRequeueCertJob
	createOrRequeueCertJob = func(string, string, int, *services.CAQueueManager) (int, bool, error) {
		return 0, false, errors.New("sql: database is locked: INSERT INTO cert_jobs")
	}
	t.Cleanup(func() { createOrRequeueCertJob = old })

	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "全部签发任务创建失败") {
		t.Fatalf("body=%s, want 固定文案", response.Body.String())
	}
	assertBodyHides(t, response.Body.String(), "sql:", "database is locked", "INSERT INTO")
}

// Given ACME 规则的域名只在执行期才会被公共 CA 拒绝（单标签）。
// When 规则保存前的共享校验门。
// Then 400 并点名公共 CA 签发要求（不得保存成功后才在任务列表里失败）。
func TestValidateRulePayloadBeforeSave_rejectsNonIssuableACMEDomains(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled)
		VALUES (1,'cfg','dnspod','{"auth_mode":"dnspod","app_id":"1","app_token":"t"}',1)`); err != nil {
		t.Fatalf("seed dns config: %v", err)
	}
	upstreams := []models.Upstream{{Host: "127.0.0.1", Port: 8080, Weight: 1, Enabled: true}}
	build := func(domain string) models.CreateRuleRequest {
		return models.CreateRuleRequest{
			Protocol: "http", Domain: domain, ListenPort: 8443,
			EnableTLS: true, TLSSource: "acme_dns", ACMEConfigID: 1,
			HealthCheckInterval: 10, HealthCheckTimeout: 5,
			HealthCheckUnhealthyThreshold: 3, HealthCheckHealthyThreshold: 2,
			Upstreams: upstreams,
		}
	}
	for _, domain := range []string{"localhost", "a"} {
		err := h.validateRulePayloadBeforeSave(build(domain))
		if err == nil || !strings.Contains(err.Error(), "公共 CA 签发要求") {
			t.Fatalf("domain=%q err=%v, want 公共 CA 签发要求", domain, err)
		}
	}
	if err := h.validateRulePayloadBeforeSave(build("example.com")); err != nil {
		t.Fatalf("合法域名被拒: %v", err)
	}
}

// Given v2 备份携带启用中的 ACME 规则，域名为单标签（只可能由手造/旧版导出产生）。
// When 导入形状校验。
// Then 整包拒绝并点名公共 CA 签发要求（不得导入后才在签发期失败）。
func TestValidateV2BackupTLSShapeSoft_rejectsNonIssuableACMEDomains(t *testing.T) {
	tables := map[string][]map[string]any{
		"lb_rules": {
			{
				"caddy_id": "lb_import_bad", "name": "bad",
				"protocol": "http", "listen_port": float64(8443),
				"enabled": true, "enable_tls": true, "tls_source": "acme_dns",
				"domain": "localhost", "acme_config_id": float64(1),
			},
		},
		"certificate_configs": {{"id": float64(1), "enabled": true}},
		"ca_providers":        {{"id": float64(1), "enabled": true}},
	}
	if _, err := validateV2BackupTLSShapeSoft(tables, true); err == nil || !strings.Contains(err.Error(), "公共 CA 签发要求") {
		t.Fatalf("err=%v, want 公共 CA 签发要求", err)
	}
}

// Given 历史/导入遗留的禁用 ACME 规则，域名是单标签（公共 CA 必然拒绝）。
// When 启用该规则。
// Then 400 并点名公共 CA 签发要求（启用侧与保存/导入共用同一写入门）。
func TestEnableRule_rejectsNonIssuableACMEDomain(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled)
		VALUES (1,'cfg','dnspod','{"auth_mode":"dnspod","app_id":"1","app_token":"t"}',1)`); err != nil {
		t.Fatalf("seed dns config: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,acme_config_id)
		VALUES ('lb_enable_bad','bad','http','localhost',8443,0,1,'acme_dns',1)`); err != nil {
		t.Fatalf("seed disabled rule: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", h.EnableRule)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_enable_bad/enable", nil))

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "公共 CA 签发要求") {
		t.Fatalf("status=%d body=%s, want 400 公共 CA 签发要求", response.Code, response.Body.String())
	}
	var enabled int
	if err := db.DB.QueryRow(`SELECT enabled FROM lb_rules WHERE caddy_id='lb_enable_bad'`).Scan(&enabled); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if enabled != 0 {
		t.Fatalf("enabled=%d, want 0（被拒规则不得启用）", enabled)
	}
}

// 证书/DNS 配置族的 5xx 出口必须走 writeInternalError（统一写点）：
// 裸写 `c.JSON(http.StatusInternalServerError, ...)` 只回文案，底层原因
// （SQL/表列/文件路径与 errno）连运行日志都不留，排障只能靠猜——错误码契约
// 允许固定文案，但不允许「服务端也无痕」。
func TestCertificateDomain_5xxExitsRouteThroughWriteInternalError(t *testing.T) {
	const rawLiteral = "c.JSON(http.StatusInternalServerError"
	for _, file := range []string{"certificates.go", "certinfo.go"} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		content := string(source)
		for offset := 0; ; {
			idx := strings.Index(content[offset:], rawLiteral)
			if idx < 0 {
				break
			}
			position := offset + idx
			line := 1 + strings.Count(content[:position], "\n")
			t.Errorf("%s:%d 裸写 5xx——必须走 writeInternalError(c, status, 固定文案, err) 以留痕底层原因", file, line)
			offset = position + len(rawLiteral)
		}
	}
}

// Given 批量 cert-info 的服务层读故障（cert_jobs 表缺失）。
// When 调用批量端点。
// Then 500 固定文案不外泄内部文本，且底层原因写进运行日志。
func TestGetRulesCertInfo_500LogsUnderlyingCause(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`DROP TABLE cert_jobs`); err != nil {
		t.Fatalf("drop cert_jobs: %v", err)
	}
	var logs strings.Builder
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })

	router := gin.New()
	router.POST("/rules/cert-info", h.GetRulesCertInfo)
	request := httptest.NewRequest(http.MethodPost, "/rules/cert-info", strings.NewReader(`{"caddy_ids":["lb_missing"]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "批量读取签发证书失败") {
		t.Fatalf("body=%s, want 固定失败文案", response.Body.String())
	}
	assertBodyHides(t, response.Body.String(), "cert_jobs", "no such table", "sql:")
	if !strings.Contains(logs.String(), "cert_jobs") {
		t.Fatalf("5xx 必须把底层原因写进运行日志，实得 %q", logs.String())
	}
}

// Given 单规则 cert-info 的服务层读故障（lb_rules 表缺失）。
// When 调用单规则端点。
// Then 500 固定文案且底层原因进运行日志（与批量端点同口径）。
func TestGetRuleCertInfo_500LogsUnderlyingCause(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`DROP TABLE lb_rules`); err != nil {
		t.Fatalf("drop lb_rules: %v", err)
	}
	var logs strings.Builder
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })

	router := gin.New()
	router.GET("/rules/:caddy_id/cert-info", h.GetRuleCertInfo)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rules/lb_missing/cert-info", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "读取规则证书信息失败") {
		t.Fatalf("body=%s, want 固定失败文案", response.Body.String())
	}
	assertBodyHides(t, response.Body.String(), "lb_rules", "no such table", "sql:")
	if !strings.Contains(logs.String(), "lb_rules") {
		t.Fatalf("5xx 必须把底层原因写进运行日志，实得 %q", logs.String())
	}
}

// Given 引用检查所需的 lb_rules 表不可用（存储故障）。
// When 禁用仍在被引用的证书配置（触发引用守卫查询）。
// Then 500 固定中文文案 + 底层原因进运行日志（此前英文 raw 5xx 且无留痕）。
func TestUpdateCertificateConfig_referenceGuardFailureLogsCause(t *testing.T) {
	h := newBackupTestHandlers(t)
	var configID int64
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled)
		VALUES ('lockprobe-config','dnspod','{"auth_mode":"dnspod","app_id":"12345","app_token":"token-value"}',1)`); err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	if err := db.DB.QueryRow(`SELECT MAX(id) FROM certificate_configs`).Scan(&configID); err != nil {
		t.Fatalf("read seeded certificate config: %v", err)
	}
	if _, err := db.DB.Exec(`DROP TABLE lb_rules`); err != nil {
		t.Fatalf("drop lb_rules: %v", err)
	}
	var logs strings.Builder
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })

	router := gin.New()
	router.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)
	request := httptest.NewRequest(http.MethodPut, "/certificate-configs/"+strconv.FormatInt(configID, 10), strings.NewReader(`{"enabled":false}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "检查规则引用失败") {
		t.Fatalf("body=%s, want 固定中文归因", response.Body.String())
	}
	assertBodyHides(t, response.Body.String(), "lb_rules", "no such table", "sql:", "Failed to")
	if !strings.Contains(logs.String(), "lb_rules") {
		t.Fatalf("5xx 必须把底层原因写进运行日志，实得 %q", logs.String())
	}
}
