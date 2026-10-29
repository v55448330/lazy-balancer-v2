package handlers

// 证书域回归网：审计口径按生效值比对、稀疏凭证更新语义、批量出口归因完整性、
// 分页上限、证书解析与日志读取的固定分支。

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
	"lazy-balancer-v2/internal/services"
)

func latestAuditDetail(t *testing.T, action, resource string) string {
	t.Helper()
	var detail string
	if err := db.AuditDB.QueryRow("SELECT detail FROM audit_log WHERE action=? AND resource=? ORDER BY id DESC LIMIT 1", action, resource).Scan(&detail); err != nil {
		t.Fatalf("read %s/%s audit: %v", action, resource, err)
	}
	return detail
}

// Given CA 提供商名称已是 trim 后的值。When 提交同一名称但带首尾空白。
// Then 审计按生效值比对，记「无修改」，不得产生「名称」变更假阳性。
func TestUpdateCAProvider_paddedSameNameIsNotAuditedAsChange(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.caProviderService = services.NewCAProviderService()
	res, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES ('LE','letsencrypt','https://acme-v02.api.letsencrypt.org/directory','',1,1000,1)`)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.PUT("/ca-providers/:id", h.UpdateCAProvider)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/ca-providers/%d", id), strings.NewReader(`{"name":"  LE  "}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	detail := latestAuditDetail(t, "更新", "CA提供商")
	if !strings.Contains(detail, "无修改") {
		t.Fatalf("audit detail=%q, want 无修改（trim 后同名不算变更）", detail)
	}
	if strings.Contains(detail, "变更：名称") {
		t.Fatalf("audit detail=%q, 名称空白填充不得记成变更", detail)
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT name FROM ca_providers WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "LE" {
		t.Fatalf("stored name=%q, want LE", stored)
	}
}

// Given 同一 provider 的完整凭证已落库。When 稀疏提交其中一个字段。
// Then 未提交字段继承库值（不得静默抹除），已提交字段生效。
func TestUpdateCertificateConfig_sparsePatchKeepsUnsubmittedCredentialKeys(t *testing.T) {
	h := newBackupTestHandlers(t)
	res, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled)
		VALUES ('sparse','dnspod','{"auth_mode":"dnspod","app_id":"app-id","app_token":"old-token"}',1)`)
	if err != nil {
		t.Fatalf("seed config: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/certificate-configs/%d", id),
		strings.NewReader(`{"dns_credentials":{"app_token":"new-token"}}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT COALESCE(dns_credentials,'') FROM certificate_configs WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	var creds map[string]string
	if err := json.Unmarshal([]byte(stored), &creds); err != nil {
		t.Fatalf("stored credentials not JSON: %v", err)
	}
	if creds["app_id"] != "app-id" || creds["app_token"] != "new-token" || creds["auth_mode"] != "dnspod" {
		t.Fatalf("stored credentials=%v, 未提交字段必须保留、提交字段必须生效", creds)
	}
}

// Given 库中存在 provider 不再接受的历史凭证形态（部分空串）。
// When 仅改名，或原样回传同一凭证。
// Then 保存成功——保持库值不是新写入，不得以 provider 校验阻断；显式改动仍 400。
func TestUpdateCertificateConfig_unchangedLegacyPartialCredentialsAreNotRevalidated(t *testing.T) {
	h := newBackupTestHandlers(t)
	res, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled)
		VALUES ('legacy-partial','dnspod','{"auth_mode":"dnspod","app_id":"","app_token":""}',1)`)
	if err != nil {
		t.Fatalf("seed config: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)
	put := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/certificate-configs/%d", id), strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, request)
		return rec
	}

	if rec := put(`{"dns_credentials":{"auth_mode":"dnspod","app_id":"","app_token":""}}`); rec.Code != http.StatusOK {
		t.Fatalf("submit-as-is status=%d body=%s, want 200（原样回传不得 400）", rec.Code, rec.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT COALESCE(dns_credentials,'') FROM certificate_configs WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !services.CredentialsSemanticallyEqual(stored, `{"auth_mode":"dnspod","app_id":"","app_token":""}`) {
		t.Fatalf("stored credentials=%q, want 原值保持", stored)
	}
	// 对照：显式改成一个仍无效的形态必须被 provider 校验拦下。
	if rec := put(`{"dns_credentials":{"auth_mode":"dnspod","app_id":"only-id"}}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid change status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
}

// Given 禁用配置携带 provider 已不接受的历史凭证，直接 API 原样回传并启用。
// When 保存禁用→启用状态迁移。
// Then 必须在落库前重新执行 provider 校验；保持原启用态的兼容豁免不得覆盖启用门。
func TestUpdateCertificateConfig_enablingRevalidatesUnchangedLegacyCredentials(t *testing.T) {
	h := newBackupTestHandlers(t)
	result, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled)
		VALUES ('legacy-disabled','dnspod','{"auth_mode":"dnspod","app_id":"","app_token":""}',0)`)
	if err != nil {
		t.Fatalf("seed disabled legacy config: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	response := putCertificateConfig(t, h, id, `{"enabled":true,"dns_credentials":{"auth_mode":"dnspod","app_id":"","app_token":""}}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（启用前必须重验原样提交的历史凭证）", response.Code, response.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow(`SELECT enabled FROM certificate_configs WHERE id=?`, id).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("无效历史凭证的配置被启用")
	}
}

// Given 批量目标中一个非法域名（必然失败）+ 一个 CA 冷却中的任务（跳过）。
// When all=true 未带 force。
// Then 500 响应必须同时携带失败与跳过计数/文案，不得只报「全部失败」。
func TestIssueCertificate_batchAllFailedCarriesSkippedCounts(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_skip_bad", "*.wildcard.example")
	seedIssueRule(t, "lb_skip_cool", "cool.example")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,updated_at)
		VALUES ('lb_skip_cool','cool.example','waiting_ca',datetime('now','+1 hour'),datetime('now','-2 hours'))`); err != nil {
		t.Fatalf("seed cooling job: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`)))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（确有失败目标）", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"failed":1`) || !strings.Contains(body, `"skipped_waiting_ca":1`) {
		t.Fatalf("body=%s, want failed=1 + skipped_waiting_ca=1", body)
	}
	if !strings.Contains(body, "冷却跳过 1 个") {
		t.Fatalf("body=%s, 全部失败出口必须携带跳过归因", body)
	}
}

// Given force=true 命中的目标在快照后规则被删除（upsert 冲突，ca 窗口未清空）。
// When 批量签发。
// Then 审计/文案不得声称「手动越过 CA 冷却」——ca_available_after 从未被清空。
func TestIssueCertificate_batchForceDoesNotClaimOverrideWhenTargetSkipped(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_force_meta", "force-meta.example")
	res, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,updated_at)
		VALUES ('lb_force_meta','force-meta.example','waiting_ca',datetime('now','+1 hour'),datetime('now','-2 hours'))`)
	if err != nil {
		t.Fatalf("seed cooling job: %v", err)
	}
	jobID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	snapshotTaken := make(chan struct{})
	allowContinue := make(chan struct{})
	oldHook := issueCertificateBatchSnapshotHook
	issueCertificateBatchSnapshotHook = func() {
		close(snapshotTaken)
		<-allowContinue
	}
	t.Cleanup(func() { issueCertificateBatchSnapshotHook = oldHook })
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue?force=true", strings.NewReader(`{"all":true}`)))
		close(done)
	}()
	select {
	case <-snapshotTaken:
	case <-time.After(5 * time.Second):
		t.Fatal("批量签发目标快照未在超时内完成")
	}
	if _, err := db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id='lb_force_meta'"); err != nil {
		close(allowContinue)
		t.Fatalf("delete rule in snapshot-to-lock window: %v", err)
	}
	close(allowContinue)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("批量签发请求未返回")
	}
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（规则状态冲突）", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "手动越过 CA 冷却") {
		t.Fatalf("body=%s, 未发生清空（规则冲突失败）不得声称越过冷却", response.Body.String())
	}
	detail := latestAuditDetail(t, "触发签发", "证书")
	if strings.Contains(detail, "手动越过 CA 冷却") {
		t.Fatalf("audit detail=%q, 未发生清空（规则冲突失败）不得声称越过冷却", detail)
	}
	var availableAfter string
	if err := db.DB.QueryRow(`SELECT COALESCE(ca_available_after,'') FROM cert_jobs WHERE id=?`, jobID).Scan(&availableAfter); err != nil {
		t.Fatal(err)
	}
	if availableAfter == "" {
		t.Fatal("ca_available_after 被清空，测试前提（未越过）被破坏")
	}
}

// 深分页上限：page 超过 1000 时按 1000 钳制并回 X-Page，不执行百万级 OFFSET。
func TestListCertJobs_clampsDeepPage(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_page','page.example','queued')`); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	router := gin.New()
	router.GET("/jobs", h.ListCertJobs)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/jobs?page=1000000&page_size=200", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if got := response.Header().Get("X-Page"); got != "1000" {
		t.Fatalf("X-Page=%q, want 1000（钳制到上限）", got)
	}
	if got := response.Header().Get("X-Page-Size"); got != "200" {
		t.Fatalf("X-Page-Size=%q, want 200", got)
	}
}

func TestParseCertificate_acceptsMatchingPairAndRejectsMismatch(t *testing.T) {
	h := &Handlers{}
	router := gin.New()
	router.POST("/certificates/parse", h.ParseCertificate)
	certPEM, keyPEM := selfSignedCertWithExpiry(t, "parse.example",
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	otherCertPEM, otherKeyPEM := selfSignedCertWithExpiry(t, "other.example",
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	post := func(body string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/certificates/parse", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, request)
		return response
	}

	success := post(fmt.Sprintf(`{"cert_pem":%q,"key_pem":%q}`, certPEM, keyPEM))
	if success.Code != http.StatusOK {
		t.Fatalf("matching pair status=%d body=%s, want 200", success.Code, success.Body.String())
	}
	if !strings.Contains(success.Body.String(), `"valid":true`) || !strings.Contains(success.Body.String(), "parse.example") {
		t.Fatalf("body=%s, want valid=true + 证书域名", success.Body.String())
	}

	mismatch := post(fmt.Sprintf(`{"cert_pem":%q,"key_pem":%q}`, otherCertPEM, keyPEM))
	if mismatch.Code != http.StatusBadRequest {
		t.Fatalf("mismatched key status=%d body=%s, want 400", mismatch.Code, mismatch.Body.String())
	}

	invalid := post(fmt.Sprintf(`{"cert_pem":"not-a-pem","key_pem":%q}`, otherKeyPEM))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid PEM status=%d body=%s, want 400", invalid.Code, invalid.Body.String())
	}
}

// Given 非 admin 会话。When 读取证书配置列表。
// Then DNS 凭证按掩码返回（前端表单原样回传也不得泄露真实值）。
func TestListCertificateConfigs_masksForNonAdminSession(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled)
		VALUES ('masked','dnspod','{"auth_mode":"dnspod","app_id":"secret-id","app_token":"secret-token"}',1)`); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	router := gin.New()
	router.GET("/certificate-configs", func(c *gin.Context) {
		c.Set("role", "user")
		h.ListCertificateConfigs(c)
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/certificate-configs", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "secret-id") || strings.Contains(response.Body.String(), "secret-token") {
		t.Fatalf("body=%s, 非 admin 不得看到真实凭证", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), maskedDNSCredentialsSentinel) {
		t.Fatalf("body=%s, want 掩码占位", response.Body.String())
	}
}

func TestGetCertJobLogs_unknownJobReturns404(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.GET("/cert-jobs/:id/logs", h.GetCertJobLogs)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/cert-jobs/999999/logs", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", response.Code, response.Body.String())
	}
}

// Given 已禁用/不存在的 CA 提供商。When 测试端点。
// Then 404 并留审计；配置缺失（无 ACME 邮箱）→ 400 且留审计。
func TestCAProvider_testBranchesRecordAudit(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.caProviderService = services.NewCAProviderService()
	router := gin.New()
	router.POST("/ca-providers/:id/test", h.TestCAProvider)

	missing := httptest.NewRecorder()
	router.ServeHTTP(missing, httptest.NewRequest(http.MethodPost, "/ca-providers/999/test", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("not found status=%d body=%s, want 404", missing.Code, missing.Body.String())
	}
	if detail := latestAuditDetail(t, "测试失败", "CA提供商"); !strings.Contains(detail, "对象不存在") {
		t.Fatalf("audit detail=%q, want not_found 结果标签（渲染为 对象不存在）", detail)
	}

	res, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES ('LE-mail','letsencrypt','https://acme-v02.api.letsencrypt.org/directory','',1,1000,1)`)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET acme_email='' WHERE id=1"); err != nil {
		t.Fatalf("clear acme email: %v", err)
	}
	noEmail := httptest.NewRecorder()
	router.ServeHTTP(noEmail, httptest.NewRequest(http.MethodPost, fmt.Sprintf("/ca-providers/%d/test", id), nil))
	if noEmail.Code != http.StatusBadRequest {
		t.Fatalf("missing email status=%d body=%s, want 400", noEmail.Code, noEmail.Body.String())
	}
	if !strings.Contains(noEmail.Body.String(), "未配置 ACME 邮箱") {
		t.Fatalf("body=%s, want 邮箱缺失文案", noEmail.Body.String())
	}
	if detail := latestAuditDetail(t, "测试失败", "CA提供商"); !strings.Contains(detail, "缺少 ACME 邮箱") {
		t.Fatalf("audit detail=%q, want missing_acme_email 结果标签（渲染为 缺少 ACME 邮箱）", detail)
	}
}
