package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 删除端点必须与同族写端点一致：导入窗口内 409 fast-fail（门先于 caddyOpMu）。
// 否则请求阻塞在导入锁上直到导入结束，再按陈旧 id 作用到导入后的行。
func TestDeleteCertJobBlockedDuringConfigImport(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status) VALUES (7,'lb_del_gate','del-gate.test','failed')`); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	router := gin.New()
	router.DELETE("/cert-jobs/:id", h.DeleteCertJob)

	beginImportWindowForTest(t)

	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/cert-jobs/7", nil))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("删除请求阻塞在导入锁上（门必须先于 caddyOpMu）")
	}
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", recorder.Code, recorder.Body.String())
	}
	var status string
	if err := db.DB.QueryRow(`SELECT status FROM cert_jobs WHERE id=7`).Scan(&status); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "failed" {
		t.Fatalf("job status=%q, want failed（导入窗口内零写库）", status)
	}
}

// 可空 enabled 的历史行不得让整表列表 500（同表 Update 已按 COALESCE(enabled,1)
// 读取）；NULL 按启用处理。
func TestListCertificateConfigs_toleratesNullEnabled(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES (1,'null-enabled','dnspod','{}',NULL)`); err != nil {
		t.Fatalf("seed null-enabled config: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/certificate-configs", nil)
	h.ListCertificateConfigs(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"enabled":true`) {
		t.Fatalf("body=%s, want enabled=true（NULL 按启用）", recorder.Body.String())
	}
}

// DNS 配置名称与 CA 提供商同族校验：trim 后非空、≤100 rune、写 trimmed 值。
func TestCertificateConfigNameValidation(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/certificate-configs", h.CreateCertificateConfig)
	router.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)

	post := func(name string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		body := `{"name":"` + name + `","dns_provider":"dnspod","dns_credentials":{"auth_mode":"dnspod","app_id":"1","app_token":"t"},"enabled":true}`
		req := httptest.NewRequest(http.MethodPost, "/certificate-configs", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, req)
		return recorder
	}

	if recorder := post("   "); recorder.Code != http.StatusBadRequest {
		t.Fatalf("blank name status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if recorder := post(strings.Repeat("a", 101)); recorder.Code != http.StatusBadRequest {
		t.Fatalf("101-rune name status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if recorder := post("  trimmed-name  "); recorder.Code != http.StatusCreated {
		t.Fatalf("normal name status=%d body=%s, want 201", recorder.Code, recorder.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT name FROM certificate_configs WHERE name='trimmed-name'`).Scan(&stored); err != nil {
		t.Fatalf("read trimmed name: %v", err)
	}
	if stored != "trimmed-name" {
		t.Fatalf("stored name=%q, want trimmed-name", stored)
	}

	// Update 空白改名同样拒绝
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/certificate-configs/1", strings.NewReader(`{"name":"   "}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("blank rename status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
}

// 审计 changed 清单按「归一后的生效值」比对：提交 0 而库值已是钳制默认值时
// 不构成变更（服务层落库仍为该默认值）。
func TestUpdateCAProviderAuditUsesClampedValues(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	if _, err := db.DB.Exec(`UPDATE ca_providers SET max_concurrent=1, min_interval_ms=2000 WHERE id=1`); err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	router := gin.New()
	router.PUT("/ca-providers/:id", h.UpdateCAProvider)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/ca-providers/1", strings.NewReader(`{"max_concurrent":0,"min_interval_ms":0}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var maxConcurrent, minInterval int
	if err := db.DB.QueryRow(`SELECT max_concurrent, min_interval_ms FROM ca_providers WHERE id=1`).Scan(&maxConcurrent, &minInterval); err != nil {
		t.Fatalf("read CA provider: %v", err)
	}
	if maxConcurrent != 1 || minInterval != 2000 {
		t.Fatalf("stored max_concurrent=%d min_interval_ms=%d, want 1/2000", maxConcurrent, minInterval)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log WHERE action='更新' AND resource='CA提供商' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read CA provider audit: %v", err)
	}
	if !strings.Contains(detail, "无修改") {
		t.Fatalf("audit detail=%q, want 无修改（请求值钳制后与库值相同）", detail)
	}
}

// force 重试的「手动越过 CA 冷却」留痕只在实际越过时记录：冷却已自然到期时
// 同一请求并未越过任何东西。
func TestRetryCertJob_forceAuditOnlyWhenCooldownActuallyActive(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_expired_cooling','cooling','http','expired-cooling.example.test',8080,1,1,'acme_dns');
		INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'cooling CA','letsencrypt','https://invalid.example/directory',1);
		INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,ca_available_after,updated_at)
		VALUES ('lb_expired_cooling','expired-cooling.example.test','waiting_ca',7,datetime('now','-1 hour'),datetime('now','-2 hours'))`); err != nil {
		t.Fatalf("seed expired cooldown job: %v", err)
	}
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/jobs/1/retry?force=true", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log WHERE action='重试' AND resource='证书任务' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read retry audit: %v", err)
	}
	if strings.Contains(detail, "手动越过 CA 冷却") {
		t.Fatalf("audit detail=%q, want 不含越权留痕（冷却已到期）", detail)
	}
}

// Given force 重试已迁移 waiting_ca 任务并清空冷却，随后 CA provider 解析失败。
// When 入队返回 changed=true + error。
// Then 失败审计仍须记录本次实际发生的手动越冷，不得只剩 enqueue_failed。
func TestRetryCertJob_forceFailureAuditKeepsCooldownOverride(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,ca_provider_id)
		VALUES ('lb_force_failure','cooling','http','force-failure.example.test',8080,1,1,'acme_dns',999);
		INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (999,'disabled CA','letsencrypt','https://invalid.example/directory',0);
		INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,ca_available_after,updated_at)
		VALUES ('lb_force_failure','force-failure.example.test','waiting_ca',999,datetime('now','+1 hour'),datetime('now','-2 hours'))`); err != nil {
		t.Fatalf("seed cooling job with unavailable provider: %v", err)
	}
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/jobs/1/retry?force=true", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500 provider resolution failure", recorder.Code, recorder.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log WHERE action='重试失败' AND resource='证书任务' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read retry failure audit: %v", err)
	}
	if !strings.Contains(detail, "手动越过 CA 冷却") {
		t.Fatalf("audit detail=%q, want 手动越过 CA 冷却（状态迁移已发生）", detail)
	}
}

// 解析端点体积超限映射 413（其余同域写端点同口径），不得折成 400「格式非法」。
func TestParseCertificate_oversizeBodyMaps413(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/certificates/parse", h.ParseCertificate)

	recorder := httptest.NewRecorder()
	// 合法 JSON 形态 + 超限字符串值：解析器会一路读到 MaxBytesReader 上限，
	// 才能真正触发 *http.MaxBytesError（裸非法字节会在首字符先报语法错误）。
	body := `{"cert_pem":"` + strings.Repeat("x", 3<<20) + `"}`
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/certificates/parse", strings.NewReader(body)))
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s, want 413", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "请求体过大") {
		t.Fatalf("body=%s, want 请求体过大", recorder.Body.String())
	}
}

// CA 提供商更新的「守卫 + 提交」必须与规则/默认 CA 写共生互斥：
// UpdateCAProvider 未取 caddyOpMu 时可提交「启用 ACME 规则 × 禁用 provider」。
func TestUpdateCAProvider_takesCaddyOpMu(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/ca-providers/:id", h.UpdateCAProvider)

	h.caddyOpMu.Lock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/ca-providers/1", strings.NewReader(`{"name":"held"}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, req)
		done <- recorder
	}()

	select {
	case recorder := <-done:
		h.caddyOpMu.Unlock()
		t.Fatalf("status=%d body=%s, want 阻塞（端点必须取 caddyOpMu）", recorder.Code, recorder.Body.String())
	case <-time.After(150 * time.Millisecond):
	}
	h.caddyOpMu.Unlock()

	select {
	case recorder := <-done:
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200（放锁后正常完成）", recorder.Code, recorder.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("放锁后请求仍未完成")
	}
}

// 任务列表的到期派生必须与规则证书卡同源：expires_at 缺失（导入/旧备份/
// 集群快照遗留）时由 cert_pem 回退派生，否则同一张证书在任务页显示「-」、
// 在规则卡显示 valid/N 天。expires_at 本身仍按原契约下发 null。
func TestListCertJobs_derivesExpiryFromPEMWhenExpiresAtNull(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	certPEM, keyPEM := certPairWithLifetime(t, 90*24*time.Hour)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at)
		VALUES ('lb_pem_fallback','pem-fallback.example.test','issued',?,?,NULL)`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	router := gin.New()
	router.GET("/certificates/jobs", h.ListCertJobs)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/certificates/jobs", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			List []struct {
				RuleID            string `json:"rule_id"`
				DaysRemaining     int    `json:"days_remaining"`
				CertificateStatus string `json:"certificate_status"`
				ExpiresAt         any    `json:"expires_at"`
				NotAfter          string `json:"not_after"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var found bool
	for _, job := range payload.Data.List {
		if job.RuleID != "lb_pem_fallback" {
			continue
		}
		found = true
		if job.ExpiresAt != nil {
			t.Fatalf("expires_at=%v, want null（列值缺失契约不变）", job.ExpiresAt)
		}
		if job.CertificateStatus != "valid" {
			t.Fatalf("certificate_status=%q, want valid（由 PEM 回退派生）", job.CertificateStatus)
		}
		if job.DaysRemaining < 89 || job.DaysRemaining > 90 {
			t.Fatalf("days_remaining=%d, want ≈90（PEM NotAfter 派生）", job.DaysRemaining)
		}
		// 派生的到期时刻必须下发给 UI——「有效期/自动重签时间」两列只认该字段，
		// 否则后端算了天数、前端仍按 expires_at 渲染「-」。
		if job.NotAfter == "" {
			t.Fatal("not_after empty, want derived RFC3339 expiry")
		}
		if _, err := time.Parse(time.RFC3339, job.NotAfter); err != nil {
			t.Fatalf("not_after=%q, want RFC3339: %v", job.NotAfter, err)
		}
	}
	if !found {
		t.Fatalf("seeded job not in response: %s", recorder.Body.String())
	}
}

func certPairWithLifetime(t *testing.T, lifetime time.Duration) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		DNSNames:     []string{"pem-fallback.example.test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(lifetime),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM)
}
