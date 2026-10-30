package handlers

// ACME 规则改域路径的两处缺口：
//  1) 迁移把 cert_jobs 行改写为新域并**抹除**旧 PEM（cert_pem/key_pem/expires_at
//     置空、status=failed），但事务内 apply 用的是迁移**之前**的任务行——提交后
//     没有任何时刻让运行配置与已提交视图重新对齐；签发持续失败时规则长期停在
//     「旧配置 + 新域 + 无证书」。修复=提交成功后补一次强制重渲染（与 Resume
//     链同构）。
//  2) 旧材料不可恢复（补偿快照只在本请求内有效），面板却只回 200「规则已更新」。
//     修复=响应 data.warnings + 操作审计披露「旧证书已弃用，签发完成前 HTTPS
//     不可用」。
//
// 两个方向都钉住：改域必须补渲染且有披露；同域更新（回归形状）不得多打一次
// /load、不得出现该披露——否则每次保存都会多一次强制重载并误报证书弃用。

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

type ruleUpdateEnvelope struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Warnings []string `json:"warnings"`
	} `json:"data"`
}

// seedDomainChangeRule 播种一条启用 ACME 规则 + 已签发任务（真实自签证书，
// 使 IsACMECertIssued / selectCertificate 走「有可用材料」路径）。
func seedDomainChangeRule(t *testing.T, caddyID, domain string) {
	t.Helper()
	// 证书物化目录：默认 /app/certs 在开发机只读（渲染会 fail-closed），
	// 不重定向会让所有用例卡在「创建证书目录」而不是被测行为。
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	seedAuditRule(t, caddyID, strings.TrimPrefix(caddyID, "lb_"), domain, 8481, true, "acme_dns", true)
	seedAuditUpstream(t, caddyID)
	var providerID int
	if err := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&providerID); err != nil {
		t.Fatalf("read CA provider: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=?,ca_provider_id=? WHERE caddy_id=?", seedR52CertificateConfig(t), providerID, caddyID); err != nil {
		t.Fatalf("bind ACME references: %v", err)
	}
	now := time.Now()
	certPEM, keyPEM, err := generateTestCertForDomains(now.Add(-time.Hour), now.Add(60*24*time.Hour), domain)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,cert_pem,key_pem,expires_at)
		VALUES (?,?,'issued',?,?,?,datetime('now','+60 days'))`, caddyID, domain, providerID, certPEM, keyPEM); err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
}

func startDomainChangeCAQueue(t *testing.T) {
	t.Helper()
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	startCertQueueDispatchForTest(t)
	t.Cleanup(services.ResetCAQueueManagerForTest)
}

// Given 启用 ACME 规则带已签发任务（旧域 + 可用 PEM）。
// When PUT 改域名。
// Then 提交成功后必须补一次强制重渲染（/load 次数 > 事务内那一次），响应
// warnings 披露旧证书弃用，且任务行已迁移为新域并抹除材料。
func TestUpdateRule_domainChangeReappliesAndWarnsDeprecatedCert(t *testing.T) {
	const caddyID = "lb_b104_change"
	harness := newUpdateAuditRuleHandlers(t, caddyID, 0, false)
	seedDomainChangeRule(t, caddyID, "old-b104.example.test")
	startDomainChangeCAQueue(t)

	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(`{"domain":"new-b104.example.test"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var envelope ruleUpdateEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, recorder.Body.String())
	}
	needle := "旧证书已弃用"
	if !warningsContain(envelope.Data.Warnings, needle) {
		t.Fatalf("warnings=%v, want 含 %q（旧材料不可恢复必须在成功响应披露）", envelope.Data.Warnings, needle)
	}
	if !warningsContain(envelope.Data.Warnings, "签发完成前该规则 HTTPS 不可用") {
		t.Fatalf("warnings=%v, want 点名不可用窗口（否则用户以为改域无损）", envelope.Data.Warnings)
	}

	// 迁移事实：任务行改写为新域、终态 failed、材料清空。
	var jobDomain, jobStatus, certPEM, keyPEM string
	if err := db.DB.QueryRow(`SELECT domain,status,COALESCE(cert_pem,''),COALESCE(key_pem,'') FROM cert_jobs WHERE rule_id=? ORDER BY id DESC LIMIT 1`, caddyID).Scan(&jobDomain, &jobStatus, &certPEM, &keyPEM); err != nil {
		t.Fatalf("read cert job: %v", err)
	}
	// 迁移语义：行改写为新域、材料清空（状态由随后入队推进为 queued，
	// 故只断言「不再是 issued 且无材料」——材料抹除才是不可恢复的那一步）。
	if jobDomain != "new-b104.example.test" || jobStatus == "issued" || certPEM != "" || keyPEM != "" {
		t.Fatalf("cert job=(%q,%q,cert=%d,key=%d), want (新域,非 issued,空,空)", jobDomain, jobStatus, len(certPEM), len(keyPEM))
	}

	// 重渲染事实：事务内 apply 一次 + 提交后强制重渲染一次（==1 说明修复缺失，
	// 运行配置会停在迁移前的渲染结果）。
	if loads := harness.loadCalls.Load(); loads < 2 {
		t.Fatalf("/load 次数=%d, want ≥2（事务内 apply + 提交后强制重渲染）", loads)
	}
}

// Given 同一条带可用材料的 ACME 规则，域名不变。
// When PUT 改名称（同域回归形状）。
// Then 不得出现「旧证书已弃用」披露，且只有事务内那一次 /load——改域专属的
// 重渲染不得泄漏到普通更新（否则每次保存都多一次全局重载）。
func TestUpdateRule_sameDomainUpdateSkipsRerenderAndWarnings(t *testing.T) {
	const caddyID = "lb_b104_same"
	harness := newUpdateAuditRuleHandlers(t, caddyID, 0, false)
	seedDomainChangeRule(t, caddyID, "same-b104.example.test")
	startDomainChangeCAQueue(t)

	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(`{"domain":"same-b104.example.test","name":"renamed-b104"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var envelope ruleUpdateEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, recorder.Body.String())
	}
	if warningsContain(envelope.Data.Warnings, "旧证书已弃用") {
		t.Fatalf("warnings=%v, want 无弃用披露（同域更新不弃用任何材料）", envelope.Data.Warnings)
	}
	if loads := harness.loadCalls.Load(); loads != 1 {
		t.Fatalf("/load 次数=%d, want 1（同域更新只走事务内 apply，不得追加强制重渲染）", loads)
	}
	// 任务材料必须原样保留（同域更新不迁移、不清材料）。
	var status, certPEM string
	if err := db.DB.QueryRow(`SELECT status,COALESCE(cert_pem,'') FROM cert_jobs WHERE rule_id=?`, caddyID).Scan(&status, &certPEM); err != nil {
		t.Fatalf("read cert job: %v", err)
	}
	if status != "issued" || certPEM == "" {
		t.Fatalf("cert job=(%q,cert=%d), want (issued,非空)", status, len(certPEM))
	}
}
