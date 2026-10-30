package handlers

import (
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

// UpdateRule acme→manual 切换必须在事务内先把非终态 cert_jobs 收敛为
// 终态（镜像 DisableRule 的 'disabled' 终态）再执行主 UPDATE，并在提交后再取消
// 队列在途签发。此前切换只做 cancelRuleJobs（零 DB 状态写）：主 UPDATE 的
// NOT EXISTS 非终态守卫恒 409（用户无法完成切换的死锁），queued/waiting_ca 行
// 还会被 30s 补扫复活重签。

// seedACMEManualSwitchFixture 建一条启用中的 acme_dns 规则（含 DNS 配置/CA 提供
// 商绑定）+ 一条指定状态的 cert_jobs 行，返回任务行 id。
func seedACMEManualSwitchFixture(t *testing.T, caddyID, domain, jobStatus string) int {
	t.Helper()
	seedAuditRule(t, caddyID, "before", domain, 8080, true, "acme_dns", true)
	seedAuditUpstream(t, caddyID)
	var providerID int
	if err := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&providerID); err != nil {
		t.Fatalf("read CA provider: %v", err)
	}
	dnsResult, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('dns','dnspod','{"token":"x"}',1)`)
	if err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	dnsConfigID, err := dnsResult.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate config ID: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=?,ca_provider_id=? WHERE caddy_id=?", dnsConfigID, providerID, caddyID); err != nil {
		t.Fatalf("set rule ACME binding: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES (?,?,?,?)`, caddyID, domain, jobStatus, providerID); err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	var jobID int
	if err := db.DB.QueryRow("SELECT id FROM cert_jobs WHERE rule_id=?", caddyID).Scan(&jobID); err != nil {
		t.Fatalf("read seeded job ID: %v", err)
	}
	return jobID
}

func putUpdateRule(t *testing.T, h *updateAuditHarness, caddyID, body string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.PUT("/rules/:caddy_id", h.handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// 主形状：acme→manual 切换携带 queued 任务——必须 200，任务行**直接删除**
// （用户裁定：脱离 ACME 即删任务，取代 的「翻终态
// disabled」——30s 补扫对象已不存在），acme_config_id 清零。
func TestUpdateRule_acmeToManual_convergesNonTerminalCertJobs(t *testing.T) {
	// Given
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	harness := newUpdateAuditRuleHandlers(t, "lb_sw_manual", 0, false)
	jobID := seedACMEManualSwitchFixture(t, "lb_sw_manual", "sw.example.test", "queued")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	startCertQueueDispatchForTest(t)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	certPEM, keyPEM, err := generateTestCert("sw.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	// When：切换到手动证书
	response := putUpdateRule(t, harness, "lb_sw_manual", fmt.Sprintf(
		`{"name":"after","enable_tls":true,"tls_source":"manual","tls_cert":%q,"tls_key":%q}`, certPEM, keyPEM))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("switch status=%d body=%s, want 200（非终态任务必须在事务内收敛，不得 409 死锁）", response.Code, response.Body.String())
	}
	var remaining int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE id=?", jobID).Scan(&remaining); err != nil {
		t.Fatalf("count cert job: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("cert job %d still present（切换必须删除任务行，防 30s 补扫复活重签）", jobID)
	}
	var tlsSource string
	var acmeConfigID int64
	if err := db.DB.QueryRow("SELECT tls_source, acme_config_id FROM lb_rules WHERE caddy_id='lb_sw_manual'").Scan(&tlsSource, &acmeConfigID); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if tlsSource != "manual" || acmeConfigID != 0 {
		t.Fatalf("rule=(tls_source=%q, acme_config_id=%d), want manual/0", tlsSource, acmeConfigID)
	}
}

// 回归形状三（事务性）：Caddy 应用失败回滚时，事务内的任务翻转必须一并撤销
// ——行回到 queued、规则维持 acme 原状（若翻转被挪到事务外，失败更新会留下
// 已翻终态的任务行与旧规则不一致的漂移）。
func TestUpdateRule_acmeToManual_flipRollsBackWhenApplyFails(t *testing.T) {
	// Given：/load 首次必失败
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	harness := newUpdateAuditRuleHandlers(t, "lb_sw_rb", 1, false)
	jobID := seedACMEManualSwitchFixture(t, "lb_sw_rb", "rb.example.test", "queued")
	certPEM, keyPEM, err := generateTestCert("rb.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	// When
	response := putUpdateRule(t, harness, "lb_sw_rb", fmt.Sprintf(
		`{"name":"after","enable_tls":true,"tls_source":"manual","tls_cert":%q,"tls_key":%q}`, certPEM, keyPEM))

	// Then：更新被拒绝（/load 强制失败），翻转随事务回滚
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "Caddy 配置应用失败") {
		t.Fatalf("status=%d body=%s, want 400 Caddy 配置应用失败（必须经应用失败路径回滚）", response.Code, response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read cert job: %v", err)
	}
	if status != "queued" {
		t.Fatalf("cert job %d status=%q, want queued（翻转必须随事务回滚）", jobID, status)
	}
	var tlsSource string
	var acmeConfigID int64
	if err := db.DB.QueryRow("SELECT tls_source, acme_config_id FROM lb_rules WHERE caddy_id='lb_sw_rb'").Scan(&tlsSource, &acmeConfigID); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if tlsSource != "acme_dns" || acmeConfigID == 0 {
		t.Fatalf("rule=(tls_source=%q, acme_config_id=%d), want acme_dns/非零（规则必须维持原状）", tlsSource, acmeConfigID)
	}
}

// 回归形状一：acme→acme 更新（非切换）不受影响——非终态任务仍触发 409 守卫，
// 任务行保持 queued 不被翻转。
func TestUpdateRule_acmeToAcme_keepsConflictGuard(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_sw_keep", 0, false)
	jobID := seedACMEManualSwitchFixture(t, "lb_sw_keep", "keep.example.test", "queued")

	// When：仅改名称（TLS 维持 acme_dns）
	response := putUpdateRule(t, harness, "lb_sw_keep", `{"name":"after"}`)

	// Then：409 守卫保持，任务行原样
	if response.Code != http.StatusConflict {
		t.Fatalf("update status=%d body=%s, want 409（acme→acme 的非终态守卫必须保持）", response.Code, response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read cert job: %v", err)
	}
	if status != "queued" {
		t.Fatalf("cert job %d status=%q, want queued（非切换路径不得翻转任务行）", jobID, status)
	}
}

// 回归形状二：manual→acme 切换不受影响——无翻转逻辑，非终态行仍 409。
func TestUpdateRule_manualToAcme_keepsConflictGuard(t *testing.T) {
	// Given：manual 规则（遗留 queued 任务）切换到 acme_dns
	harness := newUpdateAuditRuleHandlers(t, "lb_sw_toacme", 0, false)
	seedAuditRule(t, "lb_sw_toacme", "before", "toacme.example.test", 8080, true, "manual", true)
	seedAuditUpstream(t, "lb_sw_toacme")
	var providerID int
	if err := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&providerID); err != nil {
		t.Fatalf("read CA provider: %v", err)
	}
	dnsResult, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('dns2','dnspod','{"token":"x"}',1)`)
	if err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	dnsConfigID, err := dnsResult.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate config ID: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET ca_provider_id=? WHERE caddy_id='lb_sw_toacme'", providerID); err != nil {
		t.Fatalf("set rule CA provider: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES ('lb_sw_toacme','toacme.example.test','queued',?)`, providerID); err != nil {
		t.Fatalf("seed certificate job: %v", err)
	}
	var jobID int
	if err := db.DB.QueryRow("SELECT id FROM cert_jobs WHERE rule_id='lb_sw_toacme'").Scan(&jobID); err != nil {
		t.Fatalf("read seeded job ID: %v", err)
	}

	// When
	response := putUpdateRule(t, harness, "lb_sw_toacme", fmt.Sprintf(
		`{"enable_tls":true,"tls_source":"acme_dns","acme_config_id":%d,"ca_provider_id":%d}`, dnsConfigID, providerID))

	// Then：非切换路径无翻转，409 守卫保持
	if response.Code != http.StatusConflict {
		t.Fatalf("update status=%d body=%s, want 409（manual→acme 不在收敛范围内，守卫必须保持）", response.Code, response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read cert job: %v", err)
	}
	if status != "queued" {
		t.Fatalf("cert job %d status=%q, want queued（manual→acme 不得翻转任务行）", jobID, status)
	}
}
