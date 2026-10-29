package handlers

import (
	"bytes"
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

//   在途守卫前置到 cert_jobs 删除之前——仅拦「执行中/CA 往返在途」状态
//   （非终态减去 queued/pending 未起动行）；queued/pending 维持
//   「删除+提交后取消+200」语义。
//   谓词统一为 NOT IN ('failed','disabled')——失败终态行保留失败史实。
// weight<1 保存侧响亮拒绝（Create/Update 同门，含禁用上游行），

// seedCertJobWithStatus 在给定规则下补一条指定状态/域名的 cert_jobs 行
// （cert_jobs UNIQUE(rule_id,domain)，同行多条任务须用不同域名）。
func seedCertJobWithStatus(t *testing.T, caddyID, domain, status string) {
	t.Helper()
	var providerID int
	if err := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&providerID); err != nil {
		t.Fatalf("read CA provider: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id) VALUES (?,?,?,?)`, caddyID, domain, status, providerID); err != nil {
		t.Fatalf("seed cert job %s/%s: %v", caddyID, status, err)
	}
}

func certJobStatusByDomain(t *testing.T, caddyID, domain string) string {
	t.Helper()
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE rule_id=? AND domain=?", caddyID, domain).Scan(&status); err != nil {
		t.Fatalf("read cert job %s/%s: %v", caddyID, domain, err)
	}
	return status
}

// 目标形状一：执行中（creating_order，CA 往返在途）任务 + 脱离 ACME 切换
// → 必须 409 且任务行/规则原样保留（修复前：先删行致守卫失效，200 放行）。
func TestUpdateRule_orphanACME_executingJobConflict409(t *testing.T) {
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	harness := newUpdateAuditRuleHandlers(t, "lb_a86_exec", 0, false)
	seedACMEManualSwitchFixture(t, "lb_a86_exec", "exec.example.test", "creating_order")
	certPEM, keyPEM, err := generateTestCert("exec.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	response := putUpdateRule(t, harness, "lb_a86_exec", fmt.Sprintf(
		`{"name":"after","enable_tls":true,"tls_source":"manual","tls_cert":%q,"tls_key":%q}`, certPEM, keyPEM))

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（CA 往返在途任务必须前置拦截脱离 ACME 的切换）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "证书申请中") {
		t.Fatalf("409 文案应沿用「证书申请中」, body=%s", response.Body.String())
	}
	if status := certJobStatusByDomain(t, "lb_a86_exec", "exec.example.test"); status != "creating_order" {
		t.Fatalf("cert job status=%q, want creating_order（409 早退不得删行/改行）", status)
	}
	// 阻断型 409 必须留痕：运维要能从审计回答「谁在何时尝试、被什么挡住」。
	var blockedAudits int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log
		WHERE action='更新失败' AND resource='负载规则' AND detail LIKE '%lb_a86_exec%' AND detail LIKE '%证书申请中%'`).Scan(&blockedAudits); err != nil {
		t.Fatalf("read blocked conflict audit: %v", err)
	}
	if blockedAudits != 1 {
		t.Fatalf("在途签发阻断的 409 审计条数=%d, want 1（细节：更新失败/负载规则）", blockedAudits)
	}
	var tlsSource string
	if err := db.DB.QueryRow("SELECT tls_source FROM lb_rules WHERE caddy_id='lb_a86_exec'").Scan(&tlsSource); err != nil || tlsSource != "acme_dns" {
		t.Fatalf("rule tls_source=%q err=%v, want acme_dns（事务已回滚）", tlsSource, err)
	}
}

// 目标形状二：waiting_ca（CA 冷却等待，裁定点名同属在途段）同样 409。
func TestUpdateRule_orphanACME_waitingCAJobConflict409(t *testing.T) {
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	harness := newUpdateAuditRuleHandlers(t, "lb_a86_waitca", 0, false)
	seedACMEManualSwitchFixture(t, "lb_a86_waitca", "waitca.example.test", "waiting_ca")

	response := putUpdateRule(t, harness, "lb_a86_waitca", `{"name":"after","enable_tls":false}`)

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（waiting_ca 在途任务必须前置拦截禁用 TLS）", response.Code, response.Body.String())
	}
	if status := certJobStatusByDomain(t, "lb_a86_waitca", "waitca.example.test"); status != "waiting_ca" {
		t.Fatalf("cert job status=%q, want waiting_ca（409 早退不得删行/改行）", status)
	}
}

// 回归形状：pending（未起动，可复活形态）维持 200+删除。
// queued 形态由既有 TestUpdateRule_acmeToManual_convergesNonTerminalCertJobs 钉住。
func TestUpdateRule_orphanACME_pendingJobStillConverges200(t *testing.T) {
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	harness := newUpdateAuditRuleHandlers(t, "lb_a86_pend", 0, false)
	seedACMEManualSwitchFixture(t, "lb_a86_pend", "pend.example.test", "pending")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	certPEM, keyPEM, err := generateTestCert("pend.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	response := putUpdateRule(t, harness, "lb_a86_pend", fmt.Sprintf(
		`{"name":"after","enable_tls":true,"tls_source":"manual","tls_cert":%q,"tls_key":%q}`, certPEM, keyPEM))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（pending 未起动行维持历史删除语义）", response.Code, response.Body.String())
	}
	if n := countRuleCertJobs(t, "lb_a86_pend"); n != 0 {
		t.Fatalf("cert jobs remaining=%d, want 0（pending 行随脱离 ACME 删除）", n)
	}
}

// 目标形状：PUT enabled=false（UpdateRule 禁用入口）的 cert_jobs 谓词必须与
// /disable 同口径——failed 终态行保留（修复前 UpdateRule 用 status<>'disabled'
// 把 failed 一并改写为 disabled，抹掉失败史实）。
func TestUpdateRule_disableViaUpdate_preservesFailedCertJob(t *testing.T) {
	harness := newUpdateAuditRuleHandlers(t, "lb_a86_disupd", 0, false)
	seedACMEManualSwitchFixture(t, "lb_a86_disupd", "failed.example.test", "failed")
	seedCertJobWithStatus(t, "lb_a86_disupd", "queued.example.test", "queued")
	seedCertJobWithStatus(t, "lb_a86_disupd", "issued.example.test", "issued")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)

	response := putUpdateRule(t, harness, "lb_a86_disupd", `{"name":"after","enabled":false}`)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（禁用更新应成功）", response.Code, response.Body.String())
	}
	if status := certJobStatusByDomain(t, "lb_a86_disupd", "failed.example.test"); status != "failed" {
		t.Fatalf("failed job status=%q, want failed（终态失败史实不得改写为 disabled——与 /disable 同口径）", status)
	}
	if status := certJobStatusByDomain(t, "lb_a86_disupd", "queued.example.test"); status != "disabled" {
		t.Fatalf("queued job status=%q, want disabled（非终态任务须暂停）", status)
	}
	if status := certJobStatusByDomain(t, "lb_a86_disupd", "issued.example.test"); status != "disabled" {
		t.Fatalf("issued job status=%q, want disabled（禁用后任务视图不得仍显示 issued）", status)
	}
}

// 基线钉（豁免 RED）：/disable 入口既有谓词 NOT IN ('failed','disabled') 的
// 行为钉住——failed 保留、queued/processing/issued 置 disabled。与
// TestUpdateRule_disableViaUpdate_preservesFailedCertJob 构成两入口同口径对照。
func TestDisableRule_certJobPredicateKeepsFailed(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedACMEManualSwitchFixture(t, "lb_a86_dis", "failed2.example.test", "failed")
	seedCertJobWithStatus(t, "lb_a86_dis", "queued2.example.test", "queued")
	seedCertJobWithStatus(t, "lb_a86_dis", "processing2.example.test", "processing")
	seedCertJobWithStatus(t, "lb_a86_dis", "issued2.example.test", "issued")
	router := gin.New()
	router.POST("/rules/:caddy_id/disable", handler.DisableRule)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_a86_dis/disable", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	expect := map[string]string{
		"failed2.example.test":     "failed",
		"queued2.example.test":     "disabled",
		"processing2.example.test": "disabled",
		"issued2.example.test":     "disabled",
	}
	for domain, want := range expect {
		if got := certJobStatusByDomain(t, "lb_a86_dis", domain); got != want {
			t.Fatalf("job %s status=%q, want %q", domain, got, want)
		}
	}
}

// weight<1 保存侧响亮拒绝

func postCreateRule(t *testing.T, handler *Handlers, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/rules", handler.CreateRule)
	raw, _ := json.Marshal(body)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	return recorder
}

func createRulePayload(name string, upstreams []map[string]any) map[string]any {
	return map[string]any{
		"name": name, "protocol": "http", "domain": name + ".example.test",
		"listen_port": 443, "strategy": "weighted_round_robin",
		"enable_tls": false, "tls_source": "manual", "enabled": false,
		"health_check_interval": 10, "health_check_timeout": 2,
		"health_check_unhealthy_threshold": 3, "health_check_healthy_threshold": 2,
		"upstreams": upstreams,
	}
}

// 目标形状：创建载荷 weight=0 → 400 点名（修复前 0→1 静默归一放行 201）。
func TestCreateRule_rejectsZeroUpstreamWeight(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	response := postCreateRule(t, handler, createRulePayload("zero-w", []map[string]any{
		{"host": "10.0.0.1", "port": 8080, "weight": 0, "enabled": true},
	}))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("weight=0 status=%d body=%s, want 400（0→1 静默归一已废除）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "权重必须为不小于 1 的整数") {
		t.Fatalf("错误文案应点名权重下限, body=%s", response.Body.String())
	}
}

// 畸形形状：禁用上游行同样拒绝 weight=0（与导入侧整行门同口径——禁用行的
// 权重字段无业务意义但不得落 0；UI 已在载荷边界为禁用行送 1）。
func TestCreateRule_rejectsZeroWeightForDisabledUpstream(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	response := postCreateRule(t, handler, createRulePayload("zero-w-disabled", []map[string]any{
		{"host": "10.0.0.1", "port": 8080, "weight": 1, "enabled": true},
		{"host": "10.0.0.2", "port": 8080, "weight": 0, "enabled": false},
	}))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("disabled upstream weight=0 status=%d body=%s, want 400（禁用行同门，与导入侧一致）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "权重必须为不小于 1 的整数") {
		t.Fatalf("错误文案应点名权重下限, body=%s", response.Body.String())
	}
}

// 目标形状：更新路径同门——UpdateRule 的 0→1 归一一并废除。
func TestUpdateRule_rejectsZeroUpstreamWeight(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	seedAuditRule(t, "lb_a86_zerow", "before", "zerow.example.test", 8080, true, "manual", false)
	seedAuditUpstream(t, "lb_a86_zerow")
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_a86_zerow", strings.NewReader(
		`{"name":"after","upstreams":[{"host":"10.0.0.9","port":8080,"weight":0,"enabled":true}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("update weight=0 status=%d body=%s, want 400（更新路径同门拒绝）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "权重必须为不小于 1 的整数") {
		t.Fatalf("错误文案应点名权重下限, body=%s", response.Body.String())
	}
}

// 回归形状：weight=1 合法载荷 201 放行（新门不误伤下边界合法值）。
func TestCreateRule_acceptsWeightOneUpstream(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	response := postCreateRule(t, handler, createRulePayload("weight-one", []map[string]any{
		{"host": "10.0.0.1", "port": 8080, "weight": 1, "enabled": true},
		{"host": "10.0.0.2", "port": 8080, "weight": 1, "enabled": false},
	}))

	if response.Code != http.StatusCreated {
		t.Fatalf("weight=1 status=%d body=%s, want 201（下边界合法值放行）", response.Code, response.Body.String())
	}
}

// 回归形状（省略≠显式 0，与导入侧缺键→DEFAULT 1 同口径）：载荷省略 weight
// 键 → 201 且落库默认 1——MCP schema 中 weight 为可选键（required 仅
// host/port），省略是契约内合法形态，不得被新门误伤。
func TestCreateRule_omittedWeightDefaultsToOne(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	response := postCreateRule(t, handler, createRulePayload("omit-w", []map[string]any{
		{"host": "10.0.0.1", "port": 8080, "enabled": true},
		{"host": "10.0.0.2", "port": 8080, "enabled": false},
	}))

	if response.Code != http.StatusCreated {
		t.Fatalf("omitted weight status=%d body=%s, want 201（省略落默认 1）", response.Code, response.Body.String())
	}
	rows, err := db.DB.Query(`SELECT weight FROM upstreams u JOIN lb_rules r ON r.caddy_id=u.rule_id WHERE r.name='omit-w' ORDER BY u.host`)
	if err != nil {
		t.Fatalf("query weights: %v", err)
	}
	defer rows.Close()
	var weights []int
	for rows.Next() {
		var w int
		if err := rows.Scan(&w); err != nil {
			t.Fatalf("scan weight: %v", err)
		}
		weights = append(weights, w)
	}
	if len(weights) != 2 || weights[0] != 1 || weights[1] != 1 {
		t.Fatalf("weights=%v, want [1 1]（省略键默认 1 落库）", weights)
	}
}

// 启用/禁用主 UPDATE 必须校验 RowsAffected：放锁窗口（预校验/快照期间）内
// 规则被并发删除时，0 行更新若被当成成功，会产出与真实状态相反的审计并渲染
// 一条不存在的规则。RAISE(IGNORE) 触发器精确制造「行存在但更新 0 行」形态
// （先删行会让预校验提前 404，测不到目标分支）。
func TestEnableAndDisableRule_rejectWhenRowVanishesBeforeUpdate(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	router.POST("/rules/:caddy_id/disable", handler.DisableRule)
	seedTCPStoredRule(t, "lb_vanish", "vanish", 18641, false, "weighted_round_robin", false)
	if _, err := db.DB.Exec(`CREATE TRIGGER ignore_lb_vanish_update BEFORE UPDATE ON lb_rules WHEN OLD.caddy_id = 'lb_vanish' BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	enableResponse := httptest.NewRecorder()
	router.ServeHTTP(enableResponse, httptest.NewRequest(http.MethodPost, "/rules/lb_vanish/enable", nil))
	if enableResponse.Code != http.StatusConflict || !strings.Contains(enableResponse.Body.String(), "规则已被删除或并发变更") {
		t.Fatalf("enable status=%d body=%s, want 409 规则已被删除或并发变更", enableResponse.Code, enableResponse.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow(`SELECT enabled FROM lb_rules WHERE caddy_id='lb_vanish'`).Scan(&enabled); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if enabled {
		t.Fatal("0 行更新不得落成启用态")
	}

	// 禁用方向：先置启用态（绕过触发器）。
	if _, err := db.DB.Exec(`DROP TRIGGER ignore_lb_vanish_update`); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE lb_rules SET enabled=1 WHERE caddy_id='lb_vanish'`); err != nil {
		t.Fatalf("enable seed: %v", err)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER ignore_lb_vanish_update BEFORE UPDATE ON lb_rules WHEN OLD.caddy_id = 'lb_vanish' BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatalf("recreate trigger: %v", err)
	}
	disableResponse := httptest.NewRecorder()
	router.ServeHTTP(disableResponse, httptest.NewRequest(http.MethodPost, "/rules/lb_vanish/disable", nil))
	if disableResponse.Code != http.StatusConflict || !strings.Contains(disableResponse.Body.String(), "规则已被删除或并发变更") {
		t.Fatalf("disable status=%d body=%s, want 409 规则已被删除或并发变更", disableResponse.Code, disableResponse.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT enabled FROM lb_rules WHERE caddy_id='lb_vanish'`).Scan(&enabled); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if !enabled {
		t.Fatal("0 行更新不得落成禁用态")
	}
}

// downloaded = 证书已签发、仅部署退避重试（无 worker 在跑、材料已在库）：脱离
// ACME 的切换不得以「证书申请中」409 拦下——保存路径的守卫
// （ruleEditBlockingCertJobStatuses）早已把该状态列入放行集，两条路径对同一
// 状态的口径必须一致；waiting_ca 的 409 由上面用例保留。
func TestUpdateRule_orphanACME_downloadedJobConverges200(t *testing.T) {
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	harness := newUpdateAuditRuleHandlers(t, "lb_a86_down", 0, false)
	seedACMEManualSwitchFixture(t, "lb_a86_down", "down.example.test", "downloaded")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	certPEM, keyPEM, err := generateTestCert("down.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}

	response := putUpdateRule(t, harness, "lb_a86_down", fmt.Sprintf(
		`{"name":"after","enable_tls":true,"tls_source":"manual","tls_cert":%q,"tls_key":%q}`, certPEM, keyPEM))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（downloaded 无 worker 在跑，不得判为证书申请中）", response.Code, response.Body.String())
	}
	if n := countRuleCertJobs(t, "lb_a86_down"); n != 0 {
		t.Fatalf("cert jobs remaining=%d, want 0（脱离 ACME 后删除）", n)
	}
}
