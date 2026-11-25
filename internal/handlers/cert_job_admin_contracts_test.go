package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 证书任务重试/删除是 AuditPolicyExplicit 路由（中间件不做自动审计）：
// 失败/被拒出口必须留下可追溯的「失败」行，detail 只放固定归因。
func TestRetryCertJobNotFoundRecordsFailureAudit(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/999/retry", nil))

	// Then：404 + 一条失败审计（不得只有成功出口有审计）
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", response.Code, response.Body.String())
	}
	var action, detail string
	if err := db.AuditDB.QueryRow("SELECT action, detail FROM audit_log WHERE resource='证书任务' ORDER BY id DESC LIMIT 1").Scan(&action, &detail); err != nil {
		t.Fatalf("read retry failure audit: %v", err)
	}
	if action != "重试失败" {
		t.Fatalf("audit action=%q, want 重试失败", action)
	}
	if !strings.Contains(detail, "任务不存在") || !strings.Contains(detail, "999") {
		t.Fatalf("audit detail=%q, want 任务不存在 + 任务号", detail)
	}
}

// 重试端点的失败归因与删除端点同档：只有 sql.ErrNoRows 才算「任务不存在」，
// 其余读故障（DB 忙/连接中断/表不可读）必须记查询失败——把瞬时故障呈现为
// 「任务不存在」会把排障方向带偏（同函数族 DeleteCertJob 已按此分档）。
func TestRetryCertJobQueryFailureRecordsDistinctAudit(t *testing.T) {
	// Given：cert_jobs 读取面不可用（非 ErrNoRows 的读故障）
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	if _, err := db.DB.Exec(`ALTER TABLE cert_jobs RENAME TO cert_jobs_unreadable`); err != nil {
		t.Fatalf("simulate read failure: %v", err)
	}

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/1/retry", nil))

	// Then：500 + 归因「查询失败」（不得复用「任务不存在」）
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	var action, detail string
	if err := db.AuditDB.QueryRow("SELECT action, detail FROM audit_log WHERE resource='证书任务' ORDER BY id DESC LIMIT 1").Scan(&action, &detail); err != nil {
		t.Fatalf("read retry failure audit: %v", err)
	}
	if action != "重试失败" {
		t.Fatalf("audit action=%q, want 重试失败", action)
	}
	if !strings.Contains(detail, "查询失败") {
		t.Fatalf("audit detail=%q, want 查询失败（读故障不得归因为任务不存在）", detail)
	}
	if strings.Contains(detail, "任务不存在") {
		t.Fatalf("audit detail=%q 把读故障归因为任务不存在", detail)
	}
}

func TestDeleteCertJobGuardedRecordsFailureAudit(t *testing.T) {
	// Given：规则仍启用 + 任务 issued（删除受 409 守卫）
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_del_guard", "del-guard.example.com")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,updated_at)
		VALUES ('lb_del_guard','del-guard.example.com','issued','CERT-PEM','KEY-PEM',datetime('now'))`); err != nil {
		t.Fatalf("seed issued job: %v", err)
	}
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))

	// Then：409 + 失败审计（固定归因，不回显内部细节）
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	var action, detail string
	if err := db.AuditDB.QueryRow("SELECT action, detail FROM audit_log WHERE resource='证书任务' ORDER BY id DESC LIMIT 1").Scan(&action, &detail); err != nil {
		t.Fatalf("read delete failure audit: %v", err)
	}
	if action != "删除失败" || !strings.Contains(detail, "规则仍启用") {
		t.Fatalf("audit action=%q detail=%q, want 删除失败 / 规则仍启用", action, detail)
	}
}

// 重试冷却门禁与文案必须同源：门禁说冷却中时文案不得显示「0s」，失败文案
// 的剩余秒由 services.CertJobRetryRemaining 按 updated_at 扣减后派生（完整
// 窗口分钟数会在冷却过半后说谎；硬编码会随策略漂移）。文案形态是消息键 +
// 模板参数，中文母本由目录对账（apimsg.Tf(key, args...)）。
func TestCertJobRetryCooldownGateAndMessageSharePolicy(t *testing.T) {
	now := time.Now()

	// 不足 1 秒的剩余必须向上取整为 1s（0s 会引导一次必然 429 的重试）。
	if key, args := certJobCAcooldownKey(now.Add(300*time.Millisecond), now); key != "cert.caCooldownActive" {
		t.Fatalf("messageKey=%q, want cert.caCooldownActive", key)
	} else if got := apimsg.Tf(key, args...); !strings.Contains(got, "剩余约 1s") || strings.Contains(got, "剩余约 0s") {
		t.Fatalf("message=%q, want 剩余约 1s（<1s 向上取整）", got)
	}

	// failed 窗口取自 services 单源：窗口内拦截且文案剩余秒与同一判据一致
	//（窗口剩 1s 时不得报完整窗口分钟数）。
	window, retryable := services.CertJobRetryCooldown("failed")
	if !retryable {
		t.Fatal("failed 应可重试")
	}
	updated := sql.NullTime{Time: now.Add(-window + time.Second), Valid: true}
	created := sql.NullTime{Time: now.Add(-window + time.Second), Valid: true}
	wantSeconds, _ := services.CertJobRetryRemainingSeconds("failed", updated, created, sql.NullTime{}, now)
	blocked, code, messageKey, messageArgs := certJobRetryBlocked("failed", updated, created, now)
	if !blocked || code != http.StatusTooManyRequests {
		t.Fatalf("blocked=%v code=%d, want true/429（窗口内）", blocked, code)
	}
	// 键 + 参数即判据：参数是「此刻剩余秒」，模板由 1 号槽承接。
	if messageKey != "cert.jobRetryCooldownRemaining" || len(messageArgs) != 1 {
		t.Fatalf("messageKey=%q args=%v, want cert.jobRetryCooldownRemaining + 1 参", messageKey, messageArgs)
	}
	message := apimsg.Tf(messageKey, messageArgs...)
	if !strings.Contains(message, strconv.FormatInt(wantSeconds, 10)+" 秒") {
		t.Fatalf("message=%q, want 与剩余秒判据一致的 %d 秒", message, wantSeconds)
	}
	if strings.Contains(message, strconv.Itoa(int(window/time.Minute))+" 分钟") {
		t.Fatalf("message=%q, 冷却剩 %d 秒时不得报完整窗口分钟数", message, wantSeconds)
	}

	// 窗口外放行（同一来源判定）。
	past := sql.NullTime{Time: now.Add(-window - time.Second), Valid: true}
	if blocked, _, _, _ := certJobRetryBlocked("failed", past, past, now); blocked {
		t.Fatal("窗口已过仍被判冷却中")
	}
}

// /certificates 分页：page/page_size 生效且 total 报告匹配总数（此前无 LIMIT，
// 大部署每请求全表扫描+全量序列化）。
func TestListCertificatesPaginatesAndReportsTotal(t *testing.T) {
	// Given：三个任务
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES
		('lb_page_a','a.example.com','issued'),
		('lb_page_b','b.example.com','issued'),
		('lb_page_c','c.example.com','failed')`); err != nil {
		t.Fatalf("seed cert jobs: %v", err)
	}
	router := gin.New()
	router.GET("/certificates", h.ListCertificates)

	// When：第二页、每页两条
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/certificates?page=2&page_size=2", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			Certificates []map[string]any `json:"certificates"`
			Total        int              `json:"total"`
			Page         int              `json:"page"`
			PageSize     int              `json:"page_size"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.Data.Certificates) != 1 || body.Data.Total != 3 || body.Data.Page != 2 || body.Data.PageSize != 2 {
		t.Fatalf("certs=%d total=%d page=%d page_size=%d, want 1/3/2/2",
			len(body.Data.Certificates), body.Data.Total, body.Data.Page, body.Data.PageSize)
	}
	if got := body.Data.Certificates[0]["rule_id"]; got != "lb_page_c" {
		t.Fatalf("第二页首个 rule_id=%v, want lb_page_c（按 rule_id 排序）", got)
	}

	// 非法分页参数显式 400（静默回落会让调用方拼写错误无信号）。
	bad := httptest.NewRecorder()
	router.ServeHTTP(bad, httptest.NewRequest(http.MethodGet, "/certificates?page_size=abc", nil))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 for invalid page_size", bad.Code)
	}
}

// 批量签发在全局 caddyOpMu 内逐目标查询+入队：目标数必须有上限，超限在取锁
// 之前以 400 拒绝（否则数百条规则时全部规则写/Caddy 应用随批量规模排队）。
func TestIssueCertificateBatchRejectsOversizedTargetSet(t *testing.T) {
	// Given：超过单次上限的启用 ACME 规则
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatalf("begin seed tx: %v", err)
	}
	for i := range maxBatchIssueTargets + 1 {
		id := "lb_cap_" + strconv.Itoa(i)
		if _, err := tx.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
			VALUES (?,?,?, 'http', 18080, 1, 1, 'acme_dns')`, id, id, id+".example.com"); err != nil {
			_ = tx.Rollback()
			t.Fatalf("seed rule %d: %v", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit seed: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then：400 且点名上限（不得静默截断）
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), strconv.Itoa(maxBatchIssueTargets)) {
		t.Fatalf("body=%s, want 点名单次上限 %d", response.Body.String(), maxBatchIssueTargets)
	}
}

// 批量签发「部分成功」响应不得回显内部错误原文（SQL/扫描细节）：失败明细只
// 回固定分类文案，原文只进运行日志——与全失败 500 出口的脱敏口径一致。
func TestIssueCertificateBatchPartialSuccessHidesInternalError(t *testing.T) {
	// Given：目标 A 的任务行时间列被带外写成非法串（Scan 失败），目标 B 正常
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_hide_a", "hide-a.example.com")
	seedIssueRule(t, "lb_hide_b", "hide-b.example.com")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,updated_at,created_at)
		VALUES ('lb_hide_a','hide-a.example.com','failed','not-a-time',datetime('now','-10 minutes'),datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed corrupt job row: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then：部分成功 200，失败明细为固定分类文案，内部细节不外泄
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（另一目标应入队成功）", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "查询签发任务失败") {
		t.Fatalf("body=%s, want 固定分类文案", body)
	}
	assertBodyHides(t, body, "sql:", "not-a-time", "ca_available_after", "Scan")
}
