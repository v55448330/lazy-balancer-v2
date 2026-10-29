package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestGetCurrentCertJobs_rejects_more_than_200_rule_ids(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	ruleIDs := make([]string, 201)
	for index := range ruleIDs {
		ruleIDs[index] = "lb_" + strconv.Itoa(index)
	}
	payload, err := json.Marshal(map[string][]string{"rule_ids": ruleIDs})
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.POST("/jobs/current", handler.GetCurrentCertJobs)
	request := httptest.NewRequest(http.MethodPost, "/jobs/current", strings.NewReader(string(payload)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "invalid_request") || !strings.Contains(response.Body.String(), "200") {
		t.Fatalf("body=%q, want Chinese invalid_request limit message", response.Body.String())
	}
}

func TestCertJobRetryBlocked_rejects_disabled_job_without_timestamp(t *testing.T) {
	blocked, statusCode, _ := certJobRetryBlocked("disabled", sql.NullTime{}, sql.NullTime{}, time.Now())
	if !blocked {
		t.Fatal("disabled job retry was allowed")
	}
	// 永久条件用 409，不得用「稍后可重试」的 429。
	if statusCode != http.StatusConflict {
		t.Fatalf("status=%d, want 409（已退役任务永不可重试）", statusCode)
	}
}

// downloaded 态（证书已签发下载、停在部署退避窗口）
// 的重试拦截文案不得复用在途签发口径「任务正在执行中」——签发已结束，
// 用户被误导为签发流程卡住。单列部署窗口口径。
func TestCertJobRetryBlocked_downloaded_job_uses_deployment_message(t *testing.T) {
	// Given：downloaded 任务刚进入部署退避窗口（1 分钟前更新）
	now := time.Now()

	// When
	blocked, _, message := certJobRetryBlocked("downloaded", sql.NullTime{Time: now.Add(-time.Minute), Valid: true}, sql.NullTime{Time: now.Add(-time.Hour), Valid: true}, now)

	// Then：仍被拦截（部署窗口守卫不变），但文案单列
	if !blocked {
		t.Fatal("fresh downloaded job retry was allowed")
	}
	if message == "任务正在执行中，请稍后重试" {
		t.Fatalf("downloaded message=%q, 复用了在途签发文案", message)
	}
	if !strings.Contains(message, "部署") {
		t.Fatalf("downloaded message=%q, want deployment-window wording", message)
	}
}

func TestListCertJobs_exposesBackendRetryCooldowns(t *testing.T) {
	// Given：各冷却档位的真实任务行，含「冷却已到期」的历史行（updated_at 早于
	// 冷却窗口）——静态时长下发会让已过期任务永久禁用重试。
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,updated_at) VALUES
		(101,'lb_cooldown','queued.example','queued',datetime('now')),
		(102,'lb_cooldown','failed.example','failed',datetime('now')),
		(103,'lb_cooldown','disabled.example','disabled',datetime('now')),
		(104,'lb_cooldown','issued.example','issued',datetime('now')),
		(105,'lb_cooldown','waiting.example','waiting_ca',datetime('now')),
		(106,'lb_cooldown','downloaded.example','downloaded',datetime('now')),
		(107,'lb_cooldown','waiting-open.example','waiting_ca',datetime('now')),
		(108,'lb_cooldown','failed-old.example','failed',datetime('now','-6 minutes')),
		(109,'lb_cooldown','queued-old.example','queued',datetime('now','-16 minutes'))`); err != nil {
		t.Fatalf("seed cooldown jobs: %v", err)
	}
	// CA 限流退避（waiting_ca ∧ ca_available_after 未到期）比通用冷却晚得多：
	// 列表下发值不并入它，就会出现「字段说现在可重试、服务端回 429」的分叉。
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET ca_available_after=datetime('now','+2 hours') WHERE id=105`); err != nil {
		t.Fatalf("seed CA cooldown window: %v", err)
	}
	router := gin.New()
	router.GET("/jobs", h.ListCertJobs)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/jobs?page=1&page_size=50", nil))

	// Then：秒值由后端唯一下发；disabled 用 null 与零冷却区分。
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			List []struct {
				ID                   int64  `json:"id"`
				Status               string `json:"status"`
				RetryCooldownSeconds *int64 `json:"retry_cooldown_seconds"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	want := map[int64]int64{101: 900, 102: 300, 104: 0, 106: 120, 107: 0, 108: 0, 109: 0}
	// 造行用 datetime('now')（秒级截断），handler 取 now 的亚秒余量会被向上
	// 取整吸收——恰好跨秒时下发值比完整窗口少 1 秒。断言按区间（0 除外）：
	// 等值断言在慢机/-race 下会偶发假红。
	assertCooldown := func(id int64, got *int64, want int64) {
		t.Helper()
		if got == nil {
			t.Fatalf("id=%d cooldown=null, want %d", id, want)
		}
		if want == 0 {
			if *got != 0 {
				t.Fatalf("id=%d cooldown=%d, want 0（已过期/无冷却必须精确为零）", id, *got)
			}
			return
		}
		if *got > want || *got < want-1 {
			t.Fatalf("id=%d cooldown=%d, want %d（容许 1 秒秒级截断误差）", id, *got, want)
		}
	}
	seen := make(map[int64]bool)
	for _, job := range payload.Data.List {
		seen[job.ID] = true
		switch job.ID {
		case 103: // disabled 用 null 与零冷却区分。
			if job.RetryCooldownSeconds != nil {
				t.Fatalf("disabled cooldown=%d, want null", *job.RetryCooldownSeconds)
			}
		case 105: // waiting_ca 处于 CA 退避窗口：下发剩余秒数而非通用冷却的 0。
			if job.RetryCooldownSeconds == nil || *job.RetryCooldownSeconds < 7100 || *job.RetryCooldownSeconds > 7200 {
				t.Fatalf("waiting_ca with CA window cooldown=%v, want ~7200", job.RetryCooldownSeconds)
			}
		default:
			assertCooldown(job.ID, job.RetryCooldownSeconds, want[job.ID])
		}
	}
	for id := range want {
		if !seen[id] {
			t.Fatalf("cert job %d missing from list response", id)
		}
	}
	if !seen[103] {
		t.Fatal("disabled job missing from list response")
	}
}

func TestRetryCertJob_rejects_inactive_rule_atomically(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_retired','retired','http','retired.example.test',8080,0,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,updated_at) VALUES ('lb_retired','retired.example.test','failed',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed retired job: %v", err)
	}
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/1/retry", nil))
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=1").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("status=%q, want failed", status)
	}
}

func TestRetryCertJob_concurrent_status_change_returns_refresh_message(t *testing.T) {
	// worker 在 SELECT 与 UPDATE 之间流转状态时，409 文案应区分归因。
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_race','race','http','race.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (id,rule_id,domain,status,updated_at) VALUES (7,'lb_race','race.example.test','failed',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed race job: %v", err)
	}
	oldHook := retryCertJobPreEnqueueHook
	retryCertJobPreEnqueueHook = func(jobID int) {
		if _, err := db.DB.Exec("UPDATE cert_jobs SET status='creating_account', updated_at=datetime('now') WHERE id=?", jobID); err != nil {
			t.Errorf("simulate worker transition: %v", err)
		}
	}
	t.Cleanup(func() { retryCertJobPreEnqueueHook = oldHook })
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/7/retry", nil))
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "任务状态已变更，请刷新后重试") {
		t.Fatalf("body=%s, want 并发状态变更文案", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "规则已禁用") {
		t.Fatalf("body=%s, 不应误指规则已禁用", response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=7").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "creating_account" {
		t.Fatalf("status=%q, want creating_account（worker 流转结果不应被 retry 覆盖）", status)
	}
}

// 手动重试成功路径必须唤醒 cert-waiting-ca（默认调度关闭——
// waiting_ca 重排唯一属主）。此前 retry 直入队无唤醒，任务滞留至多 6h
// （cert-reconcile 间隔）才被周期路径拾起。
func TestRetryCertJob_wakesCertWaitingCA(t *testing.T) {
	initTaskEngineForTest(t)
	h := newBackupTestHandlers(t)
	te := services.TaskEngine()
	te.StopLoop("cert-waiting-ca") // 前置态：默认关闭（Given）

	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_wake','wake','http','wake.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,updated_at) VALUES ('lb_wake','wake.example.test','failed',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed rule and job: %v", err)
	}
	if te.IsRunning("cert-waiting-ca") {
		t.Fatal("前置态：cert-waiting-ca 应为关闭")
	}

	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/1/retry", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	// Then：成功入队即唤醒（StartLoop——调度开）
	if !te.IsRunning("cert-waiting-ca") {
		t.Fatal("retry 200 后应唤醒 cert-waiting-ca（StartLoop）——唤醒缺口未修")
	}
}

func TestRetryCertJob_accepts_www_first_rule_domain(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	// cert_jobs.domain 存排序规范形式，lb_rules.domain 保留用户 www 在前的输入顺序
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_www_first','www-first','http','www.example.test,example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,updated_at) VALUES ('lb_www_first','example.test,www.example.test','failed',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed www-first rule and job: %v", err)
	}
	block := make(chan struct{})
	acmeMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { <-block }))
	t.Cleanup(func() { close(block); services.GetCAQueueManager().PauseAndDrain(); acmeMock.Close() })
	if _, err := db.DB.Exec("UPDATE ca_providers SET provider='letsencrypt', directory_url=? WHERE enabled=1", acmeMock.URL); err != nil {
		t.Fatalf("redirect ACME directory: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET acme_email='acme@example.test' WHERE id=1"); err != nil {
		t.Fatalf("set ACME email: %v", err)
	}
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/1/retry", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 (www-first rule domain must match sorted job domain)", response.Code, response.Body.String())
	}
}

func TestDeleteCertJob_blocks_pending_chain_job_when_rule_still_auto_issuing(t *testing.T) {
	// failed/waiting_ca/queued 是「等待签发或等待重试」的被动状态——规则
	// 保持 active acme_dns 时删除会让该域名自动签发链永久断链且 UI 零信号
	// （周期路径只重排已存在行，CreateOrRequeueCertJob 仅规则写路径调用），
	// 与 issued/downloaded 守卫同型，必须 409 显式拒绝。
	for _, status := range []string{"failed", "waiting_ca", "queued"} {
		t.Run(status, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
				VALUES ('lb_pending','pending','http','pending.example.test',8080,1,1,'acme_dns');
				INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_pending','pending.example.test',?)`, status); err != nil {
				t.Fatalf("seed active rule and %s job: %v", status, err)
			}
			router := gin.New()
			router.DELETE("/jobs/:id", h.DeleteCertJob)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))
			if response.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "自动签发") {
				t.Fatalf("body=%s, want 自动签发中断提示", response.Body.String())
			}
			var got string
			if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=1").Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != status {
				t.Fatalf("status=%q, want %s（409 不得改变任务状态）", got, status)
			}
		})
	}
}

func TestDeleteCertJob_blocks_inflight_job_when_rule_still_auto_issuing(t *testing.T) {
	// 在途执行与 DNS 清理同样属于自动签发链；删除后周期路径不会重建行。
	for _, status := range []string{"creating_order", "validating", "cleanup_dns", "cleanup_warning"} {
		t.Run(status, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
				VALUES ('lb_inflight','inflight','http','inflight.example.test',8080,1,1,'acme_dns');
				INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_inflight','inflight.example.test',?)`, status); err != nil {
				t.Fatalf("seed active rule and %s job: %v", status, err)
			}
			router := gin.New()
			router.DELETE("/jobs/:id", h.DeleteCertJob)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))
			if response.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
			}
			var got string
			if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=1").Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != status {
				t.Fatalf("status=%q, want %s（409 不得改变任务状态）", got, status)
			}
		})
	}
}

func TestDeleteCertJob_allows_pending_chain_job_when_rule_disabled(t *testing.T) {
	// 放行形态（与既有 disabled-flow 语义一致）：规则已禁用时签发链本就
	// 停摆，删除 failed/waiting_ca/queued 任务不影响任何链，照常放行。
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_retiring','retiring','http','retiring.example.test',8080,0,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_retiring','retiring.example.test','failed'),
		                                                     ('lb_retiring','retiring2.example.test','waiting_ca'),
		                                                     ('lb_retiring','retiring3.example.test','queued')`); err != nil {
		t.Fatalf("seed disabled rule and pending jobs: %v", err)
	}
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	for _, id := range []string{"1", "2", "3"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/"+id, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("DELETE /jobs/%s status=%d body=%s, want 200", id, response.Code, response.Body.String())
		}
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("job count=%d, want 0（三条任务均应被删除）", count)
	}
}

func TestDeleteCertJob_blocks_issued_job_when_rule_still_auto_renewing(t *testing.T) {
	// 删除 issued 任务行后纯周期路径永不重建（CreateOrRequeueCertJob
	// 仅由规则写路径调用），规则自动续签永久断链且 UI 无信号——规则仍在
	// enabled+acme_dns+域名一致时必须 409 显式拒绝，先禁用规则方可删除。
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_live','live','http','live.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_live','live.example.test','issued')`); err != nil {
		t.Fatalf("seed live rule and issued job: %v", err)
	}
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "续签") {
		t.Fatalf("body=%s, want 续签中断提示", response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=1").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "issued" {
		t.Fatalf("status=%q, want issued（409 不得改变任务状态）", status)
	}
}

func TestDeleteCertJob_blocks_downloaded_job_with_reversed_rule_domain(t *testing.T) {
	// downloaded 任务持有已下载证书，删除同样断续签链；规则域名
	// 顺序与任务规范形式相反时仍须命中拦截（与续签扫描的域名判读一致）。
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_live_dl','live-dl','http','www.live-dl.example.test,live-dl.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_live_dl','live-dl.example.test,www.live-dl.example.test','downloaded')`); err != nil {
		t.Fatalf("seed live rule and downloaded job: %v", err)
	}
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE id=1").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("job count=%d, want 1（409 不得删除任务）", count)
	}
}

func TestDeleteCertJob_allows_issued_job_when_rule_not_auto_renewing(t *testing.T) {
	// 放行形态：规则已禁用或已切回 manual 证书时，删除 issued 任务
	// 不影响任何续签链（续签扫描本就跳过这些规则），按原语义放行。
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_off','off','http','off.example.test',8080,0,1,'acme_dns'),
		       ('lb_manual','manual','http','manual.example.test',8080,1,1,'manual');
		INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_off','off.example.test','issued'),
		                                                     ('lb_manual','manual.example.test','issued')`); err != nil {
		t.Fatalf("seed rules and jobs: %v", err)
	}
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	for _, id := range []string{"1", "2"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/"+id, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("DELETE /jobs/%s status=%d body=%s, want 200", id, response.Code, response.Body.String())
		}
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("job count=%d, want 0（两条任务均应被删除）", count)
	}
}

func TestDeleteCertJob_aborts_when_rule_reenabled_during_delete(t *testing.T) {
	// TOCTOU：守卫读到 enabled=0 放行后 EnableRule（持
	// caddyOpMu）完成启用，删除照常执行 → 规则无任务行、续签永久断链。
	// 修复：守卫检查与状态翻转/删除全程持 caddyOpMu 与 EnableRule 互斥——
	// EnableRule 先完成时守卫必须复核到 enabled=1 并 409。
	// Given：规则当前禁用（守卫按现状应放行），任务 issued
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_race','race','http','race.example.test',8080,0,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_race','race.example.test','issued')`); err != nil {
		t.Fatalf("seed disabled rule and issued job: %v", err)
	}
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	// 模拟 EnableRule 临界区进行中：持 caddyOpMu，删除请求必须排队等待
	h.caddyOpMu.Lock()
	responses := make(chan int, 1)
	go func() {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))
		responses <- response.Code
	}()
	select {
	case code := <-responses:
		h.caddyOpMu.Unlock()
		t.Fatalf("删除未与 EnableRule 临界区互斥，提前完成 status=%d", code)
	case <-time.After(300 * time.Millisecond):
	}
	// EnableRule 完成：规则转为启用后释放临界区
	if _, err := db.DB.Exec("UPDATE lb_rules SET enabled=1 WHERE caddy_id='lb_race'"); err != nil {
		h.caddyOpMu.Unlock()
		t.Fatal(err)
	}
	h.caddyOpMu.Unlock()
	// Then：守卫复核到 enabled=1 必须 409，任务行保留
	select {
	case code := <-responses:
		if code != http.StatusConflict {
			t.Fatalf("status=%d, want 409（规则已在删除期间重新启用）", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DeleteCertJob 未在有界时间内返回")
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE id=1").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("job count=%d, want 1（409 不得删除任务）", count)
	}
}

func TestDeleteCertJob_keeps_row_when_delete_fails(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_keep','keep.example.test','issued');
		CREATE TRIGGER fail_cert_job_delete BEFORE DELETE ON cert_jobs BEGIN SELECT RAISE(ABORT,'delete failed'); END`); err != nil {
		t.Fatalf("seed job and trigger: %v", err)
	}
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE id=1").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("job count=%d, want 1", count)
	}
	if !strings.Contains(response.Body.String(), "delete") {
		t.Fatalf("unexpected response: %s", response.Body.String())
	}
}

func TestDeleteCertJob_deleteFailureLeavesDisabledRuleJobFailed(t *testing.T) {
	// 在途态只有在规则已退出自动签发时才可进入删除；失败恢复不得留下 disabled 假象。
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_running','running','http','running.example.test',8080,0,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_running','running.example.test','creating_order');
		CREATE TRIGGER fail_running_job_delete BEFORE DELETE ON cert_jobs BEGIN SELECT RAISE(ABORT,'delete failed'); END`); err != nil {
		t.Fatalf("seed running job and trigger: %v", err)
	}
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=1").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("status=%q, want failed（删除失败且规则已停用时不重排队）", status)
	}
}
func TestDeleteCertJob_restores_downloaded_job_with_material_when_delete_fails(t *testing.T) {
	// 删除持有证书材料的 downloaded 任务失败时，恢复
	// 路径必须原地保持 'downloaded' 并把部署窗口推到 now（对齐 caqueue
	// requeueCanceledJob 的口径）——转 'queued' 会丢弃已签发证书
	// 触发整轮重签（Issue 快速路径只认 issued/downloaded）。
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	// 删除路径先 cancelCertJob 取消挂起的部署 timer——恢复必须重新登记立即
	// 部署重试，否则只能等 6h 续期扫描/启动恢复接手。
	oldRegistrar := certJobDeploymentRetryRegistrar
	var registered []string
	registrarErr := error(nil)
	certJobDeploymentRetryRegistrar = func(jobID int, ruleID string) error {
		registered = append(registered, fmt.Sprintf("%d:%s", jobID, ruleID))
		return registrarErr
	}
	t.Cleanup(func() { certJobDeploymentRetryRegistrar = oldRegistrar })
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES ('lb_dl','dl.example.test','downloaded','pem-material','key-material');
		CREATE TRIGGER fail_downloaded_job_delete BEFORE DELETE ON cert_jobs BEGIN SELECT RAISE(ABORT,'delete failed'); END`); err != nil {
		t.Fatalf("seed downloaded job and trigger: %v", err)
	}
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	var status string
	var availableAfter sql.NullTime
	if err := db.DB.QueryRow("SELECT status, deployment_available_after FROM cert_jobs WHERE id=1").Scan(&status, &availableAfter); err != nil {
		t.Fatal(err)
	}
	if status != "downloaded" {
		t.Fatalf("status=%q, want downloaded（带证书材料的任务不得转 queued/failed）", status)
	}
	if !availableAfter.Valid {
		t.Fatal("deployment_available_after 未推到 now（部署重排无法重新调度）")
	}
	if services.GetCAQueueManager().IsJobActive(1) {
		t.Fatal("downloaded 任务删除失败恢复后不得进入签发队列")
	}
	if len(registered) != 1 || registered[0] != "1:lb_dl" {
		t.Fatalf("deployment retry registrations=%v, want [1:lb_dl]（恢复后必须重新登记部署）", registered)
	}

	// 证书服务不可用（登记失败）时窗口推进保留（周期补扫接手），删除失败仍 500。
	registrarErr = services.ErrCertificateQueueInactive
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500 when delete still fails", response.Code, response.Body.String())
	}
	if len(registered) != 2 {
		t.Fatalf("deployment retry registrations=%v, want 2（登记失败也须尝试并留痕）", registered)
	}
	if err := db.DB.QueryRow("SELECT status, deployment_available_after FROM cert_jobs WHERE id=1").Scan(&status, &availableAfter); err != nil {
		t.Fatal(err)
	}
	if status != "downloaded" || !availableAfter.Valid {
		t.Fatalf("status=%q window_valid=%v, want downloaded/valid（登记失败不得回滚窗口）", status, availableAfter.Valid)
	}
}

func TestCertJobOperationLock_serializes_retry_and_delete(t *testing.T) {
	lock := certJobOperationLock(9876)
	firstHeld := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondProbe := make(chan bool, 1)
	secondEntered := make(chan struct{})
	go func() {
		lock.Lock()
		close(firstHeld)
		<-releaseFirst
		lock.Unlock()
	}()
	<-firstHeld
	go func() {
		// 非阻塞探测取代「等一小段时间确认没进入」的墙钟窗口：首持有者
		// 未释放时 TryLock 必然失败，与调度速度无关。
		if acquired := lock.TryLock(); acquired {
			lock.Unlock()
			secondProbe <- true
			return
		}
		secondProbe <- false
		lock.Lock()
		close(secondEntered)
		lock.Unlock()
	}()
	if acquired := <-secondProbe; acquired {
		t.Fatal("second operation acquired the job lock while the first still held it")
	}
	close(releaseFirst)
	select {
	case <-secondEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("second operation did not enter after first operation released the job lock")
	}
}

func TestRetryCertJob_does_not_acquire_caddyOpMu(t *testing.T) {
	// 锁序回归网：DeleteCertJob 以 caddyOpMu→certJobOperationLock 顺序持锁，
	// RetryCertJob 只持 certJobOperationLock。若未来 RetryCertJob 在 operationLock
	// 临界区内再获取 caddyOpMu，即与 DeleteCertJob 构成 AB-BA 死锁——现有测试
	// 对此全部绿灯，此处用临界区内 TryLock 探针断言该不变量。
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_lockprobe','lockprobe','http','lockprobe.example.test',8080,0,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,updated_at) VALUES ('lb_lockprobe','lockprobe.example.test','failed',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed lock probe job: %v", err)
	}
	probed := false
	oldHook := retryCertJobPreEnqueueHook
	retryCertJobPreEnqueueHook = func(int) {
		probed = true
		// 钩子运行于 operationLock 临界区内：caddyOpMu 此刻必须可获取。
		if !h.caddyOpMu.TryLock() {
			t.Error("RetryCertJob 在 operationLock 临界区内持有 caddyOpMu（与 DeleteCertJob 构成 AB-BA 死锁）")
			return
		}
		h.caddyOpMu.Unlock()
	}
	t.Cleanup(func() { retryCertJobPreEnqueueHook = oldHook })
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/1/retry", nil))
	if !probed {
		t.Fatal("pre-enqueue hook 未触发，TryLock 探针无效")
	}
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（规则禁用）", response.Code, response.Body.String())
	}
}

func TestRetryCertJob_reread_row_deleted_returns_404(t *testing.T) {
	// UPDATE 0 行后重读若返回 scanErr（SQLITE_BUSY 等瞬时错误），
	// 不能落入通用 409 把 DB 错误归因为规则禁用——必须显式 500。
	// 行被并发删除（ErrNoRows）从 500 细分为 404（对齐 DeleteCertJob
	// 三分归因）；本测试以删行模拟，断言新 404 契约。
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_reread','reread','http','reread.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (id,rule_id,domain,status,updated_at) VALUES (9,'lb_reread','reread.example.test','failed',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed reread job: %v", err)
	}
	oldHook := retryCertJobPreEnqueueHook
	retryCertJobPreEnqueueHook = func(jobID int) {
		// 让 UPDATE 匹配 0 行、重读返回 ErrNoRows：直接在 SELECT 与 UPDATE 之间删掉行。
		if _, err := db.DB.Exec("DELETE FROM cert_jobs WHERE id=?", jobID); err != nil {
			t.Errorf("simulate row disappearing: %v", err)
		}
	}
	t.Cleanup(func() { retryCertJobPreEnqueueHook = oldHook })
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/9/retry", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404（并发删除归因为 Job not found）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Job not found") {
		t.Fatalf("body=%s, want Job not found", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "规则已禁用") || strings.Contains(response.Body.String(), "队列已暂停") {
		t.Fatalf("body=%s, 不应误指规则禁用或队列暂停", response.Body.String())
	}
}

func TestRetryCertJob_blocked_by_rule_deletion_returns_409(t *testing.T) {
	// 规则删除屏障期（BlockJobsForRule 生效）用户点重试，EnqueueIfActive
	// 应走 changed=false 的冲突语义（409），而不是返回 error 落 500。
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_blocked','blocked','http','blocked.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (id,rule_id,domain,status,updated_at) VALUES (11,'lb_blocked','blocked.example.test','failed',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed blocked job: %v", err)
	}
	qm := services.GetCAQueueManager()
	token := qm.BlockJobsForRule("lb_blocked")
	t.Cleanup(func() { qm.UnblockJobsForRule("lb_blocked", token) })
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/11/retry", nil))
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（规则删除屏障期应返回冲突而非 500）", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "Failed to enqueue retry") {
		t.Fatalf("body=%s, 不应返回 500 通用文案", response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=11").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("status=%q, want failed（屏障期不应改变任务状态）", status)
	}
}

func TestRetryCertJob_active_job_returns_queue_busy_message(t *testing.T) {
	// EnqueueIfActive 在途命中走!changed 且重读状态未变时，
	// 409 文案必须归因"任务正在队列中"，不得误导为规则禁用/配置变更。
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_blocker','blocker','http','blocker.example.test',8080,1,1,'acme_dns'),
		       ('lb_active','active','http','active.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (id,rule_id,domain,status,updated_at)
		VALUES (20,'lb_blocker','blocker.example.test','queued',datetime('now','-20 minutes')),
		       (21,'lb_active','active.example.test','failed',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed jobs: %v", err)
	}
	// 占位执行堵住并发槽（MaxConcurrent=1），让 job 21 入队后停在 pending 保持
	// 在途但永不执行——确定性复现"在途命中"。
	block := make(chan struct{})
	entered := make(chan struct{})
	var enteredOnce sync.Once
	acmeMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		enteredOnce.Do(func() { close(entered) })
		<-block
	}))
	qm := services.GetCAQueueManager()
	t.Cleanup(func() {
		close(block)
		qm.PauseAndDrain()
		acmeMock.Close()
		services.ResetCAQueueManagerForTest()
	})
	if _, err := db.DB.Exec("UPDATE ca_providers SET provider='letsencrypt', directory_url=? WHERE enabled=1", acmeMock.URL); err != nil {
		t.Fatalf("redirect ACME directory: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET acme_email='acme@example.test' WHERE id=1"); err != nil {
		t.Fatalf("set ACME email: %v", err)
	}
	if err := qm.EnqueueForTest(0, 20, "lb_blocker", "blocker.example.test"); err != nil {
		t.Fatalf("enqueue blocker job: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("blocker execution did not reach the ACME mock")
	}
	if err := qm.EnqueueForTest(0, 21, "lb_active", "active.example.test"); err != nil {
		t.Fatalf("enqueue active job: %v", err)
	}

	// When
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/21/retry", nil))

	// Then
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "任务正在签发队列中，请勿重复操作") {
		t.Fatalf("body=%s, want 在途归因文案", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "规则已禁用") {
		t.Fatalf("body=%s, 不应误指规则已禁用", response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=21").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("status=%q, want failed（在途命中不得改变任务状态）", status)
	}
}

// （2026-09-05 证书域审计裁定）：任务日志查看必须按序拼接全部轮转备份
// .5→.1（旧→新）再加当前文件——写侧保留 maxRotatedFiles=5 份历史，读侧此前
// 只拼 .1，UI 可回看窗口远小于磁盘保留量。每文件保留现有 128KB/500 行截断。
func TestGetCertJobLogs_concatenates_all_rotated_backups_oldest_first(t *testing.T) {
	// Given：规则日志目录含当前文件与 .1-.5 全部轮转备份（.5 最旧）
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status) VALUES (9,'lb_logs','logs.example.test','failed')`); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	dir := t.TempDir()
	original := certJobLogPathForRule
	certJobLogPathForRule = func(ruleID string) string {
		return filepath.Join(dir, "certjob-"+ruleID+".log")
	}
	t.Cleanup(func() { certJobLogPathForRule = original })
	base := certJobLogPathForRule("lb_logs")
	for i := 5; i >= 1; i-- {
		if err := os.WriteFile(fmt.Sprintf("%s.%d", base, i), []byte(fmt.Sprintf("line-rotated-%d\n", i)), 0644); err != nil {
			t.Fatalf("write rotated backup .%d: %v", i, err)
		}
	}
	if err := os.WriteFile(base, []byte("line-current\n"), 0644); err != nil {
		t.Fatalf("write current log: %v", err)
	}
	router := gin.New()
	router.GET("/jobs/:id/logs", h.GetCertJobLogs)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/jobs/9/logs", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			Content   string `json:"content"`
			Truncated bool   `json:"truncated"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode log response: %v", err)
	}
	want := "line-rotated-5\nline-rotated-4\nline-rotated-3\nline-rotated-2\nline-rotated-1\nline-current\n"
	if got := body.Data.Content; got != want {
		t.Fatalf("content=%q, want %q", got, want)
	}
	if body.Data.Truncated {
		t.Fatal("truncated=true, want false（小日志不做尾窗截断）")
	}
}

// 单响应硬上限：总量超过 256KB 时必须尾窗保留并标注 truncated，避免
// 「N 个失败任务 × 768KB」批量拉日志造成出流量/IO 抖动。
func TestGetCertJobLogs_capsTotalResponseBytes(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status) VALUES (9,'lb_logs_cap','logs-cap.example.test','failed')`); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	dir := t.TempDir()
	original := certJobLogPathForRule
	certJobLogPathForRule = func(ruleID string) string {
		return filepath.Join(dir, "certjob-"+ruleID+".log")
	}
	t.Cleanup(func() { certJobLogPathForRule = original })
	base := certJobLogPathForRule("lb_logs_cap")
	line := strings.Repeat("x", 1023) + "\n"
	for i := 1; i <= 5; i++ {
		if err := os.WriteFile(fmt.Sprintf("%s.%d", base, i), []byte(strings.Repeat(line, 120)), 0644); err != nil {
			t.Fatalf("write rotated backup .%d: %v", i, err)
		}
	}
	if err := os.WriteFile(base, []byte(strings.Repeat(line, 120)), 0644); err != nil {
		t.Fatalf("write current log: %v", err)
	}
	router := gin.New()
	router.GET("/jobs/:id/logs", h.GetCertJobLogs)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/jobs/9/logs", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			Content   string `json:"content"`
			Truncated bool   `json:"truncated"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode log response: %v", err)
	}
	if !body.Data.Truncated {
		t.Fatal("truncated=false, want true（6×120KB 超过单响应上限）")
	}
	if len(body.Data.Content) > certJobLogsMaxResponseBytes+256 {
		t.Fatalf("content bytes=%d, want ≤ %d（尾窗硬上限）", len(body.Data.Content), certJobLogsMaxResponseBytes+256)
	}
	if !strings.Contains(body.Data.Content, "仅显示最近") {
		t.Fatal("截断响应必须带提示行")
	}
}

// 读取预算：从最新文件累计到响应上限即停止读更旧轮转（更旧内容必然落在
// 尾窗之外）。夹具给当前 + .1 + .2 + .3 各 1KB，预算 2KB ⇒ 只读当前与 .1。
func TestReadRotatedLogTail_stopsAtByteBudget(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "certjob-budget.log")
	lineFor := func(tag string) string {
		return tag + strings.Repeat("x", 1024-len(tag)-1) + "\n"
	}
	for _, name := range []string{"base", ".1", ".2", ".3"} {
		path := base
		if name != "base" {
			path = base + name
		}
		if err := os.WriteFile(path, []byte(lineFor(name)), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	content, truncated, err := readRotatedLogTail(base, 5, 128<<10, 500, 2<<10)
	if err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if want := lineFor(".1") + lineFor("base"); content != want {
		t.Fatalf("content=%q, want 最新的两份（.1 + 当前）", content)
	}
	if !truncated {
		t.Fatal("存在未读取的更旧备份时必须标记 truncated")
	}
	if strings.Contains(content, ".2") || strings.Contains(content, ".3") {
		t.Fatalf("预算耗尽后不得读取更旧备份: %q", content)
	}

	// 正向对照：预算充足时全量按旧→新拼接且不标记截断。
	content, truncated, err = readRotatedLogTail(base, 5, 128<<10, 500, 16<<10)
	if err != nil {
		t.Fatalf("read tail with full budget: %v", err)
	}
	if want := lineFor(".3") + lineFor(".2") + lineFor(".1") + lineFor("base"); content != want {
		t.Fatalf("content=%q, want 全部轮转按旧→新拼接", content)
	}
	if truncated {
		t.Fatal("预算充足时不得标记截断")
	}
}

// 非 ENOENT 的 I/O 错误必须上抛（「读不出」与「无日志」不可区分会让排障
// 误判为「尚无签发日志」）：用同名目录制造 read 失败。
func TestReadRotatedLogTail_reportsIOErrors(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "certjob-ioerr.log")
	if err := os.Mkdir(base+".1", 0o755); err != nil {
		t.Fatalf("mkdir fake rotated file: %v", err)
	}
	if _, _, err := readRotatedLogTail(base, 2, 128<<10, 500, 16<<10); err == nil {
		t.Fatal("轮转副本是目录时必须返回 I/O 错误，而不是当作无日志")
	}
	// 文件不存在不是错误。
	if content, _, err := readRotatedLogTail(filepath.Join(dir, "absent.log"), 2, 128<<10, 500, 16<<10); err != nil || content != "" {
		t.Fatalf("缺失文件必须返回 (\"\", nil)，实得 content=%q err=%v", content, err)
	}
}

// 证书日志尾窗与系统/Caddy 日志共用 tailLogWindow 的残段口径。
func TestReadCertJobLogFile_tailWindowDropsPartialFirstLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cert.log")
	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "small unchanged", content: "first\nsecond\n", want: "first\nsecond\n"},
		{name: "partial line dropped", content: strings.Repeat("x", 128<<10) + "\ncomplete\n", want: "complete\n"},
		{name: "giant line window empty", content: strings.Repeat("x", (128<<10)+32), want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.content), 0644); err != nil {
				t.Fatal(err)
			}
			got, err := readCertJobLogFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if got != tc.want {
				t.Fatalf("content length=%d, want %d (%q)", len(got), len(tc.want), tc.want)
			}
		})
	}
}

// （2026-09-05 证书域审计裁定）：cert_expiry_days 读取失败不得放大为整个
// 任务列表 500——降级默认 30 并告警，对齐 checkManualCertExpiration
// 口径。种子任务 20 天后过期：默认阈值 30 下应判 expiring，证明降级取值真实生效。
func TestListCertJobs_degrades_to_default_expiry_days_when_config_missing(t *testing.T) {
	// Given：一条 issued 任务 20 天后过期；基线（配置在）请求 200
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at)
		VALUES ('lb_degrade','degrade.example.test','issued', datetime('now','+20 days'))`); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	router := gin.New()
	router.GET("/jobs", h.ListCertJobs)
	baseline := httptest.NewRecorder()
	router.ServeHTTP(baseline, httptest.NewRequest(http.MethodGet, "/jobs", nil))
	if baseline.Code != http.StatusOK {
		t.Fatalf("baseline status=%d body=%s, want 200", baseline.Code, baseline.Body.String())
	}

	// When：global_config 行被删（该读取必然失败）
	if _, err := db.DB.Exec("DELETE FROM global_config WHERE id=1"); err != nil {
		t.Fatalf("delete global config: %v", err)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/jobs", nil))

	// Then：200，且按默认 30 天阈值把 20 天后到期判为 expiring（降级取值生效）
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（读取失败降级默认 30，不再整页 500）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"certificate_status":"expiring"`) {
		t.Fatalf("body=%s, want expiring via default 30-day threshold", response.Body.String())
	}
}

// （自 apikeys_current_test.go 迁回——本族为 cert_jobs 序列化
// 主题，此前仅因共用 newBackupTestHandlers 夹具寄居于 API Key 文件。）
func TestCertJobEndpointsSerializeNullableTimes(t *testing.T) {
	h := newBackupTestHandlers(t)
	validTime := time.Date(2026, time.July, 30, 12, 34, 56, 0, time.UTC)
	_, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, expires_at, created_at, updated_at, ca_available_after)
		VALUES ('lb_valid', 'valid.example', 'issued', ?, ?, ?, ?),
		       ('lb_null', 'null.example', 'queued', NULL, ?, NULL, NULL)`, validTime, validTime, validTime, validTime, validTime)
	if err != nil {
		t.Fatalf("seed certificate jobs: %v", err)
	}
	// 按 rule_id 反查（多行 INSERT 的 LastInsertId 只保证最后一行，连号假设
	// 在夹具预置行时静默指向错误 id）。
	var validID, nullID int64
	if err := db.DB.QueryRow("SELECT id FROM cert_jobs WHERE rule_id='lb_valid'").Scan(&validID); err != nil {
		t.Fatalf("read valid job ID: %v", err)
	}
	if err := db.DB.QueryRow("SELECT id FROM cert_jobs WHERE rule_id='lb_null'").Scan(&nullID); err != nil {
		t.Fatalf("read null job ID: %v", err)
	}

	t.Run("list", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/cert-jobs", nil)
		h.ListCertJobs(ctx)

		body := recorder.Body.String()
		if recorder.Code != http.StatusOK || !strings.Contains(body, `"expires_at":"2026-07-30T12:34:56Z"`) || !strings.Contains(body, `"updated_at":"2026-07-30T12:34:56Z"`) || !strings.Contains(body, `"ca_available_after":"2026-07-30T12:34:56Z"`) || !strings.Contains(body, `"expires_at":null`) || !strings.Contains(body, `"updated_at":null`) || !strings.Contains(body, `"ca_available_after":null`) {
			t.Fatalf("status=%d body=%s", recorder.Code, body)
		}
		if strings.Contains(body, `"Time"`) || strings.Contains(body, `"Valid"`) {
			t.Fatalf("response leaked sql.NullTime representation: %s", body)
		}
	})

	for _, tt := range []struct {
		name string
		id   int64
		want []string
	}{
		{name: "valid", id: validID, want: []string{`"expires_at":"2026-07-30T12:34:56Z"`, `"ca_available_after":"2026-07-30T12:34:56Z"`}},
		{name: "null", id: nullID, want: []string{`"expires_at":null`, `"ca_available_after":null`}},
	} {
		t.Run("detail "+tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/cert-jobs/"+strconv.FormatInt(tt.id, 10), nil)
			ctx.Params = gin.Params{{Key: "id", Value: strconv.FormatInt(tt.id, 10)}}
			h.GetCertJob(ctx)

			body := recorder.Body.String()
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, body)
			}
			for _, want := range tt.want {
				if !strings.Contains(body, want) {
					t.Fatalf("body=%s, want %s", body, want)
				}
			}
			if strings.Contains(body, `"Time"`) || strings.Contains(body, `"Valid"`) {
				t.Fatalf("response leaked sql.NullTime representation: %s", body)
			}
		})
	}
}

func TestListCertJobs_returnsStatusCountsForQueueBanner(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,created_at) VALUES
		('lb_q1','q1.example.test','queued',datetime('now')),
		('lb_q2','q2.example.test','queued',datetime('now')),
		('lb_w1','w1.example.test','waiting_ca',datetime('now')),
		('lb_d1','d1.example.test','issued',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/jobs", h.ListCertJobs)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/jobs?page=1&page_size=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			StatusCounts map[string]int64 `json:"status_counts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.StatusCounts["queued"] != 2 || body.Data.StatusCounts["waiting_ca"] != 1 || body.Data.StatusCounts["issued"] != 1 {
		t.Fatalf("status_counts=%v", body.Data.StatusCounts)
	}
}

// DeleteCertJob 删除失败的恢复分支曾在
// 持有 per-job operationLock 时反向获取 caddyOpMu——与入口锁序
// （caddyOpMu→operationLock）构成 AB-BA：同 id 连点/同桶（id%64）并发删除
// 先取到 caddyOpMu 后在桶锁排队，双向互等且 caddyOpMu 被永久占用（规则/配置
// 写与 Caddy 启停全部挂起）。本测试用 cancelCertJob 阻塞窗确定性复现：
//
//	T1（删除失败，恢复前）此时只持 operationLock；
//	按入口锁序先持 caddyOpMu，再请求同一把 operationLock。
//
// 修复前 T1 继续反向取 caddyOpMu → 死锁（5s 超时失败）；修复后 T1 先释放
// per-job 锁再按规范顺序重取，两者依次完成且行按恢复语义落库。
func TestDeleteCertJob_recoveryKeepsCanonicalLockOrder(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_lockorder','lockorder.example.test','issued');
		CREATE TRIGGER fail_lockorder_delete BEFORE DELETE ON cert_jobs BEGIN SELECT RAISE(ABORT,'delete failed'); END`); err != nil {
		t.Fatalf("seed lock-order job: %v", err)
	}

	cancelEntered := make(chan struct{})
	allowCancelReturn := make(chan struct{})
	oldCancel := cancelCertJob
	cancelCertJob = func(int) {
		close(cancelEntered)
		<-allowCancelReturn
	}
	t.Cleanup(func() { cancelCertJob = oldCancel })

	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	firstDone := make(chan int, 1)
	go func() {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))
		firstDone <- response.Code
	}()
	select {
	case <-cancelEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("DeleteCertJob 未到达取消点（夹具前置失败）")
	}

	// 与入口同锁序（caddyOpMu → operationLock）的同桶并发操作。
	secondEntered := make(chan struct{})
	secondReleased := make(chan struct{})
	go func() {
		h.caddyOpMu.Lock()
		close(secondEntered)
		lock := certJobOperationLock(1)
		lock.Lock()
		lock.Unlock()
		h.caddyOpMu.Unlock()
		close(secondReleased)
	}()
	select {
	case <-secondEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("并发方未取得 caddyOpMu（夹具前置失败）")
	}
	// 给 T2 足够时间排到桶锁上——修复前 T1 解阻后会在此反向取 caddyOpMu。
	// 这是负面条件的夹具窗口（T2 尚未排队时只会削弱断言，不会误红），
	// 留 200ms 余量以适应负载较高的 CI/并行测试。
	time.Sleep(200 * time.Millisecond)
	close(allowCancelReturn)

	select {
	case code := <-firstDone:
		if code != http.StatusInternalServerError {
			t.Fatalf("status=%d, want 500（删除失败）", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DeleteCertJob 恢复分支死锁：在持 operationLock 时等待 caddyOpMu（AB-BA）")
	}
	select {
	case <-secondReleased:
	case <-time.After(5 * time.Second):
		t.Fatal("并发同桶操作未完成：caddyOpMu 被恢复分支永久占用")
	}

	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=1").Scan(&status); err != nil {
		t.Fatalf("job row missing after failed delete: %v", err)
	}
	if status != "issued" {
		t.Fatalf("status=%q, want issued（删除失败按原状态恢复）", status)
	}
}

// cert_jobs.updated_at 在 DDL 中可空
// （internal/db/db.go 建表语句），NULL 时重试冷却门曾直接放行（fail-open）：
// 历史行/带外插入的 queued/failed 任务可连点绕过 15/5 分钟冷却、连续消耗
// CA 配额。修复：updated_at 无效时回退 created_at 计算；两列都缺失时
// fail-closed（视为刚更新，按冷却拒绝）。
func TestCertJobRetryBlocked_updatedAtNullFallsBackToCreatedAt(t *testing.T) {
	now := time.Now()
	// 目标形状：updated_at=NULL 且 created_at 刚写入 → 仍受 15 分钟冷却。
	blocked, statusCode, _ := certJobRetryBlocked("queued", sql.NullTime{}, sql.NullTime{Time: now.Add(-time.Minute), Valid: true}, now)
	if !blocked || statusCode != http.StatusTooManyRequests {
		t.Fatalf("blocked=%v status=%d, want true/429（NULL updated_at 不得放行冷却）", blocked, statusCode)
	}
	// 回归形状：updated_at 有效时以 updated_at 为准（created_at 很老也不提前放行）。
	blocked, _, _ = certJobRetryBlocked("failed", sql.NullTime{Time: now.Add(-time.Minute), Valid: true}, sql.NullTime{Time: now.Add(-time.Hour), Valid: true}, now)
	if !blocked {
		t.Fatal("updated_at 有效且未过冷却时必须拦截（不得回退 created_at）")
	}
	// fail-closed 形状：两列都缺失 → 视为冷却中（不得因缺时间戳立即放行）。
	blocked, statusCode, _ = certJobRetryBlocked("queued", sql.NullTime{}, sql.NullTime{}, now)
	if !blocked || statusCode != http.StatusTooManyRequests {
		t.Fatalf("blocked=%v status=%d, want true/429（缺时间戳 fail-closed）", blocked, statusCode)
	}
	// 回归形状：updated_at=NULL 但 created_at 已过冷却 → 放行。
	blocked, _, _ = certJobRetryBlocked("queued", sql.NullTime{}, sql.NullTime{Time: now.Add(-30 * time.Minute), Valid: true}, now)
	if blocked {
		t.Fatal("created_at 已过冷却时必须放行（不得永久锁死历史行）")
	}
}

// 导入会话持写事务且 CA 队列已 PauseAndDrain——证书
// 任务重试的 UPDATE 会阻塞写锁到 busy_timeout（500）或落到已被全量替换的
// cert_jobs 行。RetryCertJob 端点与任务监控 cert-job 触发分支共用重试核心，
// 两侧都必须在写任何行之前 409 fast-fail。
func TestRetryCertJobBlockedDuringConfigImport(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_imp','imp','http','imp.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,message,updated_at)
		VALUES ('lb_imp','imp.example.test','failed','原失败原因',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	router.POST("/system/tasks/:id/trigger", h.TriggerSystemTask)

	// 模拟导入会话进行中（configImportBusy 的事实源：窗口计数）。
	beginImportWindowForTest(t)

	for _, tc := range []struct{ name, path string }{
		{"RetryCertJob 端点", "/jobs/1/retry"},
		{"任务监控 cert-job 触发分支", "/system/tasks/cert-job:1/trigger"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, tc.path, nil))
			if recorder.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s, want 409（导入窗口必须 fast-fail）", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "配置导入进行中") {
				t.Fatalf("body=%s, want 导入窗口文案族", recorder.Body.String())
			}
		})
	}

	// 零写库：状态/消息均未被改动（重试可能迁移状态或推进部署窗）。
	var status, message string
	if err := db.DB.QueryRow(`SELECT status, COALESCE(message,'') FROM cert_jobs WHERE id=1`).Scan(&status, &message); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "failed" || message != "原失败原因" {
		t.Fatalf("导入窗口内 job 被改写: status=%q message=%q", status, message)
	}
}

// 回归形状：非导入窗口内同一入口不被误拦（门只在 busy 时生效）。
// 只做负向断言（「不是 409」「无导入窗口文案」）时 200/404/500 全都通过——
// 导入窗口门失效、进入真实查询、查询故障三者不可区分。放行后的确定性结果
// 必须是「任务不存在」的 404：它同时证明请求走过了导入窗口门并抵达查询阶段。
func TestRetryCertJobNotBlockedWhenNoImport(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)

	var certJobsBefore int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs`).Scan(&certJobsBefore); err != nil {
		t.Fatal(err)
	}
	var auditsBefore int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='重试失败'`).Scan(&auditsBefore); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/jobs/999/retry", nil))

	if recorder.Code == http.StatusConflict || strings.Contains(recorder.Body.String(), "配置导入进行中") {
		t.Fatalf("无导入会话时命中导入窗口门: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404（无导入窗口→进入真实查询→任务不存在）", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("解析响应: %v body=%s", err, recorder.Body.String())
	}
	if response.Code != http.StatusNotFound || response.Message != "任务不存在" {
		t.Fatalf("code=%d message=%q, want 404/任务不存在", response.Code, response.Message)
	}

	// 失败出口审计必须留痕（AuditPolicyExplicit 路由中间件不自动审计），
	// 且归因是 job_not_found 而不是 query_failed/其它出口（detail 经
	// AuditResultText 渲染为中文，不出现内部码字面量）。
	var jobNotFound, auditsAfter int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log
		WHERE action='重试失败' AND resource='证书任务' AND detail LIKE '%任务 999%' AND detail LIKE '%结果：任务不存在%'`).Scan(&jobNotFound); err != nil {
		t.Fatal(err)
	}
	if jobNotFound != 1 {
		t.Fatalf("job_not_found 审计行=%d, want 1（被拒重试必须可追溯）", jobNotFound)
	}
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='重试失败'`).Scan(&auditsAfter); err != nil {
		t.Fatal(err)
	}
	if auditsAfter != auditsBefore+1 {
		t.Fatalf("重试失败审计行 %d→%d, want 恰好新增 1 条（不得重复留痕）", auditsBefore, auditsAfter)
	}

	// 零写库：不存在的 job 不得新增/改写 cert_jobs 行。
	var certJobsAfter int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs`).Scan(&certJobsAfter); err != nil {
		t.Fatal(err)
	}
	if certJobsAfter != certJobsBefore {
		t.Fatalf("cert_jobs 行数 %d→%d, want 不变（404 出口不得写库）", certJobsBefore, certJobsAfter)
	}
}

// waiting_ca 的 CA 冷却（429 退避 1-3h）有明确到期时间：手动重试默认不得
// 静默越过——冷却未到期且未显式 force 时 429 并给出剩余时长；force=true
// （前端确认对话框已明示风险）显式越过，审计必须留下「手动越过 CA 冷却」
// 与「重试预算已重置」痕迹。
func TestRetryCertJob_waitingCACoolingRequiresForce(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_cooling','cooling','http','cooling.example.test',8080,1,1,'acme_dns');
		INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'cooling CA','letsencrypt','https://invalid.example/directory',1);
		INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,renewal_attempts,ca_available_after,updated_at)
		VALUES ('lb_cooling','cooling.example.test','waiting_ca',7,2,datetime('now','+1 hour'),datetime('now','-2 hours'))`); err != nil {
		t.Fatalf("seed cooling job: %v", err)
	}
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)

	// When：未带 force
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/1/retry", nil))

	// Then：429 + 剩余时长，状态保持 waiting_ca
	if response.Code != http.StatusTooManyRequests || !strings.Contains(response.Body.String(), "冷却未到期") {
		t.Fatalf("status=%d body=%s, want 429 冷却未到期", response.Code, response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=1").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "waiting_ca" {
		t.Fatalf("status=%q, want waiting_ca（未 force 不得越过冷却）", status)
	}

	// When：force=true（用户确认越过）
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/1/retry?force=true", nil))

	// Then：重排受理（200）。入队后 worker 立即异步执行（本夹具无 ACME
	// 邮箱，任务会快速失败）——DB 终态竞态不可断言，越过冷却的留痕义务
	// 由审计行承担。
	if response.Code != http.StatusOK {
		t.Fatalf("force retry status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var auditDetail string
	if err := db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log WHERE action='重试' AND resource='证书任务' ORDER BY id DESC LIMIT 1`).Scan(&auditDetail); err != nil {
		t.Fatalf("read retry audit: %v", err)
	}
	if !strings.Contains(auditDetail, "手动越过 CA 冷却") || !strings.Contains(auditDetail, "重试预算已重置") {
		t.Fatalf("audit detail=%q, want 手动越过冷却 + 预算重置留痕", auditDetail)
	}
}

// 删除任务行后，规则若已无任何仍持有可用材料的任务行，物化的证书/私钥文件
// 即为孤儿（私钥残留磁盘）——必须随删除回收；同规则其他域名的材料行仍在时
// 不得误删。
func TestDeleteCertJob_removesOrphanedCertFilesOnlyWhenNoMaterialRemains(t *testing.T) {
	h := newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_orphan_files','orphan','http','orphan.example.test',8080,0,1,'acme_dns');
		INSERT INTO cert_jobs (id,rule_id,domain,status,cert_pem,key_pem) VALUES
			(1,'lb_orphan_files','orphan.example.test','failed','CERT-A','KEY-A'),
			(2,'lb_orphan_files','www.orphan.example.test','issued','CERT-B','KEY-B')`); err != nil {
		t.Fatalf("seed rule and jobs: %v", err)
	}
	if err := services.WriteCertFiles("lb_orphan_files", "CERT-B", "KEY-B"); err != nil {
		t.Fatalf("write cert files: %v", err)
	}
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)

	// 删除第一条行后仍有另一材料行 → 文件必须保留（该域名证书仍被渲染消费）。
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("delete job 1 status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if _, err := os.Stat(filepath.Join(certDir, "lb_orphan_files.crt")); err != nil {
		t.Fatalf("仍有材料行时证书文件被误删: %v", err)
	}

	// 删除最后一行后无任何可用材料 → 物化文件（含私钥）必须回收。
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/2", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("delete job 2 status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	for _, suffix := range []string{".crt", ".key"} {
		if _, err := os.Stat(filepath.Join(certDir, "lb_orphan_files"+suffix)); err == nil {
			t.Fatalf("无可用材料后 %s 未回收（私钥残留磁盘）", suffix)
		}
	}
}

// 手动证书材料在库（同样物化到 certs/）的规则：删除其任务行不得清掉手工
// 证书文件——「无任务材料」不等于「无可用材料」。
func TestDeleteCertJob_keepsManualCertFiles(t *testing.T) {
	h := newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key)
		VALUES ('lb_manual_files','manual','http','manual.example.test',8080,1,1,'manual','MANUAL-CERT','MANUAL-KEY');
		INSERT INTO cert_jobs (id,rule_id,domain,status) VALUES (1,'lb_manual_files','manual.example.test','disabled')`); err != nil {
		t.Fatalf("seed manual rule and job: %v", err)
	}
	if err := services.WriteCertFiles("lb_manual_files", "MANUAL-CERT", "MANUAL-KEY"); err != nil {
		t.Fatalf("write cert files: %v", err)
	}
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if _, err := os.Stat(filepath.Join(certDir, "lb_manual_files.crt")); err != nil {
		t.Fatalf("手动证书文件被任务删除误删: %v", err)
	}
}

// 分页语义统一（与审计日志/安全事件同口径）：非整数 400；越界钳到上限
// （旧行为越界 400）。
func TestListCertJobs_paginationSemanticsUnified(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/jobs", handler.ListCertJobs)
	get := func(query string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/jobs?"+query, nil))
		return recorder
	}

	recorder := get("page=1&page_size=500")
	if recorder.Code != http.StatusOK {
		t.Fatalf("page_size=500 status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			PageSize int `json:"page_size"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Data.PageSize != 200 {
		t.Errorf("page_size=500 → %d, want clamp to cap 200", payload.Data.PageSize)
	}

	if rec := get("page=abc"); rec.Code != http.StatusBadRequest {
		t.Errorf("page=abc status=%d, want 400", rec.Code)
	}
	if rec := get("page_size=abc"); rec.Code != http.StatusBadRequest {
		t.Errorf("page_size=abc status=%d, want 400", rec.Code)
	}
}

// 同一秒内批量入队（created_at 完全相同）时 ORDER BY 只有 created_at 没有唯一
// tiebreaker：等值键的相对顺序由查询计划决定，翻页窗口在等值区间上可重复/漏行。
// tiebreaker 必须与 GetCurrentCertJobs 同源（created_at DESC, id DESC），
// 使同一任务在任意 page/page_size 组合下位置唯一。
func TestListCertJobs_sameSecondCreatedAtPaginationIsStable(t *testing.T) {
	handler := newBackupTestHandlers(t)
	const ruleID = "lb_same_second"
	// 同一秒的固定时刻：批量入队的真实形态（datetime('now') 逐行取值不确定，
	// 显式同值才能构造等值键）。
	const createdAt = "2026-10-24 12:00:00"
	seededIDs := make([]int64, 0, 7)
	for index := range 7 {
		result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,created_at,updated_at)
			VALUES (?,?,'queued',?,?)`, ruleID, "same-second-"+strconv.Itoa(index)+".example.test", createdAt, createdAt)
		if err != nil {
			t.Fatalf("seed job %d: %v", index, err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatalf("read job %d ID: %v", index, err)
		}
		seededIDs = append(seededIDs, id)
	}
	// 唯一排序键 = created_at DESC, id DESC → 期望顺序是插入序的逆序。
	want := make([]int64, 0, len(seededIDs))
	for index := len(seededIDs) - 1; index >= 0; index-- {
		want = append(want, seededIDs[index])
	}

	router := gin.New()
	router.GET("/jobs", handler.ListCertJobs)
	readPage := func(page int) []int64 {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet,
			"/jobs?page="+strconv.Itoa(page)+"&page_size=3", nil)
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("page=%d status=%d body=%s", page, recorder.Code, recorder.Body.String())
		}
		var payload struct {
			Data struct {
				List []struct {
					ID int64 `json:"id"`
				} `json:"list"`
			} `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode page %d: %v", page, err)
		}
		ids := make([]int64, 0, len(payload.Data.List))
		for _, item := range payload.Data.List {
			ids = append(ids, item.ID)
		}
		return ids
	}

	// 默认列表路径（无 rule_id 过滤）使用 created_at 索引扫描：等值键在索引内
	// 按 rowid 升序返回，缺 tiebreaker 时同为「最新」的任务会以 id ASC 出现，
	// 与契约（id DESC）不符且分页拼接顺序随计划漂移。
	// 三页拼接必须恰好是全集且无重复。
	paged := make([]int64, 0, len(want))
	for page := 1; page <= 3; page++ {
		paged = append(paged, readPage(page)...)
	}
	if fmt.Sprint(paged) != fmt.Sprint(want) {
		t.Fatalf("同秒批量分页拼接=%v, want %v（唯一 tiebreaker：created_at DESC, id DESC）", paged, want)
	}
	// 逐页边界：page_size=3 → [7,6,5] / [4,3,2] / [1]，等值键顺序必须确定。
	for page := 1; page <= 3; page++ {
		start := (page - 1) * 3
		end := start + 3
		if end > len(want) {
			end = len(want)
		}
		if got := readPage(page); fmt.Sprint(got) != fmt.Sprint(want[start:end]) {
			t.Fatalf("page=%d ids=%v, want %v", page, got, want[start:end])
		}
	}
}
