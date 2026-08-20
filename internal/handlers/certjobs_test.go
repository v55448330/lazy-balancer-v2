package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	blocked, _ := certJobRetryBlocked("disabled", sql.NullTime{}, time.Now())
	if !blocked {
		t.Fatal("disabled job retry was allowed")
	}
}

func TestRetryCertJob_rejects_inactive_rule_atomically(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
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
	// R42 发现4：worker 在 SELECT 与 UPDATE 之间流转状态时，409 文案应区分归因。
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
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

func TestRetryCertJob_accepts_www_first_rule_domain(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
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

func TestDeleteCertJob_blocks_issued_job_when_rule_still_auto_renewing(t *testing.T) {
	// R52 N4：删除 issued 任务行后纯周期路径永不重建（CreateOrRequeueCertJob
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
	// R52 N4：downloaded 任务持有已下载证书，删除同样断续签链；规则域名
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
	// R52 N4 放行形态：规则已禁用或已切回 manual 证书时，删除 issued 任务
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

func TestDeleteCertJob_requeues_running_job_when_delete_fails(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_running','running','http','running.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_running','running.example.test','creating_order');
		CREATE TRIGGER fail_running_job_delete BEFORE DELETE ON cert_jobs BEGIN SELECT RAISE(ABORT,'delete failed'); END`); err != nil {
		t.Fatalf("seed running job and trigger: %v", err)
	}
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
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
	if status != "queued" && status != "creating_account" {
		t.Fatalf("status=%q, want queued or creating_account (pipeline active)", status)
	}
	if !services.GetCAQueueManager().IsJobActive(1) {
		t.Fatal("restored running job is not active in the CA queue")
	}
}

func TestCertJobOperationLock_serializes_retry_and_delete(t *testing.T) {
	lock := certJobOperationLock(9876)
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondEntered := make(chan struct{})
	go func() {
		lock.Lock()
		close(firstEntered)
		<-releaseFirst
		lock.Unlock()
	}()
	<-firstEntered
	go func() {
		lock.Lock()
		close(secondEntered)
		lock.Unlock()
	}()
	select {
	case <-secondEntered:
		t.Fatal("second operation entered before first operation released the job lock")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFirst)
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("second operation did not enter after first operation released the job lock")
	}
}

func TestRetryCertJob_reread_failure_returns_500(t *testing.T) {
	// R43 A-3：UPDATE 0 行后重读若返回 scanErr（含 ErrNoRows / SQLITE_BUSY 等瞬时
	// 错误），不能落入通用 409 把 DB 错误归因为规则禁用——必须显式 500。
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
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
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "读取任务状态失败") {
		t.Fatalf("body=%s, want 读取任务状态失败", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "规则已禁用") || strings.Contains(response.Body.String(), "队列已暂停") {
		t.Fatalf("body=%s, 不应误指规则禁用或队列暂停", response.Body.String())
	}
}

func TestRetryCertJob_blocked_by_rule_deletion_returns_409(t *testing.T) {
	// R43 A-4：规则删除屏障期（BlockJobsForRule 生效）用户点重试，EnqueueIfActive
	// 应走 changed=false 的冲突语义（409），而不是返回 error 落 500。
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
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
	// R46 A-F3：EnqueueIfActive 在途命中（R45 发现2）走 !changed 且重读状态未变时，
	// 409 文案必须归因"任务正在队列中"，不得误导为规则禁用/配置变更。
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
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
	if err := qm.Enqueue(0, 20, "lb_blocker", "blocker.example.test"); err != nil {
		t.Fatalf("enqueue blocker job: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("blocker execution did not reach the ACME mock")
	}
	if err := qm.Enqueue(0, 21, "lb_active", "active.example.test"); err != nil {
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
