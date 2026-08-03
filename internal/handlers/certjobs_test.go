package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

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
