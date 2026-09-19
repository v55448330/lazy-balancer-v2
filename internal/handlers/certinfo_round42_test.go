package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// CERT42-1(第 42 轮审计):批量 GetRulesCertInfo 的 acme_dns 分支在
// SelectRuleCertificate 未选中时直接报「ACME 证书尚未签发或不存在」——
// 单规则路径(CERT40-1)已有「候选全过期按 expired 呈现」回退,批量端点缺
// 同型回退,同一规则在两个端点的过期呈现不一致。修复:共享 helper 两路径同用。
func TestGetRulesCertInfo_reportsExpiredACMECandidate(t *testing.T) {
	// Given:acme_dns 规则 + cert_jobs 候选 PEM 非空但已过期(不可选中)
	h := newBackupTestHandlers(t)
	certPEM, keyPEM, err := generateTestCert("expired-batch.test", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_batch_expired','expired','expired-batch.test','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, updated_at) VALUES ('lb_batch_expired','expired-batch.test','issued',?,?,datetime('now'))`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.POST("/rules/cert-info", h.GetRulesCertInfo)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/rules/cert-info", strings.NewReader(`{"caddy_ids":["lb_batch_expired"]}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then:expired 呈现,不得误报「尚未签发或不存在」
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var resp struct {
		Data map[string]*struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	info := resp.Data["lb_batch_expired"]
	if info == nil {
		t.Fatalf("rule info missing: %s", response.Body.String())
	}
	if info.Status != "expired" || !strings.Contains(info.Error, "已过期") {
		t.Fatalf("status=%q error=%q, want expired + ACME 证书已过期(与单规则路径同口径)", info.Status, info.Error)
	}
}

// 回归形态:无任何候选仍报「尚未签发或不存在」;正常候选照常选中。
func TestGetRulesCertInfo_acmeFallbackRegressions(t *testing.T) {
	h := newBackupTestHandlers(t)
	validPEM, validKey, err := generateTestCert("valid-batch.test", time.Now().Add(-time.Hour), time.Now().Add(720*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES
		('lb_batch_none','none','none.test','http',8081,1,1,'acme_dns'),
		('lb_batch_valid','valid','valid-batch.test','http',8082,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, updated_at) VALUES ('lb_batch_valid','valid-batch.test','issued',?,?,datetime('now'))`, validPEM, validKey); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.POST("/rules/cert-info", h.GetRulesCertInfo)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/rules/cert-info", strings.NewReader(`{"caddy_ids":["lb_batch_none","lb_batch_valid"]}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var resp struct {
		Data map[string]*struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if none := resp.Data["lb_batch_none"]; none == nil || !strings.Contains(none.Error, "尚未签发或不存在") {
		t.Fatalf("no-candidate rule must keep 尚未签发或不存在, got %+v", none)
	}
	if valid := resp.Data["lb_batch_valid"]; valid == nil || valid.Error != "" || valid.Status == "expired" || valid.Status == "unknown" {
		t.Fatalf("valid candidate must be selected without error, got %+v", valid)
	}
}
