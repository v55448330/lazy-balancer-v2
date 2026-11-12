package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 用户裁定（2026-11-13）：挑战成功（human_pass）是放行结果，不是安全事件——
// 不计入 security_events（避免污染事件日志/统计）；发放/失败仍逐请求落库。
func TestHandleIngestHuman_passNotPersisted(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb-pass','放行规则','http','pass.test',8443,1)`); err != nil {
		t.Fatal(err)
	}
	h := &SecurityEventsIPCServer{}
	body := `[{"ts":1786447300123,"rule_id":"lb-pass","client_ip":"203.0.113.90","method":"GET","uri":"/ok","ua":"Pass/1.0","kind":"pass"}]`
	req := httptest.NewRequest(http.MethodPost, services.SecurityEventsIPCIngestHumanPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type='human'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("human_pass 不得落库，实际 %d 行", n)
	}
}

func TestHandleIngestHuman_challengeAndFailPersisted(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb-cf','挑战规则','http','cf.test',8443,1)`); err != nil {
		t.Fatal(err)
	}
	h := &SecurityEventsIPCServer{}
	body := `[{"ts":1786447300123,"rule_id":"lb-cf","client_ip":"203.0.113.91","method":"GET","uri":"/c","ua":"CF/1.0","kind":"challenge"},{"ts":1786447300456,"rule_id":"lb-cf","client_ip":"203.0.113.91","method":"POST","uri":"/__lb/human/slider-verify","ua":"CF/1.0","kind":"fail"}]`
	req := httptest.NewRequest(http.MethodPost, services.SecurityEventsIPCIngestHumanPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type='human'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("发放/失败必须落库，实际 %d 行", n)
	}
}
