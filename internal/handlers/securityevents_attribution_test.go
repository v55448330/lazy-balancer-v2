package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// F2（安全评审）：归属 SQL 的 stage2 过滤在 ON 子句，非 stage2 绑定以 p.*=NULL
// 存活；规则只有 stage3（WAF）绑定、无 stage2 时，LIMIT 1 会选中 WAF 绑定，
// COALESCE(b.policy_id,0) 返回 WAF 策略 id（名称空）。人机事件 policy_id 必须
// 仅在真实 stage2 匹配时取值，否则为 0。
func TestHumanEventAttribution_nonStage2BindingYieldsZeroPolicy(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb-f2','F2规则','http','f2.test',8443,1)`); err != nil {
		t.Fatal(err)
	}
	// 仅一条 stage3（WAF）绑定，无 stage2。
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,policy_type,mode,enabled) VALUES ('F2WAF策略','stage3','blocking',1)`)
	if err != nil {
		t.Fatal(err)
	}
	wafID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id,rank) VALUES ('lb-f2',?,1)`, wafID); err != nil {
		t.Fatal(err)
	}

	h := &SecurityEventsIPCServer{}
	body := `[{"ts":1786447300123,"rule_id":"lb-f2","client_ip":"203.0.113.60","method":"GET","uri":"/x","ua":"F2/1.0","kind":"challenge"}]`
	req := httptest.NewRequest(http.MethodPost, services.SecurityEventsIPCIngestHumanPath, strings.NewReader(body))
	rec := httptest.NewRecorder()
	http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var gotPID int
	var policyName string
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(policy_id,0),COALESCE(policy_name,'') FROM security_events WHERE rule_caddy_id='lb-f2'`).Scan(&gotPID, &policyName); err != nil {
		t.Fatal(err)
	}
	if gotPID != 0 || policyName != "" {
		t.Fatalf("无 stage2 绑定时人机事件 policy_id 必须为 0，实际=(%d,%q)（不得挂到 WAF 策略 %d）", gotPID, policyName, wafID)
	}
}
