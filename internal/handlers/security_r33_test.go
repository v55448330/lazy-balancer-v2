package handlers

// allow: SIZE_OK — R33 security-domain handler regression tests (F7 page clamp,
// F10 binding rule existence).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// TestListSecurityEvents_hugePageDoesNot500 验证超大 page 参数被 clamp，
// (page-1)*pageSize 不再整数溢出为负 OFFSET（R33 F7）。
func TestListSecurityEvents_hugePageDoesNot500(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityR26Router(t)
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action)
		VALUES ('2026-08-17 10:00:00', 'lb_pg', 1, '203.0.113.9', 'GET', '/a', 'waf', '942100', 'SQL Injection', 'blocked')`); err != nil {
		t.Fatalf("seed event: %v", err)
	}

	// When：page 为 int64 最大值
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/events?page=9223372036854775807", nil)
	router.ServeHTTP(recorder, req)

	// Then：200 空页而非 500（clamp 到 100000 后 OFFSET 合法）
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Events []json.RawMessage `json:"events"`
			Total  int               `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Code != 0 || resp.Data.Total != 1 || len(resp.Data.Events) != 0 {
		t.Fatalf("response=%s, want code 0 total 1 events empty", recorder.Body.String())
	}
}

// TestListCRSRules_hugePageDoesNot500 验证超大 page 参数被 clamp，
// allRules[start:end] 不再越界 panic（R33 F7）。
func TestListCRSRules_hugePageDoesNot500(t *testing.T) {
	oldDir := crsRulesDir
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-901-INITIALIZATION.conf"), []byte("# stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	crsRulesDir = dir
	t.Cleanup(func() { crsRulesDir = oldDir })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/crs/rules", (&Handlers{}).ListCRSRules)

	// When：page 为 int64 最大值
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/crs/rules?page=9223372036854775807", nil)
	router.ServeHTTP(recorder, req)

	// Then：200 空列表而非 panic（clamp 后 start=total）
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Rules []json.RawMessage `json:"rules"`
			Total int               `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp.Code != 0 || resp.Data.Total != 1 || len(resp.Data.Rules) != 0 {
		t.Fatalf("response=%s, want code 0 total 1 rules empty", recorder.Body.String())
	}
}

// TestBindRuleToPolicy_rejectsMissingRule 验证绑定前校验规则真实存在（R33 F10）。
func TestBindRuleToPolicy_rejectsMissingRule(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	policyID := createTestPolicy(t, router, map[string]any{"name": "存在策略", "mode": "blocking", "enabled": true})

	// When：绑定一个不存在的规则 id
	recorder := postJSON(t, router, "/security/policies/"+strconv.Itoa(policyID)+"/bind", map[string]any{"rule_caddy_id": "lb_ghost"})

	// Then：400 拒绝且无悬挂绑定写入
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("bind status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_ghost'").Scan(&count); err != nil {
		t.Fatalf("count bindings: %v", err)
	}
	if count != 0 {
		t.Fatalf("dangling binding written for missing rule")
	}
}
