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
	"sync"
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

// TestBindRuleToPolicy_concurrentRuleDeleteLeavesNoDanglingBinding 验证存在性
// 检查与写入同事务（R34 D TOCTOU）：绑定与规则删除并发时，任何交错都不会留下
// 悬挂绑定（check 通过后、INSERT 前规则被删的窗口已关闭）。绑定/删除两端
// 各自使用事务，_txlock=immediate 使写事务在 BEGIN 处串行，断言确定无竞争。
func TestBindRuleToPolicy_concurrentRuleDeleteLeavesNoDanglingBinding(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	policyID := createTestPolicy(t, router, map[string]any{"name": "并发策略", "mode": "blocking", "enabled": true})
	caddyID := "lb_race"
	danglingCount := func() int {
		var n int
		err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings b LEFT JOIN lb_rules r ON b.rule_caddy_id = r.caddy_id WHERE r.caddy_id IS NULL`).Scan(&n)
		if err != nil {
			t.Fatalf("count dangling bindings: %v", err)
		}
		return n
	}
	for i := 0; i < 15; i++ {
		if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES (?, 'race-rule', 'http', 8080, 1)", caddyID); err != nil {
			t.Fatalf("round %d: seed rule: %v", i, err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			// 绑定请求：存在性校验 + DELETE + INSERT 在同一事务内
			postJSON(t, router, "/security/policies/"+strconv.Itoa(policyID)+"/bind", map[string]any{"rule_caddy_id": caddyID})
		}()
		go func() {
			defer wg.Done()
			// 模拟 DeleteRule 的原子清理：绑定与规则同事务删除
			tx, err := db.DB.Begin()
			if err != nil {
				t.Errorf("round %d: begin delete tx: %v", i, err)
				return
			}
			defer tx.Rollback()
			if _, err := tx.Exec("DELETE FROM security_policy_bindings WHERE rule_caddy_id=?", caddyID); err != nil {
				t.Errorf("round %d: delete bindings: %v", i, err)
				return
			}
			if _, err := tx.Exec("DELETE FROM lb_rules WHERE caddy_id=?", caddyID); err != nil {
				t.Errorf("round %d: delete rule: %v", i, err)
				return
			}
			if err := tx.Commit(); err != nil {
				t.Errorf("round %d: commit delete tx: %v", i, err)
			}
		}()
		wg.Wait()
		if n := danglingCount(); n != 0 {
			t.Fatalf("round %d: %d dangling binding(s) after concurrent rule delete", i, n)
		}
	}
}
