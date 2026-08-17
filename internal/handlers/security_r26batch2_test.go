package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func newSecurityR26Router(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.DELETE("/security/policies/:id", h.DeleteSecurityPolicy)
	router.DELETE("/security/block-pages/:id", h.DeleteSecurityBlockPage)
	router.GET("/security/events", h.ListSecurityEvents)
	return router
}

func deleteRequest(t *testing.T, router *gin.Engine, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, path, nil))
	return recorder
}

func TestDeleteSecurityPolicy_removesPolicyAndBindings(t *testing.T) {
	// Given：一个策略与两条规则绑定
	setupSecurityPolicyTestDB(t)
	router := newSecurityR26Router(t)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name) VALUES ('待删策略')`)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	for _, caddyID := range []string{"lb_del_a", "lb_del_b"} {
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)`, caddyID, policyID); err != nil {
			t.Fatalf("seed binding %s: %v", caddyID, err)
		}
	}

	// When
	recorder := deleteRequest(t, router, fmt.Sprintf("/security/policies/%d", policyID))

	// Then：策略与绑定一并删除，不留悬挂绑定
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var policies, bindings int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policies WHERE id=?", policyID).Scan(&policies); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policy_bindings WHERE policy_id=?", policyID).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if policies != 0 || bindings != 0 {
		t.Fatalf("policies=%d bindings=%d, want 0/0", policies, bindings)
	}
}

func TestDeleteSecurityPolicy_missingPolicyReturns404(t *testing.T) {
	// Given：数据库中不存在目标策略
	setupSecurityPolicyTestDB(t)
	router := newSecurityR26Router(t)

	// When
	recorder := deleteRequest(t, router, "/security/policies/999")

	// Then
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("delete status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
	}
}

func TestDeleteSecurityBlockPage_rejectsWhenReferencedByEnabledPolicy(t *testing.T) {
	// Given：一个非默认拦截页面被一个启用的策略引用
	setupSecurityPolicyTestDB(t)
	router := newSecurityR26Router(t)
	res, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, is_default) VALUES ('被引用页面', '<html></html>', 0)`)
	if err != nil {
		t.Fatalf("seed block page: %v", err)
	}
	pageID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, block_page_id, enabled) VALUES ('引用策略', ?, 1)`, pageID); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// When
	recorder := deleteRequest(t, router, fmt.Sprintf("/security/block-pages/%d", pageID))

	// Then：409 拒绝并提示先解绑，页面保留
	if recorder.Code != http.StatusConflict {
		t.Fatalf("delete status=%d body=%s, want 409", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "该拦截页面正被 1 个启用的安全策略使用") {
		t.Fatalf("body=%s, want reference-count message", recorder.Body.String())
	}
	var pages int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE id=?", pageID).Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if pages != 1 {
		t.Fatalf("block page rows=%d, want 1（被引用时不得删除）", pages)
	}
}

func TestDeleteSecurityBlockPage_allowsWhenOnlyDisabledPolicyReferences(t *testing.T) {
	// Given：页面仅被一个停用的策略引用（停用策略不产生拦截配置）
	setupSecurityPolicyTestDB(t)
	router := newSecurityR26Router(t)
	res, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, is_default) VALUES ('停用引用页面', '<html></html>', 0)`)
	if err != nil {
		t.Fatalf("seed block page: %v", err)
	}
	pageID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, block_page_id, enabled) VALUES ('停用策略', ?, 0)`, pageID); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// When
	recorder := deleteRequest(t, router, fmt.Sprintf("/security/block-pages/%d", pageID))

	// Then：允许删除
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
}

func TestDeleteSecurityBlockPage_deletesUnreferencedPage(t *testing.T) {
	// Given：无任何策略引用的非默认页面
	setupSecurityPolicyTestDB(t)
	router := newSecurityR26Router(t)
	res, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, is_default) VALUES ('自由页面', '<html></html>', 0)`)
	if err != nil {
		t.Fatalf("seed block page: %v", err)
	}
	pageID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	// When
	recorder := deleteRequest(t, router, fmt.Sprintf("/security/block-pages/%d", pageID))

	// Then：正常删除
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var pages int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE id=?", pageID).Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if pages != 0 {
		t.Fatalf("block page rows=%d, want 0", pages)
	}
}

func TestListSecurityEvents_ipFilterMatchesExactly(t *testing.T) {
	// Given：两条事件分别来自 1.2.3.4 与 11.2.3.40（LIKE 子串会互相误伤）
	setupSecurityPolicyTestDB(t)
	router := newSecurityR26Router(t)
	seed := func(clientIP string) {
		t.Helper()
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action)
			VALUES ('2026-08-17 10:00:00', 'lb_ip', 1, ?, 'GET', '/a', 'waf', '942100', 'SQL Injection', 'blocked')`, clientIP); err != nil {
			t.Fatalf("seed event %s: %v", clientIP, err)
		}
	}
	seed("1.2.3.4")
	seed("11.2.3.40")

	// When：按完整 IP 1.2.3.4 过滤
	recorder := getRequest(t, router, "/security/events?ip=1.2.3.4")

	// Then：只命中精确匹配的那一条
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data struct {
			Events []struct {
				ClientIP string `json:"client_ip"`
			} `json:"events"`
			Total int `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if resp.Data.Total != 1 || len(resp.Data.Events) != 1 || resp.Data.Events[0].ClientIP != "1.2.3.4" {
		t.Fatalf("filter result=%s, want exactly the 1.2.3.4 event", recorder.Body.String())
	}
}

func TestListSecurityEvents_rejectsInvalidTimeFormat(t *testing.T) {
	for _, param := range []string{"start_time", "end_time"} {
		t.Run(param, func(t *testing.T) {
			// Given：时间参数为无法解析的垃圾值
			setupSecurityPolicyTestDB(t)
			router := newSecurityR26Router(t)

			// When
			recorder := getRequest(t, router, "/security/events?"+param+"=garbage")

			// Then：显式 400 拒绝，而不是静默忽略后返回全量数据
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "时间格式无效") {
				t.Fatalf("body=%s, want 时间格式无效 message", recorder.Body.String())
			}
		})
	}
}
