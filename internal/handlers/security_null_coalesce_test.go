package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// C5 NULL 容忍残余（B5 I-C / C5 IMP-3 / C5 SUG-1）：handler 端点裸扫描可空列，
// 一行 NULL → 该端点 500。本文件三测试分别钉住三处修复：
//   FIX 1 GetSecurityPolicyBindings 逐策略查询改用 securityPolicySelectColumns
//   FIX 2 DeleteSecurityCustomRule 引用检查 COALESCE(custom_rules,'[]')
//   FIX 3 List/Update 自定义规则与拦截页裸扫描列 COALESCE（对齐 cluster_snapshot dump 侧）

// newNullCoalesceRouter 注册本文件三测试所需的全部端点。
func newNullCoalesceRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.GET("/security/rules/:caddy_id/policy", h.GetSecurityPolicyBindings)
	router.GET("/security/custom-rules", h.ListSecurityCustomRules)
	router.PUT("/security/custom-rules/:id", h.UpdateSecurityCustomRule)
	router.DELETE("/security/custom-rules/:id", h.DeleteSecurityCustomRule)
	router.GET("/security/block-pages", h.ListSecurityBlockPages)
	router.PUT("/security/block-pages/:id", h.UpdateSecurityBlockPage)
	router.DELETE("/security/block-pages/:id", h.DeleteSecurityBlockPage)
	return router
}

// FIX 1（B5 I-C）：GetSecurityPolicyBindings 的逐策略查询与 securityPolicySelectColumns
// 同 25 列但无 COALESCE——绑定策略任一可空列（如 description）为 NULL 时整列表 500。
// 修复后按常量投影返回 200 与该策略的默认值形态。
func TestGetSecurityPolicyBindings_nullPolicyColumnsReturn200(t *testing.T) {
	// Given：一条 HTTP 规则绑定一条 description（及其余可空列）为 NULL 的启用策略
	setupSecurityPolicyTestDB(t)
	router := newNullCoalesceRouter(t)
	seedHTTPRule(t, "lb_null_bind")
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, description, enabled) VALUES ('null策略', NULL, 1)`)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_null_bind', ?)`, policyID); err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	// When：读取该规则的策略绑定列表
	recorder := getRequest(t, router, "/security/rules/lb_null_bind/policy")

	// Then：200 且返回该策略（可空列按 COALESCE 默认值呈现），不得 500
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET bindings status=%d body=%s, want 200（NULL 可空列不得拖垮整接口）", recorder.Code, recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(strconv.FormatInt(policyID, 10))) {
		t.Fatalf("body=%s, want 含策略 #%d", recorder.Body.String(), policyID)
	}
}

// FIX 2（C5 IMP-3）：DeleteSecurityCustomRule 引用检查裸扫 custom_rules——任一启用
// 策略该列为 NULL 时扫描报错 500，全部自定义规则删除被阻断。修复后 COALESCE '[]'
// 落入既有的「不可解析→跳过」分支，删除按引用检查通过放行。
func TestDeleteSecurityCustomRule_nullCustomRulesPolicyDoesNot500(t *testing.T) {
	// Given：一条自定义规则 + 一条 custom_rules=NULL 的启用策略（不构成 ID 引用）
	setupSecurityPolicyTestDB(t)
	router := newNullCoalesceRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('待删规则', '[]', 'block', 5, 1)`)
	if err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}
	ruleID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, custom_rules, enabled) VALUES ('null引用策略', NULL, 1)`); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// When：删除该自定义规则
	recorder := deleteRequest(t, router, fmt.Sprintf("/security/custom-rules/%d", ruleID))

	// Then：引用检查通过（NULL 按 '[]' 处理、无 ID 引用），删除放行 200，不得 500
	if recorder.Code == http.StatusInternalServerError {
		t.Fatalf("delete status=500 body=%s（NULL custom_rules 不得阻断删除）", recorder.Body.String())
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
}

// FIX 3（C5 SUG-1）：List/Update 自定义规则与拦截页的裸扫描可空列，一行 NULL →
// 对应端点 500。修复后四个端点对同一 NULL 种子行均不得 500（List 返默认值 200，
// Update 读-合并-写放行 200）。
func TestSecurityEntityEndpoints_nullColumnsDoNot500(t *testing.T) {
	// Given：一条 description/action 为 NULL 的自定义规则 + 一条 description/is_default
	// 为 NULL 的拦截页（action/is_default 的 NULL 是 Update 读路径今天 500 的根因；
	// conditions 保持有效数组使修复后 Update 合并结果通过校验返回 200）
	setupSecurityPolicyTestDB(t)
	router := newNullCoalesceRouter(t)
	ruleRes, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, description, conditions, action, score, enabled) VALUES ('null规则', NULL, '[{"target":"uri","operator":"contains","pattern":"/x"}]', NULL, 5, 1)`)
	if err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}
	ruleID, err := ruleRes.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	pageRes, err := db.DB.Exec(`INSERT INTO security_block_pages (name, description, content, is_default) VALUES ('null拦截页', NULL, 'x', NULL)`)
	if err != nil {
		t.Fatalf("seed block page: %v", err)
	}
	pageID, err := pageRes.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	// When/Then：四个端点均不得 500（逐端点记录，一次性报告全部失败面）
	statuses := map[string]int{}
	statuses["GET /security/custom-rules"] = getRequest(t, router, "/security/custom-rules").Code
	statuses[fmt.Sprintf("PUT /security/custom-rules/%d", ruleID)] = putJSON(t, router, fmt.Sprintf("/security/custom-rules/%d", ruleID), map[string]any{"name": "null规则改名"}).Code
	statuses["GET /security/block-pages"] = getRequest(t, router, "/security/block-pages").Code
	statuses[fmt.Sprintf("PUT /security/block-pages/%d", pageID)] = putJSON(t, router, fmt.Sprintf("/security/block-pages/%d", pageID), map[string]any{"name": "null拦截页改名", "content": "x"}).Code
	for endpoint, code := range statuses {
		if code == http.StatusInternalServerError {
			t.Errorf("%s status=500（NULL 可空列不得拖垮端点）", endpoint)
		}
	}
}
