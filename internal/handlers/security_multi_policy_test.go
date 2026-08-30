package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// T2（v2.2.0 多策略绑定）：一规则绑多策略的 RED 测试。
// 覆盖：POST additive（SC-BIND-02）、PUT 原子替换（SC-BIND-01，max5/单 ID/审计/
// 排序）、DELETE 精确 unbind（SC-BIND-03）、GET 数组有序（SC-GET-01/02）。

func newMultiPolicyRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.POST("/security/policies", h.CreateSecurityPolicy)
	router.DELETE("/security/policies/:id", h.DeleteSecurityPolicy)
	router.POST("/security/policies/:id/bind", h.BindRuleToPolicy)
	router.DELETE("/security/policies/:id/bind/:caddy_id", h.UnbindRuleFromPolicy)
	router.PUT("/security/rules/:caddy_id/policies", h.SetRuleSecurityPolicies)
	router.GET("/security/rules/:caddy_id/policy", h.GetSecurityPolicyBindings)
	router.GET("/security/bindings", h.GetAllSecurityBindings)
	return router
}

func seedHTTPRule(t *testing.T, caddyID string) {
	t.Helper()
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES (?, 'mp-rule', 'http', 8080, 1)", caddyID); err != nil {
		t.Fatalf("seed http rule %s: %v", caddyID, err)
	}
}

func seedTCPRule(t *testing.T, caddyID string) {
	t.Helper()
	if _, err := db.DB.Exec("INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, enabled) VALUES (?, 'mp-tcp-rule', 'tcp', 9000, 1)", caddyID); err != nil {
		t.Fatalf("seed tcp rule %s: %v", caddyID, err)
	}
}

func createMultiPolicy(t *testing.T, router *gin.Engine, name string) int {
	t.Helper()
	recorder := postJSON(t, router, "/security/policies", map[string]any{"name": name, "mode": "blocking", "enabled": true})
	if recorder.Code != http.StatusOK {
		t.Fatalf("create policy %s status=%d body=%s", name, recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse create response: %v", err)
	}
	return resp.Data.ID
}

func putMultiJSON(t *testing.T, router *gin.Engine, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)
	return recorder
}

func queryBoundPolicyIDs(t *testing.T, caddyID string) []int {
	t.Helper()
	rows, err := db.DB.Query("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id ASC", caddyID)
	if err != nil {
		t.Fatalf("query bound policies: %v", err)
	}
	defer rows.Close()
	ids := []int{}
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan bound policy: %v", err)
		}
		ids = append(ids, id)
	}
	return ids
}

func assertIDSlice(t *testing.T, got []int, want []int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("bound policy ids=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("bound policy ids=%v, want %v", got, want)
		}
	}
}

// SC-BIND-02：POST bind 改为 additive——绑定 A 后再绑 B，A 必须保留。
func TestBindRuleToPolicy_additivePreservesSiblingBindings(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_add")
	policyA := createMultiPolicy(t, router, "策略A")
	policyB := createMultiPolicy(t, router, "策略B")

	if r := postJSON(t, router, "/security/policies/"+strconv.Itoa(policyA)+"/bind", map[string]any{"rule_caddy_id": "lb_mp_add"}); r.Code != http.StatusOK {
		t.Fatalf("bind A status=%d body=%s", r.Code, r.Body.String())
	}
	if r := postJSON(t, router, "/security/policies/"+strconv.Itoa(policyB)+"/bind", map[string]any{"rule_caddy_id": "lb_mp_add"}); r.Code != http.StatusOK {
		t.Fatalf("bind B status=%d body=%s", r.Code, r.Body.String())
	}

	got := queryBoundPolicyIDs(t, "lb_mp_add")
	want := []int{policyA, policyB}
	if policyB < policyA {
		want = []int{policyB, policyA}
	}
	assertIDSlice(t, got, want)
}

// SC-BIND-01：PUT 原子替换 + 按序返回（写入 [3,1,2]，DB 按 policy_id ASC 读出 [1,2,3]）。
func TestSetRuleSecurityPolicies_replacesAtomicallyOrderedASC(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_put")
	p1 := createMultiPolicy(t, router, "策略1")
	p2 := createMultiPolicy(t, router, "策略2")
	p3 := createMultiPolicy(t, router, "策略3")

	// 以乱序 [p3,p1,p2] 提交，服务端按 INSERT 顺序写入；读回按 policy_id ASC。
	recorder := putMultiJSON(t, router, "/security/rules/lb_mp_put/policies", map[string]any{"policy_ids": []int{p3, p1, p2}})
	if recorder.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}

	sorted := []int{p1, p2, p3}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_put"), sorted)

	// 再次 PUT [p2] 原子替换：删除旧三行，仅留 p2。
	recorder = putMultiJSON(t, router, "/security/rules/lb_mp_put/policies", map[string]any{"policy_ids": []int{p2}})
	if recorder.Code != http.StatusOK {
		t.Fatalf("second PUT status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_put"), []int{p2})
}

// SC-BIND-01：超过 5 条策略 → 400「最多绑定 5 条策略」。
func TestSetRuleSecurityPolicies_rejectsMoreThanFive(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_max")
	ids := []int{}
	for i := 1; i <= 6; i++ {
		ids = append(ids, createMultiPolicy(t, router, fmt.Sprintf("策略%d", i)))
	}
	recorder := putMultiJSON(t, router, "/security/rules/lb_mp_max/policies", map[string]any{"policy_ids": ids})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("PUT status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte("最多绑定")) {
		t.Fatalf("PUT body=%s, want message containing 最多绑定", recorder.Body.String())
	}
	if got := queryBoundPolicyIDs(t, "lb_mp_max"); len(got) != 0 {
		t.Fatalf("rejected PUT wrote bindings: %v", got)
	}
}

// SC-BIND-01 边界（B-I2）：上限判定须先去重——[1,1,2,3,4,5] 为 5 条唯一策略，
// 不得因原始数组长度 6 误判超限；写入结果按 policy_id ASC 去重后为 5 行。
func TestSetRuleSecurityPolicies_dedupsBeforeMaxFiveCheck(t *testing.T) {
	// Given 5 条策略与一条 HTTP 规则
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_dedup")
	ids := []int{}
	for i := 1; i <= 5; i++ {
		ids = append(ids, createMultiPolicy(t, router, fmt.Sprintf("策略%d", i)))
	}

	// When PUT 携带重复 id 的 6 元素数组（5 条唯一）
	recorder := putMultiJSON(t, router, "/security/rules/lb_mp_dedup/policies", map[string]any{"policy_ids": []int{ids[0], ids[0], ids[1], ids[2], ids[3], ids[4]}})

	// Then 接受 200，绑定为去重后的 5 条
	if recorder.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_dedup"), ids)
}

// SC-BIND-01：单元素 policy_ids 向后兼容（PUT [1] 与 POST bind 等价行为）。
func TestSetRuleSecurityPolicies_singleIDBackwardsCompatible(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_single")
	p := createMultiPolicy(t, router, "单条策略")
	recorder := putMultiJSON(t, router, "/security/rules/lb_mp_single/policies", map[string]any{"policy_ids": []int{p}})
	if recorder.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_single"), []int{p})
}

// PUT 含不存在的 policy_id → 400。
func TestSetRuleSecurityPolicies_rejectsMissingPolicyID(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_ghost")
	p := createMultiPolicy(t, router, "真实策略")
	recorder := putMultiJSON(t, router, "/security/rules/lb_mp_ghost/policies", map[string]any{"policy_ids": []int{p, 99999}})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("PUT status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if got := queryBoundPolicyIDs(t, "lb_mp_ghost"); len(got) != 0 {
		t.Fatalf("rejected PUT wrote bindings: %v", got)
	}
}

// PUT 到不存在的规则 → 400。
func TestSetRuleSecurityPolicies_rejectsMissingRule(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	p := createMultiPolicy(t, router, "策略")
	recorder := putMultiJSON(t, router, "/security/rules/lb_no_such/policies", map[string]any{"policy_ids": []int{p}})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("PUT status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
}

// PUT 到 TCP 规则 → 400（与 BindRuleToPolicy 同口径）。
func TestSetRuleSecurityPolicies_rejectsNonHTTPRule(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedTCPRule(t, "lb_mp_tcp")
	p := createMultiPolicy(t, router, "策略")
	recorder := putMultiJSON(t, router, "/security/rules/lb_mp_tcp/policies", map[string]any{"policy_ids": []int{p}})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("PUT status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
}

// SC-BIND-03：DELETE unbind 精确删一行——[A,B] 解绑 A 后只剩 B。
func TestUnbindRuleFromPolicy_removesOnlyTargetRow(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_unbind")
	policyA := createMultiPolicy(t, router, "策略A")
	policyB := createMultiPolicy(t, router, "策略B")
	if r := putMultiJSON(t, router, "/security/rules/lb_mp_unbind/policies", map[string]any{"policy_ids": []int{policyA, policyB}}); r.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", r.Code, r.Body.String())
	}

	recorder := deleteRequest(t, router, "/security/policies/"+strconv.Itoa(policyA)+"/bind/lb_mp_unbind")
	if recorder.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_unbind"), []int{policyB})
}

// SC-GET-01：GET /security/rules/:caddy_id/policy 返回 []policy 按 id ASC。
func TestGetSecurityPolicyBindings_returnsOrderedArray(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_get")
	p1 := createMultiPolicy(t, router, "策略1")
	p2 := createMultiPolicy(t, router, "策略2")
	p3 := createMultiPolicy(t, router, "策略3")
	if r := putMultiJSON(t, router, "/security/rules/lb_mp_get/policies", map[string]any{"policy_ids": []int{p3, p1, p2}}); r.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", r.Code, r.Body.String())
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/rules/lb_mp_get/policy", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse GET response %s: %v", recorder.Body.String(), err)
	}
	if len(resp.Data) != 3 {
		t.Fatalf("GET data len=%d, want 3 (array)", len(resp.Data))
	}
	got := []int{resp.Data[0].ID, resp.Data[1].ID, resp.Data[2].ID}
	assertIDSlice(t, got, []int{p1, p2, p3})
}

// SC-GET-01 边界：规则无绑定时返回空数组（不是 null 单对象）。
func TestGetSecurityPolicyBindings_emptyArrayWhenNoBindings(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_empty")

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/rules/lb_mp_empty/policy", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int              `json:"code"`
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse GET response %s: %v", recorder.Body.String(), err)
	}
	if resp.Data == nil {
		t.Fatalf("GET data=null, want empty array []")
	}
	if len(resp.Data) != 0 {
		t.Fatalf("GET data len=%d, want 0", len(resp.Data))
	}
}

// SC-GET-02：GET /security/bindings 返回 map[string][]BindingInfo 按 policy_id ASC。
func TestGetAllSecurityBindings_returnsArrayPerRule(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_all_a")
	seedHTTPRule(t, "lb_mp_all_b")
	p1 := createMultiPolicy(t, router, "策略1")
	p2 := createMultiPolicy(t, router, "策略2")
	p3 := createMultiPolicy(t, router, "策略3")
	if r := putMultiJSON(t, router, "/security/rules/lb_mp_all_a/policies", map[string]any{"policy_ids": []int{p3, p1}}); r.Code != http.StatusOK {
		t.Fatalf("PUT a status=%d body=%s", r.Code, r.Body.String())
	}
	if r := putMultiJSON(t, router, "/security/rules/lb_mp_all_b/policies", map[string]any{"policy_ids": []int{p2}}); r.Code != http.StatusOK {
		t.Fatalf("PUT b status=%d body=%s", r.Code, r.Body.String())
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/bindings", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data map[string][]struct {
			PolicyID int    `json:"policy_id"`
			Name     string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse GET /security/bindings response %s: %v", recorder.Body.String(), err)
	}
	if len(resp.Data["lb_mp_all_a"]) != 2 {
		t.Fatalf("lb_mp_all_a bindings len=%d, want 2", len(resp.Data["lb_mp_all_a"]))
	}
	if resp.Data["lb_mp_all_a"][0].PolicyID != p1 || resp.Data["lb_mp_all_a"][1].PolicyID != p3 {
		t.Fatalf("lb_mp_all_a order=[%d,%d], want [%d,%d] ASC",
			resp.Data["lb_mp_all_a"][0].PolicyID, resp.Data["lb_mp_all_a"][1].PolicyID, p1, p3)
	}
	if len(resp.Data["lb_mp_all_b"]) != 1 || resp.Data["lb_mp_all_b"][0].PolicyID != p2 {
		t.Fatalf("lb_mp_all_b bindings=%+v, want single %d", resp.Data["lb_mp_all_b"], p2)
	}
}

// SC-BIND-01：PUT 替换写审计日志（action=更新 / resource=安全策略 / detail 含规则与策略列表）。
func TestSetRuleSecurityPolicies_writesAuditLog(t *testing.T) {
	// Given 一条 HTTP 规则与两条策略
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_audit")
	p1 := createMultiPolicy(t, router, "审计策略1")
	p2 := createMultiPolicy(t, router, "审计策略2")

	// When PUT 原子替换绑定
	recorder := putMultiJSON(t, router, "/security/rules/lb_mp_audit/policies", map[string]any{"policy_ids": []int{p1, p2}})

	// Then 200 且审计库写入对应行
	if recorder.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var action, resource, detail string
	if err := db.AuditDB.QueryRow("SELECT action, resource, detail FROM audit_log WHERE resource='安全策略' ORDER BY id DESC LIMIT 1").Scan(&action, &resource, &detail); err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if action != "更新" || resource != "安全策略" {
		t.Fatalf("audit action=%q resource=%q, want 更新/安全策略", action, resource)
	}
	wantDetail := "设置规则 lb_mp_audit 的安全策略为"
	if !strings.Contains(detail, wantDetail) {
		t.Fatalf("audit detail=%q, want containing %q", detail, wantDetail)
	}
}

// SC-BIND-01 契约补全：PUT 空数组 policy_ids=[] = 解除该规则全部绑定——
// 200 + GET 空数组 + DB 0 行 + 审计日志（与 apidocs/MCP schema 的空数组语义对齐）。
func TestSetRuleSecurityPolicies_emptyArrayUnbindsAll(t *testing.T) {
	// Given 规则已绑定两条策略
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_unbind_all")
	p1 := createMultiPolicy(t, router, "策略1")
	p2 := createMultiPolicy(t, router, "策略2")
	if r := putMultiJSON(t, router, "/security/rules/lb_mp_unbind_all/policies", map[string]any{"policy_ids": []int{p1, p2}}); r.Code != http.StatusOK {
		t.Fatalf("seed PUT status=%d body=%s", r.Code, r.Body.String())
	}
	if got := queryBoundPolicyIDs(t, "lb_mp_unbind_all"); len(got) != 2 {
		t.Fatalf("seed bindings=%v, want 2 rows", got)
	}

	// When PUT 空数组
	recorder := putMultiJSON(t, router, "/security/rules/lb_mp_unbind_all/policies", map[string]any{"policy_ids": []int{}})

	// Then 200 且 DB 绑定行清零
	if recorder.Code != http.StatusOK {
		t.Fatalf("PUT [] status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var boundCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id=?", "lb_mp_unbind_all").Scan(&boundCount); err != nil {
		t.Fatalf("count bindings: %v", err)
	}
	if boundCount != 0 {
		t.Fatalf("bindings after unbind-all=%d, want 0", boundCount)
	}

	// And GET 返回空数组（非 null）
	recorder = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/rules/lb_mp_unbind_all/policy", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int              `json:"code"`
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse GET response %s: %v", recorder.Body.String(), err)
	}
	if resp.Data == nil {
		t.Fatalf("GET data=null, want empty array []")
	}
	if len(resp.Data) != 0 {
		t.Fatalf("GET data len=%d, want 0", len(resp.Data))
	}

	// And 审计日志记录解除全部绑定
	var action, resource, detail string
	if err := db.AuditDB.QueryRow("SELECT action, resource, detail FROM audit_log WHERE resource='安全策略' ORDER BY id DESC LIMIT 1").Scan(&action, &resource, &detail); err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if action != "更新" || resource != "安全策略" {
		t.Fatalf("audit action=%q resource=%q, want 更新/安全策略", action, resource)
	}
	wantDetail := "设置规则 lb_mp_unbind_all 的安全策略为 [全部解除]"
	if detail != wantDetail {
		t.Fatalf("audit detail=%q, want %q", detail, wantDetail)
	}
}

// 排序边界：POST additive 乱序绑定（先绑高 id 再绑低 id），两个 GET 端点仍按 policy_id ASC 返回。
func TestBindRuleToPolicy_outOfOrderBindStillReadsASC(t *testing.T) {
	// Given 两条策略（pLow < pHigh，按创建序天然成立）
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_ooo")
	pLow := createMultiPolicy(t, router, "低ID策略")
	pHigh := createMultiPolicy(t, router, "高ID策略")
	if pLow >= pHigh {
		t.Fatalf("fixture broken: pLow=%d pHigh=%d, want pLow < pHigh", pLow, pHigh)
	}

	// When 先绑高 id 再绑低 id（插入序与 id 序相反）
	if r := postJSON(t, router, "/security/policies/"+strconv.Itoa(pHigh)+"/bind", map[string]any{"rule_caddy_id": "lb_mp_ooo"}); r.Code != http.StatusOK {
		t.Fatalf("bind high status=%d body=%s", r.Code, r.Body.String())
	}
	if r := postJSON(t, router, "/security/policies/"+strconv.Itoa(pLow)+"/bind", map[string]any{"rule_caddy_id": "lb_mp_ooo"}); r.Code != http.StatusOK {
		t.Fatalf("bind low status=%d body=%s", r.Code, r.Body.String())
	}

	// Then GET /security/rules/:caddy_id/policy 按 policy_id ASC
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/rules/lb_mp_ooo/policy", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var ruleResp struct {
		Code int `json:"code"`
		Data []struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &ruleResp); err != nil {
		t.Fatalf("parse GET response %s: %v", recorder.Body.String(), err)
	}
	if len(ruleResp.Data) != 2 || ruleResp.Data[0].ID != pLow || ruleResp.Data[1].ID != pHigh {
		t.Fatalf("GET policy ids=%+v, want [%d,%d] ASC", ruleResp.Data, pLow, pHigh)
	}

	// And GET /security/bindings 同样 ASC
	recorder = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/security/bindings", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /security/bindings status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var allResp struct {
		Code int `json:"code"`
		Data map[string][]struct {
			PolicyID int `json:"policy_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &allResp); err != nil {
		t.Fatalf("parse GET /security/bindings response %s: %v", recorder.Body.String(), err)
	}
	got := allResp.Data["lb_mp_ooo"]
	if len(got) != 2 || got[0].PolicyID != pLow || got[1].PolicyID != pHigh {
		t.Fatalf("GET /security/bindings ids=%+v, want [%d,%d] ASC", got, pLow, pHigh)
	}
}

// SC-GET-01 实现口径：GET /security/rules/:caddy_id/policy 仅返回 enabled=1 的策略
// （handler 逐条 SELECT ... WHERE id=? AND enabled=1，禁用的绑定项被跳过）。
func TestGetSecurityPolicyBindings_skipsDisabledPolicies(t *testing.T) {
	// Given 规则绑定两条策略，其中一条随后被禁用
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_disabled")
	pEnabled := createMultiPolicy(t, router, "启用策略")
	pDisabled := createMultiPolicy(t, router, "禁用策略")
	if r := putMultiJSON(t, router, "/security/rules/lb_mp_disabled/policies", map[string]any{"policy_ids": []int{pEnabled, pDisabled}}); r.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", r.Code, r.Body.String())
	}
	if _, err := db.DB.Exec("UPDATE security_policies SET enabled=0 WHERE id=?", pDisabled); err != nil {
		t.Fatalf("disable policy: %v", err)
	}

	// When GET 规则的策略列表
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/rules/lb_mp_disabled/policy", nil)
	router.ServeHTTP(recorder, req)

	// Then 仅返回启用策略（绑定行仍在，但响应跳过禁用项）
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse GET response %s: %v", recorder.Body.String(), err)
	}
	if len(resp.Data) != 1 || resp.Data[0].ID != pEnabled {
		t.Fatalf("GET policy ids=%+v, want only enabled [%d]", resp.Data, pEnabled)
	}
}

// SC-CAS-01：删除策略仅清该策略的绑定行——同规则上兄弟策略的绑定保留。
func TestDeleteSecurityPolicy_preservesSiblingPolicyBindingsOnSameRules(t *testing.T) {
	// Given 两条规则各自绑定策略 X 与 Y
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_cas_a")
	seedHTTPRule(t, "lb_mp_cas_b")
	policyX := createMultiPolicy(t, router, "策略X")
	policyY := createMultiPolicy(t, router, "策略Y")
	for _, ruleID := range []string{"lb_mp_cas_a", "lb_mp_cas_b"} {
		if r := putMultiJSON(t, router, "/security/rules/"+ruleID+"/policies", map[string]any{"policy_ids": []int{policyX, policyY}}); r.Code != http.StatusOK {
			t.Fatalf("PUT %s status=%d body=%s", ruleID, r.Code, r.Body.String())
		}
	}

	// When 删除策略 X
	recorder := deleteRequest(t, router, "/security/policies/"+strconv.Itoa(policyX))

	// Then X 的绑定全清，两规则上 Y 的绑定原样保留
	if recorder.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_cas_a"), []int{policyY})
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_cas_b"), []int{policyY})
}

// SC-CAS-02：删除 LB 规则仅清该规则的绑定行——同策略上兄弟规则的绑定保留。
func TestDeleteRule_preservesOtherRulesBindingsOnSamePolicy(t *testing.T) {
	// Given 两条规则绑定同一策略
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_mp_del_a", "dela", "dela.example.test", 8080, true, "manual", false)
	seedAuditUpstream(t, "lb_mp_del_a")
	seedAuditRule(t, "lb_mp_del_b", "delb", "delb.example.test", 8081, true, "manual", false)
	seedAuditUpstream(t, "lb_mp_del_b")
	res, err := db.DB.Exec(`INSERT INTO security_policies (name) VALUES ('共享策略')`)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("policy id: %v", err)
	}
	for _, ruleID := range []string{"lb_mp_del_a", "lb_mp_del_b"} {
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)`, ruleID, policyID); err != nil {
			t.Fatalf("seed binding %s: %v", ruleID, err)
		}
	}
	router := gin.New()
	router.DELETE("/rules/:caddy_id", handler.DeleteRule)

	// When 删除其中一条规则
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/rules/lb_mp_del_a", nil))

	// Then 该规则绑定清空，兄弟规则在同一策略上的绑定保留
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_del_a"), []int{})
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_del_b"), []int{int(policyID)})
}

// Max-5 服务端守卫（B-I1）：POST additive 与 PUT 同上限——规则已绑满 5 条时
// POST 第 6 条（新策略对）→ 400「最多绑定 5 条策略」；重绑已存在的 (rule,policy)
// 对保持幂等 200（INSERT OR IGNORE 不产生新行）。
func TestBindRuleToPolicy_postAdditiveRejectsSixthBinding(t *testing.T) {
	// Given 规则已通过 PUT 绑满 5 条策略
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_six")
	ids := []int{}
	for i := 1; i <= 5; i++ {
		ids = append(ids, createMultiPolicy(t, router, fmt.Sprintf("策略%d", i)))
	}
	if r := putMultiJSON(t, router, "/security/rules/lb_mp_six/policies", map[string]any{"policy_ids": ids}); r.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", r.Code, r.Body.String())
	}
	p6 := createMultiPolicy(t, router, "第六策略")

	// When POST additive 绑定第 6 条（新策略对）
	recorder := postJSON(t, router, "/security/policies/"+strconv.Itoa(p6)+"/bind", map[string]any{"rule_caddy_id": "lb_mp_six"})

	// Then 服务端拒绝 400，绑定仍为 5 条
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("POST 6th bind status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte("最多绑定 5 条策略")) {
		t.Fatalf("POST 6th bind body=%s, want message containing 最多绑定 5 条策略", recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_six"), ids)

	// When 重绑已存在的 (rule,policy) 对
	recorder = postJSON(t, router, "/security/policies/"+strconv.Itoa(ids[0])+"/bind", map[string]any{"rule_caddy_id": "lb_mp_six"})

	// Then 幂等 200，绑定集合不变
	if recorder.Code != http.StatusOK {
		t.Fatalf("re-bind existing pair status=%d body=%s, want 200 (idempotent)", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_six"), ids)
}

// SC-GET-02 扩展（D-I1）：GET /security/bindings 每绑定携带 block_page_id——前端
// 据此计算「首个启用且配置了拦截页面的策略」，与后端生成口径（首个 enabled 且
// block_page_id>0）一致，前导策略 block_page_id=0 时不得误判。
func TestGetAllSecurityBindings_includesBlockPageID(t *testing.T) {
	// Given 一条规则按序绑定两条策略：首策略无拦截页面，次策略 block_page_id=7
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_bpid")
	p1 := createMultiPolicy(t, router, "无页策略")
	p2 := createMultiPolicy(t, router, "有页策略")
	if _, err := db.DB.Exec("UPDATE security_policies SET block_page_id=7 WHERE id=?", p2); err != nil {
		t.Fatalf("set block_page_id: %v", err)
	}
	if r := putMultiJSON(t, router, "/security/rules/lb_mp_bpid/policies", map[string]any{"policy_ids": []int{p1, p2}}); r.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", r.Code, r.Body.String())
	}

	// When GET /security/bindings
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/bindings", nil)
	router.ServeHTTP(recorder, req)

	// Then 每条绑定携带 block_page_id：首条 0，次条 7
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data map[string][]struct {
			PolicyID    int `json:"policy_id"`
			BlockPageID int `json:"block_page_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse bindings response %s: %v", recorder.Body.String(), err)
	}
	entries := resp.Data["lb_mp_bpid"]
	if len(entries) != 2 {
		t.Fatalf("bindings=%+v, want 2 entries", entries)
	}
	if entries[0].PolicyID != p1 || entries[0].BlockPageID != 0 {
		t.Fatalf("entries[0]=%+v, want policy_id=%d block_page_id=0", entries[0], p1)
	}
	if entries[1].PolicyID != p2 || entries[1].BlockPageID != 7 {
		t.Fatalf("entries[1]=%+v, want policy_id=%d block_page_id=7", entries[1], p2)
	}
}

// A-I2 硬化（GetAllSecurityBindings）：绑定 JOIN 的 p.block_page_id 可空——
// 带外编辑/备份恢复/集群继承产生 NULL 时，修复前行 Scan 报错被 continue 静默
// 跳过，绑定从 UI 地图中消失；修复后 COALESCE 归一化为 0，绑定照常返回。
func TestGetAllSecurityBindings_toleratesNullBlockPageID(t *testing.T) {
	// Given 一条绑定到 block_page_id 为 NULL 策略的规则
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_null_bpid")
	result, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, block_page_id)
		VALUES ('null-page', 'blocking', 1, NULL)`)
	if err != nil {
		t.Fatalf("seed null-block-page policy: %v", err)
	}
	policyID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read policy id: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id)
		VALUES ('lb_null_bpid', ?)`, policyID); err != nil {
		t.Fatalf("bind null-block-page policy: %v", err)
	}

	// When GET /security/bindings
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/bindings", nil)
	router.ServeHTTP(recorder, req)

	// Then 绑定照常返回，block_page_id 归一化为 0
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data map[string][]struct {
			PolicyID    int `json:"policy_id"`
			BlockPageID int `json:"block_page_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse bindings response %s: %v", recorder.Body.String(), err)
	}
	entries := resp.Data["lb_null_bpid"]
	if len(entries) != 1 {
		t.Fatalf("NULL block_page_id 不得静默丢绑定（A-I2）: bindings=%+v, want 1 entry", resp.Data)
	}
	if entries[0].PolicyID != int(policyID) || entries[0].BlockPageID != 0 {
		t.Fatalf("entries[0]=%+v, want policy_id=%d block_page_id=0", entries[0], policyID)
	}
}

// queryBindingEntries 请求 GET /security/bindings 并返回指定规则的绑定行；
// 200 以外的状态码直接失败（绑定行不得因 NULL 列静默消失，也不得拖垮接口）。
func queryBindingEntries(t *testing.T, router *gin.Engine, caddyID string) []struct {
	PolicyID  int    `json:"policy_id"`
	Mode      string `json:"mode"`
	Enabled   bool   `json:"enabled"`
	RateLimit bool   `json:"rate_limit_enabled"`
} {
	t.Helper()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/bindings", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data map[string][]struct {
			PolicyID  int    `json:"policy_id"`
			Mode      string `json:"mode"`
			Enabled   bool   `json:"enabled"`
			RateLimit bool   `json:"rate_limit_enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse bindings response %s: %v", recorder.Body.String(), err)
	}
	return resp.Data[caddyID]
}

func bindPolicyToRule(t *testing.T, caddyID string, policyID int64) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id)
		VALUES (?, ?)`, caddyID, policyID); err != nil {
		t.Fatalf("bind policy %d to %s: %v", policyID, caddyID, err)
	}
}

// I-3 硬化（GetAllSecurityBindings）：p.mode 可空——修复前仅 block_page_id 有
// COALESCE，NULL mode 触发 Scan 报错被跳过（绑定从 UI 地图消失），而生成路径
// 按 COALESCE(mode,'off') 口径正常应用该策略。
func TestGetAllSecurityBindings_toleratesNullMode(t *testing.T) {
	// Given 一条绑定到 mode 为 NULL 策略的规则
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_null_mode")
	result, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled) VALUES ('null-mode', NULL, 1)`)
	if err != nil {
		t.Fatalf("seed null-mode policy: %v", err)
	}
	policyID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read policy id: %v", err)
	}
	bindPolicyToRule(t, "lb_null_mode", policyID)

	// When GET /security/bindings
	entries := queryBindingEntries(t, router, "lb_null_mode")

	// Then 绑定照常返回，mode 归一化为 'off'
	if len(entries) != 1 {
		t.Fatalf("NULL mode 不得静默丢绑定（I-3）: bindings=%+v, want 1 entry", entries)
	}
	if entries[0].PolicyID != int(policyID) || entries[0].Mode != "off" {
		t.Fatalf("entries[0]=%+v, want policy_id=%d mode=off", entries[0], policyID)
	}
}

// I-3 硬化（GetAllSecurityBindings）：p.rate_limit_enabled 可空——NULL 同样
// 不得丢绑定，归一化为 false（与生成投影 COALESCE(rate_limit_enabled,0) 一致）。
func TestGetAllSecurityBindings_toleratesNullRateLimitEnabled(t *testing.T) {
	// Given 一条绑定到 rate_limit_enabled 为 NULL 策略的规则
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_null_rl")
	result, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, rate_limit_enabled)
		VALUES ('null-rl', 'blocking', 1, NULL)`)
	if err != nil {
		t.Fatalf("seed null-rate-limit policy: %v", err)
	}
	policyID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read policy id: %v", err)
	}
	bindPolicyToRule(t, "lb_null_rl", policyID)

	// When GET /security/bindings
	entries := queryBindingEntries(t, router, "lb_null_rl")

	// Then 绑定照常返回，rate_limit_enabled 归一化为 false
	if len(entries) != 1 {
		t.Fatalf("NULL rate_limit_enabled 不得静默丢绑定（I-3）: bindings=%+v, want 1 entry", entries)
	}
	if entries[0].PolicyID != int(policyID) || entries[0].RateLimit {
		t.Fatalf("entries[0]=%+v, want policy_id=%d rate_limit_enabled=false", entries[0], policyID)
	}
}

// I-3 硬化（GetAllSecurityBindings）：p.enabled 可空——生成路径以
// WHERE enabled=1 把 NULL 当禁用，UI 标签必须与后端行为一致：
// COALESCE(p.enabled,0) 呈现禁用态，绑定行本身仍可见。
func TestGetAllSecurityBindings_nullEnabledReadsDisabled(t *testing.T) {
	// Given 一条绑定到 enabled 为 NULL 策略的规则
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_null_enabled")
	result, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled) VALUES ('null-enabled', 'blocking', NULL)`)
	if err != nil {
		t.Fatalf("seed null-enabled policy: %v", err)
	}
	policyID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read policy id: %v", err)
	}
	bindPolicyToRule(t, "lb_null_enabled", policyID)

	// When GET /security/bindings
	entries := queryBindingEntries(t, router, "lb_null_enabled")

	// Then 绑定照常返回，enabled 归一化为 false（与生成口径一致）
	if len(entries) != 1 {
		t.Fatalf("NULL enabled 不得静默丢绑定（I-3）: bindings=%+v, want 1 entry", entries)
	}
	if entries[0].PolicyID != int(policyID) || entries[0].Enabled {
		t.Fatalf("entries[0]=%+v, want policy_id=%d enabled=false（NULL 按禁用呈现）", entries[0], policyID)
	}
}

// D-K1：策略列表摘要携带 crs_rule_groups——前端向导的跨策略重复告警直接消费摘要，
// 不再对每条启用策略 N+1 拉取详情。
func TestListSecurityPolicies_summaryIncludesCRSRuleGroups(t *testing.T) {
	// Given 一条配置 CRS 规则组 ["42","43"] 的策略
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if r := postJSON(t, router, "/security/policies", map[string]any{
		"name": "带组策略", "mode": "blocking", "enabled": true,
		"crs_rule_groups": `["42","43"]`,
	}); r.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", r.Code, r.Body.String())
	}

	// When GET /security/policies
	recorder := getRequest(t, router, "/security/policies")

	// Then 摘要项携带 crs_rule_groups 原始 JSON 数组
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			Name          string          `json:"name"`
			CRSRuleGroups json.RawMessage `json:"crs_rule_groups"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response %s: %v", recorder.Body.String(), err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("summaries=%+v, want 1 policy", resp.Data)
	}
	if string(resp.Data[0].CRSRuleGroups) != `["42","43"]` {
		t.Fatalf("crs_rule_groups=%s, want %s", resp.Data[0].CRSRuleGroups, `["42","43"]`)
	}
}
