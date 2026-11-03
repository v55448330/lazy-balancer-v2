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

// （v2.2.0 多策略绑定）：一规则绑多策略的 RED 测试。
// 覆盖：POST additive、PUT 原子替换（max8/单 ID/审计/
// 排序）、DELETE 精确 unbind、GET 数组有序。
// 上限 2026-09-21 用户裁定 5→8（maxBindingsPerRule）。

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
	router.POST("/security/policies/:id/bindings/bulk", h.BulkUpdatePolicyBindings)
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
	// 与 putJSON 同实现，保留具名包装以免本文件 30+ 调用点全部改名。
	return putJSON(t, router, path, body)
}

func queryBoundPolicyIDs(t *testing.T, caddyID string) []int {
	t.Helper()
	rows, err := db.DB.Query("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY rank ASC, policy_id ASC", caddyID)
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

// POST bind 改为 additive——绑定 A 后再绑 B，A 必须保留。
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

	// 绑定顺序（2026-11 用户裁定）：additive 追加到链末——与策略 id 大小无关，
	// 先绑 A 后绑 B → 执行序 [A, B]。
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_add"), []int{policyA, policyB})
}

// PUT 原子替换 + 请求序即执行序（写入 [3,1,2] → 读出 [3,1,2]；2026-11 用户
// 裁定：绑定顺序由请求序承载 rank，不再是 policy_id ASC）。
func TestSetRuleSecurityPolicies_replacesAtomicallyPreservingRequestOrder(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_put")
	p1 := createMultiPolicy(t, router, "策略1")
	p2 := createMultiPolicy(t, router, "策略2")
	p3 := createMultiPolicy(t, router, "策略3")

	// 以 [p3,p1,p2] 提交：请求序写入 rank 1..N，读回保持同序。
	recorder := putMultiJSON(t, router, "/security/rules/lb_mp_put/policies", map[string]any{"policy_ids": []int{p3, p1, p2}})
	if recorder.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}

	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_put"), []int{p3, p1, p2})

	// 再次 PUT [p2] 原子替换：删除旧三行，仅留 p2。
	recorder = putMultiJSON(t, router, "/security/rules/lb_mp_put/policies", map[string]any{"policy_ids": []int{p2}})
	if recorder.Code != http.StatusOK {
		t.Fatalf("second PUT status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_put"), []int{p2})
}

// 超过 8 条策略 → 400「最多绑定 8 条策略」（2026-09-21 上限 5→8）。
func TestSetRuleSecurityPolicies_rejectsMoreThanEight(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_max")
	ids := []int{}
	for i := 1; i <= 9; i++ {
		ids = append(ids, createMultiPolicy(t, router, fmt.Sprintf("策略%d", i)))
	}
	recorder := putMultiJSON(t, router, "/security/rules/lb_mp_max/policies", map[string]any{"policy_ids": ids})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("PUT status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte("最多绑定 8 条策略")) {
		t.Fatalf("PUT body=%s, want message containing 最多绑定 8 条策略", recorder.Body.String())
	}
	if got := queryBoundPolicyIDs(t, "lb_mp_max"); len(got) != 0 {
		t.Fatalf("rejected PUT wrote bindings: %v", got)
	}
}

// 上限边界：恰好 8 条唯一策略 → 200（2026-09-21 上限 5→8）。
func TestSetRuleSecurityPolicies_acceptsExactlyEight(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_cap8")
	ids := []int{}
	for i := 1; i <= 8; i++ {
		ids = append(ids, createMultiPolicy(t, router, fmt.Sprintf("策略%d", i)))
	}
	recorder := putMultiJSON(t, router, "/security/rules/lb_mp_cap8/policies", map[string]any{"policy_ids": ids})
	if recorder.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_cap8"), ids)
}

// 边界：上限判定须先去重——8 条唯一策略携带一个重复 id
// （9 元素数组）不得因原始数组长度 9 误判超限；写入结果为去重后的 8 行。
func TestSetRuleSecurityPolicies_dedupsBeforeMaxCheck(t *testing.T) {
	// Given 8 条策略与一条 HTTP 规则
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_dedup")
	ids := []int{}
	for i := 1; i <= 8; i++ {
		ids = append(ids, createMultiPolicy(t, router, fmt.Sprintf("策略%d", i)))
	}

	// When PUT 携带重复 id 的 9 元素数组（8 条唯一）
	recorder := putMultiJSON(t, router, "/security/rules/lb_mp_dedup/policies", map[string]any{"policy_ids": []int{ids[0], ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6], ids[7]}})

	// Then 接受 200，绑定为去重后的 8 条
	if recorder.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_dedup"), ids)
}

// 类型回归（2026-09-21 上限 5→8）：8 条 policy_type 各异（stage0/stage1/单条
// stage2/stage3×5）混合绑定 → 200——上限抬升不改变类型门（mixed 禁绑、限流唯一）。
func TestSetRuleSecurityPolicies_eightTypedPoliciesAccepted(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_typed")
	typed := []struct{ name, mode, ptype string }{
		{"t0", "off", "stage0"}, {"t1", "off", "stage1"}, {"t2", "off", "stage2"},
		{"t3a", "blocking", "stage3"}, {"t3b", "detection", "stage3"}, {"t3c", "off", "stage3"},
		{"t3d", "blocking", "stage3"}, {"t3e", "off", "stage3"},
	}
	ids := []int{}
	for _, tp := range typed {
		res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,policy_type,enabled) VALUES (?,?,?,1)`, tp.name, tp.mode, tp.ptype)
		if err != nil {
			t.Fatalf("seed typed policy %s: %v", tp.name, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("last id for %s: %v", tp.name, err)
		}
		ids = append(ids, int(id))
	}

	recorder := putMultiJSON(t, router, "/security/rules/lb_mp_typed/policies", map[string]any{"policy_ids": ids})
	if recorder.Code != http.StatusOK {
		t.Fatalf("PUT 8 typed policies status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_typed"), ids)
}

// 单元素 policy_ids 向后兼容（PUT [1] 与 POST bind 等价行为）。
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

// DELETE unbind 精确删一行——[A,B] 解绑 A 后只剩 B。
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

// GET /security/rules/:caddy_id/policy 返回 []policy 按绑定执行序（rank ASC=PUT 请求序）。
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
	// 绑定顺序（2026-11 用户裁定）：GET 按请求序（rank）返回。
	got := []int{resp.Data[0].ID, resp.Data[1].ID, resp.Data[2].ID}
	assertIDSlice(t, got, []int{p3, p1, p2})
}

// 边界：规则无绑定时返回空数组（不是 null 单对象）。
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

// GET /security/bindings 返回 map[string][]BindingInfo，数组按绑定执行序（rank ASC=PUT 请求序）。
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
	// 绑定顺序（2026-11）：map 数组按执行序（rank=PUT 请求序）返回。
	if resp.Data["lb_mp_all_a"][0].PolicyID != p3 || resp.Data["lb_mp_all_a"][1].PolicyID != p1 {
		t.Fatalf("lb_mp_all_a order=[%d,%d], want [%d,%d]（请求序）",
			resp.Data["lb_mp_all_a"][0].PolicyID, resp.Data["lb_mp_all_a"][1].PolicyID, p3, p1)
	}
	if len(resp.Data["lb_mp_all_b"]) != 1 || resp.Data["lb_mp_all_b"][0].PolicyID != p2 {
		t.Fatalf("lb_mp_all_b bindings=%+v, want single %d", resp.Data["lb_mp_all_b"], p2)
	}
}

// PUT 替换写审计日志（action=更新 / resource=安全策略 / detail 含规则与策略列表）。
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

// 契约补全：PUT 空数组 policy_ids=[] = 解除该规则全部绑定——
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

// 排序边界：POST additive 乱序绑定（先绑高 id 再绑低 id），两个 GET 端点按绑定执行序（rank ASC=请求序）返回。
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

	// Then GET /security/rules/:caddy_id/policy 按绑定执行序（rank ASC=请求序）
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
	// 绑定顺序（2026-11 用户裁定）：GET 按 rank 返回——先绑的在前，与 id 大小
	// 无关（本用例先绑 pHigh 后绑 pLow）。
	if len(ruleResp.Data) != 2 || ruleResp.Data[0].ID != pHigh || ruleResp.Data[1].ID != pLow {
		t.Fatalf("GET policy ids=%+v, want [%d,%d]（绑定请求序）", ruleResp.Data, pHigh, pLow)
	}

	// And GET /security/bindings 同样按 rank（绑定请求序）
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
	// 绑定顺序（2026-11）：additive 追加到链末，map 按 rank 返回 [pHigh, pLow]。
	got := allResp.Data["lb_mp_ooo"]
	if len(got) != 2 || got[0].PolicyID != pHigh || got[1].PolicyID != pLow {
		t.Fatalf("GET /security/bindings ids=%+v, want [%d,%d]（绑定请求序）", got, pHigh, pLow)
	}
}

// 实现口径：GET /security/rules/:caddy_id/policy 仅返回 enabled=1 的策略
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

// 删除策略仅清该策略的绑定行——同规则上兄弟策略的绑定保留。
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

// 删除 LB 规则仅清该规则的绑定行——同策略上兄弟规则的绑定保留。
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

// 绑定上限（2026-09-21 上限 5→8）：POST additive 与 PUT 同上限——第 8 条
// （新策略对）照常 200；规则绑满 8 条后 POST 第 9 条 → 400「最多绑定 8 条策略」；
// 重绑已存在的 (rule,policy) 对保持幂等 200（INSERT OR IGNORE 不产生新行）。
func TestBindRuleToPolicy_postAdditiveCapAtEight(t *testing.T) {
	// Given 规则已通过 PUT 绑定 7 条策略
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_cap")
	ids := []int{}
	for i := 1; i <= 7; i++ {
		ids = append(ids, createMultiPolicy(t, router, fmt.Sprintf("策略%d", i)))
	}
	if r := putMultiJSON(t, router, "/security/rules/lb_mp_cap/policies", map[string]any{"policy_ids": ids}); r.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", r.Code, r.Body.String())
	}
	p8 := createMultiPolicy(t, router, "第八策略")

	// When POST additive 绑定第 8 条（新策略对）
	recorder := postJSON(t, router, "/security/policies/"+strconv.Itoa(p8)+"/bind", map[string]any{"rule_caddy_id": "lb_mp_cap"})

	// Then 接受 200，绑定共 8 条
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST 8th bind status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	all := append(ids, p8)
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_cap"), all)

	// When POST additive 绑定第 9 条（新策略对）
	p9 := createMultiPolicy(t, router, "第九策略")
	recorder = postJSON(t, router, "/security/policies/"+strconv.Itoa(p9)+"/bind", map[string]any{"rule_caddy_id": "lb_mp_cap"})

	// Then 服务端拒绝 400，绑定仍为 8 条
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("POST 9th bind status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte("最多绑定 8 条策略")) {
		t.Fatalf("POST 9th bind body=%s, want message containing 最多绑定 8 条策略", recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_cap"), all)

	// When 重绑已存在的 (rule,policy) 对
	recorder = postJSON(t, router, "/security/policies/"+strconv.Itoa(ids[0])+"/bind", map[string]any{"rule_caddy_id": "lb_mp_cap"})

	// Then 幂等 200，绑定集合不变
	if recorder.Code != http.StatusOK {
		t.Fatalf("re-bind existing pair status=%d body=%s, want 200 (idempotent)", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_cap"), all)
}

// 扩展：GET /security/bindings 每绑定携带 block_page_id——前端
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

// GET /security/bindings 每绑定携带
// block_status_code（NULL/0 归一为 403）——前端冲突提示与 Rules 页锁形弹框
// 据此展示「<页名>(状态码 XXX)」，与后端生成口径（BlockStatusCode 0→403）一致。
func TestGetAllSecurityBindings_includesBlockStatusCode(t *testing.T) {
	// Given 一条规则按序绑定两条策略：首策略状态码 451，次策略未设置（归一 403）
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_bsc")
	p1 := createMultiPolicy(t, router, "451策略")
	p2 := createMultiPolicy(t, router, "默认状态策略")
	if _, err := db.DB.Exec("UPDATE security_policies SET block_page_id=7, block_status_code=451 WHERE id=?", p1); err != nil {
		t.Fatalf("set block_status_code: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE security_policies SET block_page_id=7 WHERE id=?", p2); err != nil {
		t.Fatalf("set block_page_id: %v", err)
	}
	if r := putMultiJSON(t, router, "/security/rules/lb_mp_bsc/policies", map[string]any{"policy_ids": []int{p1, p2}}); r.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", r.Code, r.Body.String())
	}

	// When GET /security/bindings
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/bindings", nil)
	router.ServeHTTP(recorder, req)

	// Then 每条绑定携带 block_status_code：首条 451，次条归一 403
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data map[string][]struct {
			PolicyID        int `json:"policy_id"`
			BlockStatusCode int `json:"block_status_code"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse bindings response %s: %v", recorder.Body.String(), err)
	}
	entries := resp.Data["lb_mp_bsc"]
	if len(entries) != 2 {
		t.Fatalf("bindings=%+v, want 2 entries", entries)
	}
	if entries[0].PolicyID != p1 || entries[0].BlockStatusCode != 451 {
		t.Fatalf("entries[0]=%+v, want policy_id=%d block_status_code=451", entries[0], p1)
	}
	if entries[1].PolicyID != p2 || entries[1].BlockStatusCode != 403 {
		t.Fatalf("entries[1]=%+v, want policy_id=%d block_status_code=403 (COALESCE)", entries[1], p2)
	}
}

// 硬化（GetAllSecurityBindings）：绑定 JOIN 的 p.block_page_id 可空——
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
		t.Fatalf("NULL block_page_id 不得静默丢绑定: bindings=%+v, want 1 entry", resp.Data)
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

// 硬化（GetAllSecurityBindings）：p.mode 可空——修复前仅 block_page_id 有
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
		t.Fatalf("NULL mode 不得静默丢绑定: bindings=%+v, want 1 entry", entries)
	}
	if entries[0].PolicyID != int(policyID) || entries[0].Mode != "off" {
		t.Fatalf("entries[0]=%+v, want policy_id=%d mode=off", entries[0], policyID)
	}
}

// 硬化（GetAllSecurityBindings）：p.rate_limit_enabled 可空——NULL 同样
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
		t.Fatalf("NULL rate_limit_enabled 不得静默丢绑定: bindings=%+v, want 1 entry", entries)
	}
	if entries[0].PolicyID != int(policyID) || entries[0].RateLimit {
		t.Fatalf("entries[0]=%+v, want policy_id=%d rate_limit_enabled=false", entries[0], policyID)
	}
}

// 硬化（GetAllSecurityBindings）：p.enabled 可空——生成路径以
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
		t.Fatalf("NULL enabled 不得静默丢绑定: bindings=%+v, want 1 entry", entries)
	}
	if entries[0].PolicyID != int(policyID) || entries[0].Enabled {
		t.Fatalf("entries[0]=%+v, want policy_id=%d enabled=false（NULL 按禁用呈现）", entries[0], policyID)
	}
}

// 策略列表摘要携带 crs_rule_groups——前端向导的跨策略重复告警直接消费摘要，
// 不再对每条启用策略 N+1 拉取详情。
func TestListSecurityPolicies_summaryIncludesCRSRuleGroups(t *testing.T) {
	// Given 一条配置 CRS 规则组 ["42","43"] 的策略
	setupSecurityPolicyTestDB(t)
	useCRSRuleIndexFixture(t)
	router := newSecurityRouter(t)
	if r := postJSON(t, router, "/security/policies", map[string]any{
		"name": "带组策略", "mode": "blocking", "enabled": true,
		"crs_rule_groups": `["20","42"]`,
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
	if string(resp.Data[0].CRSRuleGroups) != `["20","42"]` {
		t.Fatalf("crs_rule_groups=%s, want %s", resp.Data[0].CRSRuleGroups, `["20","42"]`)
	}
}

// 审计详情必须记录**去重后**的绑定集合。提交
// [1,1,2] 时库内终态为 [1,2]，此前审计串用原始 req.PolicyIDs 生成
// 「[1,1,2]」——取证时无法从审计还原最终绑定集。修复=归一次、写入与审计共用。
func TestSetRuleSecurityPolicies_auditUsesDeduplicatedSet(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_hc07")
	first := createMultiPolicy(t, router, "hc07-first")
	second := createMultiPolicy(t, router, "hc07-second")

	recorder := putMultiJSON(t, router, "/security/rules/lb_hc07/policies", map[string]any{
		"policy_ids": []int{first, first, second},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_hc07"), []int{first, second})

	var detail string
	if err := db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log WHERE action='更新' AND resource='安全策略' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	dup := fmt.Sprintf("[%d,%d,%d]", first, first, second)
	want := fmt.Sprintf("[%d,%d]", first, second)
	if strings.Contains(detail, dup) {
		t.Fatalf("audit detail=%q 仍含原始重复集合 %s（应记录去重后终态）", detail, dup)
	}
	if !strings.Contains(detail, want) {
		t.Fatalf("audit detail=%q, want containing %s", detail, want)
	}
}

// 无变更的解绑不得写「已解除」审计（审计真实性）：重复/并发解绑保持 200
// 幂等，但 changed=false、不落审计、不触发配置应用。
func TestUnbindRuleFromPolicy_noChangeSkipsAudit(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_unbind_nochange")
	policyA := createMultiPolicy(t, router, "策略A")
	if r := putMultiJSON(t, router, "/security/rules/lb_mp_unbind_nochange/policies", map[string]any{"policy_ids": []int{policyA}}); r.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", r.Code, r.Body.String())
	}
	unbindAudits := func() int {
		t.Helper()
		var n int
		if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE detail LIKE '%解除规则%'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	path := "/security/policies/" + strconv.Itoa(policyA) + "/bind/lb_mp_unbind_nochange"

	before := unbindAudits()
	if rec := deleteRequest(t, router, path); rec.Code != http.StatusOK {
		t.Fatalf("首次解绑 status=%d body=%s", rec.Code, rec.Body.String())
	}
	afterFirst := unbindAudits()
	if afterFirst != before+1 {
		t.Fatalf("真实变更必须写审计，before=%d after=%d", before, afterFirst)
	}

	rec := deleteRequest(t, router, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("重复解绑须保持 200 幂等，status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Changed bool `json:"changed"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response %s: %v", rec.Body.String(), err)
	}
	if resp.Data.Changed {
		t.Fatalf("无变更时 changed 必须为 false: %s", rec.Body.String())
	}
	if got := unbindAudits(); got != afterFirst {
		t.Fatalf("无变更不得写「已解除」审计，before=%d after=%d", afterFirst, got)
	}
}

// PUT rank → GET /security/bindings 顺序往返（2026-11 绑定顺序）：map 值数组
// 必须按执行序（rank）返回，否则 FE 唯一 map 源会丢弃顺序、向导重开即回退
// policy_id 序（用户读作「顺序无法保存」）。
func TestGetAllSecurityBindings_rankOrderRoundtrip(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_map")
	p1 := createMultiPolicy(t, router, "策略1")
	p2 := createMultiPolicy(t, router, "策略2")
	p3 := createMultiPolicy(t, router, "策略3")
	if r := putMultiJSON(t, router, "/security/rules/lb_mp_map/policies", map[string]any{"policy_ids": []int{p3, p1, p2}}); r.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", r.Code, r.Body.String())
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/security/bindings", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /security/bindings status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data map[string][]struct {
			PolicyID int `json:"policy_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse bindings map: %v", err)
	}
	bindings := resp.Data["lb_mp_map"]
	if len(bindings) != 3 {
		t.Fatalf("bindings=%v, want 3", bindings)
	}
	got := []int{bindings[0].PolicyID, bindings[1].PolicyID, bindings[2].PolicyID}
	assertIDSlice(t, got, []int{p3, p1, p2})
}

// bulk orders：单事务批量应用绑定顺序（一次渲染）；幂等 unchanged；单规则
// 校验失败进 skipped 不整体拒绝；与 bind 冲突 400。
func TestBulkUpdatePolicyBindings_ordersApplyAndIdempotent(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_mp_orders")
	p1 := createMultiPolicy(t, router, "策略1")
	p2 := createMultiPolicy(t, router, "策略2")
	p3 := createMultiPolicy(t, router, "策略3")
	if r := putMultiJSON(t, router, "/security/rules/lb_mp_orders/policies", map[string]any{"policy_ids": []int{p1, p2, p3}}); r.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", r.Code, r.Body.String())
	}

	// When：orders 把 p3 提到最前
	rec := postJSON(t, router, "/security/policies/"+strconv.Itoa(p3)+"/bindings/bulk",
		map[string]any{"orders": map[string]any{"lb_mp_orders": []int{p3, p1, p2}}})
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk orders status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Ordered   int `json:"ordered"`
			Unchanged int `json:"unchanged"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse bulk response %s: %v", rec.Body.String(), err)
	}
	if resp.Data.Ordered != 1 {
		t.Fatalf("ordered=%d, want 1", resp.Data.Ordered)
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_mp_orders"), []int{p3, p1, p2})

	// 幂等：同序重复提交 → unchanged=1、ordered=0（零写入）。
	rec = postJSON(t, router, "/security/policies/"+strconv.Itoa(p3)+"/bindings/bulk",
		map[string]any{"orders": map[string]any{"lb_mp_orders": []int{p3, p1, p2}}})
	if rec.Code != http.StatusOK {
		t.Fatalf("idempotent bulk status=%d body=%s", rec.Code, rec.Body.String())
	}
	resp = struct {
		Code int `json:"code"`
		Data struct {
			Ordered   int `json:"ordered"`
			Unchanged int `json:"unchanged"`
		} `json:"data"`
	}{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse idempotent response: %v", err)
	}
	if resp.Data.Ordered != 0 || resp.Data.Unchanged != 1 {
		t.Fatalf("ordered=%d unchanged=%d, want 0/1", resp.Data.Ordered, resp.Data.Unchanged)
	}

	// 单规则校验失败（引用不存在策略）→ skipped、HTTP 200，不影响其余。
	rec = postJSON(t, router, "/security/policies/"+strconv.Itoa(p3)+"/bindings/bulk",
		map[string]any{"orders": map[string]any{"lb_ghost": []int{999999, 1}}})
	if rec.Code != http.StatusOK {
		t.Fatalf("skipped-path bulk status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "skipped") {
		t.Fatalf("skipped entry missing: %s", rec.Body.String())
	}

	// 同规则同时出现在 bind 与 orders → 400。
	rec = postJSON(t, router, "/security/policies/"+strconv.Itoa(p3)+"/bindings/bulk",
		map[string]any{"bind": []string{"lb_mp_orders"}, "orders": map[string]any{"lb_mp_orders": []int{p3, p1, p2}}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("conflict status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
}

// bulk orders 此前审计只记「顺序应用 N 条」计数，
// 各规则终态顺序不可取证——单规则 PUT 端点一直全序留痕（「设置规则 X 的安全
// 策略为 [..]」），bulk 必须对齐形态。钉测：orders 应用后审计 detail 必须含
// 规则 id 与完整有序 policy 序列（规则×顺序），响应 Data 同步携带 orders 明细。
func TestBulkUpdatePolicyBindings_ordersAuditCarriesRuleSequences(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiPolicyRouter(t)
	seedHTTPRule(t, "lb_ord_a")
	seedHTTPRule(t, "lb_ord_b")
	p1 := createMultiPolicy(t, router, "策略1")
	p2 := createMultiPolicy(t, router, "策略2")
	p3 := createMultiPolicy(t, router, "策略3")
	if r := putMultiJSON(t, router, "/security/rules/lb_ord_a/policies", map[string]any{"policy_ids": []int{p1, p2, p3}}); r.Code != http.StatusOK {
		t.Fatalf("PUT lb_ord_a status=%d body=%s", r.Code, r.Body.String())
	}
	if r := putMultiJSON(t, router, "/security/rules/lb_ord_b/policies", map[string]any{"policy_ids": []int{p2, p1}}); r.Code != http.StatusOK {
		t.Fatalf("PUT lb_ord_b status=%d body=%s", r.Code, r.Body.String())
	}

	rec := postJSON(t, router, "/security/policies/"+strconv.Itoa(p2)+"/bindings/bulk",
		map[string]any{"orders": map[string]any{
			"lb_ord_a": []int{p3, p1, p2},
			"lb_ord_b": []int{p1, p2},
		}})
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk orders status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Ordered int `json:"ordered"`
			Orders  []struct {
				RuleID    string `json:"rule_id"`
				PolicyIDs []int  `json:"policy_ids"`
			} `json:"orders"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse bulk response %s: %v", rec.Body.String(), err)
	}
	if resp.Data.Ordered != 2 {
		t.Fatalf("ordered=%d, want 2", resp.Data.Ordered)
	}
	if len(resp.Data.Orders) != 2 {
		t.Fatalf("Data.orders=%v, want 2 条规则×顺序明细", resp.Data.Orders)
	}
	ordersByRule := map[string][]int{}
	for _, applied := range resp.Data.Orders {
		ordersByRule[applied.RuleID] = applied.PolicyIDs
	}
	assertIDSlice(t, ordersByRule["lb_ord_a"], []int{p3, p1, p2})
	assertIDSlice(t, ordersByRule["lb_ord_b"], []int{p1, p2})

	detail := latestAuditDetail(t, "更新", "安全策略")
	for _, want := range []string{
		fmt.Sprintf("lb_ord_a→[%d,%d,%d]", p3, p1, p2),
		fmt.Sprintf("lb_ord_b→[%d,%d]", p1, p2),
	} {
		if !strings.Contains(detail, want) {
			t.Fatalf("审计 detail=%q, want 含 %q（规则×全量有序序列留痕）", detail, want)
		}
	}
}
