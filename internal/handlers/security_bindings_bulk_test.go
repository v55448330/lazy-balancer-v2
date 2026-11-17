package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 策略侧批量绑定端点（用户裁定）：POST /security/policies/:id/bindings/bulk
// {"bind":["lb_a"],"unbind":["lb_c"]}——「策略保存/绑定规则弹框（策略模式）」
// 前端此前逐规则调 bind/unbind 单条端点，每条独立全链渲染+validate+/load
//（N×~500ms，后端配置锁串行化）。本端点单事务内批量增删**本策略**的绑定行，
// 不触碰兄弟绑定（并发安全语义保持：additive/精确删除），全程恰好
// 一次 finishTxApply（单渲染）。任一规则校验失败=400 整体拒绝且事务回滚。

func newBulkBindingsRouter(t *testing.T) (*gin.Engine, *atomic.Int64) {
	t.Helper()
	var loads atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			loads.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(srv.URL)}
	router := gin.New()
	router.POST("/security/policies", h.CreateSecurityPolicy)
	router.POST("/security/policies/:id/bind", h.BindRuleToPolicy)
	router.POST("/security/policies/:id/bindings/bulk", h.BulkUpdatePolicyBindings)
	return router, &loads
}

// 主形状：bind 两条+unbind 一条一次提交 → 200、绑定终态正确、/load 恰好 1 次
// （单渲染是本端点的存在意义）。
func TestBulkUpdatePolicyBindings_mixedBindUnbindSingleRender(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, loads := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_a")
	seedHTTPRule(t, "lb_bulk_b")
	seedHTTPRule(t, "lb_bulk_c")
	policy := createMultiPolicy(t, router, "bulk-p1")
	// 预置：c 已绑定本策略（将被 unbind）
	if r := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bind", policy), map[string]any{"rule_caddy_id": "lb_bulk_c"}); r.Code != http.StatusOK {
		t.Fatalf("preset bind: status=%d", r.Code)
	}
	baseline := loads.Load()

	body := map[string]any{"bind": []string{"lb_bulk_a", "lb_bulk_b"}, "unbind": []string{"lb_bulk_c"}}
	recorder := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bindings/bulk", policy), body)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_a"), []int{policy})
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_b"), []int{policy})
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_c"), nil)
	if n := loads.Load() - baseline; n != 1 {
		t.Fatalf("caddy /load delta=%d, want exactly 1 (single render)", n)
	}
}

// 原子性：任一规则不存在 → 400 整体拒绝，合法部分的绑定不得写入，零重载。
func TestBulkUpdatePolicyBindings_atomicRejectOnMissingRule(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, loads := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_d")
	policy := createMultiPolicy(t, router, "bulk-atomic")
	baseline := loads.Load()

	recorder := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bindings/bulk", policy), map[string]any{
		"bind":   []string{"lb_bulk_d", "lb_missing"},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_d"), nil)
	if n := loads.Load() - baseline; n != 0 {
		t.Fatalf("rejected bulk must not reload caddy, got %d extra loads", n)
	}
}

// TCP 规则 → 400 整体拒绝（与单条端点同口径）。
func TestBulkUpdatePolicyBindings_rejectsTCPRule(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, _ := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_e")
	seedTCPRule(t, "lb_bulk_tcp")
	policy := createMultiPolicy(t, router, "bulk-tcp")

	recorder := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bindings/bulk", policy), map[string]any{
		"bind":   []string{"lb_bulk_tcp"},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", recorder.Code)
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_e"), nil)
}

// 幂等：bind 已绑定/unbind 未绑定的规则 → 200（INSERT OR IGNORE/DELETE 0 行）。
func TestBulkUpdatePolicyBindings_idempotent(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, _ := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_f")
	policy := createMultiPolicy(t, router, "bulk-idem")
	if r := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bind", policy), map[string]any{"rule_caddy_id": "lb_bulk_f"}); r.Code != http.StatusOK {
		t.Fatalf("preset bind: status=%d", r.Code)
	}

	recorder := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bindings/bulk", policy), map[string]any{
		"bind":   []string{"lb_bulk_f"},
		"unbind": []string{"lb_nope"},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（幂等重放不得报错）", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_f"), []int{policy})
}

// 规模上限：bind+unbind 合计 >100 → 400。
func TestBulkUpdatePolicyBindings_enforcesSizeLimit(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, _ := newBulkBindingsRouter(t)
	policy := createMultiPolicy(t, router, "bulk-limit")
	bind := make([]string, 0, 101)
	for i := range 101 {
		bind = append(bind, fmt.Sprintf("lb_bulk_x%d", i))
	}
	recorder := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bindings/bulk", policy), map[string]any{
		"bind":   bind,
		"unbind": []string{},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("101 entries: status=%d, want 400", recorder.Code)
	}
}

func seedPolicyWithType(t *testing.T, id int, name, policyType string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,policy_type,enabled) VALUES (?,?,?,?,1)`, id, name, "off", policyType); err != nil {
		t.Fatalf("seed policy %d: %v", id, err)
	}
}

func seedBinding(t *testing.T, caddyID string, policyID int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES (?,?)`, caddyID, policyID); err != nil {
		t.Fatalf("seed binding %s→%d: %v", caddyID, policyID, err)
	}
}

// bind 侧 maxBindingsPerRule 门——规则现有绑定数（不含本策略）≥10 时
// 再 bind 新策略 → 400，且不写入、零重载（与单条 bind / batch-bind 端点同源）。
func TestBulkUpdatePolicyBindings_enforcesRuleBindingLimit(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, loads := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_cap")
	for id := 1; id <= 10; id++ {
		seedPolicyWithType(t, id, fmt.Sprintf("cap-%d", id), "stage3")
		seedBinding(t, "lb_bulk_cap", id)
	}
	seedPolicyWithType(t, 11, "cap-target", "stage3")
	baseline := loads.Load()

	recorder := postJSON(t, router, "/security/policies/11/bindings/bulk", map[string]any{
		"bind":   []string{"lb_bulk_cap"},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（已达 10 条上限）", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_cap"), []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	if n := loads.Load() - baseline; n != 0 {
		t.Fatalf("rejected bulk must not reload caddy, got %d extra loads", n)
	}
}

// 存量超限 + 已绑定本策略：bulk 重复提交本策略必须幂等 200（与单条 bind
// 同口径）。旧实现按「不含本策略的兄弟绑定数≥10」直接 400，导致历史超限规则
// 无法经 bulk 保存，且同批无关规则变更整体失败。
func TestBulkUpdatePolicyBindings_idempotentWhenAlreadyBoundAndOverLimit(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, loads := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_legacy")
	for id := 1; id <= 10; id++ {
		seedPolicyWithType(t, id, fmt.Sprintf("legacy-%d", id), "stage3")
		seedBinding(t, "lb_bulk_legacy", id)
	}
	seedPolicyWithType(t, 11, "legacy-target", "stage3")
	seedBinding(t, "lb_bulk_legacy", 11) // 存量 11 条绑定（超 10 上限），本策略已绑定
	baseline := loads.Load()

	recorder := postJSON(t, router, "/security/policies/11/bindings/bulk", map[string]any{
		"bind":   []string{"lb_bulk_legacy"},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（已绑定本策略 = 幂等，上限门不适用）", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_legacy"), []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	if n := loads.Load() - baseline; n != 1 {
		t.Fatalf("幂等 bulk 仍走单次渲染（无实变），loads delta=%d want 1", n)
	}

	// 对照：同一规则 bind 一个「未绑定」的新策略仍必须被上限拒绝。
	seedPolicyWithType(t, 12, "legacy-new", "stage3")
	recorder = postJSON(t, router, "/security/policies/12/bindings/bulk", map[string]any{
		"bind":   []string{"lb_bulk_legacy"},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("新增绑定越过上限: status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
}

// bind 侧 stage2 唯一门——本策略为 stage2 且该规则已绑其他 stage2 →
// 400；同规则绑 stage3 策略仍放行（门只针对限流叠加）。
func TestBulkUpdatePolicyBindings_rejectsSecondStage2Binding(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, _ := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_rl")
	seedPolicyWithType(t, 10, "rl-a", "stage2")
	seedPolicyWithType(t, 11, "rl-b", "stage2")
	seedPolicyWithType(t, 12, "waf-a", "stage3")
	seedBinding(t, "lb_bulk_rl", 10)

	recorder := postJSON(t, router, "/security/policies/11/bindings/bulk", map[string]any{
		"bind":   []string{"lb_bulk_rl"},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("bind second stage2: status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_rl"), []int{10})

	// 回归：已有 stage2 时绑 stage3 策略照常放行（门不误伤非限流策略）。
	recorder = postJSON(t, router, "/security/policies/12/bindings/bulk", map[string]any{
		"bind":   []string{"lb_bulk_rl"},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("bind stage3 alongside stage2: status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_rl"), []int{10, 12})
}

// bind/unbind 规则 id 归一（TrimSpace）——带空白 id 按去空白后处理，
// 不得因首尾空白被判「规则不存在」。
func TestBulkUpdatePolicyBindings_trimsRuleIDs(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, _ := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_trim")
	policy := createMultiPolicy(t, router, "trim-p")

	recorder := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bindings/bulk", policy), map[string]any{
		"bind":   []string{"  lb_bulk_trim  "},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（id 应去空白后绑定）", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_trim"), []int{policy})
}

// bulk unbind 精确删除本策略绑定，不触碰兄弟绑定——DELETE 若
// 漏掉 AND policy_id=? 会被本用例拦住。
func TestBulkUpdatePolicyBindings_unbindKeepsSiblingBindings(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, _ := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_sib")
	seedPolicyWithType(t, 20, "sib-a", "stage3")
	seedPolicyWithType(t, 21, "sib-b", "stage3")
	seedBinding(t, "lb_bulk_sib", 20)
	seedBinding(t, "lb_bulk_sib", 21)

	recorder := postJSON(t, router, "/security/policies/20/bindings/bulk", map[string]any{
		"bind":   []string{},
		"unbind": []string{"lb_bulk_sib"},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_sib"), []int{21})
}

// 同一规则同时出现在 bind 与 unbind → 400（语义冲突，早于写入）。
func TestBulkUpdatePolicyBindings_rejectsBindUnbindConflict(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, loads := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_clash")
	seedPolicyWithType(t, 30, "clash-p", "stage3")
	baseline := loads.Load()

	recorder := postJSON(t, router, "/security/policies/30/bindings/bulk", map[string]any{
		"bind":   []string{"lb_bulk_clash"},
		"unbind": []string{"lb_bulk_clash"},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_clash"), nil)
	if n := loads.Load() - baseline; n != 0 {
		t.Fatalf("conflict must not reload caddy, got %d extra loads", n)
	}
}

// （bulk applyOne）：规则查询 DB 故障 → 500「读取/写入策略绑定失败」，
// 而非把裸错误串当 400 校验失败外泄。故障注入用语义化手段（删除规则表），
// 不按 SQL 文本路由——查询形态调整不会让注入落到别的分支。
func TestBulkUpdatePolicyBindings_dbErrorReturns500(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	seedPolicyWithType(t, 7, "bulk-err-p", "stage3")
	router, _ := newBulkBindingsRouter(t)
	if _, err := db.DB.Exec(`DROP TABLE lb_rules`); err != nil {
		t.Fatalf("drop lb_rules: %v", err)
	}

	recorder := postJSON(t, router, "/security/policies/7/bindings/bulk", map[string]any{
		"bind":   []string{"lb_x"},
		"unbind": []string{},
	})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "读取/写入策略绑定失败") {
		t.Fatalf("body=%s, want 读取/写入策略绑定失败", recorder.Body.String())
	}
}

// （setRulePoliciesInTx）：规则查询 DB 故障 → 500「读取/写入策略绑定失败」。
func TestSetRuleSecurityPolicies_dbErrorReturns500(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/security/rules/:caddy_id/policies", (&Handlers{}).SetRuleSecurityPolicies)
	if _, err := db.DB.Exec(`DROP TABLE lb_rules`); err != nil {
		t.Fatalf("drop lb_rules: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/security/rules/lb_x/policies", strings.NewReader(`{"policy_ids":[1]}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "读取/写入策略绑定失败") {
		t.Fatalf("body=%s, want 读取/写入策略绑定失败", recorder.Body.String())
	}
}

// bind+unbind 数量上限必须按归一（TrimSpace+去重）
// 后的集合判定——101 个重复/空白项归一后仅 1 条规则，旧实现先按原始长度 400。
func TestBulkUpdatePolicyBindings_sizeLimitAfterNormalization(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, _ := newBulkBindingsRouter(t)
	seedHTTPRule(t, "lb_bulk_norm")
	policy := createMultiPolicy(t, router, "bulk-norm")
	bind := make([]string, 0, 101)
	for i := 0; i < 101; i++ {
		if i%2 == 0 {
			bind = append(bind, " lb_bulk_norm ")
			continue
		}
		bind = append(bind, "lb_bulk_norm")
	}
	recorder := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bindings/bulk", policy), map[string]any{
		"bind":   bind,
		"unbind": []string{},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("归一后仅 1 条规则: status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_norm"), []int{policy})
}

// unbind 侧不受「仅支持 HTTP 规则」门约束：存量 TCP 绑定（历史数据，bind 侧
// 早已拒绝新建）必须能解绑，否则旧绑定永远清不掉。协议门只保护 bind 目标。
func TestBulkUpdatePolicyBindings_unbindLegacyTCPBinding(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router, loads := newBulkBindingsRouter(t)
	seedTCPRule(t, "lb_bulk_tcp")
	policy := createMultiPolicy(t, router, "bulk-tcp")
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)`, "lb_bulk_tcp", policy); err != nil {
		t.Fatalf("seed legacy tcp binding: %v", err)
	}
	baseline := loads.Load()

	recorder := postJSON(t, router, fmt.Sprintf("/security/policies/%d/bindings/bulk", policy), map[string]any{
		"bind":   []string{},
		"unbind": []string{"lb_bulk_tcp"},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（解绑存量 TCP 绑定须放行）", recorder.Code, recorder.Body.String())
	}
	assertIDSlice(t, queryBoundPolicyIDs(t, "lb_bulk_tcp"), nil)
	if n := loads.Load() - baseline; n != 1 {
		t.Fatalf("caddy /load delta=%d, want exactly 1", n)
	}
}
