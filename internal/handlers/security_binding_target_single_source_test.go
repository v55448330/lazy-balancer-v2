package handlers

// 绑定目标校验族的单源钉测：规则的「存在性 + protocol=http」判定与「排除本
// 策略的绑定计数」此前在五个入口（SetRuleSecurityPolicies / BindRuleToPolicy /
// BulkUpdatePolicyBindings / BatchBindSecurityPolicies / SplitSecurityPolicy）
// 各写一份 SQL 与消息，语义微差无单点声明。判定收敛到 loadRuleBindingTarget /
// bindingCountExcluding(s) 后，同一 (rule, protocol) 形态在全部入口必须同结论，
// 呈现口径（400 文案 / skipped reason）留在调用方。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

func newBindingTargetRouter(t *testing.T) *gin.Engine {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(srv.URL)}
	router := gin.New()
	router.POST("/security/policies", h.CreateSecurityPolicy)
	router.PUT("/security/rules/:caddy_id/policies", h.SetRuleSecurityPolicies)
	router.POST("/security/policies/:id/bind", h.BindRuleToPolicy)
	router.POST("/security/policies/:id/bindings/bulk", h.BulkUpdatePolicyBindings)
	router.POST("/security/policies/batch-bind", h.BatchBindSecurityPolicies)
	router.POST("/security/policies/:id/split", h.SplitSecurityPolicy)
	return router
}

func TestRuleBindingTarget_tcpRuleRejectedByEveryBindingEntry(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newBindingTargetRouter(t)
	seedTCPRule(t, "lb_target_tcp")
	policyID := createMultiPolicy(t, router, "target-tcp-policy")

	// 单规则替换
	recorder := putJSON(t, router, "/security/rules/lb_target_tcp/policies", map[string]any{"policy_ids": []int{policyID}})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "仅支持绑定 HTTP") {
		t.Fatalf("setRule status=%d body=%s, want 400 含「仅支持绑定 HTTP」", recorder.Code, recorder.Body.String())
	}
	// 单条绑定
	recorder = postJSON(t, router, "/security/policies/"+strconv.Itoa(policyID)+"/bind", map[string]any{"rule_caddy_id": "lb_target_tcp"})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "仅支持绑定 HTTP") {
		t.Fatalf("bind status=%d body=%s, want 400 含「仅支持绑定 HTTP」", recorder.Code, recorder.Body.String())
	}
	// 策略侧批量
	recorder = postJSON(t, router, "/security/policies/"+strconv.Itoa(policyID)+"/bindings/bulk", map[string]any{"bind": []string{"lb_target_tcp"}})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "仅支持绑定 HTTP") {
		t.Fatalf("bulk status=%d body=%s, want 400 含「仅支持绑定 HTTP」", recorder.Code, recorder.Body.String())
	}
	// 规则侧批量：TCP 进 skipped（200 分项报告）
	recorder = postJSON(t, router, "/security/policies/batch-bind", map[string]any{"rule_ids": []string{"lb_target_tcp"}, "policy_ids": []int{policyID}})
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "TCP 规则不经过安全链") {
		t.Fatalf("batch-bind status=%d body=%s, want 200 skipped「TCP 规则不经过安全链」", recorder.Code, recorder.Body.String())
	}
	// 终态一致：任何入口都不得落库绑定。
	if bound := queryBoundPolicyIDs(t, "lb_target_tcp"); len(bound) != 0 {
		t.Fatalf("TCP 规则落库绑定 %v, want 空", bound)
	}
}

func TestRuleBindingTarget_missingRuleRejectedByEveryBindingEntry(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newBindingTargetRouter(t)
	policyID := createMultiPolicy(t, router, "target-missing-policy")

	recorder := putJSON(t, router, "/security/rules/lb_target_ghost/policies", map[string]any{"policy_ids": []int{policyID}})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "规则不存在") {
		t.Fatalf("setRule status=%d body=%s, want 400「规则不存在」", recorder.Code, recorder.Body.String())
	}
	recorder = postJSON(t, router, "/security/policies/"+strconv.Itoa(policyID)+"/bind", map[string]any{"rule_caddy_id": "lb_target_ghost"})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "规则不存在") {
		t.Fatalf("bind status=%d body=%s, want 400「规则不存在」", recorder.Code, recorder.Body.String())
	}
	recorder = postJSON(t, router, "/security/policies/"+strconv.Itoa(policyID)+"/bindings/bulk", map[string]any{"bind": []string{"lb_target_ghost"}})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "规则不存在") {
		t.Fatalf("bulk bind status=%d body=%s, want 400「规则不存在」", recorder.Code, recorder.Body.String())
	}
	// 回归形状：bulk 的 unbind 对不存在规则保持幂等 200（目标态已达成）。
	recorder = postJSON(t, router, "/security/policies/"+strconv.Itoa(policyID)+"/bindings/bulk", map[string]any{"unbind": []string{"lb_target_ghost"}})
	if recorder.Code != http.StatusOK {
		t.Fatalf("bulk unbind status=%d body=%s, want 200（幂等）", recorder.Code, recorder.Body.String())
	}
	recorder = postJSON(t, router, "/security/policies/batch-bind", map[string]any{"rule_ids": []string{"lb_target_ghost"}, "policy_ids": []int{policyID}})
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "规则不存在") {
		t.Fatalf("batch-bind status=%d body=%s, want 200 skipped「规则不存在」", recorder.Code, recorder.Body.String())
	}
}

// 结构钉：目标判定与排他计数只允许存在于单源 helper 内——任一端点重新手写
// 一份就会在下一轮把语义再分叉（受信 : 协议判定/幂等口径/上限计数）。
func TestRuleBindingTarget_helpersAreSingleSource(t *testing.T) {
	raw, err := os.ReadFile("security.go")
	if err != nil {
		t.Fatalf("read security.go: %v", err)
	}
	source := string(raw)
	for _, marker := range []string{
		"func loadRuleBindingTarget(",
		"func bindingCountExcluding(",
		"func bindingCountsExcluding(",
	} {
		if !strings.Contains(source, marker) {
			t.Errorf("security.go 缺少单源 helper %q", marker)
		}
	}
	if got := strings.Count(source, "FROM lb_rules WHERE caddy_id=?"); got != 1 {
		t.Errorf("lb_rules 目标判定 SQL 出现 %d 次, want 1（只允许在 loadRuleBindingTarget 内）", got)
	}
	if got := strings.Count(source, "FROM security_policy_bindings WHERE rule_caddy_id=? AND policy_id != ?"); got != 1 {
		t.Errorf("排他绑定计数 SQL 出现 %d 次, want 1（只允许在 bindingCountExcluding 内）", got)
	}

	consumers := []struct{ signature, helper string }{
		{"func (h *Handlers) SetRuleSecurityPolicies(c *gin.Context) {", "setRulePoliciesInTx"},
		{"func setRulePoliciesInTx(ctx context.Context, tx *sql.Tx, ruleCaddyID string, policyIDs []int) (string, error) {", "loadRuleBindingTarget"},
		{"func (h *Handlers) BindRuleToPolicy(c *gin.Context) {", "loadRuleBindingTarget"},
		{"func (h *Handlers) BulkUpdatePolicyBindings(c *gin.Context) {", "loadRuleBindingTarget"},
		{"func (h *Handlers) BatchBindSecurityPolicies(c *gin.Context) {", "loadRuleBindingTarget"},
		{"func (h *Handlers) SplitSecurityPolicy(c *gin.Context) {", "bindingCountExcluding"},
		{"func (h *Handlers) SplitSecurityPolicy(c *gin.Context) {", "loadRuleBindingTarget"},
	}
	for _, consumer := range consumers {
		body, ok := handlerFunctionBody(source, consumer.signature)
		if !ok {
			t.Fatalf("security.go 中未找到 %q（函数改名/内联会让本守卫失效）", consumer.signature)
		}
		if !strings.Contains(body, consumer.helper+"(") {
			t.Errorf("%q 未消费单源 helper %s", consumer.signature, consumer.helper)
		}
	}
}
