package handlers

// L4 阶段 0/1 绑定校验面 RED 测试（契约 C4）：
//   - TCP 规则可绑定 stage0/stage1 特征策略（四绑定入口全部放开）；
//   - 含 G2（限流）/G3（WAF）特征的策略对 TCP 绑定 → 400「该策略含 TCP 不支持的能力（限流/WAF）」；
//   - HTTP 规则绑定不受影响（回归形状）；
//   - TCP 终态解绑按新语义收口：只清 G2/G3 特征绑定，stage0/1 保留。
import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// l4GateSeedPolicy 直接落库一条指定特征组形态的策略（绑定校验走库行整列）。
func l4GateSeedPolicy(t *testing.T, name string, g0, g1, g2, g3 bool) int {
	t.Helper()
	mode := "off"
	if g3 {
		mode = "blocking"
	}
	rps := 0
	if g2 {
		rps = 100
	}
	policyType := l4GatePolicyType(g0, g1, g2, g3)
	res, err := db.DB.Exec(`INSERT INTO security_policies
		(name, policy_type, mode, enabled, ip_whitelist, ip_whitelist_enabled, ip_acl_enabled, ip_acl_mode, ip_acl_list, rate_limit_enabled, rate_limit_rps)
		VALUES (?, ?, ?, 1, ?, 1, ?, ?, ?, ?, ?)`,
		name, policyType, mode,
		l4GateListJSON(g0), l4GateInt(g1), l4GatePick(g1, "deny", ""), l4GateListJSON(g1),
		l4GateInt(g2), rps)
	if err != nil {
		t.Fatalf("seed policy %s: %v", name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return int(id)
}

// l4GatePolicyType 与 models.InferPolicyType 同构（测试侧最小形态）。
func l4GatePolicyType(g0, g1, g2, g3 bool) string {
	count := 0
	for _, b := range []bool{g0, g1, g2, g3} {
		if b {
			count++
		}
	}
	switch {
	case count > 1:
		return "mixed"
	case g0:
		return "stage0"
	case g1:
		return "stage1"
	case g2:
		return "stage2"
	default:
		return "stage3"
	}
}

func l4GateInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func l4GatePick(b bool, a, fallback string) string {
	if b {
		return a
	}
	return fallback
}

func l4GateListJSON(nonEmpty bool) string {
	if nonEmpty {
		return `["10.9.0.1/32"]`
	}
	return `[]`
}

// 四绑定入口 + mixed 拆分共用路由。
func newL4GateRouter(t *testing.T) *gin.Engine {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(srv.URL)}
	router := gin.New()
	router.PUT("/security/rules/:caddy_id/policies", h.SetRuleSecurityPolicies)
	router.POST("/security/policies/:id/bind", h.BindRuleToPolicy)
	router.POST("/security/policies/:id/bindings/bulk", h.BulkUpdatePolicyBindings)
	router.POST("/security/policies/batch-bind", h.BatchBindSecurityPolicies)
	router.POST("/security/policies/:id/split", h.SplitSecurityPolicy)
	return router
}

// l4GateBind 走指定入口绑定 policy → rule，返回响应。
func l4GateBind(t *testing.T, router *gin.Engine, entry string, policyID int, ruleCaddyID string) *httptest.ResponseRecorder {
	t.Helper()
	switch entry {
	case "put":
		return putJSON(t, router, "/security/rules/"+ruleCaddyID+"/policies", map[string]any{"policy_ids": []int{policyID}})
	case "bind":
		return postJSON(t, router, "/security/policies/"+strconv.Itoa(policyID)+"/bind", map[string]any{"rule_caddy_id": ruleCaddyID})
	case "bulk":
		return postJSON(t, router, "/security/policies/"+strconv.Itoa(policyID)+"/bindings/bulk", map[string]any{"bind": []string{ruleCaddyID}})
	case "batch":
		return postJSON(t, router, "/security/policies/batch-bind", map[string]any{"rule_ids": []string{ruleCaddyID}, "policy_ids": []int{policyID}})
	}
	t.Fatalf("unknown entry %q", entry)
	return nil
}

func TestL4BindingGate_tcpAcceptsStage01AcrossAllEntries(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newL4GateRouter(t)
	seedTCPRule(t, "lb_gate_tcp")
	stage0 := l4GateSeedPolicy(t, "gate-stage0", true, false, false, false)
	stage1 := l4GateSeedPolicy(t, "gate-stage1", false, true, false, false)

	for _, entry := range []string{"bind", "put", "bulk"} {
		if rec := l4GateBind(t, router, entry, stage1, "lb_gate_tcp"); rec.Code != http.StatusOK {
			t.Fatalf("entry=%s TCP+stage1 绑定被拒: %d %s", entry, rec.Code, rec.Body.String())
		}
	}
	// 终态：绑定落库（put 原子替换；bind/bulk additive 幂等不重复）。
	bound := queryBoundPolicyIDs(t, "lb_gate_tcp")
	if len(bound) != 1 || bound[0] != stage1 {
		t.Fatalf("bound=%v, want [stage1]", bound)
	}
	// 再补 stage0：批量入口 skipped 语义=非 G2/G3 不再跳过。
	if rec := l4GateBind(t, router, "batch", stage0, "lb_gate_tcp"); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "TCP 不支持的能力") {
		t.Fatalf("batch TCP+stage0 不得跳过: %d %s", rec.Code, rec.Body.String())
	}
	bound = queryBoundPolicyIDs(t, "lb_gate_tcp")
	if len(bound) != 2 {
		t.Fatalf("bound=%v, want stage0+stage1 都落库", bound)
	}
}

func TestL4BindingGate_tcpRejectsG23PoliciesWithNewMessage(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newL4GateRouter(t)
	seedTCPRule(t, "lb_gate_tcp_g2")
	stage2 := l4GateSeedPolicy(t, "gate-stage2", false, false, true, false)
	stage3 := l4GateSeedPolicy(t, "gate-stage3", false, false, false, true)

	for _, entry := range []string{"bind", "put", "bulk"} {
		for name, id := range map[string]int{"stage2": stage2, "stage3": stage3} {
			rec := l4GateBind(t, router, entry, id, "lb_gate_tcp_g2")
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "TCP 不支持的能力") {
				t.Fatalf("entry=%s policy=%s: %d %s, want 400「TCP 不支持的能力」", entry, name, rec.Code, rec.Body.String())
			}
		}
	}
	// 批量入口：进 skipped 分项（200），reason 同文案族。
	rec := l4GateBind(t, router, "batch", stage2, "lb_gate_tcp_g2")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "TCP 不支持的能力") {
		t.Fatalf("batch TCP+stage2: %d %s, want 200 skipped「TCP 不支持的能力」", rec.Code, rec.Body.String())
	}
	// 终态一致：任何入口都不得落库 G2/G3 绑定。
	if bound := queryBoundPolicyIDs(t, "lb_gate_tcp_g2"); len(bound) != 0 {
		t.Fatalf("G2/G3 绑定落库 %v, want 空", bound)
	}
}

func TestL4BindingGate_httpUnaffectedByGate(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newL4GateRouter(t)
	seedHTTPRule(t, "lb_gate_http")
	stage2 := l4GateSeedPolicy(t, "gate-http-stage2", false, false, true, false)
	stage3 := l4GateSeedPolicy(t, "gate-http-stage3", false, false, false, true)

	for _, id := range []int{stage2, stage3} {
		if rec := l4GateBind(t, router, "bind", id, "lb_gate_http"); rec.Code != http.StatusOK {
			t.Fatalf("HTTP 规则绑定被误拒: %d %s", rec.Code, rec.Body.String())
		}
	}
	if bound := queryBoundPolicyIDs(t, "lb_gate_http"); len(bound) != 2 {
		t.Fatalf("bound=%v, want 2（HTTP 不受门影响）", bound)
	}
}

// TCP 终态收口单源：G2/G3 特征绑定清零，stage0/1 绑定保留（新语义核心形状）。
func TestL4BindingGate_pruneKeepsStage01DropsG23(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	seedTCPRule(t, "lb_gate_tcp_term")
	stage1 := l4GateSeedPolicy(t, "gate-term-stage1", false, true, false, false)
	stage3 := l4GateSeedPolicy(t, "gate-term-stage3", false, false, false, true)
	stage0 := l4GateSeedPolicy(t, "gate-term-stage0", true, false, false, false)
	for _, id := range []int{stage1, stage3, stage0} {
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_gate_tcp_term', ?)`, id); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	dropped, err := pruneTCPUnsupportedBindings(context.Background(), tx)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped=%d, want 1（仅 G3 绑定）", dropped)
	}
	// 终态在事务视图内读取（prune 未提交，db.DB 视角仍见原状）。
	rows, err := tx.Query(`SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id='lb_gate_tcp_term' ORDER BY policy_id`)
	if err != nil {
		t.Fatal(err)
	}
	bound := []int{}
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		bound = append(bound, id)
	}
	rows.Close()
	if len(bound) != 2 || bound[0] != stage1 || bound[1] != stage0 {
		t.Fatalf("bound=%v, want [stage1 stage0] 保留（G3 已清）", bound)
	}
}

// SplitSecurityPolicy（mixed 拆分重映射）：TCP 规则绑定的 mixed 策略仅含
// G0/G1 特征时子策略照常重映射；含 G2/G3 特征时进 skipped（保留原绑定）。
func TestL4BindingGate_splitRemapRespectsTCPFeatureGate(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newL4GateRouter(t)

	// mixed 仅 G0+G1：拆分产出 stage0/stage1 子策略 → TCP 规则可重映射。
	seedTCPRule(t, "lb_gate_tcp_split")
	pure := l4GateSeedPolicy(t, "gate-split-pure", true, true, false, false)
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_gate_tcp_split', ?)`, pure); err != nil {
		t.Fatal(err)
	}
	rec := postJSON(t, router, "/security/policies/"+strconv.Itoa(pure)+"/split", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("mixed(G0+G1) 拆分失败: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"rule_id":"lb_gate_tcp_split"`) {
		t.Fatalf("纯阶段0/1 mixed 拆分不得跳过 TCP 规则: %s", rec.Body.String())
	}
	bound := queryBoundPolicyIDs(t, "lb_gate_tcp_split")
	if len(bound) == 0 || (len(bound) == 1 && bound[0] == pure) {
		t.Fatalf("TCP 规则应持有重映射后的子策略绑定: %v", bound)
	}

	// mixed 含 G2：TCP 规则进 skipped（新文案），原绑定保留。
	seedTCPRule(t, "lb_gate_tcp_split2")
	rich := l4GateSeedPolicy(t, "gate-split-rich", true, true, true, false)
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_gate_tcp_split2', ?)`, rich); err != nil {
		t.Fatal(err)
	}
	rec = postJSON(t, router, "/security/policies/"+strconv.Itoa(rich)+"/split", map[string]any{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "TCP 不支持的能力") {
		t.Fatalf("mixed(含G2) 拆分应跳过 TCP 规则: %d %s", rec.Code, rec.Body.String())
	}
	if bound := queryBoundPolicyIDs(t, "lb_gate_tcp_split2"); len(bound) != 1 || bound[0] != rich {
		t.Fatalf("原绑定必须保留: %v", bound)
	}
}

// 回归（端到端实证实锤）：PUT 是「空绑定上的原子替换」唯一入口，必须自己落库。
// 缺陷形态：TCP 分支在能力门后提前 return，DELETE+INSERT 写入段永不执行——
// 绑定静默丢失却返回 200（既有用例因 bind 入口先行写入而掩盖了 put 的丢失）。
// 本用例隔离：全新规则、首个动作即 put，终态必须有绑定行。
func TestL4BindingGate_putWritesTCPBindingsInIsolation(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newL4GateRouter(t)
	seedTCPRule(t, "lb_gate_tcp_put")
	stage1 := l4GateSeedPolicy(t, "gate-put-stage1", false, true, false, false)

	if rec := l4GateBind(t, router, "put", stage1, "lb_gate_tcp_put"); rec.Code != http.StatusOK {
		t.Fatalf("put TCP+stage1 被拒: %d %s", rec.Code, rec.Body.String())
	}
	bound := queryBoundPolicyIDs(t, "lb_gate_tcp_put")
	if len(bound) != 1 || bound[0] != stage1 {
		t.Fatalf("bound=%v, want [stage1]（put 必须落库，静默丢绑定=回归）", bound)
	}
	// 替换语义：put 只含 stage0 → 终态恰为 [stage0]。
	stage0 := l4GateSeedPolicy(t, "gate-put-stage0", true, false, false, false)
	if rec := l4GateBind(t, router, "put", stage0, "lb_gate_tcp_put"); rec.Code != http.StatusOK {
		t.Fatalf("put TCP+stage0 被拒: %d %s", rec.Code, rec.Body.String())
	}
	bound = queryBoundPolicyIDs(t, "lb_gate_tcp_put")
	if len(bound) != 1 || bound[0] != stage0 {
		t.Fatalf("bound=%v, want [stage0]（put 原子替换）", bound)
	}
}
