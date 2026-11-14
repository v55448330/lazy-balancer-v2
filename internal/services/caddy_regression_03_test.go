package services

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"lazy-balancer-v2/internal/models"
)

// 前被截断到 1KB 内且保持合法 UTF-8，防止经 last_sync_error / cert_jobs.message
// 等有界通道传播时膨胀。
func TestCaddyErrorBodyTruncation(t *testing.T) {
	// 1500 字节中文 + 3KB ASCII 的混合超长错误体：截断点落在多字节字符中间。
	longBody := strings.Repeat("中", 500) + strings.Repeat("x", 3000)
	// apply 与 validate 同为 POST /load（validate 查询参数已退役）——按调用
	// 序分发状态码：第 1 次（ApplyConfig）500，第 2 次（ValidateConfig）400。
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
		_, _ = w.Write([]byte(longBody))
	}))
	t.Cleanup(server.Close)
	service := NewCaddyService(server.URL)

	// /load 路径（applyConfigLocked）
	applyErr := service.ApplyConfig(map[string]interface{}{})
	if applyErr == nil {
		t.Fatal("ApplyConfig succeeded despite mock 500")
	}
	assertBoundedErrorBody(t, "ApplyConfig", applyErr.Error())

	// /load 路径（ValidateConfig，真实加载语义）
	validateErr := service.ValidateConfig(map[string]interface{}{})
	if validateErr == nil {
		t.Fatal("ValidateConfig succeeded despite mock 400")
	}
	assertBoundedErrorBody(t, "ValidateConfig", validateErr.Error())
}

// ValidateConfig 的状态码分类必须与 applyConfigWithOptions 同构：4xx=候选
// 配置被拒（ConfigRejectedError → handler 400），5xx=admin 系统故障（普通
// 错误 → handler 500）。把 5xx 归为「配置被拒」会让基础设施故障被表述成
// 用户配置错误，操作员会反复改一份本身正确的配置。
func TestValidateConfig_classifiesRejectionVsSystemFailure(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		wantReject bool
	}{
		{name: "4xx rejection", status: http.StatusBadRequest, wantReject: true},
		{name: "5xx system failure", status: http.StatusServiceUnavailable, wantReject: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"error":"boom"}`))
			}))
			t.Cleanup(server.Close)
			service := NewCaddyService(server.URL)

			err := service.ValidateConfig(map[string]interface{}{})
			if err == nil {
				t.Fatalf("ValidateConfig succeeded despite %d", tc.status)
			}
			if got := IsConfigRejected(err); got != tc.wantReject {
				t.Fatalf("IsConfigRejected(%d)=%v, want %v (err=%v)", tc.status, got, tc.wantReject, err)
			}
		})
	}
}

func assertBoundedErrorBody(t *testing.T, call, message string) {
	t.Helper()
	if !utf8.ValidString(message) {
		t.Fatalf("%s error contains invalid UTF-8: %q", call, message)
	}
	if len(message) > caddyErrorBodyMaxBytes+128 {
		t.Fatalf("%s error length=%d exceeds bound (%d+prefix)", call, len(message), caddyErrorBodyMaxBytes)
	}
	// 可操作的错误体前缀必须保留（前 100 个中文字符）。
	if !strings.Contains(message, strings.Repeat("中", 100)) {
		t.Fatalf("%s error lost the actionable body prefix: %.120s...", call, message)
	}
}

func TestGetSecurityPoliciesForRule_logsOnlyRealPolicyReadFailures(t *testing.T) {
	// Given a healthy binding, an enabled but type-corrupted policy, and a
	// normally disabled binding.
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_policy_scan", false)
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode,enabled,anomaly_threshold) VALUES
		(1,'healthy','off',1,5),
		(2,'corrupted','blocking',1,'not-an-integer'),
		(3,'disabled','blocking',0,5);
		INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_policy_scan',1),('lb_policy_scan',2),('lb_policy_scan',3)`); err != nil {
		t.Fatal(err)
	}
	logs := captureApplicationLogs(t)

	// When the preview/fallback path loads all bindings.
	policies := GetSecurityPoliciesForRule("lb_policy_scan")

	// Then healthy policies still load, the real read error is visible, and the
	// ordinary disabled/not-found shape remains silent.
	if len(policies) != 1 || policies[0].ID != 1 {
		t.Fatalf("policies=%+v, want only healthy policy #1", policies)
	}
	if !strings.Contains(logs.String(), "安全策略 #2") || !strings.Contains(logs.String(), "not-an-integer") {
		t.Fatalf("corrupted policy read must be visible, logs=%q", logs.String())
	}
	if strings.Contains(logs.String(), "安全策略 #3") {
		t.Fatalf("disabled policy must remain a normal empty result, logs=%q", logs.String())
	}
}

// 严格同构——每规则返回全部启用策略（policy_id ASC）。最高 policy_id 绑定指向
// 禁用策略时，预载切片恰好只含次低的启用策略（旧单策略 MAX 语义下两者都为 nil，
// 新语义下禁用绑定仅占位、不产生元素）。
func TestLoadSecurityPolicyContext_multiBindingMatchesMultiPolicyQuery(t *testing.T) {
	// Given 两条绑定：低 policy_id 启用 + 高 policy_id 禁用
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_multi_binding", false)
	seedBoundSecurityPolicy(t, database, "lb_multi_binding", "blocking", true)
	seedBoundSecurityPolicy(t, database, "lb_multi_binding", "blocking", false)

	// When 最高绑定为禁用策略：多策略查询仅返回次低的启用策略
	expected := GetSecurityPoliciesForRule("lb_multi_binding")
	if len(expected) != 1 {
		t.Fatalf("GetSecurityPoliciesForRule 应仅返回 1 条启用策略（禁用绑定被过滤），实际 %d 条", len(expected))
	}
	ctx, err := loadSecurityPolicyContext(database)
	if err != nil {
		t.Fatalf("loadSecurityPolicyContext: %v", err)
	}

	// Then 预载切片与多策略单查逐元素同构（id+mode 逐位置一致）
	assertPoliciesIsomorphic(t, expected, ctx.policyByRule["lb_multi_binding"])

	// When 删除禁用绑定（预载结果不应变化——禁用绑定本就零贡献）
	if _, err := database.Exec(`DELETE FROM security_policy_bindings WHERE policy_id = (SELECT MAX(policy_id) FROM security_policy_bindings WHERE rule_caddy_id='lb_multi_binding')`); err != nil {
		t.Fatalf("delete disabled binding: %v", err)
	}

	// Then 同构关系保持
	expectedAfter := GetSecurityPoliciesForRule("lb_multi_binding")
	ctx2, err := loadSecurityPolicyContext(database)
	if err != nil {
		t.Fatalf("loadSecurityPolicyContext(2): %v", err)
	}
	assertPoliciesIsomorphic(t, expectedAfter, ctx2.policyByRule["lb_multi_binding"])
}

// assertPoliciesIsomorphic 断言预载切片与 GetSecurityPoliciesForRule 逐元素一致
// （长度相等，每个位置的 id 与 mode 相同）。
func assertPoliciesIsomorphic(t *testing.T, want, got []*models.SecurityPolicy) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("预载策略数=%d，与 GetSecurityPoliciesForRule 的 %d 条不一致", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i].ID || got[i].Mode != want[i].Mode {
			t.Fatalf("位置 %d 预载 policy(id=%d mode=%s) 与单查 policy(id=%d mode=%s) 不一致", i, got[i].ID, got[i].Mode, want[i].ID, want[i].Mode)
		}
	}
}
