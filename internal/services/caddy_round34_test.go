package services

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"lazy-balancer-v2/internal/models"
)

// TestCaddyErrorBodyTruncation 验证 F-R34-1：Caddy 管理接口错误响应体嵌入 error
// 前被截断到 1KB 内且保持合法 UTF-8，防止经 last_sync_error / cert_jobs.message
// 等有界通道传播时膨胀。
func TestCaddyErrorBodyTruncation(t *testing.T) {
	// 1500 字节中文 + 3KB ASCII 的混合超长错误体：截断点落在多字节字符中间。
	longBody := strings.Repeat("中", 500) + strings.Repeat("x", 3000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "validate=true") {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
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

	// /load?validate=true 路径（ValidateConfig）
	validateErr := service.ValidateConfig(map[string]interface{}{})
	if validateErr == nil {
		t.Fatal("ValidateConfig succeeded despite mock 400")
	}
	assertBoundedErrorBody(t, "ValidateConfig", validateErr.Error())
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

// Round 34 F-5（v2.2.0 多策略改写）：批量预载必须与 GetSecurityPoliciesForRule
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

// Round 34 F-2/F-3: 定向 server 上下文与全量渲染同口径——enable_tls=0 的规则
// 不加载证书；同端口规则无启用上游或未开 TLS 时不进 TLS 策略。
func TestGenerateRuleServerContext_gatesByEnableTLSAndEnabledUpstreams(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedTLSCtxRule(t, database, "lb_ctx_main", 8443, 1, "main.example.test", 1)
	// 同端口：开 TLS + 有证书，但无任何启用上游 → 不进策略
	seedTLSCtxRule(t, database, "lb_ctx_no_upstream", 8443, 1, "noupstream.example.test", 0)
	// 同端口：有启用上游 + 有证书，但 enable_tls=0 → 不进策略
	seedTLSCtxRule(t, database, "lb_ctx_no_tls", 8443, 0, "notls.example.test", 1)
	// 主规则自身 enable_tls=0 的对照
	seedTLSCtxRule(t, database, "lb_ctx_main_off", 9443, 0, "mainoff.example.test", 1)

	// When
	cfg := GenerateRuleServerContext("lb_ctx_main", 8443, "http", "main.example.test")
	server := cfg["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})["http_8443"].(map[string]interface{})

	// Then 仅主规则进入 TLS 策略（no_tls/no_upstream 被门控）
	policies, _ := server["tls_connection_policies"].([]interface{})
	if len(policies) != 1 {
		t.Fatalf("tls_connection_policies 条数=%d, want 1: %#v", len(policies), server["tls_connection_policies"])
	}
	sel := policies[0].(map[string]interface{})["certificate_selection"].(map[string]interface{})
	if tags, _ := sel["any_tag"].([]string); len(tags) != 1 || tags[0] != "lb_ctx_main" {
		t.Fatalf("any_tag=%#v, want [lb_ctx_main]", sel["any_tag"])
	}
	// 主规则开 TLS + 手动证书 → 加载证书文件
	tlsApp, hasTLS := cfg["apps"].(map[string]interface{})["tls"].(map[string]interface{})
	if !hasTLS {
		t.Fatal("主规则开启 TLS 应生成 tls.load_files")
	}
	if _, ok := tlsApp["certificates"].(map[string]interface{}); !ok {
		t.Fatalf("tls app 缺 certificates: %#v", tlsApp)
	}

	// When 主规则 enable_tls=0 的对照
	cfgOff := GenerateRuleServerContext("lb_ctx_main_off", 9443, "http", "mainoff.example.test")
	// Then 不加载证书
	if _, hasTLS := cfgOff["apps"].(map[string]interface{})["tls"].(map[string]interface{}); hasTLS {
		t.Fatal("enable_tls=0 的规则不应生成 tls.load_files")
	}
}

// seedTLSCtxRule 播种一条带手动证书与（可选）启用上游的 HTTP TLS 规则。
func seedTLSCtxRule(t *testing.T, database *sql.DB, ruleID string, port int, enableTLS int, domain string, enabledUpstream int) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_tls,tls_source,tls_cert,tls_key)
		VALUES (?,?, 'http', ?, ?, 'weighted_round_robin', '', 1, ?, 'manual', 'cert', 'key')`, ruleID, ruleID, domain, port, enableTLS); err != nil {
		t.Fatalf("seed TLS ctx rule %s: %v", ruleID, err)
	}
	if enabledUpstream == 1 {
		if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES (?, '127.0.0.1', 9000, 1, 'http')`, ruleID); err != nil {
			t.Fatalf("seed TLS ctx upstream %s: %v", ruleID, err)
		}
	}
}
