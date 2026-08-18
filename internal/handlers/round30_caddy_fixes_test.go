package handlers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// Round 30 F-4: 启动校验必须一次报出全部坏规则——首错即 return 会让多条坏规则
// 需要重启多次才能逐一暴露；聚合错误每条含规则名 + caddy_id。
func TestValidateEnabledStoredRuleConfigs_reports_all_bad_rules(t *testing.T) {
	// Given
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_http_redirect) VALUES
		('lb_bad_a','坏规则甲','http','a.example.test',80,1,1,1),
		('lb_bad_b','坏规则乙','http','b.example.test',80,1,1,1)`); err != nil {
		t.Fatalf("seed bad rules: %v", err)
	}

	// When
	err := validateEnabledStoredRuleConfigs(context.Background())

	// Then: 两条坏规则在同一次校验中全部报出
	if err == nil {
		t.Fatal("validateEnabledStoredRuleConfigs 接受了两条 80 端口 TLS 跳转自环规则")
	}
	message := err.Error()
	for _, want := range []string{"坏规则甲", "lb_bad_a", "坏规则乙", "lb_bad_b"} {
		if !strings.Contains(message, want) {
			t.Fatalf("错误信息必须包含 %q，实际: %s", want, message)
		}
	}
}

// Round 31 C-2: 零上游规则的特判必须保留——全量渲染路径对零上游规则是跳过
// 而非失败（caddy.go 按启用上游数 continue），预校验返回 nil 与之对齐。
func TestValidateRuleConfigGeneration_zeroUpstreams_returnsNil(t *testing.T) {
	newBackupTestHandlers(t)
	rule := models.LbRule{CaddyID: "lb_zero", Protocol: "http", Domain: "zero.example.test", ListenPort: 80}

	if err := validateRuleConfigGeneration(rule); err != nil {
		t.Fatalf("零上游规则应返回 nil（全量渲染跳过），实际: %v", err)
	}
}

// Round 31 C-2: dynamic-DNS 错误保留既有中文 configValidationError 语义。
func TestValidateRuleConfigGeneration_dynamicDNS_returnsValidationError(t *testing.T) {
	newBackupTestHandlers(t)
	rule := models.LbRule{
		CaddyID: "lb_ddns", Protocol: "http", Domain: "ddns.example.test", ListenPort: 80,
		DynamicDNS: true, DnsFamily: "both",
		Upstreams: []models.Upstream{
			{Host: "up1.example.test", Port: 8080, Enabled: true},
			{Host: "up2.example.test", Port: 8080, Enabled: true},
		},
	}

	err := validateRuleConfigGeneration(rule)
	if err == nil {
		t.Fatal("dynamic-DNS 多上游应返回 configValidationError")
	}
	var validationErr *configValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("应为 configValidationError，实际: %T %v", err, err)
	}
	if !strings.Contains(validationErr.Error(), "动态 DNS 模式仅支持一个启用的上游") {
		t.Fatalf("错误信息不符，实际: %s", validationErr.Error())
	}
}

// Round 31 C-2: 合法规则基线——生成无错误时不误报。
func TestValidateRuleConfigGeneration_validRule_returnsNil(t *testing.T) {
	newBackupTestHandlers(t)
	rule := models.LbRule{
		CaddyID: "lb_ok", Protocol: "http", Domain: "ok.example.test", ListenPort: 80,
		Upstreams: []models.Upstream{
			{Host: "up1.example.test", Port: 8080, Enabled: true},
		},
	}

	if err := validateRuleConfigGeneration(rule); err != nil {
		t.Fatalf("合法规则应返回 nil，实际: %v", err)
	}
}

// Round 31 C-2 (INFO): 保存侧 normalizedRuleDomains 对 CanonicalDomains 失败
// （含 IP 等非法域名时整串报错）必须回退小写拆分保留，而非返回 nil 丢弃域名——
// 与渲染侧 normalizedDomainSet（caddy.go）同口径，避免遮蔽检查静默通过。
func TestNormalizedRuleDomains_fallsBackOnCanonicalizationFailure(t *testing.T) {
	// CanonicalDomains 对 IP 报错 → 整串失败 → 回退小写拆分
	got := normalizedRuleDomains("Example.COM, 192.168.0.1")
	want := []string{"example.com", "192.168.0.1"}
	if len(got) != len(want) {
		t.Fatalf("回退结果长度 %d，want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("回退结果[%d]=%q，want %q", i, got[i], want[i])
		}
	}
}

// Round 31 C-2 (INFO): 规范化成功时保持原语义（小写+punycode 去重），不因回退改动。
func TestNormalizedRuleDomains_keepsCanonicalResult(t *testing.T) {
	got := normalizedRuleDomains("Example.COM, example.com")
	if len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("规范化结果应为去重后的 [example.com]，实际: %v", got)
	}
}
