package services

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// TestBuildIPPrecheckDirectives_crawlerExemption 两形态（v2.3.8 爬虫豁免）：
// 开启豁免+勾选引擎 → 逐引擎 ctl 放行规则 + 伪装事件规则；
// 关闭豁免 → 无任何 X-LB-Crawler 规则。
func TestBuildIPPrecheckDirectives_crawlerExemption(t *testing.T) {
	on := &models.SecurityPolicy{
		ID: 7, Mode: "blocking", Enabled: true,
		GeoIPMode:           "deny",
		GeoIPCountries:      json.RawMessage(`["海外"]`),
		GeoIPCrawlerExempt:  true,
		GeoIPCrawlerEngines: json.RawMessage(`["googlebot","baiduspider"]`),
		IPWhitelistEnabled:  true,
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{on}, 403, "lb_crawler"))
	// 勾选引擎逐条 ctl 放行
	for _, engine := range []string{"googlebot", "baiduspider"} {
		want := `X-LB-Crawler-Verified "@streq ` + engine + `"`
		if !strings.Contains(directives, want) {
			t.Errorf("directives missing engine %s exemption rule:\n%s", engine, directives)
		}
	}
	// 未勾选引擎不得出现
	if strings.Contains(directives, `@streq bingbot`) {
		t.Errorf("未勾选引擎 bingbot 不应发射:\n%s", directives)
	}
	// 伪装事件规则（UA 声称引擎但 PTR 验证失败）
	if !strings.Contains(directives, "X-LB-Crawler-Spoof") || !strings.Contains(directives, "搜索引擎爬虫伪装") {
		t.Errorf("directives missing spoof event rule:\n%s", directives)
	}
	// ctl 指向本策略 GeoIP 链 id（800000+policyID）
	if !strings.Contains(directives, "ctl:ruleRemoveById=800007") {
		t.Errorf("ctl must target geoip chain id 800007:\n%s", directives)
	}

	// 关闭形态：零爬虫规则（含 GeoIP 仍启用的策略）
	off := &models.SecurityPolicy{
		ID: 8, Mode: "blocking", Enabled: true,
		GeoIPMode:          "deny",
		GeoIPCountries:     json.RawMessage(`["海外"]`),
		IPWhitelistEnabled: true,
	}
	directivesOff := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{off}, 403, "lb_off"))
	if strings.Contains(directivesOff, "X-LB-Crawler") {
		t.Errorf("豁免关闭时不得有任何爬虫规则:\n%s", directivesOff)
	}
	// GeoIP 主体链仍在（豁免不改变地域拦截本体）
	if !strings.Contains(directivesOff, "GeoIP 区域拦截") {
		t.Errorf("GeoIP 主体链缺失:\n%s", directivesOff)
	}
}

// TestBuildIPPrecheckDirectives_crawlerExemptionEmptyEnginesAllEngines：
// 豁免开启但 engines 空/非法 JSON → 全部引擎（向后兼容形态）。
func TestBuildIPPrecheckDirectives_crawlerExemptionEmptyEnginesAllEngines(t *testing.T) {
	p := &models.SecurityPolicy{
		ID: 9, Mode: "blocking", Enabled: true,
		GeoIPMode:          "deny",
		GeoIPCountries:     json.RawMessage(`["海外"]`),
		GeoIPCrawlerExempt: true,
		IPWhitelistEnabled: true,
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p}, 403, "lb_x"))
	for _, engine := range []string{"googlebot", "bingbot", "gptbot", "so360spider"} {
		if !strings.Contains(directives, `@streq `+engine) {
			t.Errorf("空 engines 应发射全部引擎（含 %s）:\n%s", engine, directives)
		}
	}
}

// TestEngineGate_crawlerExemptionDirectives（R-10）：爬虫豁免/伪装规则的
// 真实渲染产物必须被同版 coraza 引擎编译接受（字符串断言不构成验证终点）。
func TestEngineGate_crawlerExemptionDirectives(t *testing.T) {
	p := &models.SecurityPolicy{
		ID: 3, Mode: "blocking", Enabled: true,
		GeoIPMode:           "deny",
		GeoIPCountries:      json.RawMessage(`["海外"]`),
		GeoIPCrawlerExempt:  true,
		GeoIPCrawlerEngines: json.RawMessage(`["googlebot","so360spider"]`),
		IPWhitelistEnabled:  true,
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p}, 403, "lb_gate"))
	compileForEngineGate(t, directives)
}

// TestEngineGate_crawlerPassLogDetectedAction（v2.3.8）：豁免规则须为
// pass,log（检测动作事件完整落库），非 pass,nolog。
func TestEngineGate_crawlerPassLogDetectedAction(t *testing.T) {
	p := &models.SecurityPolicy{
		ID: 3, Mode: "blocking", Enabled: true,
		GeoIPMode:           "deny",
		GeoIPCountries:      json.RawMessage(`["海外"]`),
		GeoIPCrawlerExempt:  true,
		GeoIPCrawlerEngines: json.RawMessage(`["googlebot"]`),
		IPWhitelistEnabled:  true,
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p}, 403, "lb_gate"))
	if strings.Contains(directives, "pass,nolog") {
		t.Errorf("豁免规则不得为 pass,nolog（须落检测事件）:\n%s", directives)
	}
	if !strings.Contains(directives, "pass,log") || !strings.Contains(directives, "搜索引擎爬虫放行（已验证）") {
		t.Errorf("豁免规则缺 pass,log + 放行 msg:\n%s", directives)
	}
	compileForEngineGate(t, directives)
}
