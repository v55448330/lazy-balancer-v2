// 主题：v1 规则导入转换的负载策略告警口径——空 balancer_type 静默落入默认
// weighted_round_robin（不告警）；非空且不可映射的值保留告警。文件名
// balancer_check 为历史遗留，实质钉的是 convertV1Rules 的 warnings 行为。
package handlers

import "testing"

func TestConvertV1Rules_emptyBalancerTypeProducesNoWarning(t *testing.T) {
	newProxy := func(name, balancerType string) v1Proxy {
		p := v1Proxy{PK: 1}
		p.Fields.ProxyName = name
		p.Fields.BalancerType = balancerType
		p.Fields.ServerName = name + ".example.com"
		p.Fields.Listen = 80
		p.Fields.Status = true
		return p
	}
	proxies := []v1Proxy{newProxy("ql", ""), newProxy("home", ""), newProxy("odd", "round_robin_custom")}
	_, warnings := convertV1Rules(proxies, nil)
	for _, w := range zhWarnings(warnings) {
		if w == `规则 ql 的负载策略 "" 无法映射，已使用 weighted_round_robin` || w == `规则 home 的负载策略 "" 无法映射，已使用 weighted_round_robin` {
			t.Fatalf("empty balancer_type still warned: %s", w)
		}
	}
	foundOdd := false
	for _, w := range zhWarnings(warnings) {
		if w == `规则 odd 的负载策略 "round_robin_custom" 无法映射，已使用 weighted_round_robin` {
			foundOdd = true
		}
	}
	if !foundOdd {
		t.Fatalf("non-empty unmappable should still warn, got: %v", warnings)
	}
}
