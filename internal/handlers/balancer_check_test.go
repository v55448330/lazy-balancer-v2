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
	for _, w := range warnings {
		if w == `规则 ql 的负载策略 "" 无法映射，已使用 weighted_round_robin` || w == `规则 home 的负载策略 "" 无法映射，已使用 weighted_round_robin` {
			t.Fatalf("empty balancer_type still warned: %s", w)
		}
	}
	foundOdd := false
	for _, w := range warnings {
		if w == `规则 odd 的负载策略 "round_robin_custom" 无法映射，已使用 weighted_round_robin` {
			foundOdd = true
		}
	}
	if !foundOdd {
		t.Fatalf("non-empty unmappable should still warn, got: %v", warnings)
	}
}
