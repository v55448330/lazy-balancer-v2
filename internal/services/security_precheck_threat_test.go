package services

import "testing"

// 归因族（v2.3.2）：id:14 归入 IP 族（能力首选层/fallback 共用谓词）——
// id:14 发射已随名单化重构移除，本谓词保留给历史事件归因（存量事件
// rule_triggered='14' 仍须可归族，与旧共享 id:8 历史保留先例同族）。
func TestThreatAttribution_id14IsIPFamily(t *testing.T) {
	if !securityEventsRuleIsIPFamily("14") {
		t.Fatal("id:14 必须归入 IP 族（securityEventsRuleIsIPFamily，历史事件口径）")
	}
}
