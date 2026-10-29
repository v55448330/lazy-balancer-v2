package services

import (
	"sync"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given IPC 批摄取与 live 尾读取得同一代际的共享策略映射。
// When 两路在首次事件归因时并发读取策略分析结果。
// Then 分析快照只允许完整发布，所有归因结果保持一致且通过竞态检测。
func TestSecurityEventsMappings_sharedPolicyAnalysisRaceFree(t *testing.T) {
	if err := initSecurityEventsTestDB(t, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	resetSecurityEventsMappingsCacheForTest()
	if _, err := db.DB.Exec(`INSERT INTO security_policies
		(id, name, mode, enabled, crs_rule_groups, custom_rules, ip_acl_enabled, ip_acl_mode, ip_acl_list, ip_blacklist)
		VALUES (1, 'shared-analysis', 'blocking', 1, '["42"]', '[{"id":7,"name":"embedded","enabled":true,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/admin"}]}]', 1, 'deny', '["203.0.113.0/24"]', '["198.51.100.0/24"]')`); err != nil {
		t.Fatal(err)
	}
	_, _, first, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatal(err)
	}
	_, _, second, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatal(err)
	}
	policy := first[1]
	if policy == nil || second[1] != policy {
		t.Fatal("同一代际必须复用同一策略映射快照")
	}
	if !policy.CustomRulesCached || len(policy.CustomRulesCache) != 1 {
		t.Fatalf("内嵌自定义规则必须在映射发布前完成解析: cached=%v rules=%d", policy.CustomRulesCached, len(policy.CustomRulesCache))
	}

	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	for range 4 {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			for range 50 {
				securityEventsPolicyCRSGroups(policy)
				securityEventsPolicyCustomEmitIDs(policy)
				securityEventsPolicyACLIndex(policy)
				securityEventsPolicyBlacklistIndex(policy)
				policyCustomRulesCached(policy, nil)
			}
		}()
	}
	start.Done()
	done.Wait()

	groups, groupsOK := securityEventsPolicyCRSGroups(policy)
	_, customOK := securityEventsPolicyCustomEmitIDs(policy)
	acl := securityEventsPolicyACLIndex(policy)
	blacklist := securityEventsPolicyBlacklistIndex(policy)
	if _, ok := groups["42"]; !groupsOK || !ok || !customOK {
		t.Fatalf("规则分析快照不完整: groups=%v groupsOK=%v customOK=%v", groups, groupsOK, customOK)
	}
	if !acl.Built || !acl.OK || acl.Entries != 1 || !blacklist.Built || !blacklist.OK || blacklist.Entries != 1 {
		t.Fatalf("名单分析快照不完整: acl=%+v blacklist=%+v", acl, blacklist)
	}
}
