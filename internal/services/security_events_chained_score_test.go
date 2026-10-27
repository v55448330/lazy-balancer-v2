package services

import (
	"encoding/json"
	"fmt"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 多条件链式自定义规则把 setvar 迁到链尾，
// coraza 审计 raw 只含起始条（无 setvar）→ anomaly_score 恒 0 且固定语义分不覆盖
// 自定义族。摄入侧必须按发射 id 回查 cr.Score 补分。

const securityEventsChainedCustomRaw = `{
  "transaction": {
    "id": "tx-chain-1",
    "unix_timestamp": 1786000000000000000,
    "client_ip": "198.51.100.9",
    "is_interrupted": true,
    "request": {"method": "GET", "uri": "/chain"},
    "server_id": "example.com"
  },
  "messages": [
    {
      "message": "自定义规则 拦截规则 命中",
      "data": {
        "id": 10042,
        "raw": "SecRule ARGS \"@rx foo\" \"id:10042,phase:1,deny,log,msg:'自定义规则 拦截规则 命中',skipAfter:SECURITY_RULES_END,chain\""
      }
    }
  ]
}`

func TestParseTransaction_flagsChainedCustomRuleWithoutScore(t *testing.T) {
	rec, err := securityEventsParseTransaction(json.RawMessage(securityEventsChainedCustomRaw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.RuleTriggered != "10042" {
		t.Fatalf("rule=%q, want 10042", rec.RuleTriggered)
	}
	if !rec.customRuleScoreFallback {
		t.Fatal("链式起始条（raw 以 ,chain 结尾）必须被识别，才能走补分路径")
	}
	if rec.AnomalyScore != 0 {
		t.Fatalf("anomaly_score=%d, want 0（raw 无 setvar，需补分）", rec.AnomalyScore)
	}
}

func TestSecurityEventsChainedCustomRuleScore(t *testing.T) {
	policyByID := map[int]*models.SecurityPolicy{
		7: {
			ID:          7,
			CustomRules: json.RawMessage(`[{"id":42,"name":"拦截规则","conditions":[{"target":"args","operator":"rx","pattern":"foo"},{"target":"uri","operator":"rx","pattern":"/chain"}],"action":"block","score":5,"enabled":true}]`),
		},
	}

	if got := securityEventsChainedCustomRuleScore("10042", policyByID, 0); got != 5 {
		t.Fatalf("score=%d, want 5（发射 id 10042 → 自定义规则 42）", got)
	}
	// 非自定义段（CRS / GeoIP / IP 族）永不补分
	for _, id := range []string{"942100", "800001", "2", "1000000", "abc"} {
		if got := securityEventsChainedCustomRuleScore(id, policyByID, 0); got != 0 {
			t.Fatalf("id=%s score=%d, want 0（不属自定义段）", id, got)
		}
	}
	// 规则不存在 / 策略为空时不补分
	if got := securityEventsChainedCustomRuleScore("10999", policyByID, 0); got != 0 {
		t.Fatalf("score=%d, want 0（规则 999 不存在）", got)
	}
	if got := securityEventsChainedCustomRuleScore("10042", nil, 0); got != 0 {
		t.Fatalf("score=%d, want 0（无策略装载）", got)
	}
}

// 同一规则 id 被两个策略以不同 score 内嵌引用（旧数据/带外改写）时，取值
// 必须确定：优先归因策略，未命中按最小 policy_id——map 迭代序会让同一事件
// 在不同 tick/重放得到 3 或 7 分（评分列/大屏分档抖动）。
func TestSecurityEventsChainedCustomRuleScore_isDeterministic(t *testing.T) {
	rule := func(score int) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`[{"id":42,"name":"r","conditions":[{"target":"uri","operator":"rx","pattern":"/x"}],"action":"block","score":%d,"enabled":true}]`, score))
	}
	policyByID := map[int]*models.SecurityPolicy{
		3: {ID: 3, CustomRules: rule(7)},
		9: {ID: 9, CustomRules: rule(3)},
	}
	for range 50 {
		if got := securityEventsChainedCustomRuleScore("10042", policyByID, 0); got != 7 {
			t.Fatalf("score=%d, want 7（无归因策略时取最小 policy_id=3）", got)
		}
	}
	// 归因策略自身引用该规则时以它为准
	if got := securityEventsChainedCustomRuleScore("10042", policyByID, 9); got != 3 {
		t.Fatalf("score=%d, want 3（归因策略 #9 的引用分）", got)
	}
}
