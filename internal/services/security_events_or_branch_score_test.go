package services

import (
	"encoding/json"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// OR 计分规则的评分点在父规则级（分支只置命中标记），因此分支的审计 raw 不再
// 携带 setvar:tx.inbound_anomaly_score_pl1=+N 字面量——事件评分必须按发射 id
// 回查父规则 cr.Score 补齐，否则检测/仅自定义模式（无 949 累计分文本）下事件
// 评分列与大屏危险等级会从 N 掉到 0。
const securityEventsORBranchRaw = `{
  "transaction": {
    "id": "tx-or-branch-1",
    "unix_timestamp": 1786000000000000000,
    "client_ip": "198.51.100.11",
    "is_interrupted": false,
    "request": {"method": "GET", "uri": "/admin"},
    "server_id": "example.com"
  },
  "messages": [
    {
      "message": "自定义规则 任一满足 命中",
      "data": {
        "id": 3642688,
        "raw": "SecRule REQUEST_URI \"@contains /admin\" \"id:3642688,phase:1,pass,log,setvar:tx.lb_cr_or_hit_10042=1,msg:'自定义规则 任一满足 命中'\""
      }
    }
  ]
}`

func TestParseTransaction_flagsORScoringBranchWithoutScore(t *testing.T) {
	rec, err := securityEventsParseTransaction(json.RawMessage(securityEventsORBranchRaw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.RuleTriggered != "3642688" {
		t.Fatalf("rule=%q, want 分支发射 id 3642688", rec.RuleTriggered)
	}
	if !rec.customRuleScoreFallback {
		t.Fatal("OR 计分分支（raw 只置命中标记）必须走「按父规则补分」路径")
	}
	if rec.AnomalyScore != 0 {
		t.Fatalf("anomaly_score=%d, want 0（分支 raw 不含评分字面量）", rec.AnomalyScore)
	}
	policyByID := map[int]*models.SecurityPolicy{
		7: {
			ID:          7,
			CustomRules: json.RawMessage(`[{"id":42,"name":"任一满足","conditions":[{"target":"uri","operator":"contains","pattern":"/admin"},{"target":"uri","operator":"contains","pattern":"/secret"}],"action":"pass","score":5,"enabled":true}]`),
		},
	}
	if got := securityEventsChainedCustomRuleScore(rec.RuleTriggered, policyByID, 0); got != 5 {
		t.Fatalf("补分=%d, want 5（分支 id → 父规则 42；多分支命中不得累加）", got)
	}
}

// 回归形状：block 动作的 OR 分支仍内联评分字面量（deny 是破坏性动作，首个命中
// 即中断），raw 解析出的评分保持原样，不得被补分路径改写。
func TestParseTransaction_keepsInlineScoreForBlockORBranch(t *testing.T) {
	raw := `{
  "transaction": {"id": "tx-or-block-1", "unix_timestamp": 1786000000000000000, "client_ip": "198.51.100.12",
    "is_interrupted": true, "request": {"method": "GET", "uri": "/admin"}, "server_id": "example.com"},
  "messages": [{"message": "自定义规则 拦截 命中", "data": {"id": 3642689,
    "raw": "SecRule REQUEST_URI \"@contains /admin\" \"id:3642689,phase:1,deny,log,setvar:tx.inbound_anomaly_score_pl1=+5,msg:'自定义规则 拦截 命中',skipAfter:SECURITY_RULES_END\""}}]
}`
	rec, err := securityEventsParseTransaction(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.customRuleScoreFallback {
		t.Fatal("block OR 分支 raw 自带评分，不得标记补分")
	}
	if rec.AnomalyScore != 5 {
		t.Fatalf("anomaly_score=%d, want 5（raw 字面量原样解析）", rec.AnomalyScore)
	}
}
