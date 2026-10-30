package services

// L4 合成审计事件行摄取映射 RED 测试（契约 C1）：X-LB-Protocol: tcp 头是
// event_type='tcp' 的唯一信号；归因/去重/评分/族分类零新增（复用既有分支）。
// 缺失该头按 'waf'（向后兼容回归形状）。
import (
	"encoding/json"
	"fmt"
	"testing"
)

func l4SecSyntheticRow(ruleID int, message string) []byte {
	return []byte(fmt.Sprintf(`{
		"transaction": {
			"unix_timestamp": 1799000000123456789,
			"id": "l4-1799000000123456789-a1b2c3d4",
			"client_ip": "203.0.113.7",
			"server_id": "",
			"request": {
				"method": "",
				"uri": "",
				"headers": {
					"X-LB-Rule-ID": ["lb_tcp_target"],
					"X-LB-Protocol": ["tcp"]
				}
			},
			"is_interrupted": true
		},
		"messages": [{"data": {"id": %d}, "message": %s}]
	}`, ruleID, mustJSONString(message)))
}

func mustJSONString(s string) string {
	raw, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func l4SecParseRow(t *testing.T, ruleID int, message string) *securityEventRecord {
	t.Helper()
	rec, err := securityEventsParseTransaction(l4SecSyntheticRow(ruleID, message))
	if err != nil {
		t.Fatalf("parse synthetic L4 row: %v", err)
	}
	return rec
}

// 合成行（deny 段位 id:2）全字段钉测：event_type/归因/去重/评分/action/文案。
func TestSecurityEventsParseTransaction_tcpSyntheticRowDenySegment(t *testing.T) {
	rec := l4SecParseRow(t, 2, "IP 黑名单拒绝")
	if rec.EventType != "tcp" {
		t.Fatalf("event_type=%q, want tcp", rec.EventType)
	}
	if rec.TransactionID != "l4-1799000000123456789-a1b2c3d4" {
		t.Fatalf("transaction_id=%q（去重幂等键必须来自 transaction.id）", rec.TransactionID)
	}
	if rec.AttributionRuleID != "lb_tcp_target" {
		t.Fatalf("归因规则=%q, want lb_tcp_target", rec.AttributionRuleID)
	}
	if rec.Action != "blocked" {
		t.Fatalf("action=%q, want blocked（is_interrupted:true）", rec.Action)
	}
	if rec.RuleTriggered != "2" {
		t.Fatalf("rule_triggered=%q, want 2", rec.RuleTriggered)
	}
	if rec.RuleMsg != "IP 黑名单拒绝" {
		t.Fatalf("rule_msg=%q, want 预检同款文案", rec.RuleMsg)
	}
	if rec.AnomalyScore != 12 {
		t.Fatalf("anomaly_score=%d, want 12（预检段固定语义分）", rec.AnomalyScore)
	}
	if rec.Method != "" || rec.URI != "" {
		t.Fatalf("method/uri=%q/%q, want 空（TCP 连接无 HTTP 语义）", rec.Method, rec.URI)
	}
	if rec.ClientIP != "203.0.113.7" {
		t.Fatalf("client_ip=%q", rec.ClientIP)
	}
}

// 独立黑名单（id:4）与 allow 交集外（id:7）同样落 12 分（既有 IsStage1 分支复用）。
func TestSecurityEventsParseTransaction_tcpSyntheticRowBlacklistAndAllowSegments(t *testing.T) {
	for _, tc := range []struct {
		ruleID int
		msg    string
	}{
		{ruleID: 4, msg: "IP 黑名单"},
		{ruleID: 7, msg: "IP 白名单拒绝"},
	} {
		rec := l4SecParseRow(t, tc.ruleID, tc.msg)
		if rec.EventType != "tcp" {
			t.Fatalf("id %d: event_type=%q, want tcp", tc.ruleID, rec.EventType)
		}
		if rec.AnomalyScore != 12 {
			t.Fatalf("id %d: anomaly_score=%d, want 12", tc.ruleID, rec.AnomalyScore)
		}
	}
}

// GeoIP 段位（800000+policyID）：event_type=tcp 且走既有 6 分分支。
func TestSecurityEventsParseTransaction_tcpSyntheticRowGeoipSegment(t *testing.T) {
	rec := l4SecParseRow(t, 800001, "GeoIP 区域拦截")
	if rec.EventType != "tcp" {
		t.Fatalf("event_type=%q, want tcp", rec.EventType)
	}
	if rec.RuleTriggered != "800001" {
		t.Fatalf("rule_triggered=%q, want 800001", rec.RuleTriggered)
	}
	if rec.AnomalyScore != 6 {
		t.Fatalf("anomaly_score=%d, want 6（GeoIP 中危）", rec.AnomalyScore)
	}
}

// 缺 X-LB-Protocol 头 → 'waf'（向后兼容）。
func TestSecurityEventsParseTransaction_missingProtocolHeaderStaysWaf(t *testing.T) {
	raw := []byte(`{
		"transaction": {
			"unix_timestamp": 1799000000123456789,
			"id": "waf-tx-1",
			"client_ip": "198.51.100.9",
			"request": {"method": "GET", "uri": "/a", "headers": {"X-LB-Rule-ID": ["lb_http_1"]}},
			"is_interrupted": true
		},
		"messages": [{"data": {"id": 2}, "message": "IP 黑名单拒绝"}]
	}`)
	rec, err := securityEventsParseTransaction(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.EventType != "waf" {
		t.Fatalf("event_type=%q, want waf（缺头向后兼容）", rec.EventType)
	}
}

// 非 tcp 值不触发改判：只有字面 tcp 落 'tcp'，其余按 waf。
func TestSecurityEventsParseTransaction_nonTcpProtocolHeaderStaysWaf(t *testing.T) {
	raw := []byte(`{
		"transaction": {
			"unix_timestamp": 1799000000123456789,
			"id": "waf-tx-2",
			"client_ip": "198.51.100.9",
			"request": {"method": "GET", "uri": "/a", "headers": {"X-LB-Protocol": ["http"]}},
			"is_interrupted": false
		},
		"messages": []
	}`)
	rec, err := securityEventsParseTransaction(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.EventType != "waf" {
		t.Fatalf("event_type=%q, want waf", rec.EventType)
	}
}
