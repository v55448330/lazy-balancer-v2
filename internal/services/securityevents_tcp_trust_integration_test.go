package services

// L4 信任检测（trust_detect）TCP 摄取级集成钉：caddyl4sec 合成事件行
//（X-LB-Protocol: tcp + id:12 + is_interrupted=false）经完整 process pass
// 后必须升格 action=trust 落库——「今日/昨日检测 TCP 拆分」读侧按
// event_type='tcp' 窗口直算，直 seed tcp+logged 的旧夹具绕过升格，无法证明
// 生产形态（tcp+trust）可被统计。本文件从写侧形态出发覆盖升格→落库→
// 按协议/动作可查的完整链路。

import (
	"context"
	"fmt"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// l4TrustDetectRow 构造 caddyl4sec buildL4EventLine 同形态的信任检测事件行
// （契约 C1：messages 是 transaction 的顶层兄弟；method/uri 恒空；
// is_interrupted=false → 摄取侧 logged，再经 id:12 升格 trust）。
func l4TrustDetectRow(txID, clientIP string, ts time.Time) string {
	return fmt.Sprintf(`{"transaction":{"unix_timestamp":%d,"id":%q,"client_ip":%q,"server_id":"","request":{"method":"","uri":"","headers":{"X-LB-Rule-ID":["lb_tcp_trust"],"X-LB-Protocol":["tcp"]}},"is_interrupted":false},"messages":[{"data":{"id":12},"message":"信任检测"}]}`,
		ts.UnixNano(), txID, clientIP)
}

// Given TCP 规则绑定 stage0 信任检测，信任 IP 连接产生 trust_detect 事件行。
// When 经 IPC/spool 共用的批摄取入口（完整 process pass）入库。
// Then 事件行 event_type='tcp' 且 action='trust'（升格发生在摄取期，不是
// 读侧补偿）；按 TCP 拆分同款的 event_type+action 窗口查询可统计到该行。
func TestSecurityEventsIngest_tcpTrustDetectPromotedAndQueryable(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	resetSecurityEventsMappingsCacheForTest()
	t.Cleanup(resetSecurityEventsMappingsCacheForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_tcp_trust','tcp-trust','tcp',9000,1)`); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}

	now := time.Now().UTC()
	raw := []byte(l4TrustDetectRow("l4-trust-1", "45.33.32.201", now) + "\n" +
		l4TrustDetectRow("l4-trust-2", "45.33.32.202", now.Add(time.Second)) + "\n")
	n, err := IngestSecurityEventBatch(context.Background(), raw)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if n != 2 {
		t.Fatalf("ingested=%d, want 2", n)
	}

	// 落库终态：升格后的 action 与协议类型（读侧拆分列的事实来源）。
	rows, err := db.MetricsDB.Query(`SELECT action, event_type, rule_triggered FROM security_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var action, eventType, triggered string
		if err := rows.Scan(&action, &eventType, &triggered); err != nil {
			t.Fatal(err)
		}
		if eventType != "tcp" || action != "trust" || triggered != "12" {
			t.Fatalf("落库形态=(%q,%q,%q), want (tcp,trust,12)——trust_detect 必须在摄取期升格", eventType, action, triggered)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("落库行数=%d, want 2", count)
	}

	// TCP 拆分同款窗口查询（event_type='tcp' AND action='trust'）必须计到
	// 生产形态事件——直 seed tcp+logged 的旧路径在此查询下恒 0。
	var split int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type='tcp' AND action='trust' AND event_time >= ?`,
		now.Add(-time.Minute).Format("2006-01-02 15:04:05")).Scan(&split); err != nil {
		t.Fatal(err)
	}
	if split != 2 {
		t.Fatalf("TCP trust 拆分计数=%d, want 2（升格后的生产形态必须可统计）", split)
	}
	// 攻击口径不含 trust：信任检测是可见性记录，不是攻击证据。
	if SecurityEventCountsAsAttack("trust", "12") {
		t.Fatal("trust 动作不得计入攻击口径")
	}
}

// 回归形状：TCP 拦截族（is_interrupted=true）不受升格影响，仍落 blocked；
// 缺 X-LB-Protocol 头的 HTTP 形态 id:12 同样升格 trust（既有语义零变化）。
func TestSecurityEventsIngest_tcpBlockedAndHttpTrustUnaffected(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	resetSecurityEventsMappingsCacheForTest()
	t.Cleanup(resetSecurityEventsMappingsCacheForTest)

	now := time.Now().UTC()
	tcpBlocked := fmt.Sprintf(`{"transaction":{"unix_timestamp":%d,"id":"l4-deny-1","client_ip":"45.33.32.203","server_id":"","request":{"method":"","uri":"","headers":{"X-LB-Rule-ID":["lb_tcp_trust"],"X-LB-Protocol":["tcp"]}},"is_interrupted":true},"messages":[{"data":{"id":2},"message":"IP 黑名单拒绝"}]}`, now.UnixNano())
	httpTrust := fmt.Sprintf(`{"transaction":{"unix_timestamp":%d,"id":"http-trust-1","client_ip":"45.33.32.204","server_id":"example.com","request":{"method":"GET","uri":"/","headers":{"host":["example.com"]}},"is_interrupted":false},"messages":[{"data":{"id":12},"message":"信任检测"}]}`, now.UnixNano())
	if _, err := IngestSecurityEventBatch(context.Background(), []byte(tcpBlocked+"\n"+httpTrust+"\n")); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	var tcpAction, httpAction, tcpType string
	if err := db.MetricsDB.QueryRow(`SELECT action, event_type FROM security_events WHERE transaction_id='l4-deny-1'`).Scan(&tcpAction, &tcpType); err != nil {
		t.Fatal(err)
	}
	if tcpAction != "blocked" || tcpType != "tcp" {
		t.Fatalf("TCP 拦截族=(%q,%q), want (blocked,tcp)——升格只针对 id:12 logged", tcpAction, tcpType)
	}
	if err := db.MetricsDB.QueryRow(`SELECT action FROM security_events WHERE transaction_id='http-trust-1'`).Scan(&httpAction); err != nil {
		t.Fatal(err)
	}
	if httpAction != "trust" {
		t.Fatalf("HTTP id:12 logged 升格=%q, want trust（既有语义零变化）", httpAction)
	}
}
