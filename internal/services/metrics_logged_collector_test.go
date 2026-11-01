package services

// 检测放行拆分（logged）采集侧 RED→GREEN 用例：
//   - HTTP：lazybalancer_security_logged_total{rule=} 单趟扫描进
//     ruleLabelAggregate.logged，storePerRuleMetrics 落 metrics_history.requests_logged；
//   - TCP：/lb/l4-conn-stats 快照新键 logged_total 差分落 lb_l4_conn_history.logged
//     （per-rule 行 + 全局聚合行，与 allowed/denied 同口径）。

import (
	"sync/atomic"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// sumL4HistoryColsLogged 三列求和（allowed/denied/logged）。
func sumL4HistoryColsLogged(t *testing.T, ruleID string) (allowed, denied, logged int) {
	t.Helper()
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(allowed),0), COALESCE(SUM(denied),0), COALESCE(SUM(logged),0)
		FROM lb_l4_conn_history WHERE rule_id=?`, ruleID).Scan(&allowed, &denied, &logged); err != nil {
		t.Fatalf("sum lb_l4_conn_history(%s): %v", ruleID, err)
	}
	return allowed, denied, logged
}

func TestMetricsService_storeRuleMetricsText_loggedColumn(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	service := &MetricsService{}
	// fixture 必须是真实 exposition 形态（class/direction 在前，rule 在后）。
	text := `lazybalancer_requests_total{rule="lb_lg1"} 100
lazybalancer_request_status_total{class="2xx",rule="lb_lg1"} 90
lazybalancer_security_blocked_total{rule="lb_lg1"} 5
lazybalancer_security_logged_total{rule="lb_lg1"} 7`

	if err := service.storeRuleMetricsText(text); err != nil {
		t.Fatalf("store rule-label metrics: %v", err)
	}
	var requests, blocked, logged int64
	if err := db.MetricsDB.QueryRow(`SELECT requests_total, requests_blocked, requests_logged
		FROM metrics_history WHERE rule_id='lb_lg1'`).Scan(&requests, &blocked, &logged); err != nil {
		t.Fatalf("query stored row: %v", err)
	}
	if requests != 100 || blocked != 5 || logged != 7 {
		t.Fatalf("stored=(%d,%d,%d), want (100,5,7)", requests, blocked, logged)
	}
}

func TestMetricsService_storeRuleMetricsText_loggedMultipleRulesIndependent(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	service := &MetricsService{}
	text := `lazybalancer_security_logged_total{rule="lb_lg2"} 3
lazybalancer_security_logged_total{rule="lb_lg3"} 11`
	if err := service.storeRuleMetricsText(text); err != nil {
		t.Fatalf("store: %v", err)
	}
	var c2, c3 int64
	if err := db.MetricsDB.QueryRow(`SELECT requests_logged FROM metrics_history WHERE rule_id='lb_lg2'`).Scan(&c2); err != nil {
		t.Fatal(err)
	}
	if err := db.MetricsDB.QueryRow(`SELECT requests_logged FROM metrics_history WHERE rule_id='lb_lg3'`).Scan(&c3); err != nil {
		t.Fatal(err)
	}
	if c2 != 3 || c3 != 11 {
		t.Fatalf("lg2=%d lg3=%d, want 3/11", c2, c3)
	}
}

// TCP 差分落库：logged_total 与 allowed/denied 同口径差分（per-rule 行 +
// 全局聚合行）；logged 独立推进而 allowed 不动时也要落行。
func TestCollectL4ConnHistory_loggedDiffRowsAndGlobalAggregate(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	var body atomic.Value
	var hits atomic.Int32
	admin := newL4HistoryAdmin(t, &body, &hits)
	t.Cleanup(admin.Close)

	service := NewMetricsService(admin.URL+"/metrics", 30)
	service.SetL4AdminURL(admin.URL)

	// 首轮基线（含 logged）只记基线不落行。
	body.Store(`{"rules":{"lb_tcp_l":{"allowed_total":10,"denied_total":3,"logged_total":4}}}`)
	service.collectL4ConnHistory()
	if got := countL4HistoryRows(t, "1=1"); got != 0 {
		t.Fatalf("基线轮行数=%d, want 0", got)
	}

	// 第二轮差分：allowed 16−10、denied 5−3、logged 6−4。
	body.Store(`{"rules":{"lb_tcp_l":{"allowed_total":16,"denied_total":5,"logged_total":6}}}`)
	service.collectL4ConnHistory()
	allowedG, deniedG, loggedG := sumL4HistoryColsLogged(t, "")
	if allowedG != 6 || deniedG != 2 || loggedG != 2 {
		t.Fatalf("差分轮全局行=(%d,%d,%d), want (6,2,2)", allowedG, deniedG, loggedG)
	}
	allowedR, deniedR, loggedR := sumL4HistoryColsLogged(t, "lb_tcp_l")
	if allowedR != 6 || deniedR != 2 || loggedR != 2 {
		t.Fatalf("差分轮 per-rule 行=(%d,%d,%d), want (6,2,2)", allowedR, deniedR, loggedR)
	}

	// 旧镜像形态（快照无 logged_total 键）→ decoded 0 → 差分 0，不误落。
	body.Store(`{"rules":{"lb_tcp_l":{"allowed_total":18,"denied_total":5}}}`)
	service.collectL4ConnHistory()
	allowedG2, deniedG2, loggedG2 := sumL4HistoryColsLogged(t, "")
	if allowedG2 != 8 || deniedG2 != 2 || loggedG2 != 2 {
		t.Fatalf("旧镜像轮全局行=(%d,%d,%d), want (8,2,2)（缺键=logged 零差分）", allowedG2, deniedG2, loggedG2)
	}
}
