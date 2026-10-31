package services

// lb_l4_conn_history 写侧（指标采集 30s 轮伴生抓 /lb/l4-conn-stats 差分落库）
// 与保留期清理的 RED→GREEN 用例。fetch+差分的单源在 services
// （FetchL4ConnStats/DeltaUint64），威胁大屏消费面同源复用。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// newL4HistoryAdmin 起一个假 caddy admin：/lb/l4-conn-stats 返回 bodyKeeper 里的
// 最新快照，其余路径 404。hits 统计 l4-conn-stats 命中次数（404 禁用断言用）。
func newL4HistoryAdmin(t *testing.T, bodyKeeper *atomic.Value, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lb/l4-conn-stats" {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		body, _ := bodyKeeper.Load().(string)
		_, _ = w.Write([]byte(body))
	}))
}

func countL4HistoryRows(t *testing.T, where string, args ...any) int {
	t.Helper()
	var n int
	if err := db.MetricsDB.QueryRow("SELECT COUNT(*) FROM lb_l4_conn_history WHERE "+where, args...).Scan(&n); err != nil {
		t.Fatalf("count lb_l4_conn_history(%s): %v", where, err)
	}
	return n
}

func sumL4HistoryCols(t *testing.T, ruleID string) (allowed, denied int) {
	t.Helper()
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(allowed),0), COALESCE(SUM(denied),0)
		FROM lb_l4_conn_history WHERE rule_id=?`, ruleID).Scan(&allowed, &denied); err != nil {
		t.Fatalf("sum lb_l4_conn_history(%s): %v", ruleID, err)
	}
	return allowed, denied
}

func TestCollectL4ConnHistory_diffRowsAndGlobalAggregate(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	var body atomic.Value
	var hits atomic.Int32
	admin := newL4HistoryAdmin(t, &body, &hits)
	t.Cleanup(admin.Close)

	service := NewMetricsService(admin.URL+"/metrics", 30)
	service.SetL4AdminURL(admin.URL)

	// 首轮基线样本：只记基线不落行（面板进程单独重启、Caddy 不重启形态下
	// prev 为零值——若按「差分=当前值」落行，会把 caddy 计数器全量落成当日行，
	// 与 HTTP 侧持久累计锚点不对称）。
	body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":10,"denied_total":3},"lb_tcp_2":{"allowed_total":1,"denied_total":0}}}`)
	service.collectL4ConnHistory()
	if got := countL4HistoryRows(t, "1=1"); got != 0 {
		t.Fatalf("首轮（基线）行数=%d, want 0（基线样本不落行）", got)
	}

	// 第二轮起正常差分：计数器推进 → 差分增量落库。
	body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":16,"denied_total":5},"lb_tcp_2":{"allowed_total":1,"denied_total":0}}}`)
	service.collectL4ConnHistory()
	if allowed, denied := sumL4HistoryCols(t, ""); allowed != 6 || denied != 2 {
		t.Fatalf("差分轮全局行=(%d,%d), want (6,2)（16−10/5−3；lb_tcp_2 零增量不计）", allowed, denied)
	}
	if allowed, denied := sumL4HistoryCols(t, "lb_tcp_1"); allowed != 6 || denied != 2 {
		t.Fatalf("差分轮 lb_tcp_1=(%d,%d), want (6,2)", allowed, denied)
	}
	// 零增量规则不落行；总行数 = lb_tcp_1 per-rule 1 + 全局聚合 1。
	if got := countL4HistoryRows(t, "rule_id=?", "lb_tcp_2"); got != 0 {
		t.Fatalf("lb_tcp_2 行数=%d, want 0（零增量轮不落行）", got)
	}
	if got := countL4HistoryRows(t, "1=1"); got != 2 {
		t.Fatalf("差分轮总行数=%d, want 2（lb_tcp_1 per-rule + 全局聚合）", got)
	}
}

func TestCollectL4ConnHistory_counterResetTakesCurrent(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	var body atomic.Value
	var hits atomic.Int32
	admin := newL4HistoryAdmin(t, &body, &hits)
	t.Cleanup(admin.Close)

	service := NewMetricsService(admin.URL+"/metrics", 30)
	service.SetL4AdminURL(admin.URL)

	// 首轮基线（100/10）只记基线不落行。
	body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":100,"denied_total":10}}}`)
	service.collectL4ConnHistory()
	if got := countL4HistoryRows(t, "1=1"); got != 0 {
		t.Fatalf("基线轮行数=%d, want 0（基线样本不落行）", got)
	}
	// 正常推进轮：差分 (5,2) 落行。
	body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":105,"denied_total":12}}}`)
	service.collectL4ConnHistory()
	// /load 归零形态：cur < prev → 差分取 cur（不出现负数）。
	body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":2,"denied_total":0}}}`)
	service.collectL4ConnHistory()
	if allowed, denied := sumL4HistoryCols(t, "lb_tcp_1"); allowed != 7 || denied != 2 {
		t.Fatalf("重置钳制后累计=(%d,%d), want (7,2)（推进轮 5/2 + 重置轮差分取 cur=2/0）", allowed, denied)
	}
}

func TestCollectL4ConnHistory_fetchFailureKeepsPrevBaseline(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	var body atomic.Value
	var hits atomic.Int32
	var failRound atomic.Bool
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lb/l4-conn-stats" {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		if failRound.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		b, _ := body.Load().(string)
		_, _ = w.Write([]byte(b))
	}))
	t.Cleanup(admin.Close)

	service := NewMetricsService(admin.URL+"/metrics", 30)
	service.SetL4AdminURL(admin.URL)

	// 基线轮：10/0 只记基线不落行。
	body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":10,"denied_total":0}}}`)
	service.collectL4ConnHistory()
	if got := countL4HistoryRows(t, "1=1"); got != 0 {
		t.Fatalf("基线轮行数=%d, want 0（基线样本不落行）", got)
	}
	// 正常轮：12/0 → 差分 2 落行，基线推进到 12。
	body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":12,"denied_total":0}}}`)
	service.collectL4ConnHistory()
	baselineRows := countL4HistoryRows(t, "1=1")
	if baselineRows == 0 {
		t.Fatal("前置失败：差分轮未落行")
	}
	// 中间轮失败（同 URL 500）：基线不得推进（否则恢复轮会把中断期全量算进差分）。
	failRound.Store(true)
	body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":20,"denied_total":0}}}`)
	service.collectL4ConnHistory()
	if got := countL4HistoryRows(t, "1=1"); got != baselineRows {
		t.Fatalf("失败轮不得落行: rows=%d, want %d", got, baselineRows)
	}
	// 恢复轮：prev=12（失败轮未推进），差分=20−12=8 → 累计 2+8=10。
	failRound.Store(false)
	service.collectL4ConnHistory()
	if allowed, _ := sumL4HistoryCols(t, "lb_tcp_1"); allowed != 10 {
		t.Fatalf("恢复轮累计=%d, want 10（失败轮不推进基线，差分=20−12）", allowed)
	}
}

func TestCollectL4ConnHistory_endpoint404DisablesSilently(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	var hits atomic.Int32
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lb/l4-conn-stats" {
			hits.Add(1)
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(admin.Close)

	service := NewMetricsService(admin.URL+"/metrics", 30)
	service.SetL4AdminURL(admin.URL)

	// 旧镜像无端点（404）：首轮标记缺失，后续轮不再打端点（静默跳过）。
	for range 3 {
		service.collectL4ConnHistory()
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("l4-conn-stats 命中=%d, want 1（404 后进程内禁用，不再轮询）", got)
	}
	if got := countL4HistoryRows(t, "1=1"); got != 0 {
		t.Fatalf("404 形态不得落行: rows=%d", got)
	}
}

func TestCollectL4ConnHistory_unwiredSkipsFetch(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	var hits atomic.Int32
	body := atomic.Value{}
	admin := newL4HistoryAdmin(t, &body, &hits)
	t.Cleanup(admin.Close)

	// 未接线（测试/嵌入形态）：零抓取零落行，不得 panic。
	NewMetricsService(admin.URL+"/metrics", 30).collectL4ConnHistory()
	if got := hits.Load(); got != 0 {
		t.Fatalf("未接线不得抓取: hits=%d", got)
	}
	if got := countL4HistoryRows(t, "1=1"); got != 0 {
		t.Fatalf("未接线不得落行: rows=%d", got)
	}
}

func TestCleanupL4ConnHistory_retention(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	seed := func(ruleID, ts string) {
		t.Helper()
		if _, err := db.MetricsDB.Exec(`INSERT INTO lb_l4_conn_history (timestamp, rule_id, allowed, denied)
			VALUES (?, ?, 1, 0)`, ts, ruleID); err != nil {
			t.Fatalf("seed row: %v", err)
		}
	}
	seed("", time.Now().UTC().AddDate(0, 0, -8).Format("2006-01-02 15:04:05"))
	seed("lb_keep", time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02 15:04:05"))

	if err := db.CleanupL4ConnHistory(7); err != nil {
		t.Fatalf("CleanupL4ConnHistory: %v", err)
	}
	if got := countL4HistoryRows(t, "1=1"); got != 1 {
		t.Fatalf("清理后行数=%d, want 1（8 天行清、1 天行留）", got)
	}
	if got := countL4HistoryRows(t, "rule_id=?", "lb_keep"); got != 1 {
		t.Fatal("保留期内的行被误删")
	}
}

// FetchL4ConnStats/DeltaUint64 单源契约：404 用哨兵错误标识（调用方按
// 「端点缺失」禁用轮询），其余失败普通错误；DeltaUint64 重置钳制取 cur。
func TestFetchL4ConnStats_errorContract(t *testing.T) {
	var body atomic.Value
	var hits atomic.Int32
	admin := newL4HistoryAdmin(t, &body, &hits)
	t.Cleanup(admin.Close)

	body.Store(`{"rules":{"lb_tcp_1":{"allowed_total":7,"denied_total":1}}}`)
	snap, err := FetchL4ConnStats(admin.URL)
	if err != nil {
		t.Fatalf("healthy fetch: %v", err)
	}
	if got := snap.Rules["lb_tcp_1"].AllowedTotal; got != 7 {
		t.Fatalf("allowed_total=%d, want 7", got)
	}

	if _, err := FetchL4ConnStats("http://127.0.0.1:1"); err == nil {
		t.Fatal("不可达 admin 必须返回错误")
	}

	missing := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(missing.Close)
	if _, err := FetchL4ConnStats(missing.URL); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404 错误=%v, want 含 404 语义（端点缺失哨兵）", err)
	} else if !IsL4ConnEndpointMissing(err) {
		t.Fatalf("404 必须可经 IsL4ConnEndpointMissing 判定: %v", err)
	}

	if got := DeltaUint64(2, 100); got != 2 {
		t.Fatalf("DeltaUint64(reset)=%d, want 2（重置取 cur）", got)
	}
	if got := DeltaUint64(105, 100); got != 5 {
		t.Fatalf("DeltaUint64(normal)=%d, want 5", got)
	}
}
