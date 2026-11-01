package services

// 正常请求日聚合持久化（2026-11）采集侧 RED→GREEN 用例。
//
// 根因：Caddy /load 重建 metrics registry → lazybalancer_* 计数族归零 →
// 30s 采样差分把「重载前未结算增量」整段丢掉；频繁重载形态下当日统计严重
// 偏低，且行帽/保留期裁剪原始表后历史日无法补算。
//
// 方案：采集侧每轮在 metrics_history 落库后，把「checkpoint → 当前累计」的
// 钳制差分增量按本地日历日 UPSERT 进 metrics_daily_agg 并推进 checkpoint：
//   - 冷启动（无 checkpoint 行）只记基线不落增量（与 L4 consumeL4Delta 同
//     口径——避免把 Caddy 累计值整段落成当日增量）；
//   - 计数器归零（cur < checkpoint）增量取 cur（归零后全部为新增量）；
//   - 单事务 + 进程内互斥：30s daemon 轮与重载前快照并发不双计；
//   - 重载前快照：apply 链在真实 /load 前同步执行一轮完整采集。

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// aggDailyRow 读单规则单日的聚合行（缺行 ok=false）。
func aggDailyRow(t *testing.T, ruleID, localDate string) (total, blocked, logged int64, ok bool) {
	t.Helper()
	err := db.MetricsDB.QueryRow(`SELECT requests_delta, blocked_delta, logged_delta
		FROM metrics_daily_agg WHERE rule_id=? AND local_date=?`, ruleID, localDate).Scan(&total, &blocked, &logged)
	if err != nil && err.Error() == "sql: no rows in result set" {
		return 0, 0, 0, false
	}
	if err != nil {
		t.Fatalf("query metrics_daily_agg(%s,%s): %v", ruleID, localDate, err)
	}
	return total, blocked, logged, true
}

func aggDailySumAll(t *testing.T) (total, blocked, logged int64) {
	t.Helper()
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(requests_delta),0), COALESCE(SUM(blocked_delta),0), COALESCE(SUM(logged_delta),0)
		FROM metrics_daily_agg`).Scan(&total, &blocked, &logged); err != nil {
		t.Fatalf("sum metrics_daily_agg: %v", err)
	}
	return total, blocked, logged
}

func checkpointRow(t *testing.T, ruleID string) (total, blocked, logged int64, ok bool) {
	t.Helper()
	err := db.MetricsDB.QueryRow(`SELECT requests_total, requests_blocked, requests_logged
		FROM metrics_counter_checkpoint WHERE rule_id=?`, ruleID).Scan(&total, &blocked, &logged)
	if err != nil && err.Error() == "sql: no rows in result set" {
		return 0, 0, 0, false
	}
	if err != nil {
		t.Fatalf("query checkpoint(%s): %v", ruleID, err)
	}
	return total, blocked, logged, true
}

func cstDate(t *testing.T, offsetDays int, now time.Time) string {
	t.Helper()
	d := now.In(CurrentLocation()).AddDate(0, 0, offsetDays)
	return d.Format("2006-01-02")
}

// 冷启动：首轮（无 checkpoint 行）只记基线不落增量——metrics_history 计数器
// 是 Caddy 启动以来的累计值，整段落成当日增量会虚高。
func TestAccumulateDailyAgg_coldStartBaselineOnly(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	service := NewMetricsService("", 30)

	err := service.accumulateDailyAgg(map[string]*ruleLabelAggregate{
		"lb_a": {requests: 100, blocked: 10, logged: 5},
	})
	if err != nil {
		t.Fatalf("accumulate: %v", err)
	}
	if _, _, _, ok := aggDailyRow(t, "lb_a", cstDate(t, 0, time.Now())); ok {
		t.Fatal("冷启动轮不得落聚合行（累计值非增量）")
	}
	total, blocked, logged, ok := checkpointRow(t, "lb_a")
	if !ok || total != 100 || blocked != 10 || logged != 5 {
		t.Fatalf("checkpoint=(%d,%d,%d) ok=%v, want (100,10,5) true", total, blocked, logged, ok)
	}
}

// 正常增量：第二轮起 delta = cur − checkpoint 逐列累加；多规则独立。
func TestAccumulateDailyAgg_deltaRoundsAccumulate(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	service := NewMetricsService("", 30)
	now := time.Now()
	today := cstDate(t, 0, now)

	// 首轮基线。
	if err := service.accumulateDailyAgg(map[string]*ruleLabelAggregate{
		"lb_a": {requests: 100, blocked: 10, logged: 5},
		"lb_b": {requests: 7},
	}); err != nil {
		t.Fatalf("baseline round: %v", err)
	}
	// 第二轮增量：lb_a +50/+2/+1；lb_b +3/0/0。
	if err := service.accumulateDailyAgg(map[string]*ruleLabelAggregate{
		"lb_a": {requests: 150, blocked: 12, logged: 6},
		"lb_b": {requests: 10},
	}); err != nil {
		t.Fatalf("delta round: %v", err)
	}
	if total, blocked, logged, ok := aggDailyRow(t, "lb_a", today); !ok || total != 50 || blocked != 2 || logged != 1 {
		t.Fatalf("lb_a 行=(%d,%d,%d) ok=%v, want (50,2,1) true", total, blocked, logged, ok)
	}
	if total, _, _, ok := aggDailyRow(t, "lb_b", today); !ok || total != 3 {
		t.Fatalf("lb_b 行 total=%d ok=%v, want 3 true", total, ok)
	}
	// checkpoint 推进到当前累计。
	if total, blocked, logged, _ := checkpointRow(t, "lb_a"); total != 150 || blocked != 12 || logged != 6 {
		t.Fatalf("checkpoint 未推进: (%d,%d,%d), want (150,12,6)", total, blocked, logged)
	}
	// 第三轮零增量（快照不变）：聚合不变、checkpoint 不动。
	if err := service.accumulateDailyAgg(map[string]*ruleLabelAggregate{
		"lb_a": {requests: 150, blocked: 12, logged: 6},
	}); err != nil {
		t.Fatalf("zero-delta round: %v", err)
	}
	if total, _, _, _ := aggDailyRow(t, "lb_a", today); total != 50 {
		t.Fatalf("零增量轮聚合被重复累加: total=%d, want 50", total)
	}
}

// 计数器归零（/load 重载/重启）钳制：cur < checkpoint → 增量取 cur；归零前
// 的增量必须已入账，归零后的增量继续正确累加。
func TestAccumulateDailyAgg_counterResetAttribution(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	service := NewMetricsService("", 30)
	now := time.Now()
	today := cstDate(t, 0, now)

	// 基线 100 → 增至 150（+50 入账）。
	if err := service.accumulateDailyAgg(map[string]*ruleLabelAggregate{"lb_a": {requests: 100, blocked: 10, logged: 5}}); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := service.accumulateDailyAgg(map[string]*ruleLabelAggregate{"lb_a": {requests: 150, blocked: 12, logged: 6}}); err != nil {
		t.Fatalf("pre-reset round: %v", err)
	}
	// /load 重载：计数器归零后重新累到 20（total 20 < checkpoint 150，
	// logged 3 < checkpoint 6）。
	if err := service.accumulateDailyAgg(map[string]*ruleLabelAggregate{"lb_a": {requests: 20, blocked: 1, logged: 3}}); err != nil {
		t.Fatalf("post-reset round: %v", err)
	}
	// 归零前 +50/+2/+1 已入账，归零后 +20/+1/+3 继续累加：(70,3,4)。
	total, blocked, logged, ok := aggDailyRow(t, "lb_a", today)
	if !ok || total != 70 || blocked != 3 || logged != 4 {
		t.Fatalf("重置钳制 broken: (%d,%d,%d) ok=%v, want (70,3,4) true——归零前增量丢失或归零后未累加", total, blocked, logged, ok)
	}
	if total, _, _, _ := checkpointRow(t, "lb_a"); total != 20 {
		t.Fatalf("checkpoint 未推进到归零后值: total=%d, want 20", total)
	}
}

// 日界跨天：跨过本地 0 点的采样增量归属后一日期（与 L4 差分行同口径的
// ≤30s 归属偏移）；同日内增量落当日。
func TestAccumulateDailyAgg_dayBoundaryAttribution(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	service := NewMetricsService("", 30)
	now := time.Now()
	today := cstDate(t, 0, now)
	tomorrow := cstDate(t, 1, now)

	// 昨日 23:59:50 基线与增量（注入时间缝：构造「昨天」的采集时刻）。
	yday2359 := now.In(CurrentLocation()).AddDate(0, 0, -1)
	yday2359 = time.Date(yday2359.Year(), yday2359.Month(), yday2359.Day(), 23, 59, 50, 0, CurrentLocation())
	if err := service.accumulateDailyAggAt(map[string]*ruleLabelAggregate{"lb_a": {requests: 100}}, yday2359); err != nil {
		t.Fatalf("yday baseline: %v", err)
	}
	if err := service.accumulateDailyAggAt(map[string]*ruleLabelAggregate{"lb_a": {requests: 160}}, yday2359.Add(9*time.Second)); err != nil {
		t.Fatalf("yday delta: %v", err)
	}
	if total, _, _, ok := aggDailyRow(t, "lb_a", cstDate(t, -1, now)); !ok || total != 60 {
		t.Fatalf("昨日增量未落昨日: total=%d ok=%v, want 60 true", total, ok)
	}
	// 今日 00:00:05 采样（累计 180）：+20 全部归属今日（跨天增量归后一日）。
	today0000 := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 5, 0, CurrentLocation())
	if err := service.accumulateDailyAggAt(map[string]*ruleLabelAggregate{"lb_a": {requests: 180}}, today0000); err != nil {
		t.Fatalf("today round: %v", err)
	}
	if total, _, _, ok := aggDailyRow(t, "lb_a", today); !ok || total != 20 {
		t.Fatalf("跨天增量归属 broken: 今日 total=%d ok=%v, want 20 true", total, ok)
	}
	if _, _, _, ok := aggDailyRow(t, "lb_a", tomorrow); ok {
		t.Fatal("明日无采样不得有聚合行")
	}
}

// 导入/还原形态：metrics 库被还原出陈旧（更高）checkpoint 时，首个样本按
// 重置钳制取 cur 全额入账，不出现负增量。
func TestAccumulateDailyAgg_staleCheckpointFromRestore(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	service := NewMetricsService("", 30)
	today := cstDate(t, 0, time.Now())

	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_counter_checkpoint (rule_id, requests_total, requests_blocked, requests_logged)
		VALUES ('lb_r', 5000, 100, 20)`); err != nil {
		t.Fatalf("seed stale checkpoint: %v", err)
	}
	if err := service.accumulateDailyAgg(map[string]*ruleLabelAggregate{"lb_r": {requests: 30, blocked: 2, logged: 0}}); err != nil {
		t.Fatalf("accumulate: %v", err)
	}
	total, blocked, logged, ok := aggDailyRow(t, "lb_r", today)
	if !ok || total != 30 || blocked != 2 || logged != 0 {
		t.Fatalf("还原陈旧 checkpoint 形态: (%d,%d,%d) ok=%v, want (30,2,0) true", total, blocked, logged, ok)
	}
}

// 并发轮（30s daemon 与重载前快照同时触发）：同快照并发累加只入账一次，
// 不双计（进程内互斥 + 单事务推进 checkpoint）。
func TestAccumulateDailyAgg_concurrentRoundsNoDoubleCount(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	service := NewMetricsService("", 30)
	today := cstDate(t, 0, time.Now())

	if err := service.accumulateDailyAgg(map[string]*ruleLabelAggregate{"lb_c": {requests: 100}}); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	snapshot := map[string]*ruleLabelAggregate{"lb_c": {requests: 140}}
	var wg sync.WaitGroup
	const rounds = 8
	for range rounds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := service.accumulateDailyAgg(snapshot); err != nil {
				t.Errorf("concurrent accumulate: %v", err)
			}
		}()
	}
	wg.Wait()
	total, _, _, ok := aggDailyRow(t, "lb_c", today)
	if !ok || total != 40 {
		t.Fatalf("并发轮双计: total=%d ok=%v, want 40（同快照多轮只结算一个区间）", total, ok)
	}
}

// 规则删除：checkpoint 行残留无害——规则不再出现在样本中即不参与结算，
// 既有聚合行（历史真实流量）保留参与读路径求和。
func TestAccumulateDailyAgg_deletedRuleResidueHarmless(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	service := NewMetricsService("", 30)
	today := cstDate(t, 0, time.Now())

	if err := service.accumulateDailyAgg(map[string]*ruleLabelAggregate{
		"lb_gone": {requests: 100},
		"lb_kept": {requests: 200},
	}); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := service.accumulateDailyAgg(map[string]*ruleLabelAggregate{
		"lb_gone": {requests: 140},
		"lb_kept": {requests: 210},
	}); err != nil {
		t.Fatalf("delta round: %v", err)
	}
	// 规则删除：后续样本不再含 lb_gone。
	if err := service.accumulateDailyAgg(map[string]*ruleLabelAggregate{
		"lb_kept": {requests: 260},
	}); err != nil {
		t.Fatalf("post-delete round: %v", err)
	}
	if total, _, _, _ := aggDailyRow(t, "lb_gone", today); total != 40 {
		t.Fatalf("已删规则历史聚合被改写: total=%d, want 40", total)
	}
	if total, _, _, _ := aggDailyRow(t, "lb_kept", today); total != 60 {
		t.Fatalf("存活规则聚合 broken: total=%d, want 60（50+10）", total)
	}
}

// 端到端：collect() 真实解析链——首轮基线、增量轮入账、模拟 /load 归零轮
// 继续正确累加（历史行照常落库，互不影响）。
func TestCollect_dailyAggEndToEndThroughExposition(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	var body atomic.Value
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if text, ok := body.Load().(string); ok {
			_, _ = w.Write([]byte(text))
		}
	}))
	t.Cleanup(metrics.Close)

	service := NewMetricsService(metrics.URL, 30)
	now := time.Now()
	today := cstDate(t, 0, now)

	body.Store(`lazybalancer_requests_total{rule="lb_e"} 200
lazybalancer_security_blocked_total{rule="lb_e"} 20
lazybalancer_security_logged_total{rule="lb_e"} 10`)
	service.collect()
	if _, _, _, ok := aggDailyRow(t, "lb_e", today); ok {
		t.Fatal("端到端首轮（基线）不得落聚合行")
	}

	body.Store(`lazybalancer_requests_total{rule="lb_e"} 300
lazybalancer_security_blocked_total{rule="lb_e"} 25
lazybalancer_security_logged_total{rule="lb_e"} 14`)
	service.collect()
	total, blocked, logged, ok := aggDailyRow(t, "lb_e", today)
	if !ok || total != 100 || blocked != 5 || logged != 4 {
		t.Fatalf("端到端增量轮: (%d,%d,%d) ok=%v, want (100,5,4) true", total, blocked, logged, ok)
	}

	// 模拟 /load：计数器归零后重新累到 35。
	body.Store(`lazybalancer_requests_total{rule="lb_e"} 35
lazybalancer_security_blocked_total{rule="lb_e"} 2
lazybalancer_security_logged_total{rule="lb_e"} 1`)
	service.collect()
	total, blocked, logged, _ = aggDailyRow(t, "lb_e", today)
	if total != 135 || blocked != 7 || logged != 5 {
		t.Fatalf("端到端归零轮: (%d,%d,%d), want (135,7,5)——重载前增量丢失", total, blocked, logged)
	}
	// 历史行链路照常（末样本为归零后值）。
	var histTotal int64
	if err := db.MetricsDB.QueryRow(`SELECT requests_total FROM metrics_history WHERE rule_id='lb_e'
		ORDER BY id DESC LIMIT 1`).Scan(&histTotal); err != nil {
		t.Fatal(err)
	}
	if histTotal != 35 {
		t.Fatalf("metrics_history 末样本 total=%d, want 35", histTotal)
	}
}

// 未接线形态：TriggerImmediateMetricsCollection 在采集服务未装配时 no-op
// （启动早期/测试/嵌入）。
func TestTriggerImmediateMetricsCollection_nilCollectorNoop(t *testing.T) {
	t.Cleanup(func() { SetMetricsCollector(nil) })
	SetMetricsCollector(nil)
	TriggerImmediateMetricsCollection() // 不得 panic
}

// 重载前快照接线：真实 /load 前必须完成一轮完整采集（GET /metrics 先于
// POST /load）——计数器归零前的最后一段增量借此入账，消灭 ≤30s 盲区。
func TestApplyConfig_snapshotsMetricsBeforeLoad(t *testing.T) {
	setupIsolatedDBWithMetrics(t)
	var order []string
	var mu sync.Mutex
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/metrics":
			order = append(order, "metrics")
			_, _ = w.Write([]byte("lazybalancer_requests_total{rule=\"lb_s\"} 42\n"))
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			order = append(order, "config")
			_, _ = w.Write([]byte(`{"apps":{"running":true}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			order = append(order, "load")
			_, _ = w.Write([]byte("ok"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(admin.Close)

	t.Cleanup(func() { SetMetricsCollector(nil) })
	SetMetricsCollector(NewMetricsService(admin.URL+"/metrics", 30))

	service := NewCaddyService(admin.URL)
	if err := service.ApplyConfig(map[string]interface{}{"apps": map[string]interface{}{"candidate": true}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	metricsIdx, loadIdx := -1, -1
	for i, step := range order {
		switch step {
		case "metrics":
			if metricsIdx < 0 {
				metricsIdx = i
			}
		case "load":
			loadIdx = i
		}
	}
	if metricsIdx < 0 || loadIdx < 0 {
		t.Fatalf("采集/重载未发生: order=%v", order)
	}
	if metricsIdx > loadIdx {
		t.Fatalf("快照必须在 /load 之前: order=%v", order)
	}
	// 快照轮已把重载前累计入账（基线轮）+checkpoint 在位。
	if _, _, _, ok := checkpointRow(t, "lb_s"); !ok {
		t.Fatal("重载前快照未推进 checkpoint")
	}
}
