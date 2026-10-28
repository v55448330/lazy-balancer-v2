package handlers

// 指标读路径的共享快照契约：规则/主机/Caddy/面板四个消费面读同一
// CaddyMetricsURL，抓取结果在短 TTL 内共享、并发 miss 合并为一趟（一次最多
// 16MB 文本不再被 N 个客户端重复拉取）；失败短负缓存，客户端取消不写负缓存
// （否则一次断开会让同窗内其余请求拿到伪造的上游失败）。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func TestMetricsEndpoints_shareOneScrapeSnapshotAcrossConsumers(t *testing.T) {
	newMetricsTestDatabase(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_snapshot','snap','http','snap.example.test',80,1)`); err != nil {
		t.Fatal(err)
	}
	resetMetricsDashboardCacheForTest()
	t.Cleanup(resetMetricsDashboardCacheForTest)

	var fetches atomic.Int32
	overrideDashboardFetch(t, func(context.Context, string) ([]byte, error) {
		fetches.Add(1)
		return []byte("caddy_http_requests_total{host=\"snap.example.test\",server=\"http_80\"} 7\n"), nil
	})
	h := &Handlers{cfg: &config.Config{CaddyMetricsURL: "http://127.0.0.1:9/metrics"}}
	router := gin.New()
	router.GET("/metrics", h.GetCaddyMetrics)
	router.GET("/metrics/hosts", h.GetHostMetrics)
	router.GET("/rules/:caddy_id/metrics", h.GetRuleMetrics)

	// When：三个端点依次命中（同一 CaddyMetricsURL）。
	for _, path := range []string{"/metrics", "/metrics/hosts", "/rules/lb_snapshot/metrics"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s, want 200", path, rec.Code, rec.Body.String())
		}
	}

	// Then：只抓取一次（快照共享），不是每端点各拉一次。
	if got := fetches.Load(); got != 1 {
		t.Fatalf("三端点抓取 %d 次, want 1（共享快照未生效，每端点重复拉取大文本）", got)
	}

	// When：8 个并发请求同时到达（TTL 内）。
	var wg sync.WaitGroup
	wg.Add(8)
	for range 8 {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		}()
	}
	wg.Wait()

	// Then：仍是一次抓取。
	if got := fetches.Load(); got != 1 {
		t.Fatalf("并发请求后抓取 %d 次, want 1", got)
	}
}

func TestLoadCaddyMetricsSnapshot_negativeCacheAndSelfTimeoutNotCached(t *testing.T) {
	withIsolatedGlobal(t)
	resetCaddyMetricsSnapshotCacheForTest()
	t.Cleanup(resetCaddyMetricsSnapshotCacheForTest)
	oldNeg := caddyMetricsSnapshotNegativeTTL
	caddyMetricsSnapshotNegativeTTL = 40 * time.Millisecond
	t.Cleanup(func() { caddyMetricsSnapshotNegativeTTL = oldNeg })

	// Given：抓取失败。
	var calls atomic.Int32
	overrideDashboardFetch(t, func(context.Context, string) ([]byte, error) {
		calls.Add(1)
		return nil, context.DeadlineExceeded
	})
	if _, err := loadCaddyMetricsSnapshot(context.Background(), "http://snap.invalid/metrics", true); err == nil {
		t.Fatal("抓取失败必须返回 error")
	}
	// Then：负缓存窗口内不重复击穿。
	if _, err := loadCaddyMetricsSnapshot(context.Background(), "http://snap.invalid/metrics", true); err == nil {
		t.Fatal("负缓存命中仍须返回失败")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("负缓存窗口内抓取 %d 次, want 1", got)
	}

	// Given：leader 客户端已取消（单请求 ctx 已被 cancel）。
	resetCaddyMetricsSnapshotCacheForTest()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	var liveCtx atomic.Bool
	overrideDashboardFetch(t, func(ctx context.Context, _ string) ([]byte, error) {
		calls.Add(1)
		liveCtx.Store(ctx.Err() == nil)
		return []byte("ok 1\n"), nil
	})
	body, err := loadCaddyMetricsSnapshot(canceled, "http://snap.invalid/metrics", true)
	// Then：共享抓取脱离请求取消信号（否则同批等待者会收到伪造的上游失败）。
	if err != nil || string(body) != "ok 1\n" {
		t.Fatalf("取消请求 body=%q err=%v, want 抓取仍成功（脱钩取消信号）", string(body), err)
	}
	if !liveCtx.Load() {
		t.Fatal("抓取收到的 context 已被 leader 取消, want context.WithoutCancel 存活")
	}

	// Given：抓取自身超时（自有超时上限触发）。
	resetCaddyMetricsSnapshotCacheForTest()
	oldTimeout := caddyMetricsFetchTimeout
	caddyMetricsFetchTimeout = 20 * time.Millisecond
	t.Cleanup(func() { caddyMetricsFetchTimeout = oldTimeout })
	overrideDashboardFetch(t, func(ctx context.Context, _ string) ([]byte, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if _, err := loadCaddyMetricsSnapshot(context.Background(), "http://snap.invalid/metrics", true); err == nil {
		t.Fatal("自身超时抓取必须返回 error")
	}
	// Then：超时不写负缓存——下一次健康请求立刻重新抓取（不被瞬时超时毒化）。
	overrideDashboardFetch(t, func(context.Context, string) ([]byte, error) {
		calls.Add(1)
		return []byte("ok 2\n"), nil
	})
	body, err = loadCaddyMetricsSnapshot(context.Background(), "http://snap.invalid/metrics", true)
	if err != nil || string(body) != "ok 2\n" {
		t.Fatalf("超时后健康请求 body=%q err=%v, want 立即重新抓取成功", string(body), err)
	}
}

func TestGetRuleMetrics_unknownRuleUsesFamilyNotFoundShape(t *testing.T) {
	newMetricsTestDatabase(t)
	h := &Handlers{cfg: &config.Config{CaddyMetricsURL: "http://127.0.0.1:9/metrics"}}
	router := gin.New()
	router.GET("/rules/:caddy_id/metrics", h.GetRuleMetrics)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/rules/lb_missing/metrics", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", rec.Code, rec.Body.String())
	}
	var payload struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 与规则历史/证书任务同族口径（中文且不把「规则已删」当服务故障）。
	if payload.Code != 404 || payload.Message != "规则不存在" {
		t.Fatalf("payload=%+v, want 404/规则不存在（dbQueryNotFound 单源）", payload)
	}
}

func TestLoadCaddyMetricsSnapshot_callerPolicyControlsFailureReuse(t *testing.T) {
	// 面板传 cacheFailure=false 的契约：其他端点写入的失败负缓存不得让面板
	// 「每次都重新抓取」被静默吞掉（策略在 single-flight 闭包内同样生效）。
	resetCaddyMetricsSnapshotCacheForTest()
	t.Cleanup(resetCaddyMetricsSnapshotCacheForTest)

	const url = "http://snap.invalid/policy-metrics"
	var calls atomic.Int32
	overrideDashboardFetch(t, func(context.Context, string) ([]byte, error) {
		calls.Add(1)
		return nil, errors.New("upstream down")
	})
	if _, err := loadCaddyMetricsSnapshot(context.Background(), url, true); err == nil {
		t.Fatal("抓取失败必须返回 error")
	}
	// 同策略（true）命中负缓存：不再抓取。
	if _, err := loadCaddyMetricsSnapshot(context.Background(), url, true); err == nil {
		t.Fatal("负缓存命中仍须返回失败")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("cacheFailure=true 负缓存窗口内抓取 %d 次, want 1", got)
	}
	// 面板策略（false）必须绕过该失败条目并重新抓取。
	overrideDashboardFetch(t, func(context.Context, string) ([]byte, error) {
		calls.Add(1)
		return []byte("ok 1\n"), nil
	})
	body, err := loadCaddyMetricsSnapshot(context.Background(), url, false)
	if err != nil || string(body) != "ok 1\n" {
		t.Fatalf("面板策略 body=%q err=%v, want 重新抓取成功", string(body), err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("面板策略下抓取累计=%d, want 2（闭包内不得复用失败条目）", got)
	}
}

func TestLoadCaddyMetricsSnapshot_canceledLeaderDoesNotFailWaiters(t *testing.T) {
	// 并发消费面共用一个 single-flight：leader 客户端断开不得把 ctx 错误交给
	// 其余健康请求（否则一次断开瞬断同批所有指标请求）。
	resetCaddyMetricsSnapshotCacheForTest()
	t.Cleanup(resetCaddyMetricsSnapshotCacheForTest)

	const url = "http://snap.invalid/waiter-metrics"
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var fetches atomic.Int32
	overrideDashboardFetch(t, func(ctx context.Context, _ string) ([]byte, error) {
		fetches.Add(1)
		once.Do(func() { close(started) })
		<-release
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []byte("ok-waiter 1\n"), nil
	})

	// 屏障而非墙钟：hook 计数到第 2 次＝waiter 已到达 group.Do（leader 正在
	// 抓取中持飞），此刻取消 leader 才真正验证「取消不传染等待者」。hook 必须
	// 在 leader 启动前安装，否则 leader 不计数、屏障永远等不到第 2 次。
	var doCalls atomic.Int32
	joined := make(chan struct{})
	caddyMetricsSnapshotDoBeforeForTest = func() {
		if doCalls.Add(1) == 2 {
			close(joined)
		}
	}
	t.Cleanup(func() { caddyMetricsSnapshotDoBeforeForTest = nil })
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		// leader 结果本身不参与断言：请求已取消，其调用方通常也已离开。
		_, _ = loadCaddyMetricsSnapshot(leaderCtx, url, true)
	}()
	<-started

	type result struct {
		body []byte
		err  error
	}
	waiterDone := make(chan result, 1)
	go func() {
		body, err := loadCaddyMetricsSnapshot(context.Background(), url, true)
		waiterDone <- result{body: body, err: err}
	}()
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		t.Fatal("waiter 未进入 single-flight（屏障超时，无法证明共享一次抓取）")
	}
	cancelLeader()
	close(release)

	select {
	case got := <-waiterDone:
		if got.err != nil || string(got.body) != "ok-waiter 1\n" {
			t.Fatalf("waiter body=%q err=%v, want leader 取消后仍成功", string(got.body), got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter 未在超时内返回")
	}
	<-leaderDone
	// 共享一次抓取：waiter 若另起一次抓取（leader 取消传染或时序错位），
	// 计数会变成 2——这是原用例缺失的判别力。
	if got := fetches.Load(); got != 1 {
		t.Fatalf("抓取次数=%d, want 1（leader/waiter 必须共享同一趟抓取）", got)
	}
}

func TestFetchCaddyMetrics_rejectsOver16MB(t *testing.T) {
	// 16MB 上限（limit+1 探测读取）：超限显式报错，避免指标基数膨胀时无界分配。
	payload := make([]byte, 16<<20+1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	t.Cleanup(server.Close)

	if _, err := fetchCaddyMetrics(context.Background(), server.URL); err == nil {
		t.Fatal("超过 16MB 的指标响应必须报错")
	} else if !strings.Contains(err.Error(), "16MB") {
		t.Fatalf("err=%v, want 提及 16MB 上限", err)
	}

	// 恰好上限（16MB 整）不报错——上限是「大于」而非「大于等于」。
	exact := make([]byte, 16<<20)
	serverExact := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(exact)
	}))
	t.Cleanup(serverExact.Close)
	if body, err := fetchCaddyMetrics(context.Background(), serverExact.URL); err != nil || len(body) != 16<<20 {
		t.Fatalf("16MB 整响应 body=%d err=%v, want 通过", len(body), err)
	}
}

func TestGetMetricsDashboard_dbReadFailureIsLogged(t *testing.T) {
	// 面板 DB 读失败必须在日志留痕（此前只有响应文案，锁冲突/表损坏不可区分）。
	newMetricsTestDatabase(t)
	if _, err := db.DB.Exec(`DROP TABLE lb_rules`); err != nil {
		t.Fatal(err)
	}
	resetMetricsDashboardCacheForTest()
	t.Cleanup(resetMetricsDashboardCacheForTest)
	overrideDashboardFetch(t, func(context.Context, string) ([]byte, error) {
		return []byte("caddy_http_requests_total 1\n"), nil
	})

	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	h := &Handlers{cfg: &config.Config{CaddyMetricsURL: "http://127.0.0.1:9/metrics"}}
	if code := requestDashboard(t, h); code != http.StatusInternalServerError {
		t.Fatalf("DB 读失败状态码=%d, want 500", code)
	}
	if !strings.Contains(logBuf.String(), "指标面板读取规则配置失败") {
		t.Fatalf("日志未留痕 DB 读失败, log=%q", logBuf.String())
	}
}

// 快照 TTL 以「抓取完成」时刻起算：抓取耗时 ≥ TTL 时条目不得出生即过期
// （否则最需要共享的慢抓取场景反而每次都重新抓取，面板/规则/主机三端点的
// 轮询叠加成「越慢越抓」）。
func TestLoadCaddyMetricsSnapshot_ttlAnchoredAtFetchCompletion(t *testing.T) {
	withIsolatedGlobal(t)
	resetCaddyMetricsSnapshotCacheForTest()
	t.Cleanup(resetCaddyMetricsSnapshotCacheForTest)
	oldTTL := caddyMetricsSnapshotTTL
	caddyMetricsSnapshotTTL = 60 * time.Millisecond
	t.Cleanup(func() { caddyMetricsSnapshotTTL = oldTTL })

	var calls atomic.Int32
	overrideDashboardFetch(t, func(context.Context, string) ([]byte, error) {
		calls.Add(1)
		time.Sleep(80 * time.Millisecond) // 抓取耗时 > TTL
		return []byte("ok 1\n"), nil
	})

	const url = "http://snap.slow/metrics"
	if _, err := loadCaddyMetricsSnapshot(context.Background(), url, true); err != nil {
		t.Fatalf("首次抓取 err = %v", err)
	}
	// When：抓取刚完成，TTL 内第二次读取
	body, err := loadCaddyMetricsSnapshot(context.Background(), url, true)
	if err != nil || string(body) != "ok 1\n" {
		t.Fatalf("第二次 body=%q err=%v, want 共享快照", string(body), err)
	}

	// Then：仍是一次抓取（TTL 从抓取完成时刻起算）
	if got := calls.Load(); got != 1 {
		t.Fatalf("抓取 %d 次, want 1（TTL 以抓取开始时刻为基准时，慢抓取条目出生即过期）", got)
	}
}

// 快照缓存按「进程单指标源」实现单条目语义（改地址后旧 URL 的正文不得常驻，
// 单条最多 16MB）；面板缓存必须按 URL 区分，避免不同实例互相读到对方视角。
func TestMetricsCaches_areScopedToCurrentMetricsURL(t *testing.T) {
	resetMetricsDashboardCacheForTest()
	t.Cleanup(resetMetricsDashboardCacheForTest)
	resetCaddyMetricsSnapshotCacheForTest()
	t.Cleanup(resetCaddyMetricsSnapshotCacheForTest)
	now := time.Now()

	storeCaddyMetricsSnapshot("http://a/metrics", []byte("a"), nil, now)
	storeCaddyMetricsSnapshot("http://b/metrics", []byte("b"), nil, now)
	caddyMetricsSnapshots.Lock()
	entries := len(caddyMetricsSnapshots.entries)
	_, hasLatest := caddyMetricsSnapshots.entries["http://b/metrics"]
	caddyMetricsSnapshots.Unlock()
	if entries != 1 || !hasLatest {
		t.Fatalf("快照条目=%d hasLatest=%v, want 单条目且为最新 URL", entries, hasLatest)
	}

	storeMetricsDashboardOutcome("http://a/metrics", metricsDashboardOutcome{payload: gin.H{"x": 1}}, now)
	if _, ok := loadMetricsDashboardCache("http://b/metrics", now); ok {
		t.Fatal("面板缓存命中其他 URL 的结果（改地址/多实例会串味）")
	}
	if _, ok := loadMetricsDashboardCache("http://a/metrics", now); !ok {
		t.Fatal("同 URL 缓存必须命中")
	}
}
