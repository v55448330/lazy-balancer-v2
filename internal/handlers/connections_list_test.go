package handlers

// 连接明细端点的截断/计数/上游解析契约：
//   - 超 500 行截断按连接态优先级保留（established 优先，其次 time_wait，
//     最后 closed）——活跃连接是排障主视图，字母序截断会把它们先丢光。
//   - conn_counts/counts 按截断前全集统计——截断只收窄明细行，不得让活跃
//     计数低报（truncated=true 单独披露明细被截断）。
//   - 上游域名解析带超时上下文（DNS 挂起不得阻塞连接刷新），解析缓存有容量
//     上限（上游域名集合更替不得让缓存键只增不逐出）。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

// netstatLine 生成一行 netstat -tan 输出（本地端口固定 443=规则监听端口，
// 远端按序号变化，避免归属地缓存把多行折叠成一次查库）。
func netstatLine(state string, i int) string {
	return fmt.Sprintf("tcp4 0 0 10.0.0.1:443 203.0.113.%d:51000 %s", i%250+1, state)
}

// resetConnectionsListCachesForTest 复位连接明细的 TTL 缓存/负缓存与上游解析
// 缓存，保证用例从冷态出发（他测残留会让截断/计数断言失真）。
func resetConnectionsListCachesForTest(t *testing.T) {
	t.Helper()
	connectionsListMu.Lock()
	connectionsListCache = connectionsListPayload{}
	connectionsListExpireAt = time.Time{}
	connectionsListNegUntil = time.Time{}
	connectionsListNegErr = nil
	connectionsListMu.Unlock()
	upstreamResolveMu.Lock()
	upstreamResolveCache = nil
	upstreamResolveMu.Unlock()
	t.Cleanup(func() {
		connectionsListMu.Lock()
		connectionsListCache = connectionsListPayload{}
		connectionsListExpireAt = time.Time{}
		connectionsListNegUntil = time.Time{}
		connectionsListNegErr = nil
		connectionsListMu.Unlock()
		upstreamResolveMu.Lock()
		upstreamResolveCache = nil
		upstreamResolveMu.Unlock()
	})
}

// 截断优先级 + 全集计数：600 closed + 10 established + 5 time_wait，截到 500
// 行后必须保留全部 established/time_wait，计数仍是截断前全集。
func TestGetConnectionsList_truncationKeepsEstablishedFirstAndCountsFullSet(t *testing.T) {
	withIsolatedGlobal(t)
	setupSecurityPolicyTestDB(t)
	resetConnectionsListCachesForTest(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb-trunc','截断规则','http','trunc.test',443,1)`); err != nil {
		t.Fatal(err)
	}

	lines := []string{"Proto Recv-Q Send-Q Local Address Foreign Address (state)"}
	for i := range 600 {
		lines = append(lines, netstatLine("CLOSE_WAIT", i))
	}
	for i := range 10 {
		lines = append(lines, netstatLine("ESTABLISHED", 1000+i))
	}
	for i := range 5 {
		lines = append(lines, netstatLine("TIME_WAIT", 2000+i))
	}
	sample := strings.Join(lines, "\n")
	oldNetstat := netstatCommand
	netstatCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "printf", "%s", sample)
	}
	t.Cleanup(func() { netstatCommand = oldNetstat })

	h := &Handlers{cfg: &config.Config{}}
	payload, err := h.getConnectionsListCached()
	if err != nil {
		t.Fatalf("connections list: %v", err)
	}
	if !payload.Truncated {
		t.Fatal("615 行 > 500 上限，truncated 必须为 true")
	}
	if len(payload.Connections) != connectionsListMaxRows {
		t.Fatalf("明细行数=%d, want %d（截断上限）", len(payload.Connections), connectionsListMaxRows)
	}
	// 保留行按优先级：10 established + 5 time_wait 必须全在，closed 补足余额。
	kept := map[string]int{}
	for _, e := range payload.Connections {
		kept[e.Category]++
	}
	if kept["established"] != 10 || kept["time_wait"] != 5 {
		t.Fatalf("保留行分类=%v, want established=10/time_wait=5 全保留（活跃优先）", kept)
	}
	if kept["closed"] != connectionsListMaxRows-15 {
		t.Fatalf("保留 closed=%d, want %d（余额补 closed）", kept["closed"], connectionsListMaxRows-15)
	}
	// 计数按截断前全集：established=10/time_wait=5/closed=600。
	if payload.ConnCounts["established"] != 10 || payload.ConnCounts["time_wait"] != 5 || payload.ConnCounts["closed"] != 600 {
		t.Fatalf("conn_counts=%v, want 截断前全集 established=10/time_wait=5/closed=600", payload.ConnCounts)
	}
	if payload.Counts["established"] != 10 || payload.Counts["closed"] != 600 {
		t.Fatalf("counts=%v, want 连接视图同全集口径", payload.Counts)
	}
}

// 回归形态：未超上限不截断、不排序改写，计数=行数。
func TestGetConnectionsList_belowCapNoTruncation(t *testing.T) {
	withIsolatedGlobal(t)
	setupSecurityPolicyTestDB(t)
	resetConnectionsListCachesForTest(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb-small','小规则','http','small.test',443,1)`); err != nil {
		t.Fatal(err)
	}
	sample := strings.Join([]string{
		"Proto Recv-Q Send-Q Local Address Foreign Address (state)",
		netstatLine("ESTABLISHED", 1),
		netstatLine("TIME_WAIT", 2),
		netstatLine("CLOSE_WAIT", 3),
	}, "\n")
	oldNetstat := netstatCommand
	netstatCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "printf", "%s", sample)
	}
	t.Cleanup(func() { netstatCommand = oldNetstat })

	h := &Handlers{cfg: &config.Config{}}
	payload, err := h.getConnectionsListCached()
	if err != nil {
		t.Fatalf("connections list: %v", err)
	}
	if payload.Truncated {
		t.Fatal("3 行未超上限，truncated 必须为 false")
	}
	if len(payload.Connections) != 3 {
		t.Fatalf("明细行数=%d, want 3", len(payload.Connections))
	}
	if payload.ConnCounts["established"] != 1 || payload.ConnCounts["time_wait"] != 1 || payload.ConnCounts["closed"] != 1 {
		t.Fatalf("conn_counts=%v, want 各 1", payload.ConnCounts)
	}
}

// 上游解析超时：DNS 挂起（解析缝被注入为阻塞到 ctx 取消）时，loadCaddyEndpoints
// 必须在超时窗口内返回，而不是无限等待。真实失败注入——解析缝阻塞到 ctx.Done，
// 只有带超时的上下文才能让它返回；无 ctx 超时的实现会永久挂起。
func TestLoadCaddyEndpoints_dnsHangBoundedByTimeout(t *testing.T) {
	withIsolatedGlobal(t)
	setupSecurityPolicyTestDB(t)
	resetConnectionsListCachesForTest(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb-dns','DNS规则','http','dns.test',443,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb-dns','hang.invalid',8080,1)`); err != nil {
		t.Fatal(err)
	}

	oldLookup := upstreamResolveLookup
	upstreamResolveLookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		<-ctx.Done() // 模拟 DNS 挂起：直到上下文超时才返回
		return nil, ctx.Err()
	}
	t.Cleanup(func() { upstreamResolveLookup = oldLookup })

	done := make(chan struct{})
	go func() {
		loadCaddyEndpoints()
		close(done)
	}()
	select {
	case <-done:
		// 在超时窗口内返回即通过。
	case <-time.After(upstreamResolveTimeout + 3*time.Second):
		t.Fatal("DNS 挂起时 loadCaddyEndpoints 未在超时窗口内返回（无 ctx 超时）")
	}
}

// 解析缓存容量上限：写入超过上限的不同域名键后，缓存条目数必须有界
// （只增不逐出会让上游域名集合更替时无界增长）。
func TestUpstreamResolveCache_boundedByCapacity(t *testing.T) {
	resetConnectionsListCachesForTest(t)
	upstreamResolveMu.Lock()
	upstreamResolveCache = make(map[string]upstreamResolveEntry)
	upstreamResolveMu.Unlock()

	now := time.Now()
	for i := range upstreamResolveCacheMax + 50 {
		key := fmt.Sprintf("host-%d.invalid", i)
		storeUpstreamResolveEntry(key, upstreamResolveEntry{ips: map[string]struct{}{}, expiresAt: now.Add(time.Minute)})
	}
	upstreamResolveMu.Lock()
	n := len(upstreamResolveCache)
	upstreamResolveMu.Unlock()
	if n > upstreamResolveCacheMax {
		t.Fatalf("解析缓存条目=%d, want ≤ %d（容量上限淘汰）", n, upstreamResolveCacheMax)
	}
}

// 共享总预算：多台上游域名同时 DNS 挂起时，loadCaddyEndpoints 的总时延
// 必须落在单份预算窗口内——逐域名各给一份预算会让总时延随上游数量线性
// 放大（3 台挂起=3×6s）。真实失败注入：解析缝阻塞到 ctx.Done。
func TestLoadCaddyEndpoints_sharedBudgetAcrossHangingHosts(t *testing.T) {
	withIsolatedGlobal(t)
	setupSecurityPolicyTestDB(t)
	resetConnectionsListCachesForTest(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb-budget','预算规则','http','budget.test',443,1)`); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb-budget',?,8080,1)`, fmt.Sprintf("hang%d.invalid", i)); err != nil {
			t.Fatal(err)
		}
	}

	oldLookup := upstreamResolveLookup
	upstreamResolveLookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		<-ctx.Done() // 模拟 DNS 挂起：直到上下文取消才返回
		return nil, ctx.Err()
	}
	t.Cleanup(func() { upstreamResolveLookup = oldLookup })

	done := make(chan struct{})
	go func() {
		loadCaddyEndpoints()
		close(done)
	}()
	select {
	case <-done:
		// 共享预算内返回即通过。
	case <-time.After(upstreamResolveTimeout + 3*time.Second):
		t.Fatal("3 台 DNS 挂起时 loadCaddyEndpoints 未在单份预算窗口内返回（预算未共享，逐域名放大）")
	}
}

// OpenAPI 示例必须与实现的三源 payload 同形：顶层键集 + connections[]/
// requests[]/domains[] 行视图键集双向对账（真实 handler 响应为基准）。
// 旧示例停留 WAF 叠加形态（entries/waf_blocked/last_rule），按文档建模的
// 消费方解析必失败。
func TestAPIDocs_connectionsListExampleKeysMatchImplementation(t *testing.T) {
	withIsolatedGlobal(t)
	setupSecurityPolicyTestDB(t)
	resetConnectionsListCachesForTest(t)
	reqMonMu.Lock()
	reqMonUnavailableAt = time.Time{}
	reqMonMu.Unlock()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb-doc','文档规则','http','doc.test',443,1)`); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/lb/reqmon/snapshot"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"capacity": 100,
				"entries": []map[string]any{{
					"ts": now.UnixMilli(), "client_ip": "203.0.113.7", "method": "GET",
					"proto": "HTTP/2.0", "scheme": "https", "rule_id": "lb-doc", "ua": "test-agent",
					"host": "doc.test", "uri": "/", "status": 200, "duration_ms": 1.5, "size": 10, "req_size": 5,
				}},
			})
		case r.URL.Path == "/metrics":
			_, _ = io.WriteString(w, `caddy_http_requests_total{host="doc.test"} 3`+"\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(admin.Close)

	sample := strings.Join([]string{
		"Proto Recv-Q Send-Q Local Address Foreign Address (state)",
		netstatLine("ESTABLISHED", 1),
	}, "\n")
	oldNetstat := netstatCommand
	netstatCommand = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "printf", "%s", sample)
	}
	t.Cleanup(func() { netstatCommand = oldNetstat })
	resetCaddyMetricsSnapshotCacheForTest()
	t.Cleanup(resetCaddyMetricsSnapshotCacheForTest)

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL, CaddyMetricsURL: admin.URL + "/metrics"}}
	router := gin.New()
	router.GET("/metrics/connections/list", h.GetConnectionsList)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics/connections/list", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}
	if impl.Data["req_mon"] != true {
		t.Fatalf("req_mon=%v, want true（requests 行视图对账需要快照在场）", impl.Data["req_mon"])
	}

	docExample := docResponseExample(t, "GET /metrics/connections/list")
	assertKeySetsEqual(t, "connections/list 顶层", mapKeysOf(docExample), mapKeysOf(impl.Data))
	for _, pair := range []struct {
		key    string
		sample any
	}{
		{"connections", connectionEntry{}},
		{"requests", requestEntry{}},
		{"domains", domainStat{}},
	} {
		docRows, _ := docExample[pair.key].([]any)
		implRows, _ := impl.Data[pair.key].([]any)
		if len(docRows) == 0 || len(implRows) == 0 {
			t.Fatalf("%s 行视图对账失效：doc=%d impl=%d（两侧都必须有行）", pair.key, len(docRows), len(implRows))
		}
		docRow, _ := docRows[0].(map[string]any)
		implRow, _ := implRows[0].(map[string]any)
		assertKeySetsEqual(t, "connections/list "+pair.key+"[]", mapKeysOf(docRow), mapKeysOf(implRow))
		assertStructKeysDocumented(t, "connections/list "+pair.key+"[]", mapKeysOf(docRow), pair.sample)
	}
}

// 人机事件丢失对账计数必须经面板代理透传（lbhuman/events.go 契约：
// events_dropped=队列饱和丢弃、events_deliver_failed=投递失败丢弃，
// 经 /lb/human/stats 下发）——代理只解码三计数会让丢失量在面板侧不可对账。
func TestGetHumanVerifyStats_passesThroughEventLossCounters(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"challenges":12,"passes":9,"fails":3,"events_dropped":4,"events_deliver_failed":5}`))
	}))
	t.Cleanup(admin.Close)

	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	router := gin.New()
	router.GET("/security/human/stats", h.GetHumanVerifyStats)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/human/stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	for key, want := range map[string]float64{"challenges": 12, "passes": 9, "fails": 3, "events_dropped": 4, "events_deliver_failed": 5} {
		if got, _ := envelope.Data[key].(float64); got != want {
			t.Fatalf("data[%s]=%v, want %v（丢失对账计数必须透传）body=%s", key, envelope.Data[key], want, rec.Body.String())
		}
	}
	// 文档示例键集与代理响应双向对账（新增键不得漂移）。
	docExample := docResponseExample(t, "GET /security/human/stats")
	assertKeySetsEqual(t, "human/stats", mapKeysOf(docExample), mapKeysOf(envelope.Data))
}
