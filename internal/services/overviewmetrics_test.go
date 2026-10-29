package services

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Fixture modelled on live Caddy admin /metrics output:
// caddy_http_request_duration_seconds_count{code="429",handler="headers",host="go029.com",method="GET",server="http_443"} 7
const rateLimit429MetricsFixture = `# HELP caddy_http_request_duration_seconds Histogram of request durations
# TYPE caddy_http_request_duration_seconds histogram
caddy_http_request_duration_seconds_bucket{code="429",handler="headers",host="go029.com",method="GET",server="http_443",le="0.005"} 3
caddy_http_request_duration_seconds_count{code="429",handler="headers",host="go029.com",method="GET",server="http_443"} 7
caddy_http_request_duration_seconds_count{code="429",handler="headers",host="go029.com",method="POST",server="http_443"} 2
caddy_http_request_duration_seconds_sum{code="429",handler="headers",host="go029.com",method="GET",server="http_443"} 0.31
caddy_http_request_duration_seconds_count{code="200",handler="headers",host="go029.com",method="GET",server="http_443"} 100
caddy_http_request_duration_seconds_count{code="429",handler="headers",host="go029.com",method="GET",server="http_443"} 5
caddy_http_request_duration_seconds_count{code="429",handler="headers",host="api.example.com",method="GET",server="http_443"} 3
caddy_http_request_duration_seconds_count{code="429",handler="headers",host="api.example.com",method="GET",server="http_80"} 4
caddy_http_requests_total{handler="headers",host="go029.com",server="http_443"} 42
`

func TestRateLimitBlocksParse_aggregatesPerHostByCode429(t *testing.T) {
	// Given metrics text mixing codes, handlers, methods, servers, and sibling histogram series
	// When the counters are parsed——仅按 code="429" 过滤（handler 标签自 自此恒为
	// 主路由链首 headers，不可作区分维度；上游自返 429 如实纳入计数，卡片已标注口径）
	counts := rateLimit429HostCounts(parseRateLimit429CountsByServer(rateLimit429MetricsFixture))

	// Then all code="429" count series contribute, summed per host
	if len(counts) != 2 {
		t.Fatalf("hosts=%v, want exactly go029.com and api.example.com", counts)
	}
	if counts["go029.com"] != 14 {
		t.Errorf("go029.com=%v, want 14 (7 GET + 2 POST + 5 upstream-429)", counts["go029.com"])
	}
	if counts["api.example.com"] != 7 {
		t.Errorf("api.example.com=%v, want 7 (3 http_443 + 4 http_80)", counts["api.example.com"])
	}
}

func TestRateLimitBlocksParse_skipsMalformedLines(t *testing.T) {
	// Given a body with a non-numeric value, a missing host label, and one valid line
	body := `caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="bad.example.com",method="GET",server="http_443"} notanumber
caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",method="GET",server="http_443"} 5
caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="broken.example.com"
caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="ok.example.com",method="GET",server="http_443"} 1.5
`
	// When the counters are parsed
	counts := rateLimit429HostCounts(parseRateLimit429CountsByServer(body))

	// Then only the valid line is counted
	if len(counts) != 1 || counts["ok.example.com"] != 1.5 {
		t.Fatalf("counts=%v, want {ok.example.com: 1.5}", counts)
	}
}

func TestRateLimitBlocksParse_emptyBodyYieldsEmpty(t *testing.T) {
	// Given an empty metrics body
	// When parsed
	counts := rateLimit429HostCounts(parseRateLimit429CountsByServer(""))

	// Then the result is empty
	if len(counts) != 0 {
		t.Fatalf("counts=%v, want empty", counts)
	}
}

func TestRateLimitBlocksParse_skipsGeoipPassSeries(t *testing.T) {
	// Given：同一 429 响应在被 geoip 透传路由与主路由各记一条时长计数序列
	body := strings.Join([]string{
		`caddy_http_request_duration_seconds_count{code="429",handler="headers",host="example.com",method="GET",server="http_443"} 7`,
		`caddy_http_request_duration_seconds_count{code="429",handler="http.handlers.geoip2region",host="example.com",method="GET",server="http_443"} 7`,
		`caddy_http_request_duration_seconds_count{code="429",handler="headers",host="plain.example.com",method="GET",server="http_443"} 3`,
	}, "\n")

	// When：按站点聚合
	counts := rateLimit429HostCounts(parseRateLimit429CountsByServer(body))

	// Then：透传序列整行剔除（与采集链/实时指标同口径），未启用 geoip 的站点不变
	if counts["example.com"] != 7 {
		t.Errorf("example.com=%v, want 7（透传序列不得重复计入）", counts["example.com"])
	}
	if counts["plain.example.com"] != 3 {
		t.Errorf("plain.example.com=%v, want 3", counts["plain.example.com"])
	}
}

func TestRateLimitBlocksParse_keepsServerDimensionForSingleRuleChips(t *testing.T) {
	// Given：同域两个端口的 429 计数（server 标签区分监听端口）
	// When：按 (host, server) 解析
	counts := parseRateLimit429CountsByServer(rateLimit429MetricsFixture)

	// Then：端口维度保留（站点级视图仍按 host 求和，二者同源）
	if got := counts[rateLimitHostServerKey{host: "api.example.com", server: "http_443"}]; got != 3 {
		t.Errorf("api.example.com/http_443=%v, want 3", got)
	}
	if got := counts[rateLimitHostServerKey{host: "api.example.com", server: "http_80"}]; got != 4 {
		t.Errorf("api.example.com/http_80=%v, want 4", got)
	}
	if got := counts[rateLimitHostServerKey{host: "go029.com", server: "http_443"}]; got != 14 {
		t.Errorf("go029.com/http_443=%v, want 14 (同端口 method 序列求和)", got)
	}
}

func TestScrapeRateLimitBlocksByHostServer_sharesFetchWithHostView(t *testing.T) {
	// Given：一个计数抓取次数的 Caddy 指标桩
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(rateLimit429MetricsFixture))
	}))
	t.Cleanup(server.Close)
	resetOverviewMetricsCacheForTest()
	t.Cleanup(resetOverviewMetricsCacheForTest)

	// When：两个视图各取一次（5s 缓存窗口内）
	blocks, err := ScrapeRateLimitBlocks(server.URL)
	if err != nil {
		t.Fatalf("host view: %v", err)
	}
	byServer, err := ScrapeRateLimitBlocksByHostServer(server.URL)
	if err != nil {
		t.Fatalf("host+server view: %v", err)
	}

	// Then：只抓取一次，两个视图内容同源
	if hits.Load() != 1 {
		t.Errorf("metrics fetches=%d, want 1（两个消费端点共享缓存/单飞）", hits.Load())
	}
	if len(blocks) != 2 || len(byServer) != 3 {
		t.Fatalf("blocks=%v byServer=%v", blocks, byServer)
	}
	// 返回副本：改动调用方切片不得污染缓存
	blocks[0].Count = -1
	again, err := ScrapeRateLimitBlocks(server.URL)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if again[0].Count < 0 {
		t.Fatalf("cached result mutated through returned slice: %+v", again)
	}
}

func TestScrapeRateLimitBlocks_returnsSortedPerHostCounts(t *testing.T) {
	// Given a Caddy metrics endpoint serving 429 rate_limit counters
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(rateLimit429MetricsFixture))
	}))
	t.Cleanup(server.Close)

	// When the endpoint is scraped
	blocks, err := ScrapeRateLimitBlocks(server.URL)

	// Then per-host aggregates are returned, highest count first
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	if len(blocks) != 2 {
		t.Fatalf("blocks=%+v, want 2 hosts", blocks)
	}
	if blocks[0].Host != "go029.com" || blocks[0].Count != 14 {
		t.Errorf("blocks[0]=%+v, want {go029.com 14}", blocks[0])
	}
	if blocks[1].Host != "api.example.com" || blocks[1].Count != 7 {
		t.Errorf("blocks[1]=%+v, want {api.example.com 7}", blocks[1])
	}
}

func TestScrapeRateLimitBlocks_errorOnNon2xxStatus(t *testing.T) {
	// Given a metrics endpoint answering 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	// When scraped
	_, err := ScrapeRateLimitBlocks(server.URL)

	// Then an error is returned (caller degrades, never silently empty)
	if err == nil {
		t.Fatal("want error on 500 status, got nil")
	}
}

func TestScrapeRateLimitBlocks_errorOnUnreachableServer(t *testing.T) {
	// Given an unreachable metrics URL
	// When scraped
	_, err := ScrapeRateLimitBlocks("http://127.0.0.1:1/metrics")

	// Then an error is returned
	if err == nil {
		t.Fatal("want error on connection refused, got nil")
	}
}

// 5s TTL 进程内缓存——仪表盘多调用点在窗口内只抓一次。
func TestScrapeRateLimitBlocks_cachedWithinTTL(t *testing.T) {
	resetOverviewMetricsCacheForTest()
	oldTTL := overviewMetricsCacheTTL
	overviewMetricsCacheTTL = time.Minute
	t.Cleanup(func() {
		overviewMetricsCacheTTL = oldTTL
		resetOverviewMetricsCacheForTest()
	})
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(rateLimit429MetricsFixture))
	}))
	t.Cleanup(server.Close)

	for range 2 {
		blocks, err := ScrapeRateLimitBlocks(server.URL)
		if err != nil {
			t.Fatalf("scrape: %v", err)
		}
		if len(blocks) != 2 {
			t.Fatalf("blocks=%+v, want 2 hosts", blocks)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("TTL 内抓取次数=%d, want 1（缓存未生效）", got)
	}

	// 缓存返回副本：调用方改动不得污染缓存。
	first, err := ScrapeRateLimitBlocks(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	first[0].Count = -1
	again, err := ScrapeRateLimitBlocks(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Count < 0 {
		t.Fatal("缓存返回共享切片（调用方改动回写缓存）")
	}
}

// 失败轮不写缓存——瞬态故障后的下一个请求仍会重试。
func TestScrapeRateLimitBlocks_failureNotCached(t *testing.T) {
	resetOverviewMetricsCacheForTest()
	oldTTL := overviewMetricsCacheTTL
	overviewMetricsCacheTTL = time.Minute
	t.Cleanup(func() {
		overviewMetricsCacheTTL = oldTTL
		resetOverviewMetricsCacheForTest()
	})
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	for range 2 {
		if _, err := ScrapeRateLimitBlocks(server.URL); err == nil {
			t.Fatal("want error on 500 status")
		}
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("失败轮抓取次数=%d, want 2（失败不得缓存）", got)
	}
}

// 同 URL 并发单飞——在途请求共用一次抓取。
// 缓存窗口置 0：只断言 hits==1 时，1 分钟 TTL 会让「串行/缓存命中」与
// 「单飞合并」不可区分（单飞失效也能通过）；等 4 个等待方进入单飞等待后
// 才放行响应，抓取次数=1 才是单飞的直接证据。
func TestScrapeRateLimitBlocks_singleFlight(t *testing.T) {
	resetOverviewMetricsCacheForTest()
	oldTTL := overviewMetricsCacheTTL
	overviewMetricsCacheTTL = 0
	waiterCount := atomic.Int64{}
	allWaiters := make(chan struct{})
	var waiterOnce sync.Once
	oldHook := overviewMetricsWaiterHook
	overviewMetricsWaiterHook = func() {
		if waiterCount.Add(1) == 4 {
			waiterOnce.Do(func() { close(allWaiters) })
		}
	}
	t.Cleanup(func() {
		overviewMetricsCacheTTL = oldTTL
		overviewMetricsWaiterHook = oldHook
		resetOverviewMetricsCacheForTest()
	})

	var hits atomic.Int64
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		// 有界等待：单飞失效时其余请求也会到此，测试失败后不得把 Close 挂死。
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
		_, _ = w.Write([]byte(rateLimit429MetricsFixture))
	}))
	t.Cleanup(server.Close)

	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ScrapeRateLimitBlocks(server.URL); err != nil {
				errs <- err
			}
		}()
	}
	waitForCond(t, 3*time.Second, func() bool { return hits.Load() == 1 })
	waitForSignal(t, allWaiters, "等待方未全部进入单飞（单飞未合并并发请求）")
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("scrape: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("并发抓取次数=%d, want 1（单飞未生效）", got)
	}
}

// 作废旧代际后，旧抓取完成只能清理自己的单飞登记，不能摘掉新代际的
// 在途调用；否则第三个请求会在新抓取尚未完成时重复抓 /metrics。
func TestScrapeRateLimitBlocks_staleCompletionKeepsNewInflight(t *testing.T) {
	resetOverviewMetricsCacheForTest()
	oldTTL := overviewMetricsCacheTTL
	overviewMetricsCacheTTL = 0
	t.Cleanup(func() {
		overviewMetricsCacheTTL = oldTTL
		resetOverviewMetricsCacheForTest()
	})

	firstStarted := make(chan struct{})
	secondStarted := make(chan struct{})
	unexpectedThirdFetch := make(chan struct{})
	releaseFirst := make(chan struct{})
	releaseSecond := make(chan struct{})
	var firstRelease, secondRelease, thirdSignal sync.Once
	releaseOld := func() { firstRelease.Do(func() { close(releaseFirst) }) }
	releaseNew := func() { secondRelease.Do(func() { close(releaseSecond) }) }
	t.Cleanup(releaseOld)
	t.Cleanup(releaseNew)

	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch hits.Add(1) {
		case 1:
			close(firstStarted)
			<-releaseFirst
		case 2:
			close(secondStarted)
			<-releaseSecond
		default:
			thirdSignal.Do(func() { close(unexpectedThirdFetch) })
		}
		_, _ = w.Write([]byte(rateLimit429MetricsFixture))
	}))
	t.Cleanup(server.Close)

	firstDone := make(chan error, 1)
	go func() {
		_, err := ScrapeRateLimitBlocks(server.URL)
		firstDone <- err
	}()
	waitForSignal(t, firstStarted, "旧代际抓取未开始")
	InvalidateOverviewMetricsCache()

	secondDone := make(chan error, 1)
	go func() {
		_, err := ScrapeRateLimitBlocks(server.URL)
		secondDone <- err
	}()
	waitForSignal(t, secondStarted, "新代际抓取未开始")
	releaseOld()
	if err := <-firstDone; err != nil {
		t.Fatalf("旧代际抓取返回错误: %v", err)
	}

	thirdWaiting := make(chan struct{})
	oldHook := overviewMetricsWaiterHook
	var waiterOnce sync.Once
	overviewMetricsWaiterHook = func() { waiterOnce.Do(func() { close(thirdWaiting) }) }
	t.Cleanup(func() { overviewMetricsWaiterHook = oldHook })
	thirdDone := make(chan error, 1)
	go func() {
		_, err := ScrapeRateLimitBlocks(server.URL)
		thirdDone <- err
	}()

	joinedNewCall := false
	select {
	case <-thirdWaiting:
		joinedNewCall = true
	case <-unexpectedThirdFetch:
	case <-time.After(2 * time.Second):
	}
	releaseNew()
	if err := <-secondDone; err != nil {
		t.Fatalf("新代际抓取返回错误: %v", err)
	}
	if err := <-thirdDone; err != nil {
		t.Fatalf("第三请求返回错误: %v", err)
	}
	if !joinedNewCall {
		t.Fatal("旧代际完成删除了新代际登记，第三请求未加入既有单飞")
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("抓取次数=%d, want 2（旧完成不得诱发第三次抓取）", got)
	}
}

// host 标签归一是「带端口部署的规则限流计数恒 0」的修复载体：metrics 的
// host 是原文 r.Host（可能带 :port / IPv6 方括号），lb_rules.domain 不带端口。
func TestNormalizeMetricsHost(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "plain domain", in: "go029.com", want: "go029.com"},
		{name: "uppercase", in: "A.COM", want: "a.com"},
		{name: "surrounding spaces", in: " go029.com ", want: "go029.com"},
		{name: "domain with port", in: "go029.com:8443", want: "go029.com"},
		{name: "uppercase with port", in: "GO029.COM:8443", want: "go029.com"},
		{name: "ipv6 with port", in: "[::1]:8443", want: "::1"},
		{name: "bracketed ipv6", in: "[::1]", want: "::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeMetricsHost(tc.in); got != tc.want {
				t.Fatalf("NormalizeMetricsHost(%q)=%q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// 同一 CaddyMetricsURL 的两条抓取链必须共用超时预算：预算分叉时慢实例上会
// 出现「首页指标正常、限流卡片超时不可用」的同源不同可用性。
func TestCaddyMetricsClientsShareScrapeBudget(t *testing.T) {
	service := NewMetricsService("http://127.0.0.1:2019/metrics", 30)
	if service.client.Timeout != caddyMetricsScrapeTimeout {
		t.Fatalf("collect client timeout=%v, want %v", service.client.Timeout, caddyMetricsScrapeTimeout)
	}
	if got := overviewMetricsHTTPClient.Timeout; got != caddyMetricsScrapeTimeout {
		t.Fatalf("overview client timeout=%v, want %v", got, caddyMetricsScrapeTimeout)
	}
}

// 指标响应超过 16MB 上限必须返回明确错误（fail-visible），不得静默返回空表——
// 空表会让「限流拦截」卡片显示 0 而非「指标不可用」。
func TestScrapeRateLimitBlocksRejectsOversizeBody(t *testing.T) {
	resetOverviewMetricsCacheForTest()
	t.Cleanup(resetOverviewMetricsCacheForTest)
	oversize := make([]byte, overviewMetricsReadLimit+1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(oversize)
	}))
	t.Cleanup(server.Close)

	blocks, err := ScrapeRateLimitBlocks(server.URL)

	if err == nil {
		t.Fatalf("超限响应必须报错，实际返回 blocks=%v", blocks)
	}
	if !strings.Contains(err.Error(), "上限") {
		t.Fatalf("err=%v, want 明确的超限说明", err)
	}
	if blocks != nil {
		t.Fatalf("超限不得返回部分数据: %v", blocks)
	}
}

func TestScrapeRateLimitBlocks_emptyMetricsReturnsNonNilSlice(t *testing.T) {
	// 无 429 行时 JSON 必须是 [] 而不是 null——前端直接读 hosts.length。
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# no ratelimit metrics\n"))
	}))
	t.Cleanup(server.Close)
	blocks, err := ScrapeRateLimitBlocks(server.URL)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	if blocks == nil {
		t.Fatal("empty result must be a non-nil slice (JSON hosts:[], not null)")
	}
	if len(blocks) != 0 {
		t.Fatalf("blocks=%+v, want empty", blocks)
	}
}

// 按 Prometheus exposition 规范解码标签值转义（\\ \" \n）——
// 此前反斜杠被吞掉后原样写下一字节，\n 被解析成字面 n。规范未定义的转义
// （\t 等）原样保留（含反斜杠），不静默丢字节。
func TestParsePromLabelPairs_prometheusEscapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "escaped newline", in: `host="a\nb",code="429"`, want: "a\nb"},
		{name: "escaped backslash", in: `host="a\\b",code="429"`, want: `a\b`},
		{name: "escaped quote", in: `host="a\"b",code="429"`, want: `a"b`},
		{name: "undefined escape kept verbatim", in: `host="a\tb",code="429"`, want: `a\tb`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			labels := parsePromLabelPairs(tt.in)
			if got := labels["host"]; got != tt.want {
				t.Fatalf("host=%q, want %q", got, tt.want)
			}
			if labels["code"] != "429" {
				t.Fatalf("code=%q, want 429（转义处理不得影响后续标签）", labels["code"])
			}
		})
	}
}

// /load 成功即失效缓存：重载重建 registry（限流计数归零），缓存不感知会让
// 安全总览在 ≤5s 内继续显示重载前的累计值。
func TestInvalidateOverviewMetricsCache_forcesRefetch(t *testing.T) {
	resetOverviewMetricsCacheForTest()
	oldTTL := overviewMetricsCacheTTL
	overviewMetricsCacheTTL = time.Minute
	t.Cleanup(func() {
		overviewMetricsCacheTTL = oldTTL
		resetOverviewMetricsCacheForTest()
	})
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(rateLimit429MetricsFixture))
	}))
	t.Cleanup(server.Close)

	for range 2 {
		if _, err := ScrapeRateLimitBlocks(server.URL); err != nil {
			t.Fatalf("scrape: %v", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("TTL 内抓取次数=%d, want 1", got)
	}

	InvalidateOverviewMetricsCache()
	if _, err := ScrapeRateLimitBlocks(server.URL); err != nil {
		t.Fatalf("scrape after invalidate: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("失效后抓取次数=%d, want 2（/load 后必须重新抓取）", got)
	}
}
