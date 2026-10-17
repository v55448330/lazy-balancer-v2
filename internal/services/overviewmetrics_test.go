package services

import (
	"net/http"
	"net/http/httptest"
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
	// When the counters are parsed——仅按 code="429" 过滤（handler 标签自 F3 起恒为
	// 主路由链首 headers，不可作区分维度；上游自返 429 如实纳入计数，卡片已标注口径）
	counts := parseRateLimit429Counts(rateLimit429MetricsFixture)

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
	counts := parseRateLimit429Counts(body)

	// Then only the valid line is counted
	if len(counts) != 1 || counts["ok.example.com"] != 1.5 {
		t.Fatalf("counts=%v, want {ok.example.com: 1.5}", counts)
	}
}

func TestRateLimitBlocksParse_emptyBodyYieldsEmpty(t *testing.T) {
	// Given an empty metrics body
	// When parsed
	counts := parseRateLimit429Counts("")

	// Then the result is empty
	if len(counts) != 0 {
		t.Fatalf("counts=%v, want empty", counts)
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

// U08-F06：5s TTL 进程内缓存——仪表盘多调用点在窗口内只抓一次。
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

// U08-F06：失败轮不写缓存——瞬态故障后的下一个请求仍会重试。
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

// U08-F06：同 URL 并发单飞——在途请求共用一次抓取。
func TestScrapeRateLimitBlocks_singleFlight(t *testing.T) {
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
		time.Sleep(100 * time.Millisecond)
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
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("scrape: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("并发抓取次数=%d, want 1（单飞未生效）", got)
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
