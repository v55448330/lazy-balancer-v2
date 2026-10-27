package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
)

const rateLimitBlocksMetricsFixture = `caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="go029.com",method="GET",server="http_443"} 7
caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="go029.com",method="POST",server="http_443"} 2
caddy_http_request_duration_seconds_count{code="200",handler="rate_limit",host="go029.com",method="GET",server="http_443"} 100
caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="api.example.com",method="GET",server="http_443"} 3
`

type rateLimitBlocksPayload struct {
	Code int `json:"code"`
	Data struct {
		Total float64 `json:"total"`
		Hosts []struct {
			Host  string  `json:"host"`
			Count float64 `json:"count"`
		} `json:"hosts"`
	} `json:"data"`
}

func newRateLimitBlocksRouter(metricsURL string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{CaddyMetricsURL: metricsURL}}
	router := gin.New()
	router.GET("/security/rate-limit-blocks", h.GetSecurityRateLimitBlocks)
	return router
}

func TestGetSecurityRateLimitBlocks_returnsTotalsAndHosts(t *testing.T) {
	// Given a Caddy metrics endpoint with per-host 429 rate_limit counters
	resetCaddyMetricsSnapshotCacheForTest()
	t.Cleanup(resetCaddyMetricsSnapshotCacheForTest)
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(rateLimitBlocksMetricsFixture))
	}))
	t.Cleanup(metrics.Close)
	router := newRateLimitBlocksRouter(metrics.URL)

	// When the rate-limit blocks endpoint is requested
	recorder := getRequest(t, router, "/security/rate-limit-blocks")

	// Then the response carries the grand total and per-host breakdown
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q, want 200", recorder.Code, recorder.Body.String())
	}
	var payload rateLimitBlocksPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Code != 0 {
		t.Errorf("code=%d, want 0", payload.Code)
	}
	if payload.Data.Total != 12 {
		t.Errorf("total=%v, want 12 (7+2+3, code=200 excluded)", payload.Data.Total)
	}
	if len(payload.Data.Hosts) != 2 {
		t.Fatalf("hosts=%+v, want 2 entries", payload.Data.Hosts)
	}
	if payload.Data.Hosts[0].Host != "go029.com" || payload.Data.Hosts[0].Count != 9 {
		t.Errorf("hosts[0]=%+v, want {go029.com 9}", payload.Data.Hosts[0])
	}
	if payload.Data.Hosts[1].Host != "api.example.com" || payload.Data.Hosts[1].Count != 3 {
		t.Errorf("hosts[1]=%+v, want {api.example.com 3}", payload.Data.Hosts[1])
	}
}

func TestGetSecurityRateLimitBlocks_scrapeFailureReturns500(t *testing.T) {
	// Given an unreachable Caddy metrics endpoint
	router := newRateLimitBlocksRouter("http://127.0.0.1:1/metrics")

	// When the endpoint is requested
	recorder := getRequest(t, router, "/security/rate-limit-blocks")

	// Then the scrape failure surfaces as 500 so the frontend error state is
	// reachable（三-4：200+空列表会让「Caddy 指标不可达」与「暂无限流拦截」
	// 不可区分，前端 catch 路径已就绪）
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%q, want 500", recorder.Code, recorder.Body.String())
	}
}

// 规则通配域与 Caddy host matcher 同语义：*.example.com 恰好覆盖一级子域，
// 不覆盖裸域与二级以上子域（caddyhttp.MatchHost 要求标签数相等）。此前用
// HasSuffix 会把 a.b.example.com 的 429 计数并入通配规则（chip 偏高）。
func TestSecurityRuleHostMatches_singleLabelWildcard(t *testing.T) {
	const rule = "*.example.com"
	for _, tc := range []struct {
		metric string
		want   bool
	}{
		{"foo.example.com", true},
		{"FOO.Example.COM", true}, // host matcher 大小写不敏感
		{"a.b.example.com", false},
		{"example.com", false},    // 通配不覆盖裸域
		{"fooexample.com", false}, // 后缀相似但不是子域
		{"foo.example.com.evil", false},
		{"", false},
	} {
		if got := securityRuleHostMatches(rule, tc.metric); got != tc.want {
			t.Errorf("securityRuleHostMatches(%q, %q)=%v, want %v", rule, tc.metric, got, tc.want)
		}
	}
	// 精确域：大小写不敏感，通配进程不影响精确分支
	if !securityRuleHostMatches("go029.com", "GO029.com") {
		t.Error("精确域必须大小写不敏感匹配")
	}
	if securityRuleHostMatches("go029.com", "api.go029.com") {
		t.Error("精确域不得匹配子域")
	}
	if securityRuleHostMatches("", "go029.com") || securityRuleHostMatches("go029.com", "") {
		t.Error("空 host 一律不匹配")
	}
}
