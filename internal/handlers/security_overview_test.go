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
	// reachable（R38 三-4：200+空列表会让「Caddy 指标不可达」与「暂无限流拦截」
	// 不可区分，前端 catch 路径已就绪）
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%q, want 500", recorder.Code, recorder.Body.String())
	}
}
