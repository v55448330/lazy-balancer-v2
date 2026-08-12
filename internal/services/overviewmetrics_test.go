package services

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Fixture modelled on live Caddy admin /metrics output:
// caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="go029.com",method="GET",server="http_443"} 7
const rateLimit429MetricsFixture = `# HELP caddy_http_request_duration_seconds Histogram of request durations
# TYPE caddy_http_request_duration_seconds histogram
caddy_http_request_duration_seconds_bucket{code="429",handler="rate_limit",host="go029.com",method="GET",server="http_443",le="0.005"} 3
caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="go029.com",method="GET",server="http_443"} 7
caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="go029.com",method="POST",server="http_443"} 2
caddy_http_request_duration_seconds_sum{code="429",handler="rate_limit",host="go029.com",method="GET",server="http_443"} 0.31
caddy_http_request_duration_seconds_count{code="200",handler="rate_limit",host="go029.com",method="GET",server="http_443"} 100
caddy_http_request_duration_seconds_count{code="429",handler="reverse_proxy",host="go029.com",method="GET",server="http_443"} 5
caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="api.example.com",method="GET",server="http_443"} 3
caddy_http_request_duration_seconds_count{code="429",handler="rate_limit",host="api.example.com",method="GET",server="http_80"} 4
caddy_http_requests_total{handler="rate_limit",host="go029.com",server="http_443"} 42
`

func TestRateLimitBlocksParse_aggregatesPerHostOnly429RateLimit(t *testing.T) {
	// Given metrics text mixing codes, handlers, methods, servers, and sibling histogram series
	// When the counters are parsed
	counts := parseRateLimit429Counts(rateLimit429MetricsFixture)

	// Then only code="429" + handler="rate_limit" count series contribute, summed per host
	if len(counts) != 2 {
		t.Fatalf("hosts=%v, want exactly go029.com and api.example.com", counts)
	}
	if counts["go029.com"] != 9 {
		t.Errorf("go029.com=%v, want 9 (7 GET + 2 POST)", counts["go029.com"])
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
	if blocks[0].Host != "go029.com" || blocks[0].Count != 9 {
		t.Errorf("blocks[0]=%+v, want {go029.com 9}", blocks[0])
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
