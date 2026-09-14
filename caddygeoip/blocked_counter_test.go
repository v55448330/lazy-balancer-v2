package caddygeoip

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// 表驱动:仅 coraza 中断(ID 非空+4xx)计数,其余形态零误计。
func TestSecurityBlockedCounter_ServeHTTP(t *testing.T) {
	rule := "lb_test_rule"
	before := testutil.ToFloat64(securityBlockedTotal.WithLabelValues(rule))

	cases := []struct {
		name      string
		nextErr   error
		wantCount float64
	}{
		{"nil error passes through", nil, 0},
		{"coraza 403 interruption counts", caddyhttp.HandlerError{StatusCode: 403, ID: "tx123"}, 1},
		{"coraza 429 custom block counts", caddyhttp.HandlerError{StatusCode: 429, ID: "tx456"}, 1},
		{"rate limit 429 (caddyhttp.Error generated ID) counts", caddyhttp.HandlerError{StatusCode: 429, ID: "rA9kX2mPq"}, 1},
		{"WAF internal 500 not counted", caddyhttp.HandlerError{StatusCode: 500, ID: "tx789"}, 0},
		{"caddy 404 no ID not counted", caddyhttp.HandlerError{StatusCode: 404, ID: ""}, 0},
		{"plain error not counted", errors.New("boom"), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &SecurityBlockedCounter{Rule: rule}
			next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return tc.nextErr })
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			gotErr := h.ServeHTTP(rec, req, next)
			// 返回值必须原样透传(链语义零改动)
			if gotErr != tc.nextErr {
				t.Fatalf("ServeHTTP returned %v, want passthrough %v", gotErr, tc.nextErr)
			}
		})
	}
	after := testutil.ToFloat64(securityBlockedTotal.WithLabelValues(rule))
	wantTotal := before + 3 // coraza 403 + coraza 429 + ratelimit 429 三笔
	if after != wantTotal {
		t.Fatalf("counter=%v, want %v (before=%v)", after, wantTotal, before)
	}
}
