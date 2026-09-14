package caddygeoip

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// 表驱动:仅 coraza 中断(ID 非空+4xx)计数,其余形态零误计。
func TestSecurityBlockedCounter_ServeHTTP(t *testing.T) {
	rule := "lb_test_rule"
	testCounter := newSecurityBlockedCounterVec(prometheus.NewRegistry())
	before := testutil.ToFloat64(testCounter.WithLabelValues(rule))

	cases := []struct {
		name      string
		nextErr   error
		wantCount float64
	}{
		{"nil error passes through", nil, 0},
		{"coraza 403 interruption counts", caddyhttp.HandlerError{StatusCode: 403, ID: "abcdefghijklmnop"}, 1},
		{"coraza 429 custom block counts", caddyhttp.HandlerError{StatusCode: 429, ID: "qrstuvwxyzabcdef"}, 1},
		{"rate limit 429 (caddyhttp.Error generated ID) counts", caddyhttp.HandlerError{StatusCode: 429, ID: "rA9kX2mPq"}, 1},
		{"WAF internal 500 not counted", caddyhttp.HandlerError{StatusCode: 500, ID: "tx789"}, 0},
		{"caddy 404 no ID not counted", caddyhttp.HandlerError{StatusCode: 404, ID: ""}, 0},
		{"plain error not counted", errors.New("boom"), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &SecurityBlockedCounter{Rule: rule, metrics: testCounter}
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
	after := testutil.ToFloat64(testCounter.WithLabelValues(rule))
	wantTotal := before + 3 // coraza 403 + coraza 429 + ratelimit 429 三笔
	if after != wantTotal {
		t.Fatalf("counter=%v, want %v (before=%v)", after, wantTotal, before)
	}
}

// P4-1(第 28.5 轮审计):Provision/registerOrExisting 护栏——7723d76d registry
// 事故(指标恒 0)的回归测试。
func TestRegisterOrExisting(t *testing.T) {
	reg := prometheus.NewRegistry()

	// 形状①:首次注册成功,返回新实例
	first := newSecurityBlockedCounterVec(reg)
	first.WithLabelValues("rule_a").Inc()
	var mfs []*dto.MetricFamily
	var err error
	mfs, err = reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() == "lazybalancer_security_blocked_total" {
			found = true
		}
	}
	if !found {
		t.Fatal("first registration: metric not exposed")
	}

	// 形状②:同 registry 重复注册复用实例(不丢数据,不 panic)
	second := newSecurityBlockedCounterVec(reg)
	if first != second {
		t.Fatal("re-registration on same registry must reuse existing instance (data preserved)")
	}
	if got := testutil.ToFloat64(first.WithLabelValues("rule_a")); got != 1 {
		t.Fatalf("reused instance lost data: count=%v, want 1", got)
	}

	// 形状③:跨 reload 新 registry 全新注册(归零,与 caddy_http_* 同纪元)
	reg2 := prometheus.NewRegistry()
	third := newSecurityBlockedCounterVec(reg2)
	if third == first {
		t.Fatal("cross-reload new registry must get fresh instance (reset to zero)")
	}
	if got := testutil.ToFloat64(third.WithLabelValues("rule_a")); got != 0 {
		t.Fatalf("cross-reload instance not zeroed: count=%v, want 0", got)
	}
}
