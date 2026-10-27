package caddygeoip

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

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
		{"WAF internal 500 (16-char ID, F1 regression guard) not counted", caddyhttp.HandlerError{StatusCode: 500, ID: "abcdefghijklmnop"}, 0},
		{"caddy 404 no ID not counted", caddyhttp.HandlerError{StatusCode: 404, ID: ""}, 0},
		{"proxy 499 client-cancel (9-char ID) not counted", caddyhttp.HandlerError{StatusCode: 499, ID: "rA9kX2mPq"}, 0},
		{"request_body 413 (9-char ID) not counted", caddyhttp.HandlerError{StatusCode: 413, ID: "xY8kL2mNp"}, 0},
		{"plain error not counted", errors.New("boom"), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caseBefore := testutil.ToFloat64(testCounter.WithLabelValues(rule))
			h := &SecurityBlockedCounter{Rule: rule, metrics: testCounter}
			next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return tc.nextErr })
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			gotErr := h.ServeHTTP(rec, req, next)
			// 返回值必须原样透传(链语义零改动)
			if gotErr != tc.nextErr {
				t.Fatalf("ServeHTTP returned %v, want passthrough %v", gotErr, tc.nextErr)
			}
			// 逐例分类断言:聚合值在「该计的不计」与「不该计的计入」相互抵消时
			// 仍可能相等，只有逐例增量能钉住每一格的计数语义。
			caseDelta := testutil.ToFloat64(testCounter.WithLabelValues(rule)) - caseBefore
			if caseDelta != tc.wantCount {
				t.Fatalf("counter delta=%v, want %v (case=%s, err=%v)", caseDelta, tc.wantCount, tc.name, tc.nextErr)
			}
		})
	}
	after := testutil.ToFloat64(testCounter.WithLabelValues(rule))
	wantTotal := before + 3 // coraza 403 + coraza 429 + ratelimit 429 三笔
	if after != wantTotal {
		t.Fatalf("counter=%v, want %v (before=%v)", after, wantTotal, before)
	}
}

// 无 geoip handler 的链上，客户端伪造国名头不得进入流量统计；
// 有 geoip handler 时也只能采用其写入的服务端变量，不能被同名请求头覆盖。
func TestSecurityBlockedCounter_trafficCountryTrustsServerVar(t *testing.T) {
	cases := []struct {
		name        string
		vars        map[string]any
		wantBuckets int
		wantCountry string
	}{
		{name: "missing geoip var ignores forged header", wantBuckets: 0},
		{name: "server var wins over forged header", vars: map[string]any{"geoip.country_name": "中国"}, wantBuckets: 1, wantCountry: "中国"},
		{name: "non string var is ignored", vars: map[string]any{"geoip.country_name": 42}, wantBuckets: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetTrafficState(t)
			useTestTimingRegistry(t)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-LB-GeoIP-Country", "attacker-controlled")
			if tc.vars != nil {
				req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, tc.vars))
			}
			h := &SecurityBlockedCounter{Rule: "lb_traffic_source"}
			next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
			if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
				t.Fatalf("ServeHTTP: %v", err)
			}

			trafficMu.RLock()
			buckets := len(trafficCountries)
			e := trafficCountries[tc.wantCountry]
			trafficMu.RUnlock()
			if buckets != tc.wantBuckets {
				t.Fatalf("country buckets=%d, want %d (forged header must not be trusted)", buckets, tc.wantBuckets)
			}
			if tc.wantCountry != "" && (e == nil || e.normal.Load() != 1 || e.attack.Load() != 0) {
				t.Fatalf("trusted country entry=%+v, want one normal request", e)
			}
		})
	}
}

func TestSecurityBlockedCounter_panicFinalizesTimingAndTraffic(t *testing.T) {
	resetTrafficState(t)
	useTestTimingRegistry(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
		"geoip.country_name": "中国",
	}))
	h := &SecurityBlockedCounter{Rule: "lb_panic_finalization"}
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		panic("injected downstream panic")
	})

	func() {
		defer func() {
			if got := recover(); got != "injected downstream panic" {
				t.Fatalf("panic propagation=%v, want injected downstream panic", got)
			}
		}()
		_ = h.ServeHTTP(httptest.NewRecorder(), req, next)
	}()

	// panic 向外传播的同时，审计计时不得留下「等待中」的条目（无
	// 分段写点时 close 不建条；drain 首轮查表即返，不为该行等满超时），流量
	// 也不能静默丢失。
	id := req.Header.Get(securityTimingHeader)
	if id == "" {
		t.Fatal("missing injected timing id")
	}
	if snap := auditTimingLookupForTest(t, id); snap.hasAny() || snap.closed {
		t.Fatalf("timing snapshot after panic=%+v, want no registered entry", snap)
	}
	if polls := auditTimingPollCountForTest.Load(); polls != 0 {
		t.Fatalf("drain must not poll for a never-registered timing id, got %d polls", polls)
	}
	trafficMu.RLock()
	e := trafficCountries["中国"]
	trafficMu.RUnlock()
	if e == nil || e.normal.Load() != 1 || e.attack.Load() != 0 {
		t.Fatalf("traffic after panic=%+v, want one normal finalized request", e)
	}
}

// 历史（预检拦耗时口径）：拦截耗时写点的分段选键——
// 形状①预检段拦：起始头仍=注入原值（链未抵达 timing_pre 收点）→ 写 pre
// （决策后、403 写出前的纯预检评估），不得写 end（防同 ID 双段）；
// 形状②WAF/限流段拦：起始头已被 timing_pre 重写为分段锚点 → 写 end
// （链首至此全链，读侧 end-pre 得 WAF 段），不得写 pre。
// 断言目标从侧车文件行改为进程内注册表快照；post-next 终态标记
// （auditTimingClose）一并钉住——审计写插件 drain 依赖该标记停止等待。
func TestSecurityBlockedCounter_timingSegmentSelection(t *testing.T) {
	const id = "0123456789abcdef"
	cases := []struct {
		name          string
		nextErr       error
		rewriteInNext bool // next 模拟 timing_pre 已过（重写起始头为锚点）
		wantSegment   string
	}{
		{"precheck interruption writes pre", caddyhttp.HandlerError{StatusCode: 403, ID: id}, false, "pre"},
		{"precheck interruption stage page 481 writes pre", caddyhttp.HandlerError{StatusCode: 481, ID: id}, false, "pre"},
		{"waf interruption after pre writes end", caddyhttp.HandlerError{StatusCode: 403, ID: id}, true, "end"},
		{"ratelimit 429 after pre writes end", caddyhttp.HandlerError{StatusCode: http.StatusTooManyRequests, ID: "rA9kX2mPq"}, true, "end"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useTestTimingRegistry(t)
			h := &SecurityBlockedCounter{Rule: "lb_seg_rule"}
			next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
				if tc.rewriteInNext {
					// 模拟 timing_pre 的锚点交接契约：重写值严格大于注入原值
					//（时钟分辨率下同值会被误判为预检段拦——见实现注释）。
					old, _ := strconv.ParseInt(r.Header.Get(securityTimingStartHeader), 10, 64)
					r.Header.Set(securityTimingStartHeader, strconv.FormatInt(old+1, 10))
				}
				return tc.nextErr
			})
			req := httptest.NewRequest(http.MethodGet, "/", nil)

			if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != tc.nextErr {
				t.Fatalf("ServeHTTP = %v; want passthrough %v", err, tc.nextErr)
			}
			// timing ID 由 ServeHTTP 注入（覆盖客户端伪造值）——运行时取真实关联键
			id := req.Header.Get(securityTimingHeader)
			if len(id) != 16 {
				t.Fatalf("timing id header = %q; want 16-char injected id", id)
			}

			snap := auditTimingLookupForTest(t, id)
			if !snap.closed {
				t.Fatal("blocked_counter post-next must close the timing entry (terminal marker)")
			}
			switch tc.wantSegment {
			case "pre":
				if !snap.preSet || snap.endSet {
					t.Fatalf("snapshot = %+v; want exactly pre segment", snap)
				}
				if snap.preUs < 0 {
					t.Fatalf("pre=%d; want non-negative µs", snap.preUs)
				}
			case "end":
				if !snap.endSet || snap.preSet {
					t.Fatalf("snapshot = %+v; want exactly end segment", snap)
				}
				if snap.endUs < 0 {
					t.Fatalf("end=%d; want non-negative µs", snap.endUs)
				}
			}
		})
	}

	// 非拦截形态（logged 放行）：本 handler 之外无任何分段写点（无 timing_pre/
	// timing_end）——自此 close 不再建条，因此不产生注册表条目；
	// 审计 drain 对未知 tid 首轮即返，同样不等待。
	t.Run("logged passthrough without segment writes leaves no entry", func(t *testing.T) {
		useTestTimingRegistry(t)
		h := &SecurityBlockedCounter{Rule: "lb_seg_rule"}
		next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		id := req.Header.Get(securityTimingHeader)
		if id == "" {
			t.Fatal("timing id header must be injected")
		}
		auditTimingMu.Lock()
		_, exists := auditTimingEntries[id]
		count := len(auditTimingEntries)
		auditTimingMu.Unlock()
		if exists || count != 0 {
			t.Fatalf("close must not create entries (历史问题), got %d entries", count)
		}
		// AND：drain 侧零轮询立即返回（不注入 lb_timing）。
		snap := auditTimingWait(id, 50*time.Millisecond)
		if snap.hasAny() || snap.closed {
			t.Fatalf("snapshot = %+v; want empty", snap)
		}
		if polls := auditTimingPollCountForTest.Load(); polls != 0 {
			t.Fatalf("unknown tid must return without polling, got %d polls", polls)
		}
	})
}

// Provision/registerOrExisting 护栏——7723d76d registry
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

// 采集租约关闭时热路径跳过 trafficRecord：即使请求带 GeoIP 变量也不得产生桶。
func TestSecurityBlockedCounter_collectorDisabledSkipsTraffic(t *testing.T) {
	resetTrafficState(t)
	trafficCollectorEnabled.Store(false)
	t.Cleanup(func() { trafficCollectorEnabled.Store(true) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
		"geoip.country_name": "中国",
	}))
	h := &SecurityBlockedCounter{Rule: "lb_collector_disabled"}
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	trafficMu.RLock()
	defer trafficMu.RUnlock()
	if len(trafficCountries) != 0 {
		t.Fatalf("collector disabled created buckets: %+v", trafficCountries)
	}
}

// ID 生成失败（crypto/rand 出错）时客户端伪造的计时头必须被剥离。
// 两段收点（recordSecurityTiming）只校验 16 字符小写 hex 形态、不校验来源，
// 直接放行等于让客户端自选计时注册表 key 与起始纳秒：审计行 lb_timing 可被
// 注入任意耗时，且该头是安全事件的请求级去重键（两个请求可被误并为一条）。
func TestSecurityBlockedCounter_stripsForgedTimingHeadersWhenIDGenerationFails(t *testing.T) {
	oldRand := securityTimingRandRead
	securityTimingRandRead = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	t.Cleanup(func() { securityTimingRandRead = oldRand })

	const forgedID = "0123456789abcdef"
	const forgedStart = "1700000000000000000"
	var seenID, seenStart string
	h := &SecurityBlockedCounter{Rule: "lb_forged_timing", metrics: newSecurityBlockedCounterVec(prometheus.NewRegistry())}
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) error {
		seenID = req.Header.Get(securityTimingHeader)
		seenStart = req.Header.Get(securityTimingStartHeader)
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(securityTimingHeader, forgedID)
	req.Header.Set(securityTimingStartHeader, forgedStart)
	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if seenID != "" || seenStart != "" {
		t.Fatalf("ID 生成失败时伪造计时头必须被剥离, got id=%q start=%q", seenID, seenStart)
	}
}
