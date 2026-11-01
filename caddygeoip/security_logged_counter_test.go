package caddygeoip

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// 检测放行拆分（logged）计数器 RED→GREEN 用例：
//   - 发射点=审计写侧（lbAuditWriter.Write）：审计行存在 ⟺ 命中规则带 log/auditlog
//     （coraza `log` 蕴含 auditlog、`nolog` 蕴含 noauditlog，actions/log.go+nolog.go
//     实证）；行未中断（含 DetectionOnly 伪中断）=「安全层记录了干预但放行」。
//   - 计数点=链最外层收点（blocked_counter post-next）：终态裁决放行且打标 →
//     logged 计数；拦截 → 只计 blocked——两列严格互斥；正常请求（无审计行）
//     零打标零计数。
//   - 引擎级形态走真实 coraza WAF + 真实 lbfile 写插件（进程内标记）+ 真实
//     counter 中间件，复刻生产链序（coraza defer ProcessLogging 先于
//     blocked_counter post-next）。

// newTestLoggedCounterPair 独立 registry 上的 blocked/logged 双计数器。
func newTestLoggedCounterPair(t *testing.T) (blocked, logged *prometheus.CounterVec) {
	t.Helper()
	return newSecurityBlockedCounterVec(prometheus.NewRegistry()),
		newSecurityLoggedCounterVec(prometheus.NewRegistry())
}

// runCorazaWAFStep 在 composed 链内运行一次真实 coraza 事务（复刻 coraza-caddy
// handler 语义：处理请求头 → 中断判定 → defer ProcessLogging 先于返回）。
// 返回 (被中断, tx ID, 中断状态码)。
func runCorazaWAFStep(t *testing.T, waf coraza.WAF, req *http.Request) (bool, string, int) {
	t.Helper()
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	for k, vals := range req.Header {
		for _, v := range vals {
			tx.AddRequestHeader(k, v)
		}
	}
	// deny 中断以 *Interruption 形态返回（types.Transaction 接口：
	// ProcessRequestHeaders() *Interruption）——这正是拦截路径；
	// 检测放行（DetectionOnly）无 interruption。
	if it := tx.ProcessRequestHeaders(); it != nil {
		status := it.Status
		tx.ProcessLogging()
		return true, tx.ID(), status
	}
	it := tx.Interruption()
	status := 0
	if it != nil {
		status = it.Status
	}
	// coraza-caddy 在 handler 入口 defer ProcessLogging+Close——Write（打标）
	// 严格先于本 handler 返回，先于 blocked_counter post-next 读取。
	tx.ProcessLogging()
	return it != nil, tx.ID(), status
}

// detectionWAFForTest 构造 DetectionOnly 引擎（deny 规则命中=logged 放行）。
func detectionWAFForTest(t *testing.T, logPath string) coraza.WAF {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine DetectionOnly",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat JSON",
		"SecAuditLogType lbfile",
		"SecAuditLogParts ABIJDEFHKZ",
		"SecRule REQUEST_HEADERS:X-Probe \"@streq hit\" \"id:990010,phase:1,deny,status:403,log,msg:'probe'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF(detection): %v", err)
	}
	return waf
}

// blockingWAFForTest 构造拦截引擎（deny 规则命中=blocked）。
func blockingWAFForTest(t *testing.T, logPath string) coraza.WAF {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat JSON",
		"SecAuditLogType lbfile",
		"SecAuditLogParts ABIJDEFHKZ",
		"SecRule REQUEST_HEADERS:X-Probe \"@streq hit\" \"id:990011,phase:1,deny,status:403,log,msg:'probe'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF(blocking): %v", err)
	}
	return waf
}

// Given: 真实 coraza DetectionOnly 引擎命中（logged 放行）+ 真实写插件打标
// When: 请求穿过 blocked_counter 组合链
// Then: logged 计数 +1、blocked 计数 +0
func TestSecurityLoggedChain_detectionHitCountedAsLogged(t *testing.T) {
	useTestTimingRegistry(t)
	useTestAuditPipeline(t)
	closeTestAuditPipelines(t)
	dir := t.TempDir()
	waf := detectionWAFForTest(t, dir+"/audit.log")
	blockedVec, loggedVec := newTestLoggedCounterPair(t)
	h := &SecurityBlockedCounter{Rule: "lb_logged_e2e", metrics: blockedVec, loggedMetrics: loggedVec}
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) error {
		if req.Header.Get(securityTimingHeader) == "" {
			t.Fatal("counter must inject timing ID before downstream")
		}
		runCorazaWAFStep(t, waf, req) // DetectionOnly 命中：logged 放行，无中断
		return nil
	})
	if err := h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/probe", nil),
		withProbeHeader(next)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if got := testutil.ToFloat64(loggedVec.WithLabelValues("lb_logged_e2e")); got != 1 {
		t.Fatalf("logged counter=%v, want 1（检测放行必须计入检测列）", got)
	}
	if got := testutil.ToFloat64(blockedVec.WithLabelValues("lb_logged_e2e")); got != 0 {
		t.Fatalf("blocked counter=%v, want 0（放行不得计拦截）", got)
	}
}

// Given: 真实 coraza 拦截引擎命中（blocked）
// Then: blocked +1、logged +0（互斥：中断行不打卡，收点只计拦截）
func TestSecurityLoggedChain_denyCountedAsBlockedNotLogged(t *testing.T) {
	useTestTimingRegistry(t)
	useTestAuditPipeline(t)
	closeTestAuditPipelines(t)
	dir := t.TempDir()
	waf := blockingWAFForTest(t, dir+"/audit.log")
	blockedVec, loggedVec := newTestLoggedCounterPair(t)
	h := &SecurityBlockedCounter{Rule: "lb_logged_e2e", metrics: blockedVec, loggedMetrics: loggedVec}
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) error {
		interrupted, txID, status := runCorazaWAFStep(t, waf, req)
		if !interrupted {
			t.Fatal("blocking rule must interrupt")
		}
		// coraza-caddy 错误映射形态：HandlerError 携 tx.ID（16 字符）。
		return caddyhttp.HandlerError{ID: txID, StatusCode: status}
	})
	// 返回值原样透传是既有链语义——拦截错误属预期。
	if err := h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/probe", nil),
		withProbeHeader(next)); err == nil {
		t.Fatal("ServeHTTP must pass through the HandlerError")
	}
	if got := testutil.ToFloat64(blockedVec.WithLabelValues("lb_logged_e2e")); got != 1 {
		t.Fatalf("blocked counter=%v, want 1", got)
	}
	if got := testutil.ToFloat64(loggedVec.WithLabelValues("lb_logged_e2e")); got != 0 {
		t.Fatalf("logged counter=%v, want 0（拦截不得计检测——两列互斥）", got)
	}
}

// Given: 真实 coraza 引擎、规则不命中（正常请求，无审计行）
// Then: 两列均 +0
func TestSecurityLoggedChain_normalRequestCountedAsNeither(t *testing.T) {
	useTestTimingRegistry(t)
	useTestAuditPipeline(t)
	closeTestAuditPipelines(t)
	dir := t.TempDir()
	waf := blockingWAFForTest(t, dir+"/audit.log")
	blockedVec, loggedVec := newTestLoggedCounterPair(t)
	h := &SecurityBlockedCounter{Rule: "lb_logged_e2e", metrics: blockedVec, loggedMetrics: loggedVec}
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) error {
		interrupted, _, _ := runCorazaWAFStep(t, waf, req)
		if interrupted {
			t.Fatal("probe header absent: rule must not match")
		}
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/normal", nil) // 不带 X-Probe
	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if got := testutil.ToFloat64(loggedVec.WithLabelValues("lb_logged_e2e")); got != 0 {
		t.Fatalf("logged counter=%v, want 0（无审计行=正常请求）", got)
	}
	if got := testutil.ToFloat64(blockedVec.WithLabelValues("lb_logged_e2e")); got != 0 {
		t.Fatalf("blocked counter=%v, want 0", got)
	}
}

// Given: 多引擎形态——引擎 A 检测放行（打标 logged）后引擎 B 拦截
// Then: 终态=blocked：blocked +1、logged +0（先录后拦的请求只计拦截列）
func TestSecurityLoggedChain_loggedThenBlockedCountsBlockedOnly(t *testing.T) {
	useTestTimingRegistry(t)
	useTestAuditPipeline(t)
	closeTestAuditPipelines(t)
	dir := t.TempDir()
	detection := detectionWAFForTest(t, dir+"/audit-a.log")
	blocking := blockingWAFForTest(t, dir+"/audit-b.log")
	blockedVec, loggedVec := newTestLoggedCounterPair(t)
	h := &SecurityBlockedCounter{Rule: "lb_logged_e2e", metrics: blockedVec, loggedMetrics: loggedVec}
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) error {
		runCorazaWAFStep(t, detection, req) // 引擎 A：logged 放行
		interrupted, txID, status := runCorazaWAFStep(t, blocking, req)
		if !interrupted {
			t.Fatal("second engine must interrupt")
		}
		return caddyhttp.HandlerError{ID: txID, StatusCode: status}
	})
	// 返回值原样透传是既有链语义——拦截错误属预期。
	if err := h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/probe", nil),
		withProbeHeader(next)); err == nil {
		t.Fatal("ServeHTTP must pass through the HandlerError")
	}
	if got := testutil.ToFloat64(blockedVec.WithLabelValues("lb_logged_e2e")); got != 1 {
		t.Fatalf("blocked counter=%v, want 1", got)
	}
	if got := testutil.ToFloat64(loggedVec.WithLabelValues("lb_logged_e2e")); got != 0 {
		t.Fatalf("logged counter=%v, want 0（终态拦截时打标作废——互斥裁决在收点）", got)
	}
}

// 单元形态：同一请求两条 logged 审计行（多策略引擎）幂等打标 → 恰计 1 次。
func TestSecurityBlockedCounter_loggedMarkCountedOncePerRequest(t *testing.T) {
	useTestTimingRegistry(t)
	blockedVec, loggedVec := newTestLoggedCounterPair(t)
	h := &SecurityBlockedCounter{Rule: "lb_logged_unit", metrics: blockedVec, loggedMetrics: loggedVec}
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) error {
		// timing_pre 收点建条（生产链序），随后两条策略引擎审计行打标。
		pre := &SecurityTimingPre{}
		if err := pre.ServeHTTP(httptest.NewRecorder(), req,
			caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })); err != nil {
			t.Fatalf("timing pre: %v", err)
		}
		tid := req.Header.Get(securityTimingHeader)
		if tid == "" {
			t.Fatal("timing ID must be injected")
		}
		auditTimingRecord(tid, timingSegmentLogged, 0)
		auditTimingRecord(tid, timingSegmentLogged, 0)
		return nil
	})
	if err := h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if got := testutil.ToFloat64(loggedVec.WithLabelValues("lb_logged_unit")); got != 1 {
		t.Fatalf("logged counter=%v, want 1（多行同键幂等，每请求至多一次）", got)
	}
	if got := testutil.ToFloat64(blockedVec.WithLabelValues("lb_logged_unit")); got != 0 {
		t.Fatalf("blocked counter=%v, want 0", got)
	}
}

// 单元形态：打标在册但终态拦截 → 只计 blocked（收点互斥裁决）。
func TestSecurityBlockedCounter_blockedWinsOverLoggedMark(t *testing.T) {
	useTestTimingRegistry(t)
	blockedVec, loggedVec := newTestLoggedCounterPair(t)
	h := &SecurityBlockedCounter{Rule: "lb_logged_unit", metrics: blockedVec, loggedMetrics: loggedVec}
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) error {
		tid := req.Header.Get(securityTimingHeader)
		auditTimingRecord(tid, timingSegmentLogged, 0)
		return caddyhttp.HandlerError{ID: "abcdefghijklmnop", StatusCode: 403}
	})
	// 返回值原样透传是既有链语义——错误属预期（终态=拦截）。
	if err := h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), next); err == nil {
		t.Fatal("ServeHTTP must pass through the HandlerError")
	}
	if got := testutil.ToFloat64(blockedVec.WithLabelValues("lb_logged_unit")); got != 1 {
		t.Fatalf("blocked counter=%v, want 1", got)
	}
	if got := testutil.ToFloat64(loggedVec.WithLabelValues("lb_logged_unit")); got != 0 {
		t.Fatalf("logged counter=%v, want 0（拦截终态吞掉打标）", got)
	}
}

// 降级形态：计时 ID 生成失败（无计时头）→ 无键无打标，logged 不计、不 panic。
func TestSecurityBlockedCounter_timingIDFailureSkipsLogged(t *testing.T) {
	useTestTimingRegistry(t)
	oldRand := securityTimingRandRead
	securityTimingRandRead = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	t.Cleanup(func() { securityTimingRandRead = oldRand })
	blockedVec, loggedVec := newTestLoggedCounterPair(t)
	h := &SecurityBlockedCounter{Rule: "lb_logged_unit", metrics: blockedVec, loggedMetrics: loggedVec}
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) error {
		if req.Header.Get(securityTimingHeader) != "" {
			t.Fatal("ID generation failed: no timing header expected")
		}
		return nil
	})
	if err := h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if got := testutil.ToFloat64(loggedVec.WithLabelValues("lb_logged_unit")); got != 0 {
		t.Fatalf("logged counter=%v, want 0（无计时 ID 降级形态不计）", got)
	}
}

// —— 测试小夹具 ——

func withProbeHeader(next caddyhttp.HandlerFunc) caddyhttp.HandlerFunc {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		r.Header.Set("X-Probe", "hit")
		return next.ServeHTTP(w, r)
	})
}
