package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/services"
)

func TestControlThreatScreenCollector_proxiesLease(t *testing.T) {
	services.ResetThreatScreenAttackFlowForTest()
	t.Cleanup(services.ResetThreatScreenAttackFlowForTest)
	var gotMethod, gotPath, gotBody string
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enabled":true}`))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)
	r.DELETE("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)

	body := `{"lease_id":"tab-1","ttl_ms":30000,"sample_n":1}`
	req := httptest.NewRequest(http.MethodPost, "/security/overview/threat-screen/collector", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if gotMethod != http.MethodPost || gotPath != "/lb/traffic-collector" || gotBody != body {
		t.Fatalf("admin got method=%s path=%s body=%s", gotMethod, gotPath, gotBody)
	}
	if got := services.ThreatScreenAttackFlowSampleN(); got != 1 {
		t.Fatalf("attack flow sample_n=%d, want 1（与大屏采集租约同步）", got)
	}

	req = httptest.NewRequest(http.MethodDelete, "/security/overview/threat-screen/collector", strings.NewReader(body))
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if gotMethod != http.MethodDelete {
		t.Fatalf("DELETE method=%s", gotMethod)
	}
	if got := services.ThreatScreenAttackFlowSampleN(); got != 0 {
		t.Fatalf("attack flow sample_n=%d after release, want 0", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/security/overview/threat-screen/collector", strings.NewReader(`{"lease_id":"tab-default","ttl_ms":30000}`))
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("default sample_n status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := services.ThreatScreenAttackFlowSampleN(); got != 0 {
		t.Fatalf("omitted sample_n produced local sample_n=%d, want 0", got)
	}
}

// 代理层把 lease_id 传入本地攻击光流租约表——单租约释放不误杀
// 其他租约（旧码 DELETE 全局置 0）；有效档位=存活租约 min（最密）。
func TestControlThreatScreenCollector_releaseKeepsSurvivingLeases(t *testing.T) {
	services.ResetThreatScreenAttackFlowForTest()
	t.Cleanup(services.ResetThreatScreenAttackFlowForTest)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enabled":true}`))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)
	r.DELETE("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)
	call := func(method, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/security/overview/threat-screen/collector", strings.NewReader(body))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	// Given 两个标签页租约 A(8)/B(1) 并存
	if rec := call(http.MethodPost, `{"lease_id":"tab-a","ttl_ms":30000,"sample_n":8}`); rec.Code != http.StatusOK {
		t.Fatalf("POST tab-a status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, `{"lease_id":"tab-b","ttl_ms":30000,"sample_n":1}`); rec.Code != http.StatusOK {
		t.Fatalf("POST tab-b status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := services.ThreatScreenAttackFlowSampleN(); got != 1 {
		t.Fatalf("sample_n=%d, want 1（存活租约最密档）", got)
	}
	// When B 关闭释放 Then A(8) 仍生效（旧码全局置 0 误杀 A）
	if rec := call(http.MethodDelete, `{"lease_id":"tab-b"}`); rec.Code != http.StatusOK {
		t.Fatalf("DELETE tab-b status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := services.ThreatScreenAttackFlowSampleN(); got != 8 {
		t.Fatalf("after DELETE tab-b sample_n=%d, want 8（A 存活）", got)
	}
	// When A 也释放 Then 归 0
	if rec := call(http.MethodDelete, `{"lease_id":"tab-a"}`); rec.Code != http.StatusOK {
		t.Fatalf("DELETE tab-a status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := services.ThreatScreenAttackFlowSampleN(); got != 0 {
		t.Fatalf("after DELETE tab-a sample_n=%d, want 0", got)
	}
}

// admin 请求失败（503）时本地租约不得已变更——先转发成功再落本地。
func TestControlThreatScreenCollector_adminFailureKeepsLocalLeases(t *testing.T) {
	services.ResetThreatScreenAttackFlowForTest()
	t.Cleanup(services.ResetThreatScreenAttackFlowForTest)
	status := http.StatusOK
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"enabled":true}`))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)
	r.DELETE("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)
	call := func(method, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/security/overview/threat-screen/collector", strings.NewReader(body))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	// Given 租约 A(1) 已生效
	if rec := call(http.MethodPost, `{"lease_id":"tab-a","ttl_ms":30000,"sample_n":1}`); rec.Code != http.StatusOK {
		t.Fatalf("POST tab-a status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := services.ThreatScreenAttackFlowSampleN(); got != 1 {
		t.Fatalf("sample_n=%d, want 1", got)
	}
	// When admin 故障（503）时申请/释放 Then 本地租约保持不变
	status = http.StatusServiceUnavailable
	if rec := call(http.MethodPost, `{"lease_id":"tab-b","ttl_ms":30000,"sample_n":8}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST tab-b status=%d, want 503 透传", rec.Code)
	}
	if got := services.ThreatScreenAttackFlowSampleN(); got != 1 {
		t.Fatalf("after failed POST sample_n=%d, want 1（失败不落本地）", got)
	}
	if rec := call(http.MethodDelete, `{"lease_id":"tab-a"}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("DELETE tab-a status=%d, want 503 透传", rec.Code)
	}
	if got := services.ThreatScreenAttackFlowSampleN(); got != 1 {
		t.Fatalf("after failed DELETE sample_n=%d, want 1（失败不释放本地）", got)
	}
}

// 本地登记失败（lease_id 超长）不得影响 admin 侧已生效租约：响应原样透传
// 200，本地光流档位保持旧值（不回滚、不误设）。
func TestControlThreatScreenCollector_localLeaseFailureKeepsTier(t *testing.T) {
	services.ResetThreatScreenAttackFlowForTest()
	t.Cleanup(services.ResetThreatScreenAttackFlowForTest)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enabled":true}`))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)

	// admin 成功、本地登记失败（65 字节 > 64 上限）：响应仍为 admin 的成功体。
	longLease := strings.Repeat("x", 65)
	body := `{"lease_id":"` + longLease + `","ttl_ms":30000,"sample_n":8}`
	req := httptest.NewRequest(http.MethodPost, "/security/overview/threat-screen/collector", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("status=%d body=%s, want 200 + admin 体透传", rec.Code, rec.Body.String())
	}
	if got := services.ThreatScreenAttackFlowSampleN(); got != 0 {
		t.Fatalf("本地登记失败后 sample_n=%d, want 0（档位保持旧值）", got)
	}
}

// DELETE 空体时以 ?lease_id= 回退取租约 id——否则页面关闭（fetch 不带 body）
// 的释放会被当成空 id，本地光流租约永不回收。
func TestControlThreatScreenCollector_deleteQueryLeaseIDFallback(t *testing.T) {
	services.ResetThreatScreenAttackFlowForTest()
	t.Cleanup(services.ResetThreatScreenAttackFlowForTest)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enabled":true}`))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)
	r.DELETE("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)

	acquire := httptest.NewRequest(http.MethodPost, "/security/overview/threat-screen/collector",
		strings.NewReader(`{"lease_id":"tab-query","ttl_ms":30000,"sample_n":4}`))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, acquire)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := services.ThreatScreenAttackFlowSampleN(); got != 4 {
		t.Fatalf("sample_n=%d, want 4", got)
	}

	// 空体 DELETE + 查询参数
	release := httptest.NewRequest(http.MethodDelete, "/security/overview/threat-screen/collector?lease_id=tab-query", strings.NewReader(""))
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, release)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := services.ThreatScreenAttackFlowSampleN(); got != 0 {
		t.Fatalf("空体 DELETE 后 sample_n=%d, want 0（必须用 ?lease_id= 回退释放）", got)
	}
}

// 上游响应超限/读取失败必须显式失败（对齐同文件 GetThreatScreenFlowEvents 的
// 413/503 口径）：截断 JSON 以 200 透传会让客户端解析失败却看到成功状态码，
// 而本地租约已按成功登记（services.AcquireThreatScreenAttackFlowLease），形成
// 「本地已生效 / 客户端认为失败」分叉。
func TestControlThreatScreenCollector_oversizedAdminResponseFailsLoudly(t *testing.T) {
	services.ResetThreatScreenAttackFlowForTest()
	t.Cleanup(services.ResetThreatScreenAttackFlowForTest)
	big := `{"enabled":true,"pad":"` + strings.Repeat("x", 8192) + `"}`
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(big))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)

	req := httptest.NewRequest(http.MethodPost, "/security/overview/threat-screen/collector",
		strings.NewReader(`{"lease_id":"tab-oversize","ttl_ms":30000,"sample_n":1}`))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("status=%d body=%s, want 非 2xx（截断 JSON 不得以 200 透传）", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", rec.Code, rec.Body.String())
	}
	// 非恒真前置：截断响应绝不登记本地租约（否则客户端认为失败而本地已生效）
	if got := services.ThreatScreenAttackFlowSampleN(); got != 0 {
		t.Fatalf("oversized 响应后本地 sample_n=%d, want 0（不得按成功登记租约）", got)
	}
}

// 边界回归：恰为 4KB 上限的响应仍原样成功透传（判据是 >上限，不是 >=）
func TestControlThreatScreenCollector_responseAtLimitStillSucceeds(t *testing.T) {
	services.ResetThreatScreenAttackFlowForTest()
	t.Cleanup(services.ResetThreatScreenAttackFlowForTest)
	const pre, suf = `{"enabled":true,"pad":"`, `"}`
	exact := pre + strings.Repeat("y", 4096-len(pre)-len(suf)) + suf
	if len(exact) != 4096 {
		t.Fatalf("夹具长度=%d, want 4096", len(exact))
	}
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(exact))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)

	req := httptest.NewRequest(http.MethodPost, "/security/overview/threat-screen/collector",
		strings.NewReader(`{"lease_id":"tab-limit","ttl_ms":30000,"sample_n":1}`))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（上限内不截断）", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 4096 {
		t.Fatalf("透传长度=%d, want 4096（不得截断）", rec.Body.Len())
	}
	if got := services.ThreatScreenAttackFlowSampleN(); got != 1 {
		t.Fatalf("sample_n=%d, want 1（成功路径照常登记租约）", got)
	}
}
