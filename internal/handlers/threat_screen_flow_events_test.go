package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
)

// 威胁大屏逐请求正常流量事件代理必须返回应用统一信封（APIResponse）
// 且把 Caddy 发射的英文国名翻成中文——前端按 res.data 消费，裸 JSON
// 会让 flowTask 每轮判 enabled=false 并重置游标为 0，正常蓝色光流永不绘制。
func TestGetThreatScreenFlowEvents_envelopesAndTranslatesCountries(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lb/traffic-events" {
			t.Errorf("admin path=%s, want /lb/traffic-events", r.URL.Path)
		}
		if r.URL.RawQuery != "since=7&limit=1000" {
			t.Errorf("admin query=%q, want since=7&limit=1000", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enabled":true,"events":[{"seq":7,"country":"United States","at":1792351849814},{"seq":8,"country":"中国","province":"广东省","at":1792351849815}],"next_seq":8,"sample_n":1,"gap":true,"gap_skipped":3}`))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/security/overview/threat-screen/events", h.GetThreatScreenFlowEvents)

	req := httptest.NewRequest(http.MethodGet, "/security/overview/threat-screen/events?since=7&limit=1000", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"code":0`, `"data":{`, `"enabled":true`, `"country":"美国"`, `"country":"中国"`, `"province":"广东省"`, `"next_seq":8`, `"sample_n":1`, `"gap":true`, `"gap_skipped":3`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body=%s, want %s", body, want)
		}
	}
	if strings.Contains(body, `"country":"United States"`) {
		t.Fatalf("body=%s, want country translated to Chinese", body)
	}
}

// 光流事件 seq/at 必须原样透传：seq 是增量游标基准、at 是绘制时间轴——
// 代理层改写/清零任一会让 flowTask 游标失配（重复/漏绘）或光流时间错位。
// 既有信封钉只断言国名/next_seq，事件级 seq/at 无守卫：本用例用变异输入
// （与生产夹具不同的 seq/at 值）钉住逐事件透传。
func TestGetThreatScreenFlowEvents_passesThroughSeqAndAt(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enabled":true,"events":[{"seq":41,"country":"中国","at":1792351849901},{"seq":42,"country":"中国","at":1792351849902}],"next_seq":42,"sample_n":1}`))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/security/overview/threat-screen/events", h.GetThreatScreenFlowEvents)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/overview/threat-screen/events?since=40&limit=1000", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"seq":41`, `"seq":42`, `"at":1792351849901`, `"at":1792351849902`, `"next_seq":42`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body=%s, want %s（seq/at 必须逐事件原样透传）", body, want)
		}
	}
}

// Caddy 返回畸形 JSON 时必须显式 502，而不是把残缺内容包成成功信封。
func TestGetThreatScreenFlowEvents_rejectsMalformedAdminBody(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"enabled":true,"events":`))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/security/overview/threat-screen/events", h.GetThreatScreenFlowEvents)

	req := httptest.NewRequest(http.MethodGet, "/security/overview/threat-screen/events", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", rec.Code, rec.Body.String())
	}
}

// admin 不可达 → 503 语义化（大屏轮询据 code 决定是否暂停，不得 500/裸连）。
func TestGetThreatScreenFlowEvents_adminUnreachableReturns503(t *testing.T) {
	closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := closed.URL
	closed.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: url}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/security/overview/threat-screen/events", h.GetThreatScreenFlowEvents)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/overview/threat-screen/events", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s, want 503", rec.Code, rec.Body.String())
	}
}

// 响应体超过 1MB → 413 显式拒绝（截断的 JSON 不得以 200 当完整增量透传）。
func TestGetThreatScreenFlowEvents_oversizeResponseReturns413(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enabled":true,"events":[`))
		_, _ = w.Write([]byte(strings.Repeat(" ", 1<<20+16)))
		_, _ = w.Write([]byte(`]}`))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/security/overview/threat-screen/events", h.GetThreatScreenFlowEvents)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/overview/threat-screen/events", nil))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s, want 413", rec.Code, rec.Body.String())
	}
}
