package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
)

// Caddy admin 的 /lb/traffic-events 返回非 200 时，错误体往往也是合法 JSON
// （例如 503 {"error":"temporarily unavailable"}）。不查状态码就解码会把它包成
// 200 + enabled=false 的成功信封：前端 flowTask 随即清除错误标志并把
// flowSince 归零——用户看到的是「正常光流消失」而不是「事件流接口故障」。
func TestGetThreatScreenFlowEvents_rejectsNon200AdminResponse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		adminCode  int
		adminBody  string
		wantStatus int
	}{
		{"上游 5xx", http.StatusServiceUnavailable, `{"error":"temporarily unavailable"}`, http.StatusServiceUnavailable},
		{"上游非 5xx 非 200", http.StatusNotFound, `{"enabled":false,"events":[]}`, http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.adminCode)
				_, _ = w.Write([]byte(tc.adminBody))
			}))
			defer admin.Close()

			h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
			gin.SetMode(gin.TestMode)
			r := gin.New()
			r.GET("/security/overview/threat-screen/events", h.GetThreatScreenFlowEvents)

			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/overview/threat-screen/events", nil))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s, want %d（上游故障不得伪装成成功空响应）", rec.Code, rec.Body.String(), tc.wantStatus)
			}
			if strings.Contains(rec.Body.String(), `"enabled":false`) {
				t.Fatalf("body=%s, want 显式错误而非 enabled=false 的业务数据", rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), `"code":0`) {
				t.Fatalf("body=%s, want 失败信封而不是 code=0 成功信封", rec.Body.String())
			}
		})
	}
}

// 回归形状：上游 200 时照常包装成功信封（状态码门不得影响正常路径）。
func TestGetThreatScreenFlowEvents_accepts200WithEmptyEvents(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enabled":true,"events":[],"next_seq":0,"sample_n":0}`))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/security/overview/threat-screen/events", h.GetThreatScreenFlowEvents)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/overview/threat-screen/events", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"code":0`) {
		t.Fatalf("status=%d body=%s, want 200 成功信封", rec.Code, rec.Body.String())
	}
}
