package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// 公开 GET /branding 与同批 caddy 读端点的 nil-cfg 零值契约对齐：未装配 cfg
// 的嵌入/降级形态必须返回默认品牌响应（跳过需数据目录的幂等副作用），
// 不得裸解引用 panic 被 gin Recovery 吞成空体 500 —— 访客看到登录页白屏
// 且无法定位。
func TestGetBranding_nilConfigReturnsDefaults(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.GET("/branding", (&Handlers{}).GetBranding)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/branding", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("nil-cfg GET /branding status=%d body=%q, want 200（默认品牌零值响应）", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Code int              `json:"code"`
		Data brandingResponse `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, recorder.Body.String())
	}
	if payload.Data.AppName != defaultBranding.AppName {
		t.Fatalf("app_name=%q, want %q", payload.Data.AppName, defaultBranding.AppName)
	}
	if payload.Data.FooterText != defaultFooterText {
		t.Fatalf("footer_text=%q, want %q（默认回退）", payload.Data.FooterText, defaultFooterText)
	}
	if payload.Data.LandingText != services.DefaultLandingText {
		t.Fatalf("landing_text=%q, want %q（默认回退）", payload.Data.LandingText, services.DefaultLandingText)
	}
	if !payload.Data.FooterUsesDefault || !payload.Data.LandingUsesDefault {
		t.Fatalf("uses_default 标记=%v/%v, want true/true", payload.Data.FooterUsesDefault, payload.Data.LandingUsesDefault)
	}
}
