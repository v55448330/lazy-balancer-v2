package handlers

// 配置校验端点的 admin 自锁护栏：CLI 校验器不可用时回退路径会真实 /load
// 候选配置——与逃生口 PUT 同后果（admin off/改址后面板控制面全失联，只能
// 重启容器）。两个真实 /load 入口必须同护栏：校验回退在加载前拦截自锁形态。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/services"
)

func TestValidateConfig_fallbackRejectsAdminLockoutBeforeLoad(t *testing.T) {
	handler := newBackupTestHandlers(t)
	var candidateLoads atomic.Int64
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			buf := make([]byte, 4096)
			n, _ := r.Body.Read(buf)
			body := string(buf[:n])
			if strings.Contains(body, `"off"`) || strings.Contains(body, `"disabled"`) {
				candidateLoads.Add(1)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	handler.caddyService = services.NewCaddyService(fakeCaddy.URL)
	handler.cfg = &config.Config{CaddyAdminURL: fakeCaddy.URL}
	// CLI 校验器不可用（生产实证形态：线程耗尽/超时/二进制故障）→ 回退真实 /load。
	handler.caddyService.SetCLIValidatorForTest(func([]byte) error {
		return services.ErrCLIValidatorUnavailable
	})

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/validate", handler.ValidateConfig)

	for _, payload := range []string{
		`{"admin":"off","apps":{}}`,
		`{"admin":{"disabled":true},"apps":{}}`,
		`{"admin":{"listen":"127.0.0.1:2020"},"apps":{}}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("payload=%s status=%d body=%s, want 400（admin 自锁必须在回退加载前拦截）", payload, resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), "admin") {
			t.Fatalf("拒绝文案必须点名 admin 段: %s", resp.Body.String())
		}
	}
	if candidateLoads.Load() != 0 {
		t.Fatalf("自锁候选 /load 发射 %d 次, want 0（护栏必须早于加载）", candidateLoads.Load())
	}
}

// 回归形状：合法 admin 段（省略/回环变体）在 CLI 不可用回退路径仍正常校验。
func TestValidateConfig_fallbackAllowsPanelAdminVariants(t *testing.T) {
	handler := newBackupTestHandlers(t)
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	handler.caddyService = services.NewCaddyService(fakeCaddy.URL)
	handler.cfg = &config.Config{CaddyAdminURL: fakeCaddy.URL}
	handler.caddyService.SetCLIValidatorForTest(func([]byte) error {
		return services.ErrCLIValidatorUnavailable
	})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/validate", handler.ValidateConfig)
	addr := fakeCaddy.Listener.Addr().String()
	_, port, _ := strings.Cut(addr, ":")
	for _, payload := range []string{
		`{"admin":{"listen":"` + addr + `"},"apps":{}}`,
		`{"admin":{"listen":"0.0.0.0:` + port + `"},"apps":{}}`,
		`{"admin":"` + addr + `","apps":{}}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("payload=%s status=%d body=%s, want 200（合法 admin 形态不得误拒）", payload, resp.Code, resp.Body.String())
		}
	}
}
