package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// 只读 API Key 的导入导出/备份面收口（2026-09-24 用户裁定：导入导出/备份视为
// 写入操作）：F49-1——GET /auto-backup/:id/download 下发与 config/export 同级的
// lbbak（私钥+凭证明文），此前 GET 特卡仅覆盖 export，只读 Key 可旁路下载。
// 矩阵钉住整个表面：两敏感 GET + 三个写端点（基线钉），全部 403。

func readOnlyKeyRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_type", "api_key")
		c.Set("api_key_read_only", true)
		c.Next()
	}, apiKeyReadOnlyGuard())
	router.GET("/api/v1/config/export", noContent)
	router.GET("/api/v1/auto-backup/:id/download", noContent)
	router.POST("/api/v1/config/import", noContent)
	router.POST("/api/v1/auto-backup/run", noContent)
	router.POST("/api/v1/auto-backup/:id/restore", noContent)
	return router
}

func TestAPIKeyReadOnlyGuard_backupSurfaceDenied(t *testing.T) {
	// Given 只读 API Key 上下文
	router := readOnlyKeyRouter()

	cases := []struct {
		name   string
		method string
		path   string
	}{
		// F49-1：下载完整备份（含私钥+凭证明文）——修复前放行（本用例的 RED 形状）
		{"备份下载", http.MethodGet, "/api/v1/auto-backup/3/download"},
		// 基线钉（既有正确行为，防回归）
		{"配置导出", http.MethodGet, "/api/v1/config/export"},
		{"配置导入", http.MethodPost, "/api/v1/config/import"},
		{"手动备份", http.MethodPost, "/api/v1/auto-backup/run"},
		{"备份还原", http.MethodPost, "/api/v1/auto-backup/3/restore"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// When
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			router.ServeHTTP(recorder, req)

			// Then 一律 403（导入导出/备份=写入操作，只读 Key 禁止）
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("%s %s: status=%d body=%s, want 403", tc.method, tc.path, recorder.Code, recorder.Body.String())
			}
		})
	}
}

// 读写 Key 不受本守卫影响（回归形状：同一表面放行到 handler）。
func TestAPIKeyReadOnlyGuard_backupSurfaceAllowsWritableKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_type", "api_key")
		c.Set("api_key_read_only", false)
		c.Next()
	}, apiKeyReadOnlyGuard())
	router.GET("/api/v1/auto-backup/:id/download", noContent)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auto-backup/3/download", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code == http.StatusForbidden {
		t.Fatalf("读写 Key 不应被只读守卫拦截: %d", recorder.Code)
	}
}
