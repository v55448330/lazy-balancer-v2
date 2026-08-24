package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

// R68 F-B1：公开 auth 端点的请求体上限——ContentLength 预检 413、chunked 读中途
// 超限走 binding 400 分支、合法小 body 照常进业务分支。限频中间件不在链上
// （仅验体积门；loginRateLimit 只限次数不限体积正是缺陷背景）。
func TestAuthEndpoints_reject_oversized_body(t *testing.T) {
	setupAuthTestDB(t)
	if _, err := db.DB.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER); INSERT INTO global_config VALUES (1,1,20)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	gin.SetMode(gin.TestMode)
	oversized := `{"username":"root","password":"` + strings.Repeat("a", 128<<10) + `"}`

	t.Run("login 预检 413", func(t *testing.T) {
		router := gin.New()
		router.POST("/auth/login", h.Login)
		request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(oversized))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status=%d, want 413（预检在物化前拒绝）", response.Code)
		}
	})

	t.Run("login chunked 读中途超限走 400 分支", func(t *testing.T) {
		router := gin.New()
		router.POST("/auth/login", h.Login)
		request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(oversized))
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = -1 // 模拟无 Content-Length 的流式 body，预检失效走读路径
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status=%d, want 400（MaxBytesReader 读中途掐断 → binding 错误分支）", response.Code)
		}
	})

	t.Run("ticket-login 预检 413", func(t *testing.T) {
		router := gin.New()
		router.POST("/auth/ticket-login", h.TicketLogin)
		request := httptest.NewRequest(http.MethodPost, "/auth/ticket-login",
			strings.NewReader(`{"ticket":"`+strings.Repeat("a", 128<<10)+`"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status=%d, want 413", response.Code)
		}
	})

	t.Run("合法小 body 仍走业务分支", func(t *testing.T) {
		router := gin.New()
		router.POST("/auth/login", h.Login)
		request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"secret123"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d, want 401（空库无用户 → 业务分支，体积门透传）", response.Code)
		}
	})
}
