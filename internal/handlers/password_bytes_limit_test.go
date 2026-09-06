package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// S-2（2026-09-05 审计）：validator 的 max=72 按 rune 计数，25-72 个多字节
// 字符（>72 字节）的密码通过绑定层后，bcrypt v0.55 对 >72 字节返回
// ErrPasswordTooLong，各改密端点落 500。契约：字节级预检在 bcrypt 之前拦截，
// 统一 400「密码长度超过 72 字节限制」；恰好 72 字节的多字节密码不受影响。
func TestUserPasswordEndpoints_reject_passwords_over_72_bytes(t *testing.T) {
	// 40 个中文 rune = 120 字节（≤72 rune，通过 binding；>72 字节，须 400）
	multibytePassword := strings.Repeat("密", 40)
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		mount  func(*gin.Engine, *Handlers)
	}{
		{name: "create user", method: http.MethodPost, path: "/users", body: `{"username":"mb-create","password":"` + multibytePassword + `","role":"user"}`, mount: func(r *gin.Engine, h *Handlers) { r.POST("/users", h.CreateUser) }},
		{name: "update user", method: http.MethodPut, path: "/users/1", body: `{"password":"` + multibytePassword + `"}`, mount: func(r *gin.Engine, h *Handlers) { r.PUT("/users/:id", h.UpdateUser) }},
		{name: "reset password", method: http.MethodPost, path: "/users/1/reset-password", body: `{"new_password":"` + multibytePassword + `"}`, mount: func(r *gin.Engine, h *Handlers) { r.POST("/users/:id/reset-password", h.ResetUserPassword) }},
		{name: "update current user", method: http.MethodPatch, path: "/users/me", body: `{"password":"` + multibytePassword + `","current_password":"old-password"}`, mount: func(r *gin.Engine, h *Handlers) {
			r.PATCH("/users/me", func(c *gin.Context) { c.Set("user_id", 1); h.UpdateCurrentUser(c) })
		}},
		{name: "setup admin", method: http.MethodPost, path: "/auth/setup", body: `{"username":"mb-setup","password":"` + multibytePassword + `"}`, mount: func(r *gin.Engine, h *Handlers) {
			r.POST("/auth/setup", h.SetupAdmin)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given（setup admin 依赖空用户表，其余用例需要一个已存在用户）
			h := newBackupTestHandlers(t)
			if test.name != "setup admin" {
				if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,display_name) VALUES (1,'existing','old-hash','admin','Before')"); err != nil {
					t.Fatalf("seed user: %v", err)
				}
			}
			router := gin.New()
			test.mount(router, h)
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then：字节超限在 bcrypt 之前以 400 拒绝（当前为 500「密码加密失败」）
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400（>72 字节密码须校验层拒绝而非 bcrypt 500）", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "72 字节") {
				t.Fatalf("body=%s, want byte-limit message", response.Body.String())
			}
			if test.name != "setup admin" {
				var passwordHash string
				if err := db.DB.QueryRow("SELECT password_hash FROM users WHERE id=1").Scan(&passwordHash); err != nil {
					t.Fatalf("read user: %v", err)
				}
				if passwordHash != "old-hash" {
					t.Fatalf("password hash=%q, want unchanged", passwordHash)
				}
			}
		})
	}
}

// 边界：恰好 72 字节（24 个中文 rune）的多字节密码是 bcrypt 完整上限，须正常
// 创建成功——证明预检按字节而非 rune 计。
func TestCreateUser_accepts_password_of_exactly_72_bytes(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/users", h.CreateUser)

	// When：24 个三字节中文 = 72 字节
	body := `{"username":"mb-edge72","password":"` + strings.Repeat("密", 24) + `","role":"user"}`
	request := httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201（72 字节恰为 bcrypt 上限，不得误拒）", response.Code, response.Body.String())
	}
}
