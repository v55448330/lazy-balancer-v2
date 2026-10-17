package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 密码策略 8-24 可打印 ASCII（2026-09-28 用户裁定），超限密码以 400 拒绝：
// >24 由 validatePasswordPolicy 给出友好中文文案（F-SYSR-3 收口 UpdateUser），
// >72（bcrypt 物理上限，v0.55 起 ErrPasswordTooLong）仍由绑定层兜底——
// 不能先落库再让用户以被截断的密码登录失败。
func TestUserPasswordEndpoints_reject_passwords_over_policy_max(t *testing.T) {
	longPassword := strings.Repeat("a", 33)
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		mount  func(*gin.Engine, *Handlers)
	}{
		{name: "create user", method: http.MethodPost, path: "/users", body: `{"username":"long-create","password":"` + longPassword + `","role":"user"}`, mount: func(r *gin.Engine, h *Handlers) { r.POST("/users", h.CreateUser) }},
		{name: "update user", method: http.MethodPut, path: "/users/1", body: `{"password":"` + longPassword + `"}`, mount: func(r *gin.Engine, h *Handlers) { r.PUT("/users/:id", h.UpdateUser) }},
		{name: "reset password", method: http.MethodPost, path: "/users/1/reset-password", body: `{"new_password":"` + longPassword + `"}`, mount: func(r *gin.Engine, h *Handlers) { r.POST("/users/:id/reset-password", h.ResetUserPassword) }},
		{name: "update current user", method: http.MethodPut, path: "/me", body: `{"password":"` + longPassword + `"}`, mount: func(r *gin.Engine, h *Handlers) {
			r.PUT("/me", func(c *gin.Context) { c.Set("user_id", 1); h.UpdateCurrentUser(c) })
		}},
		{name: "setup admin", method: http.MethodPost, path: "/setup", body: `{"username":"long-setup","password":"` + longPassword + `"}`, mount: func(r *gin.Engine, h *Handlers) {
			r.POST("/setup", h.SetupAdmin)
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

			// Then
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			if test.name != "setup admin" {
				var passwordHash string
				if err := db.DB.QueryRow("SELECT password_hash FROM users WHERE id=1").Scan(&passwordHash); err != nil {
					t.Fatalf("read password hash: %v", err)
				}
				if passwordHash != "old-hash" {
					t.Fatalf("password hash=%q, want unchanged", passwordHash)
				}
			}
		})
	}
}

// F-SYSR-3（第 71 轮审计）：UpdateUser 密码长度边界交 validatePasswordPolicy
// （R63-P2-5 只收敛了 CreateUser）——修复前 25-32 位密码走绑定层 max=24
// 泛化 400「请求格式错误」，拿不到「密码长度不能超过 24 位」友好文案。
func TestUpdateUser_passwordLengthRejectedByPolicyWithFriendlyMessage(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,display_name) VALUES (1,'pw-len','old-hash','admin','A')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := gin.New()
	router.PUT("/users/:id", h.UpdateUser)
	request := httptest.NewRequest(http.MethodPut, "/users/1", strings.NewReader(`{"password":"`+strings.Repeat("a", 25)+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "密码长度不能超过 24 位") {
		t.Fatalf("须由密码策略校验器给出友好文案: %s", response.Body.String())
	}
	var passwordHash string
	if err := db.DB.QueryRow("SELECT password_hash FROM users WHERE id=1").Scan(&passwordHash); err != nil {
		t.Fatalf("read password hash: %v", err)
	}
	if passwordHash != "old-hash" {
		t.Fatalf("password hash=%q, want unchanged", passwordHash)
	}
}
