package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// bcrypt 只取前 72 字节且静默截断，超长密码必须在绑定层以 400 拒绝，
// 不能先落库再让用户以被截断的密码登录失败。
func TestUserPasswordEndpoints_reject_passwords_longer_than_72_characters(t *testing.T) {
	longPassword := strings.Repeat("a", 73)
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		mount  func(*gin.Engine, *Handlers)
	}{
		{name: "create user", method: http.MethodPost, path: "/users", body: `{"username":"long-create","password":"` + longPassword + `","role":"user"}`, mount: func(r *gin.Engine, h *Handlers) { r.POST("/users", h.CreateUser) }},
		{name: "update user", method: http.MethodPut, path: "/users/1", body: `{"password":"` + longPassword + `"}`, mount: func(r *gin.Engine, h *Handlers) { r.PUT("/users/:id", h.UpdateUser) }},
		{name: "reset password", method: http.MethodPost, path: "/users/1/password", body: `{"new_password":"` + longPassword + `"}`, mount: func(r *gin.Engine, h *Handlers) { r.POST("/users/:id/password", h.ResetUserPassword) }},
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

func TestCreateUser_accepts_password_of_exactly_72_characters(t *testing.T) {
	// Given a clean database
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/users", h.CreateUser)

	// When a 72-character password (bcrypt 的完整上限) is submitted
	body := `{"username":"edge72","password":"` + strings.Repeat("a", 72) + `","role":"user"}`
	request := httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then the user is created (201) and the hash verifies against the full password
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var hash string
	if err := db.DB.QueryRow("SELECT password_hash FROM users WHERE username='edge72'").Scan(&hash); err != nil {
		t.Fatalf("read password hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$2a$") {
		t.Fatalf("password hash=%q, want bcrypt", hash)
	}
}
