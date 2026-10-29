package handlers

// users.go 的 handler 级用例与断言辅助（自 config_backup_test.go 迁入——
// 该文件只保留备份/导入主题，避免 3500 行混合主题文件里的用例错位）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// adminAuthForTest 注入管理员认证上下文：UpdateUser 的管理语义门按
// 「role != admin」fail-closed，handler 级用例必须显式模拟已过认证中间件的
// 管理员请求，否则会命中非管理员自助限制。
func adminAuthForTest(router *gin.Engine) {
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "99")
		c.Set("role", "admin")
	})
}

func TestUpdateUser_rejects_invalid_id_and_body(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "invalid id", path: "/users/not-a-number", body: `{}`},
		{name: "invalid body", path: "/users/1", body: `{"role":`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (1, 'original', 'original-hash', 'admin', 'Original Name'), (99, 'backup-admin', 'x', 'admin', '')"); err != nil {
				t.Fatalf("seed user: %v", err)
			}
			router := gin.New()
			adminAuthForTest(router)
			router.PUT("/users/:id", h.UpdateUser)
			request := httptest.NewRequest(http.MethodPut, tt.path, strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")

			// When
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			assertUserState(t, "original", "admin", "Original Name", "original-hash")
		})
	}
}

func TestUpdateUser_preserves_omitted_display_name(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (1, 'setup-admin', 'x', 'admin', ''), (2, 'original', 'original-hash', 'admin', 'Original Name'), (99, 'backup-admin', 'x', 'admin', '')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := gin.New()
	adminAuthForTest(router)
	router.PUT("/users/:id", h.UpdateUser)
	request := httptest.NewRequest(http.MethodPut, "/users/2", strings.NewReader(`{"role":"user"}`))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	assertUserStateByID(t, 2, "original", "user", "Original Name", "original-hash")
}

func TestUpdateUser_preserves_all_fields_when_password_rejected(t *testing.T) {
	// Given（bcrypt 只取前 72 字节；73 字符密码由 validatePasswordPolicy 的
	// 长度上限拒绝——绑定层只拦空值；拒绝路径不得产生任何部分写入）
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (1, 'original', 'original-hash', 'admin', 'Original Name'), (99, 'backup-admin', 'x', 'admin', '')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := gin.New()
	adminAuthForTest(router)
	router.PUT("/users/:id", h.UpdateUser)
	body := `{"username":"changed","role":"user","display_name":"Changed Name","password":"` + strings.Repeat("p", 73) + `"}`
	request := httptest.NewRequest(http.MethodPut, "/users/1", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then（400 来自 validatePasswordPolicy 的长度上限；绑定层只拦空值，
	// 故此断言验证的是拒绝发生在写库之前）
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	assertUserState(t, "original", "admin", "Original Name", "original-hash")
}

func TestUpdateUser_preserves_all_fields_when_update_fails(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (1, 'original', 'original-hash', 'admin', 'Original Name'), (99, 'backup-admin', 'x', 'admin', '')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (2, 'original2', 'original-hash', 'admin', 'Original Name') ON CONFLICT(id) DO NOTHING"); err != nil {
		t.Fatalf("seed target user: %v", err)
	}
	if _, err := db.DB.Exec("CREATE TRIGGER fail_user_role_update BEFORE UPDATE ON users WHEN NEW.role='user' BEGIN SELECT RAISE(ABORT,'role update failed'); END"); err != nil {
		t.Fatalf("create update failure trigger: %v", err)
	}
	router := gin.New()
	adminAuthForTest(router)
	router.PUT("/users/:id", h.UpdateUser)
	request := httptest.NewRequest(http.MethodPut, "/users/2", strings.NewReader(`{"username":"changed","role":"user","display_name":"Changed Name"}`))
	request.Header.Set("Content-Type", "application/json")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	assertUserStateByID(t, 2, "original2", "admin", "Original Name", "original-hash")
}

func assertUserState(t *testing.T, username, role, displayName, passwordHash string) {
	t.Helper()
	assertUserStateByID(t, 1, username, role, displayName, passwordHash)
}

func assertUserStateByID(t *testing.T, id int, username, role, displayName, passwordHash string) {
	t.Helper()
	var gotUsername, gotRole, gotDisplayName, gotPasswordHash string
	if err := db.DB.QueryRow("SELECT username, role, COALESCE(display_name,''), password_hash FROM users WHERE id=?", id).Scan(&gotUsername, &gotRole, &gotDisplayName, &gotPasswordHash); err != nil {
		t.Fatalf("query user state: %v", err)
	}
	if gotUsername != username || gotRole != role || gotDisplayName != displayName || gotPasswordHash != passwordHash {
		t.Fatalf("user state=(%q,%q,%q,%q), want (%q,%q,%q,%q)", gotUsername, gotRole, gotDisplayName, gotPasswordHash, username, role, displayName, passwordHash)
	}
}
