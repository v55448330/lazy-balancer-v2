package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestPasswordUpdatesIncrementPasswordVersion(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		serve  func(*Handlers, *gin.Context)
	}{
		{
			name: "current user", method: http.MethodPatch, path: "/users/me", body: `{"password":"second-password"}`,
			serve: func(h *Handlers, c *gin.Context) { c.Set("user_id", 1); h.UpdateCurrentUser(c) },
		},
		{
			name: "administrator update", method: http.MethodPut, path: "/users/1", body: `{"password":"second-password"}`,
			serve: func(h *Handlers, c *gin.Context) { c.Params = gin.Params{{Key: "id", Value: "1"}}; h.UpdateUser(c) },
		},
		{
			name: "administrator reset", method: http.MethodPost, path: "/users/1/reset-password", body: `{"new_password":"second-password"}`,
			serve: func(h *Handlers, c *gin.Context) {
				c.Params = gin.Params{{Key: "id", Value: "1"}}
				h.ResetUserPassword(c)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database := setupAuthTestDB(t)
			if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,display_name,is_enabled,password_version) VALUES (1,'alice','hash','admin','Alice',1,4)`); err != nil {
				t.Fatalf("seed user: %v", err)
			}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")
			context, _ := gin.CreateTestContext(response)
			context.Request = request

			tt.serve(&Handlers{}, context)

			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var version int
			if err := database.QueryRow("SELECT password_version FROM users WHERE id=1").Scan(&version); err != nil {
				t.Fatalf("read password version: %v", err)
			}
			if version != 5 {
				t.Fatalf("password_version=%d, want 5", version)
			}
		})
	}
}
