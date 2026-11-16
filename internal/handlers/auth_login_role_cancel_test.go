package handlers

// 登录响应的 node_mode 角色读必须脱离请求取消（与 GetSystemInfo 同口径）：
// 客户端在密码校验后断开，角色读不得被记成「查询失败」而下发 unknown——
// 前端按只读视图呈现刚成功登录的主节点，排障方向被误导。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/config"
)

func TestLogin_nodeModeIndependentOfClientCancel(t *testing.T) {
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('root',?,'admin',1)`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)

	// Given：请求 ctx 在登录处理前已取消（客户端断开）。
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`))
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithCancel(req.Context())
	cancel()

	// When
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(ctx))

	// Then：登录成功且 node_mode 为真实角色（不得因请求取消落 unknown）。
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var resp struct {
		NodeMode string `json:"node_mode"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.NodeMode != "master" {
		t.Fatalf("node_mode=%q, want master（角色读必须脱离请求取消，与 /system/info 同口径）", resp.NodeMode)
	}
}
