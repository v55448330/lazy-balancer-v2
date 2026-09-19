package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

// SYS42-3(第 42 轮审计):公开路由 /auth/setup 无 JWT,从节点(is_master=0)
// 的 users 表由主端同步下发——同步未收敛的瞬态空表会让 GetSetupStatus 报
// needs_setup=true 并允许 SetupAdmin 建号,建号随即被同步覆盖,且与主端
// 首个管理员语义冲突。从节点:SetupAdmin 403,GetSetupStatus needs_setup=false。
// 主节点(is_master=1)与 global_config 不可读(老库形态)的行为不变(既有
// TestSetupAdmin_first_run_flow 钉住)。
func TestSetupAdmin_slaveNodeGate(t *testing.T) {
	// Given:从节点(is_master=0)+ users 空表
	setupAuthTestDB(t)
	if _, err := db.DB.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN); INSERT INTO global_config VALUES (1,0)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.GET("/auth/setup", h.GetSetupStatus)
	router.POST("/auth/setup", h.SetupAdmin)

	// When / Then 1:GetSetupStatus 不得引导初始化
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/auth/setup", nil))
	var statusBody struct {
		Data struct {
			NeedsSetup bool `json:"needs_setup"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("decode setup status: %v body=%s", err, response.Body.String())
	}
	if statusBody.Data.NeedsSetup {
		t.Fatalf("slave node must not report needs_setup, body=%s", response.Body.String())
	}

	// When / Then 2:SetupAdmin 必须 403 且不落用户
	response = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/auth/setup", strings.NewReader(`{"username":"root","password":"secret123"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("slave setup status=%d body=%s, want 403", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("slave setup must not create user: count=%d err=%v", count, err)
	}
}
