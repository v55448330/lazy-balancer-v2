package handlers

// GITHUB_TOKEN 配置面（2026-09-25 用户裁定；第 52 轮 P2-3 改三态）：响应面
// 永不回显原文（仅 has_github_token 显隐）；PUT 省略=保持、空串=清除、
// 非空=覆盖。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestGetConfig_masksGitHubToken(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/config", handler.GetConfig)
	if _, err := db.DB.Exec(`UPDATE global_config SET github_token='ghp_secret_12345' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", response.Code)
	}
	body := response.Body.String()
	if strings.Contains(body, "ghp_secret_12345") {
		t.Fatalf("响应面泄漏令牌原文: %s", body[:200])
	}
	if !strings.Contains(body, `"has_github_token":true`) {
		t.Fatalf("缺少 has_github_token=true: %s", body[:200])
	}
}

func TestPutConfig_githubTokenSetClearAndKeep(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)
	put := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	readToken := func() string {
		var token string
		if err := db.DB.QueryRow(`SELECT COALESCE(github_token,'') FROM global_config WHERE id=1`).Scan(&token); err != nil {
			t.Fatal(err)
		}
		return token
	}

	// When：非空令牌写入
	if r := put(`{"source":"basic","github_token":"ghp_new_token"}`); r.Code != http.StatusOK {
		t.Fatalf("写入 status=%d body=%s, want 200", r.Code, r.Body.String())
	}
	if got := readToken(); got != "ghp_new_token" {
		t.Fatalf("token=%q, want ghp_new_token（非空覆盖）", got)
	}

	// When：显式空串——清除（第 52 轮 P2-3，用户裁定三态语义：
	// nil=保持、空串=清除、非空=覆盖；令牌必须有撤销路径，对照 OIDC 整清端点）
	if r := put(`{"source":"basic","github_token":""}`); r.Code != http.StatusOK {
		t.Fatalf("空串 status=%d, want 200", r.Code)
	}
	if got := readToken(); got != "" {
		t.Fatalf("空串后 token=%q, want 已清除为空", got)
	}

	// When：省略字段——保持现值（nil 语义不变）
	if r := put(`{"source":"basic","github_token":"ghp_second"}`); r.Code != http.StatusOK {
		t.Fatalf("重写 status=%d, want 200", r.Code)
	}
	if r := put(`{"source":"basic","log_level":"info"}`); r.Code != http.StatusOK {
		t.Fatalf("省略 status=%d, want 200", r.Code)
	}
	if got := readToken(); got != "ghp_second" {
		t.Fatalf("省略后 token=%q, want 保持 ghp_second", got)
	}
}
