package handlers

// GitHub 加速代理设置（global_config.github_proxy_url）：基础设置读写白名单
// 与取值校验（仅三内置选项，防 SSRF）测试。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

func githubProxyRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", h.UpdateConfig)
	router.GET("/config", h.GetConfig)
	return router
}

func getGitHubProxyURLSetting(t *testing.T, router *gin.Engine) string {
	t.Helper()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET /config status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			GitHubProxyURL string `json:"github_proxy_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode config response: %v", err)
	}
	return body.Data.GitHubProxyURL
}

func putGitHubProxyURLSetting(t *testing.T, router *gin.Engine, payload string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestGitHubProxyURL_roundtrip_through_PUT_and_GET(t *testing.T) {
	// Given 默认配置
	handler := newBackupTestHandlers(t)
	router := githubProxyRouter(handler)
	if got := getGitHubProxyURLSetting(t, router); got != "https://v4.gh-proxy.org/" {
		t.Fatalf("initial github_proxy_url=%q, want default", got)
	}

	// When 切换到 AxisNow v4
	response := putGitHubProxyURLSetting(t, router,
		`{"source":"basic","github_proxy_url":"https://axisnow.gh-proxy.org/"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("PUT /config status=%d body=%s", response.Code, response.Body.String())
	}

	// Then GET 读回新值
	if got := getGitHubProxyURLSetting(t, router); got != "https://axisnow.gh-proxy.org/" {
		t.Fatalf("github_proxy_url=%q, want https://axisnow.gh-proxy.org/", got)
	}
}

func TestGitHubProxyURL_rejectsArbitraryValue(t *testing.T) {
	// Given 默认配置
	handler := newBackupTestHandlers(t)
	router := githubProxyRouter(handler)

	// When 提交白名单外的任意地址（SSRF 尝试）
	response := putGitHubProxyURLSetting(t, router,
		`{"source":"basic","github_proxy_url":"http://169.254.169.254/latest/meta-data"}`)

	// Then 400 拒绝且不落库
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if got := getGitHubProxyURLSetting(t, router); got != "https://v4.gh-proxy.org/" {
		t.Fatalf("github_proxy_url=%q, want default preserved after rejection", got)
	}
}

func TestPlanConfigChanges_detectsGitHubProxyURL(t *testing.T) {
	// Given 当前值为默认，请求改为 Fastly v4
	value := "https://cdn.gh-proxy.org/"
	req := models.UpdateConfigRequest{GitHubProxyURL: &value}

	// When 计算变更计划
	plan := planConfigChanges(req, configSnapshot{GitHubProxyURL: "https://v4.gh-proxy.org/"})

	// Then 计划标记变更并给出展示词条
	if !plan.Changed {
		t.Fatal("plan.Changed=false, want github_proxy_url change detected")
	}
	found := false
	for _, change := range plan.Changes {
		if change == "GitHub加速代理" {
			found = true
		}
	}
	if !found {
		t.Fatalf("plan.Changes=%v, want GitHub加速代理 label", plan.Changes)
	}
}
