package handlers

// LB40-5/LB40-6(第 40 轮):host_header 字符校验(CRLF/控制字符注入
// reverse_proxy 头部)、dns_server 形状校验(空 host/非数字端口)、
// extractLabel 精确键匹配(x_host 不得误归集 host)。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRulePayload_hostHeaderAndDnsServerValidation(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	base := func(extra string) string {
		return `{"name":"payload-v","protocol":"http","domain":"payload.test","listen_port":18582,` +
			`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}],` + extra + `}`
	}
	create := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	// 形状一:host_header 含 CRLF → 400
	rec := create(base(`"host_header":"evil.com\r\nX-Injected: 1"`))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "后端域名含非法字符") {
		t.Fatalf("CRLF host_header must 400, got %d %s", rec.Code, rec.Body.String())
	}

	// 形状二:垃圾 dns_server(非数字端口) → 400
	rec = create(base(`"dynamic_dns":true,"dns_server":"8.8.8.8:notaport"`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("garbage dns_server must 400, got %d %s", rec.Code, rec.Body.String())
	}

	// 形状三(回归):合法形状放行
	rec = create(base(`"host_header":"api.backend.local"`))
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("legit host_header must pass, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestExtractLabel_exactKeyMatch(t *testing.T) {
	// x_host 不得被 host 子串匹配误归集
	if got := extractLabel(`caddy_http_requests_total{x_host="evil"}`, "host"); got != "" {
		t.Fatalf("host label must not match x_host, got %q", got)
	}
	if got := extractLabel(`caddy_http_requests_total{x_host="evil",host="real"}`, "host"); got != "real" {
		t.Fatalf("host label must match exact key, got %q", got)
	}
	if got := extractLabel(`caddy_http_requests_total{host="first",x_host="evil"}`, "host"); got != "first" {
		t.Fatalf("leading host label must match, got %q", got)
	}
	if got := extractLabel(`caddy_http_requests_total{x_host="evil"}`, "x_host"); got != "evil" {
		t.Fatalf("x_host label must match its own key, got %q", got)
	}
}
