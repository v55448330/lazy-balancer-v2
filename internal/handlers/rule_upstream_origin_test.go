package handlers

// 逐上游回源域名 + 健康检查域名（2026-10-10）保存侧字段校验：
// origin_domain 空或 host[:port]（Host 头可带端口；SNI 渲染期剥端口），
// 仅 HTTP 规则静态上游可用（dynamic_dns 池 dial=解析后 IP，映射永不命中；
// TCP 无 Host/SNI 语义）；health_check_host 空或纯 host（probe Host 头不带
// 端口，与 Caddy headers.Host 特判语义对齐，healthchecks.go:453-458）。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRulePayload_originDomainAndHealthCheckHostValidation(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	cases := []struct {
		name       string
		protocol   string
		extra      string
		upstream   string
		wantStatus int
		wantErr    string
	}{
		// 合法形状（回归形：纯域名/健康检查域名；带端口 2026-10-10 用户裁定拒绝——端口已有独立配置列）
		{"回源域名纯域名放行", "http", "", `{"host":"127.0.0.1","port":9000,"enabled":true,"origin_domain":"origin.example.com"}`, http.StatusCreated, ""},
		{"回源域名带端口拒绝", "http", "", `{"host":"127.0.0.1","port":9000,"enabled":true,"origin_domain":"origin.example.com:8443"}`, http.StatusBadRequest, "回源域名"},
		{"健康检查域名放行", "http", `"health_check_host":"probe.example.com","enable_active_health_check":true`, `{"host":"127.0.0.1","port":9000,"enabled":true}`, http.StatusCreated, ""},
		{"两字段皆空现状放行", "http", "", `{"host":"127.0.0.1","port":9000,"enabled":true}`, http.StatusCreated, ""},
		// 畸形形状
		{"回源域名 CRLF 拒绝", "http", "", `{"host":"127.0.0.1","port":9000,"enabled":true,"origin_domain":"evil.com\r\nX-Evil: 1"}`, http.StatusBadRequest, "回源域名"},
		{"回源域名端口越界拒绝", "http", "", `{"host":"127.0.0.1","port":9000,"enabled":true,"origin_domain":"origin.example.com:99999"}`, http.StatusBadRequest, "回源域名"},
		{"回源域名空端口拒绝", "http", "", `{"host":"127.0.0.1","port":9000,"enabled":true,"origin_domain":"origin.example.com:"}`, http.StatusBadRequest, "回源域名"},
		{"健康检查域名带端口拒绝", "http", `"health_check_host":"probe.example.com:8443"`, `{"host":"127.0.0.1","port":9000,"enabled":true}`, http.StatusBadRequest, "健康检查域名"},
		{"健康检查域名 CRLF 拒绝", "http", `"health_check_host":"evil.com\r\nX-Evil: 1"`, `{"host":"127.0.0.1","port":9000,"enabled":true}`, http.StatusBadRequest, "健康检查域名"},
		// 模式门
		{"TCP 规则回源域名拒绝", "tcp", "", `{"host":"127.0.0.1","port":9000,"enabled":true,"protocol":"tcp","origin_domain":"origin.example.com"}`, http.StatusBadRequest, "回源域名"},
		{"TCP 规则健康检查域名拒绝", "tcp", `"health_check_host":"probe.example.com"`, `{"host":"127.0.0.1","port":9000,"enabled":true,"protocol":"tcp"}`, http.StatusBadRequest, "健康检查域名"},
		{"动态上游回源域名拒绝", "http", `"dynamic_dns":true`, `{"host":"up.example.com","port":9000,"enabled":true,"origin_domain":"origin.example.com"}`, http.StatusBadRequest, "动态上游"},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			extra := tc.extra
			if extra != "" {
				extra += ","
			}
			body := fmt.Sprintf(`{"name":"origin-v-%d","protocol":%q,"domain":"origin-%d.test","listen_port":%d,%s`+
				`"upstreams":[%s]}`, i, tc.protocol, i, 18700+i, extra, tc.upstream)
			request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != tc.wantStatus {
				t.Fatalf("status=%d, want %d; body=%s", response.Code, tc.wantStatus, response.Body.String())
			}
			if tc.wantErr != "" && !strings.Contains(response.Body.String(), tc.wantErr) {
				t.Fatalf("body must contain %q, got %s", tc.wantErr, response.Body.String())
			}
		})
	}
}
