package handlers

// 自定义路由「直接返回/301 跳转」（2026-10-10 用户裁定）保存侧校验：
// response_mode ∈ {''转发, static 静态响应, redirect 301 跳转}；
// static=常用状态码白名单 + 响应体 ≤64 字符 + 格式 {plain/json/html}，禁 redirect_to/上游；
// redirect=目标必填（/ 开头相对路径或 http(s) 绝对 URL，拒 CRLF），禁 body/上游。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRulePayload_pathRuleResponseModeValidation(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	longBody := strings.Repeat("x", 65)
	cases := []struct {
		name     string
		pathRule string
		wantCode int
		wantErr  string
	}{
		// 合法形态（回归形）
		{"转发模式现状放行", `{"sort_order":0,"match_type":"prefix","path":"/api/","upstreams":null}`, http.StatusCreated, ""},
		{"static 合法放行", `{"sort_order":0,"match_type":"exact","path":"/maint","response_mode":"static","response_status":503,"response_body":"维护中","response_content_type":"text/html"}`, http.StatusCreated, ""},
		{"static 缺省状态码与格式放行", `{"sort_order":0,"match_type":"exact","path":"/ping","response_mode":"static","response_body":"pong"}`, http.StatusCreated, ""},
		{"redirect 绝对 URL 放行", `{"sort_order":0,"match_type":"prefix","path":"/old/","response_mode":"redirect","redirect_to":"https://new.example.com/landing"}`, http.StatusCreated, ""},
		{"redirect 相对路径放行", `{"sort_order":0,"match_type":"prefix","path":"/old/","response_mode":"redirect","redirect_to":"/new/"}`, http.StatusCreated, ""},
		// 畸形形状
		{"未知模式拒绝", `{"sort_order":0,"match_type":"exact","path":"/x","response_mode":"bogus"}`, http.StatusBadRequest, "response_mode"},
		{"static 非常用状态码拒绝", `{"sort_order":0,"match_type":"exact","path":"/x","response_mode":"static","response_status":299}`, http.StatusBadRequest, "状态码"},
		{"static 响应体超 64 字符拒绝", fmt.Sprintf(`{"sort_order":0,"match_type":"exact","path":"/x","response_mode":"static","response_body":%q}`, longBody), http.StatusBadRequest, "64"},
		{"static 非法格式拒绝", `{"sort_order":0,"match_type":"exact","path":"/x","response_mode":"static","response_content_type":"text/xml"}`, http.StatusBadRequest, "格式"},
		{"static 带跳转目标拒绝", `{"sort_order":0,"match_type":"exact","path":"/x","response_mode":"static","redirect_to":"https://a.b"}`, http.StatusBadRequest, "互斥"},
		{"static 带上游拒绝", `{"sort_order":0,"match_type":"exact","path":"/x","response_mode":"static","upstreams":[{"address":"127.0.0.1","port":9000}]}`, http.StatusBadRequest, "互斥"},
		{"redirect 空目标拒绝", `{"sort_order":0,"match_type":"prefix","path":"/old/","response_mode":"redirect"}`, http.StatusBadRequest, "跳转地址"},
		{"redirect CRLF 目标拒绝", `{"sort_order":0,"match_type":"prefix","path":"/old/","response_mode":"redirect","redirect_to":"https://a.b/\r\nX-Evil: 1"}`, http.StatusBadRequest, "跳转地址"},
		{"redirect 带响应体拒绝", `{"sort_order":0,"match_type":"prefix","path":"/old/","response_mode":"redirect","redirect_to":"https://a.b/","response_body":"x"}`, http.StatusBadRequest, "互斥"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"name":"prresp-%d","protocol":"http","domain":"prresp-%d.test","listen_port":%d,"custom_routes_enabled":true,`+
				`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}],"path_rules":[%s]}`, i, i, 19100+i, tc.pathRule)
			request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != tc.wantCode {
				t.Fatalf("status=%d, want %d; body=%s", response.Code, tc.wantCode, response.Body.String())
			}
			if tc.wantErr != "" && !strings.Contains(response.Body.String(), tc.wantErr) {
				t.Fatalf("body must contain %q, got %s", tc.wantErr, response.Body.String())
			}
		})
	}
}
