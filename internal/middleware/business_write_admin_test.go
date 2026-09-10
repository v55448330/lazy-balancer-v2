package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 2026-09-10 审计裁定（权限模型 2026-09-05 的执行缺口）：非管理员在主节点仅
// 自助写（本人密码/显示名、MFA 自助、本人 API Key）。管理面写端点——负载规则
// CRUD、DNS 证书配置 CRUD/测试、证书签发/任务重试/删除、管理面 TLS 证书解析
// ——此前误挂 business 组（任意登录角色可写），全部收紧为 admin。
// 读形态的批量查询 POST（/rules/cert-info、/certificates/parse、
// /certificates/jobs/current）保留 business。
func TestBusinessWriteEndpoints_requireAdmin(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	adminKey := "lb_sk_bizwrite-admin"
	addClusterRouteTestAPIKey(t, 201, "bizwrite-admin", "admin", adminKey)
	userKey := "lb_sk_bizwrite-user"
	addClusterRouteTestAPIKey(t, 202, "bizwrite-user", "user", userKey)

	cases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/v1/rules", `{}`},
		{http.MethodPut, "/api/v1/rules/r1", `{}`},
		{http.MethodDelete, "/api/v1/rules/r1", ""},
		{http.MethodPost, "/api/v1/rules/r1/enable", ""},
		{http.MethodPost, "/api/v1/rules/r1/disable", ""},
		{http.MethodPost, "/api/v1/rules/r1/duplicate", ""},
		{http.MethodPost, "/api/v1/certificate-configs", `{}`},
		{http.MethodPut, "/api/v1/certificate-configs/1", `{}`},
		{http.MethodDelete, "/api/v1/certificate-configs/1", ""},
		{http.MethodPost, "/api/v1/certificate-configs/test", `{}`},
		{http.MethodPost, "/api/v1/certificate-configs/1/test", `{}`},
		{http.MethodPost, "/api/v1/certificates/issue", `{}`},
		{http.MethodPost, "/api/v1/certificates/jobs/1/retry", ""},
		{http.MethodDelete, "/api/v1/certificates/jobs/1", ""},
		{http.MethodPost, "/api/v1/admin-tls/inspect", ""},
	}

	for _, tc := range cases {
		// When：非管理员 Key 调用管理面写端点
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", userKey)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		// Then：必须 403（adminOnly）
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s：非管理员状态=%d body=%s，要求 403", tc.method, tc.path, rec.Code, rec.Body.String())
		}

		// When：管理员 Key 调用同一端点
		req = httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", adminKey)
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		// Then：通过权限门（非 403；具体业务码 200/400/404 由 handler 决定）
		if rec.Code == http.StatusForbidden {
			t.Errorf("%s %s：管理员被拒（403 body=%s），要求通过权限门", tc.method, tc.path, rec.Body.String())
		}
	}
}

// 边界钉子：自助写与只读查询不受收紧影响。
func TestBusinessWriteEndpoints_selfServiceAndReadsStayOpen(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	userKey := "lb_sk_bizread-user"
	addClusterRouteTestAPIKey(t, 203, "bizread-user", "user", userKey)

	// 自助写：本人 API Key 创建（body 走 handler 校验，权限门必须放行）
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys", strings.NewReader(`{"name":"k"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", userKey)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("自助写被误拦：%s", rec.Body.String())
	}

	// 只读：规则列表
	req = httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	req.Header.Set("X-API-Key", userKey)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("只读列表被误拦：%s", rec.Body.String())
	}

	// 读形态批量查询 POST：规则证书信息
	req = httptest.NewRequest(http.MethodPost, "/api/v1/rules/cert-info", strings.NewReader(`{"caddy_ids":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", userKey)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("读形态 POST 被误拦：%s", rec.Body.String())
	}
}
