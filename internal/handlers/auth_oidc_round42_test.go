package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// SYS42-4(第 42 轮审计):OIDCSettingsUpdate 的 issuer 校验此前是
// strings.HasPrefix(issuer, "http")——「httpxy://evil」可写入并被 discovery/
// 回调链路消费。改 url.Parse + Scheme∈{http,https} 白名单;http/https 正常、
// 空 issuer(清除语义)行为不变。
func TestOIDCSettingsUpdate_rejectsNonHTTPScheme(t *testing.T) {
	// Given
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putRaw := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// When / Then 1:httpxy scheme 必须 400(现行经 HasPrefix 放行)
	if rec := putRaw(`{"issuer":"httpxy://evil.example.com"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("httpxy issuer status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	// When / Then 2:无 scheme 的裸主机名同样 400
	if rec := putRaw(`{"issuer":"evil.example.com"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("schemaless issuer status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	// 回归:http issuer(mock IdP)照常保存(enabled 缺席保持 false——
	// 启用前置门「启用时 issuer 必填」是既有不变量,不属于本项范围)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"super-secret-123"}`)
	// 回归:空 issuer(清除语义)不 400
	if rec := putRaw(`{"issuer":""}`); rec.Code != http.StatusOK {
		t.Fatalf("empty issuer status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
}
