package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// CERT42-2(第 42 轮审计):UpdateCertificateConfig 收到全掩码凭证回传
// (非 admin GET 后未改动即保存)时,effectiveCredentials 此前直接持掩码串
// 进入 BuildCredentialsJSON 校验 → 400「请选择认证方式」,尽管落库侧
// (isMasked 分支)本就按「未提交」处理。修复:全掩码判定前置到校验之前——
// 校验以库中旧值为准,落库侧分支保留作防御。
func TestCertificateConfig_fullMaskedCredentialsKeepStored(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newCertConfigRouter(t)
	// Given:已有配置(表单字段 auth_mode=tencent_cloud + 真实 secret 对)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/certificates/configs", strings.NewReader(
		`{"name":"cfg","dns_provider":"dnspod","dns_credentials":{"auth_mode":"tencent_cloud","secret_id":"id1","secret_key":"key1"},"enabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create config: %d %s", rec.Code, rec.Body.String())
	}
	var before string
	if err := db.DB.QueryRow("SELECT dns_credentials FROM certificate_configs WHERE id=1").Scan(&before); err != nil {
		t.Fatal(err)
	}

	// When:全掩码回传(含 auth_mode 掩码——非 admin GET 后未改动即保存的形态)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/certificates/configs/1", strings.NewReader(
		`{"dns_credentials":{"auth_mode":"***","secret_id":"***","secret_key":"***"}}`))
	router.ServeHTTP(rec, req)

	// Then:200 且库中凭证原值不变(现行 400「请选择认证方式」)
	if rec.Code != http.StatusOK {
		t.Fatalf("full masked update: %d %s, want 200", rec.Code, rec.Body.String())
	}
	var after string
	if err := db.DB.QueryRow("SELECT dns_credentials FROM certificate_configs WHERE id=1").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before || strings.Contains(after, "***") {
		t.Fatalf("stored credentials changed: before=%s after=%s", before, after)
	}
}
