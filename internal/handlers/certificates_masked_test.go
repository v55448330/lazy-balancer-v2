package handlers

// CERT40-2(第 40 轮):DNS 凭证部分掩码回传逐字段合并——改一个字段+其余
// 掩码时,掩码字段必须取库中原值;掩码串整体覆盖会把真实凭证写坏。
// Create 路径含掩码占位直接 400(无库值可取)。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func newCertConfigRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.POST("/certificates/configs", h.CreateCertificateConfig)
	router.PUT("/certificates/configs/:id", h.UpdateCertificateConfig)
	return router
}

func TestCertificateConfig_partialMaskedCredentialsMerge(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newCertConfigRouter(t)

	// Given:已有配置(secret1=真实值)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/certificates/configs", strings.NewReader(
		`{"name":"cfg","dns_provider":"dnspod","dns_credentials":{"mode":"tencent","secret_id":"id1","secret_key":"key1"},"enabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create config: %d %s", rec.Code, rec.Body.String())
	}

	// When:改 api_token,其余字段回传掩码
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/certificates/configs/1", strings.NewReader(
		`{"dns_credentials":{"secret_key":"key2","secret_id":"***"}}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("partial masked update: %d %s", rec.Code, rec.Body.String())
	}

	// Then:提交字段更新,掩码字段保持库值(不得把 *** 落库)
	var stored string
	if err := db.DB.QueryRow("SELECT dns_credentials FROM certificate_configs WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored, "key2") || !strings.Contains(stored, "id1") || strings.Contains(stored, "***") {
		t.Fatalf("merged credentials wrong: %s (want key2 + stored id1 without mask)", stored)
	}
}

func TestCertificateConfig_maskedFieldWithoutStoredValueRejected(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newCertConfigRouter(t)

	// Given:库中凭证只有 api_token
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/certificates/configs", strings.NewReader(
		`{"name":"cfg2","dns_provider":"dnspod","dns_credentials":{"mode":"tencent","secret_id":"sid","secret_key":"skey"},"enabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create config: %d %s", rec.Code, rec.Body.String())
	}

	// When:掩码字段库中不存在(无处可取) → 400
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/certificates/configs/1", strings.NewReader(
		`{"dns_credentials":{"secret_key":"changed","never_stored_field":"***"}}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "掩码") {
		t.Fatalf("mask without stored value must 400, got %d %s", rec.Code, rec.Body.String())
	}

	// And:Create 含掩码占位 → 400(无库值可取)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/certificates/configs", strings.NewReader(
		`{"name":"cfg3","dns_provider":"dnspod","dns_credentials":{"secret_id":"***"},"enabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create with mask must 400, got %d %s", rec.Code, rec.Body.String())
	}
}
