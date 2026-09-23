package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 受信代理四字段（v2.3.x CDN 真实 IP 支持）：合法值写入成功并经 GET 回读；
// 网段过宽（</8 v4、</96 v6）与非法头名 400；预览端点同校验。
func TestUpdateConfig_trustedProxy_roundtrip(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)
	router.GET("/config", handler.GetConfig)

	body := `{"source":"caddy","trusted_proxy_enabled":true,"trusted_proxy_strict":false,` +
		`"trusted_proxy_ranges":"[\"203.0.113.0/24\",\"198.51.100.7\"]","trusted_proxy_headers":"[\"CF-Connecting-IP\",\"X-Forwarded-For\"]"}`
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	// Then GET 回读四字段（裸 IP 归一为 /32）
	getReq := httptest.NewRequest(http.MethodGet, "/config", nil)
	getResp := httptest.NewRecorder()
	router.ServeHTTP(getResp, getReq)
	if getResp.Code != http.StatusOK {
		t.Fatalf("get status=%d", getResp.Code)
	}
	var payload struct {
		Data struct {
			TrustedProxyEnabled bool   `json:"trusted_proxy_enabled"`
			TrustedProxyRanges  string `json:"trusted_proxy_ranges"`
			TrustedProxyHeaders string `json:"trusted_proxy_headers"`
			TrustedProxyStrict  bool   `json:"trusted_proxy_strict"`
		} `json:"data"`
	}
	if err := json.Unmarshal(getResp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !payload.Data.TrustedProxyEnabled || payload.Data.TrustedProxyStrict {
		t.Fatalf("enabled=%v strict=%v, want true/false", payload.Data.TrustedProxyEnabled, payload.Data.TrustedProxyStrict)
	}
	var ranges, headers []string
	if err := json.Unmarshal([]byte(payload.Data.TrustedProxyRanges), &ranges); err != nil {
		t.Fatalf("ranges not JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(payload.Data.TrustedProxyHeaders), &headers); err != nil {
		t.Fatalf("headers not JSON: %v", err)
	}
	if len(ranges) != 2 || ranges[0] != "203.0.113.0/24" || ranges[1] != "198.51.100.7/32" {
		t.Fatalf("ranges=%v, want [203.0.113.0/24 198.51.100.7/32]", ranges)
	}
	if len(headers) != 2 || headers[0] != "CF-Connecting-IP" || headers[1] != "X-Forwarded-For" {
		t.Fatalf("headers=%v, want [CF-Connecting-IP X-Forwarded-For]", headers)
	}
}

func TestUpdateConfig_trustedProxy_rejectsOverwideRanges(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)

	for _, tc := range []struct {
		name   string
		ranges string
	}{
		{"v4 /7", `["10.0.0.0/7"]`},
		{"v4 /0", `["0.0.0.0/0"]`},
		{"v6 /95", `["2001:db8::/95"]`},
		{"v6 /0", `["::/0"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"source":"caddy","trusted_proxy_enabled":true,"trusted_proxy_ranges":"` +
				strings.ReplaceAll(tc.ranges, `"`, `\"`) + `"}`
			request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "过宽") {
				t.Fatalf("body=%s, want 含「过宽」", response.Body.String())
			}
		})
	}
}

func TestUpdateConfig_trustedProxy_rejectsInvalidHeaders(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)

	for _, headers := range []string{
		`["X Bad-Header"]`,
		`["X_Header"]`,
		`["` + strings.Repeat("a", 65) + `"]`,
	} {
		body := `{"source":"caddy","trusted_proxy_enabled":true,"trusted_proxy_headers":"` +
			strings.ReplaceAll(headers, `"`, `\"`) + `"}`
		request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("headers=%s status=%d body=%s, want 400", headers, response.Code, response.Body.String())
		}
	}
}

// 预览端点与保存端点同校验（未过校验的载荷不得给出变更清单）。
func TestPreviewConfigUpdate_trustedProxy_sameValidation(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/preview", handler.PreviewConfigUpdate)

	body := `{"source":"caddy","trusted_proxy_enabled":true,"trusted_proxy_ranges":"[\"0.0.0.0/0\"]"}`
	request := httptest.NewRequest(http.MethodPost, "/config/preview", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
}
