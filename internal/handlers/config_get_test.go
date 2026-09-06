package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// C-03（2026-09-05 证书域审计裁定）：global_config.dns_credentials 为遗留字段
// （签发链唯一凭证来源是 certificate_configs.dns_credentials，前端零消费），
// GET /config 不再返回其值——管理员与非管理员视角均须为空。
func TestGetConfig_omits_legacy_global_dns_credentials(t *testing.T) {
	// Given：遗留字段中存有真实凭证
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET dns_credentials='legacy-id,legacy-token', acme_email='ops@example.com' WHERE id=1`); err != nil {
		t.Fatalf("seed legacy dns credentials: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/config", h.GetConfig)
	adminRouter := gin.New()
	adminRouter.Use(func(c *gin.Context) { c.Set("role", "admin") })
	adminRouter.GET("/config", h.GetConfig)

	for name, target := range map[string]*gin.Engine{"anonymous": router, "admin": adminRouter} {
		t.Run(name, func(t *testing.T) {
			// When
			response := httptest.NewRecorder()
			target.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))

			// Then
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "legacy-id") || strings.Contains(response.Body.String(), "legacy-token") {
				t.Fatalf("response leaks legacy dns credentials: %s", response.Body.String())
			}
			var body struct {
				Data struct {
					DNSCredentials string `json:"dns_credentials"`
					DNSProvider    string `json:"dns_provider"`
					ACMEEmail      string `json:"acme_email"`
				} `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode config response: %v", err)
			}
			if body.Data.DNSCredentials != "" {
				t.Fatalf("dns_credentials=%q, want empty (field no longer served)", body.Data.DNSCredentials)
			}
			if body.Data.ACMEEmail != "ops@example.com" {
				t.Fatalf("acme_email=%q, want unaffected field intact", body.Data.ACMEEmail)
			}
		})
	}
}
