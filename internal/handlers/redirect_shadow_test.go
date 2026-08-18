package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

// TLS+HTTP 跳转规则会在 80 端口服务器头部生成 terminal 跳转路由（redirectRoutes），
// 同域名直接监听 80 的规则会被遮蔽为死规则——保存/启用两条路径都必须拒绝。
func TestRuleDomainConflict_redirectShadow(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)

	certPEM, keyPEM, err := generateTestCert("shadow.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	seedShadowRule := func(caddyID, domain string, listenPort int, tlsRedirect bool, enabled int) {
		t.Helper()
		enableTLS, redirect := 0, 0
		tlsCert, tlsKey := "", ""
		if tlsRedirect {
			enableTLS, redirect = 1, 1
			tlsCert, tlsKey = certPEM, keyPEM
		}
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress,enable_tls,tls_source,tls_cert,tls_key,tls_http_redirect)
			VALUES (?,?,?,'http',?,?,'weighted_round_robin',?,1,?,'manual',?,?,?)`,
			caddyID, caddyID, "", domain, listenPort, enabled, enableTLS, tlsCert, tlsKey, redirect); err != nil {
			t.Fatalf("seed shadow rule %s: %v", caddyID, err)
		}
		if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'http')`, caddyID); err != nil {
			t.Fatalf("seed upstream %s: %v", caddyID, err)
		}
	}
	create := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	port80Body := func(name, domain string) string {
		return fmt.Sprintf(`{"name":%q,"protocol":"http","domain":%q,"listen_port":80,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, name, domain)
	}
	tlsRedirectBody := func(name, domain string) string {
		return fmt.Sprintf(`{"name":%q,"protocol":"http","domain":%q,"listen_port":443,"enable_tls":true,"tls_source":"manual","tls_cert":%q,"tls_key":%q,"tls_http_redirect":true,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, name, domain, certPEM, keyPEM)
	}

	t.Run("create port-80 rule shadowed by existing TLS redirect rule rejected", func(t *testing.T) {
		seedShadowRule("lb_shd_tls1", "shadow-a.test", 443, true, 1)
		response := create(port80Body("shadow-victim-a", "shadow-a.test"))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "HTTPS 跳转占用") {
			t.Fatalf("status=%d body=%s, want 400 redirect shadow", response.Code, response.Body.String())
		}
	})

	t.Run("create TLS redirect rule shadowing existing port-80 rule rejected", func(t *testing.T) {
		seedShadowRule("lb_shd_80b", "shadow-b.test", 80, false, 1)
		response := create(tlsRedirectBody("shadow-redirect-b", "shadow-b.test"))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "直接监听 80 端口") {
			t.Fatalf("status=%d body=%s, want 400 shadow on enable redirect", response.Code, response.Body.String())
		}
	})

	t.Run("different domains allowed", func(t *testing.T) {
		seedShadowRule("lb_shd_tls2", "shadow-c1.test", 443, true, 1)
		response := create(port80Body("shadow-victim-c", "shadow-c2.test"))
		if response.Code != http.StatusCreated && response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 2xx", response.Code, response.Body.String())
		}
	})

	t.Run("multi-domain overlap rejected", func(t *testing.T) {
		seedShadowRule("lb_shd_tls3", "shadow-d1.test,shadow-d2.test", 443, true, 1)
		response := create(port80Body("shadow-victim-d", "shadow-d2.test"))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "HTTPS 跳转占用") {
			t.Fatalf("status=%d body=%s, want 400 multi-domain overlap", response.Code, response.Body.String())
		}
	})

	t.Run("disabled TLS redirect rule does not block", func(t *testing.T) {
		seedShadowRule("lb_shd_tls4", "shadow-e.test", 443, true, 0)
		response := create(port80Body("shadow-victim-e", "shadow-e.test"))
		if response.Code != http.StatusCreated && response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 2xx (disabled redirect rule occupies nothing)", response.Code, response.Body.String())
		}
	})

	t.Run("enable port-80 rule shadowed by TLS redirect rule rejected", func(t *testing.T) {
		seedShadowRule("lb_shd_tls5", "shadow-f.test", 443, true, 1)
		seedShadowRule("lb_shd_80f", "shadow-f.test", 80, false, 0)
		request := httptest.NewRequest(http.MethodPost, "/rules/lb_shd_80f/enable", nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "HTTPS 跳转占用") {
			t.Fatalf("status=%d body=%s, want 400 redirect shadow on enable", response.Code, response.Body.String())
		}
	})
}
