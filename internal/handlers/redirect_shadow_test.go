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

// Round 29 G-5: 存量冲突组合（导入态 80 规则 + 跳转规则并存）下，仅改名称的更新
// 不应被遮蔽检查 400 阻塞；相关字段（域名）变化时遮蔽检查仍须生效。
func TestUpdateRule_name_only_change_passes_with_legacy_shadow_combo(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	certPEM, keyPEM, err := generateTestCert("shadow-g.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	seed := func(caddyID, domain string, listenPort int, tlsRedirect bool) {
		t.Helper()
		enableTLS, redirect := 0, 0
		tlsCert, tlsKey := "", ""
		if tlsRedirect {
			enableTLS, redirect = 1, 1
			tlsCert, tlsKey = certPEM, keyPEM
		}
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress,enable_tls,tls_source,tls_cert,tls_key,tls_http_redirect)
			VALUES (?,?,?,'http',?,?,'weighted_round_robin',1,1,?,'manual',?,?,?)`,
			caddyID, caddyID, "", domain, listenPort, enableTLS, tlsCert, tlsKey, redirect); err != nil {
			t.Fatalf("seed rule %s: %v", caddyID, err)
		}
		if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'http')`, caddyID); err != nil {
			t.Fatalf("seed upstream %s: %v", caddyID, err)
		}
	}
	update := func(caddyID, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	t.Run("仅改名称的 80 规则更新不再被存量跳转规则遮蔽检查 400", func(t *testing.T) {
		seed("lb_shd_80g", "shadow-g.test", 80, false)
		seed("lb_shd_tlsg", "shadow-g.test", 443, true)
		response := update("lb_shd_80g", `{"name":"改名后的 80 规则"}`)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200 for name-only update", response.Code, response.Body.String())
		}
	})

	t.Run("跳转规则域名变化时遮蔽检查仍生效", func(t *testing.T) {
		seed("lb_shd_80h", "shadow-h.test", 80, false)
		seed("lb_shd_tlsh", "shadow-i.test", 443, true)
		response := update("lb_shd_tlsh", `{"domain":"shadow-h.test"}`)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "直接监听 80 端口") {
			t.Fatalf("status=%d body=%s, want 400 shadow on domain change", response.Code, response.Body.String())
		}
	})
}

// R38 C-2: 域名冲突检查须与遮蔽检查同样加变更门控——导入遗留的「一启用一禁用
// 同域名」组合中，禁用方仅改名等无关更新不应被 400 卡死（ruleDomainConflict 只
// 统计 enabled=1 的规则）；域名/启用态真正变化时检查仍须生效。
func TestUpdateRule_domain_conflict_check_gated_on_change(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	seed := func(caddyID, domain string, enabled int) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress)
			VALUES (?,?,?,'http',?,8080,'weighted_round_robin',?,1)`, caddyID, caddyID, "", domain, enabled); err != nil {
			t.Fatalf("seed rule %s: %v", caddyID, err)
		}
		if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'http')`, caddyID); err != nil {
			t.Fatalf("seed upstream %s: %v", caddyID, err)
		}
	}
	update := func(caddyID, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	t.Run("存量冲突组合下仅改名称的禁用方更新不再被 400", func(t *testing.T) {
		seed("lb_dc_on", "conflict.test", 1)
		seed("lb_dc_off", "conflict.test", 0)
		response := update("lb_dc_off", `{"name":"改名后的禁用方"}`)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200 for name-only update", response.Code, response.Body.String())
		}
	})

	t.Run("禁用方改域名到启用规则占用值时仍 400", func(t *testing.T) {
		seed("lb_dc_on2", "conflict2.test", 1)
		seed("lb_dc_off2", "conflict2.test", 0)
		seed("lb_dc_taken", "taken.test", 1)
		response := update("lb_dc_off2", `{"domain":"taken.test"}`)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "域名已被其他 HTTP/HTTPS 规则使用") {
			t.Fatalf("status=%d body=%s, want 400 domain conflict on domain change", response.Code, response.Body.String())
		}
	})

	t.Run("禁用方 PUT 启用时被存量启用方阻塞", func(t *testing.T) {
		seed("lb_dc_on3", "conflict3.test", 1)
		seed("lb_dc_off3", "conflict3.test", 0)
		response := update("lb_dc_off3", `{"enabled":true}`)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "域名已被其他 HTTP/HTTPS 规则使用") {
			t.Fatalf("status=%d body=%s, want 400 domain conflict on enable change", response.Code, response.Body.String())
		}
	})
}

// R39 C-2: shadowRelevantChanged 门控须含 enabled 变化——仅提交 {"enabled":true}
// 启用一条「443 跳转规则」时，若同域名存在启用中的 80 直听规则，遮蔽检查必须
// 触发（与 EnableRule 端点口径一致），否则跳转路由会把 80 规则遮蔽成死规则。
func TestUpdateRule_enable_trigger_redirect_shadow_check(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	certPEM, keyPEM, err := generateTestCert("shadow-u.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	seed := func(caddyID string, listenPort int, tlsRedirect bool, enabled int) {
		t.Helper()
		enableTLS, redirect := 0, 0
		tlsCert, tlsKey := "", ""
		if tlsRedirect {
			enableTLS, redirect = 1, 1
			tlsCert, tlsKey = certPEM, keyPEM
		}
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress,enable_tls,tls_source,tls_cert,tls_key,tls_http_redirect)
			VALUES (?,?,?,'http',?,?,'weighted_round_robin',?,1,?,'manual',?,?,?)`,
			caddyID, caddyID, "", "shadow-u.test", listenPort, enabled, enableTLS, tlsCert, tlsKey, redirect); err != nil {
			t.Fatalf("seed rule %s: %v", caddyID, err)
		}
		if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'http')`, caddyID); err != nil {
			t.Fatalf("seed upstream %s: %v", caddyID, err)
		}
	}
	seed("lb_shd_80u", 80, false, 1)
	seed("lb_shd_tlsu", 443, true, 0)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_shd_tlsu", strings.NewReader(`{"enabled":true}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "直接监听 80 端口") {
		t.Fatalf("status=%d body=%s, want 400 redirect shadow on enable via UpdateRule", response.Code, response.Body.String())
	}
}

// R40 F-1: 遮蔽/域名冲突门控的启用态条件收敛为仅启用方向——存量冲突组合
// （80 直听启用 + 443 TLS+跳转启用同域名；或同域名同端口双启用）下禁用任一方
// 不应被 400 误拦（禁用方不渲染，检查无意义，与 DisableRule 端点口径一致）；
// 启用方向仍须触发检查。
func TestUpdateRule_disable_direction_skips_conflict_checks(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	certPEM, keyPEM, err := generateTestCert("shadow-v.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	seedShadowCombo := func(caddyID, domain string, listenPort int, tlsRedirect bool) {
		t.Helper()
		enableTLS, redirect := 0, 0
		tlsCert, tlsKey := "", ""
		if tlsRedirect {
			enableTLS, redirect = 1, 1
			tlsCert, tlsKey = certPEM, keyPEM
		}
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress,enable_tls,tls_source,tls_cert,tls_key,tls_http_redirect)
			VALUES (?,?,?,'http',?,?,'weighted_round_robin',1,1,?,'manual',?,?,?)`,
			caddyID, caddyID, "", domain, listenPort, enableTLS, tlsCert, tlsKey, redirect); err != nil {
			t.Fatalf("seed rule %s: %v", caddyID, err)
		}
		if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'http')`, caddyID); err != nil {
			t.Fatalf("seed upstream %s: %v", caddyID, err)
		}
	}
	seedPlain := func(caddyID, domain string, listenPort, enabled int) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress)
			VALUES (?,?,?,'http',?,?,'weighted_round_robin',?,1)`, caddyID, caddyID, "", domain, listenPort, enabled); err != nil {
			t.Fatalf("seed rule %s: %v", caddyID, err)
		}
		if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'http')`, caddyID); err != nil {
			t.Fatalf("seed upstream %s: %v", caddyID, err)
		}
	}
	update := func(caddyID, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	t.Run("存量遮蔽组合下禁用 80 直听方放行", func(t *testing.T) {
		seedShadowCombo("lb_f1_80a", "shadow-v.test", 80, false)
		seedShadowCombo("lb_f1_tlsa", "shadow-v.test", 443, true)
		response := update("lb_f1_80a", `{"enabled":false}`)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200 for disable on shadow combo", response.Code, response.Body.String())
		}
	})

	t.Run("存量遮蔽组合下禁用 TLS 跳转方放行", func(t *testing.T) {
		seedShadowCombo("lb_f1_80b", "shadow-w.test", 80, false)
		seedShadowCombo("lb_f1_tlsb", "shadow-w.test", 443, true)
		response := update("lb_f1_tlsb", `{"enabled":false}`)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200 for disable on shadow combo", response.Code, response.Body.String())
		}
	})

	t.Run("同域名同端口双启用存量组合下禁用一方放行", func(t *testing.T) {
		seedPlain("lb_f1_dup1", "dup.test", 8080, 1)
		seedPlain("lb_f1_dup2", "dup.test", 8080, 1)
		response := update("lb_f1_dup2", `{"enabled":false}`)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200 for disable on duplicate combo", response.Code, response.Body.String())
		}
	})

	t.Run("启用方向仍触发遮蔽检查", func(t *testing.T) {
		seedShadowCombo("lb_f1_80c", "shadow-x.test", 80, false)
		seedShadowCombo("lb_f1_tlsc", "shadow-x.test", 443, true)
		if _, err := db.DB.Exec(`UPDATE lb_rules SET enabled=0 WHERE caddy_id='lb_f1_tlsc'`); err != nil {
			t.Fatalf("disable redirect rule: %v", err)
		}
		response := update("lb_f1_tlsc", `{"enabled":true}`)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "直接监听 80 端口") {
			t.Fatalf("status=%d body=%s, want 400 redirect shadow on enable direction", response.Code, response.Body.String())
		}
	})

	t.Run("启用方向仍触发域名冲突检查", func(t *testing.T) {
		seedPlain("lb_f1_dup3", "dup2.test", 8081, 1)
		seedPlain("lb_f1_dup4", "dup2.test", 8081, 0)
		response := update("lb_f1_dup4", `{"enabled":true}`)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "域名已被其他 HTTP/HTTPS 规则使用") {
			t.Fatalf("status=%d body=%s, want 400 domain conflict on enable direction", response.Code, response.Body.String())
		}
	})
}
