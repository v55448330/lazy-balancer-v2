package handlers

// LB40-1(第 40 轮):同端口 TLS/明文混布拦截——Caddy 监听器按端口二选一,
// 混布会把整个端口监听器切为 TLS,明文规则流量全部握手失败。创建/更新/
// 启用三入口按 enable_tls 意图拦截(不看证书存在性,ACME 延迟翻转一并覆盖)。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func newTLSMixRouter(t *testing.T, handler *Handlers) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	return router
}

func seedTLSMixRule(t *testing.T, caddyID, domain string, listenPort int, enableTLS bool, enabled int) {
	t.Helper()
	certPEM, keyPEM, err := generateTestCert(domain, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	tlsFlag := 0
	tlsCert, tlsKey := "", ""
	if enableTLS {
		tlsFlag = 1
		tlsCert, tlsKey = certPEM, keyPEM
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress,enable_tls,tls_source,tls_cert,tls_key)
		VALUES (?,?,?,'http',?,?,'weighted_round_robin',?,1,?,'manual',?,?)`,
		caddyID, caddyID, "", domain, listenPort, enabled, tlsFlag, tlsCert, tlsKey); err != nil {
		t.Fatalf("seed rule %s: %v", caddyID, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'http')`, caddyID); err != nil {
		t.Fatalf("seed upstream %s: %v", caddyID, err)
	}
}

func tlsMixBody(name, domain string, listenPort int, enableTLS bool) string {
	if enableTLS {
		certPEM, keyPEM, _ := generateTestCert(domain, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
		return fmt.Sprintf(`{"name":%q,"protocol":"http","domain":%q,"listen_port":%d,"enable_tls":true,"tls_source":"manual","tls_cert":%q,"tls_key":%q,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, name, domain, listenPort, certPEM, keyPEM)
	}
	return fmt.Sprintf(`{"name":%q,"protocol":"http","domain":%q,"listen_port":%d,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, name, domain, listenPort)
}

func TestRulePortTLSMix_rejected(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	oldCertDir := testServicesCertDir
	testServicesCertDir = t.TempDir()
	t.Cleanup(func() { testServicesCertDir = oldCertDir })
	router := newTLSMixRouter(t, handler)
	create := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	enable := func(caddyID string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/"+caddyID+"/enable", nil))
		return response
	}

	// 形状一:明文规则已启用,同端口新建 TLS 规则 → 400
	seedTLSMixRule(t, "lb_mix_plain1", "mix-a.test", 18443, false, 1)
	rec := create(tlsMixBody("mix-tls-1", "mix-b.test", 18443, true))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "不能混布") {
		t.Fatalf("create TLS onto plaintext port must 400, got %d %s", rec.Code, rec.Body.String())
	}

	// 形状二(反向):TLS 规则已启用,同端口新建明文规则 → 400
	seedTLSMixRule(t, "lb_mix_tls2", "mix-c.test", 18444, true, 1)
	rec = create(tlsMixBody("mix-plain-2", "mix-d.test", 18444, false))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "不能混布") {
		t.Fatalf("create plaintext onto TLS port must 400, got %d %s", rec.Code, rec.Body.String())
	}

	// 形状三(回归):同 TLS 形态共存放行
	seedTLSMixRule(t, "lb_mix_tls3", "mix-e.test", 18445, true, 1)
	rec = create(tlsMixBody("mix-tls-4", "mix-f.test", 18445, true))
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("same-TLS coexistence must pass, got %d %s", rec.Code, rec.Body.String())
	}

	// 形状四:启用方向——禁用明文规则 + 同端口已启用 TLS 规则 → enable 400
	seedTLSMixRule(t, "lb_mix_tls5", "mix-g.test", 18446, true, 1)
	seedTLSMixRule(t, "lb_mix_plain6", "mix-h.test", 18446, false, 0)
	rec = enable("lb_mix_plain6")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "不能混布") {
		t.Fatalf("enable plaintext onto TLS port must 400, got %d %s", rec.Code, rec.Body.String())
	}
}
