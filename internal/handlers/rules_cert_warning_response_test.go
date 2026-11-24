package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// responseWarnings 取保存响应 data.warnings（缺键=空）。
func responseWarnings(t *testing.T, body []byte) []string {
	t.Helper()
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode response %s: %v", body, err)
	}
	var out []string
	raw, _ := resp.Data["warnings"].([]any)
	for _, w := range raw {
		s, ok := w.(string)
		if !ok {
			continue
		}
		out = append(out, s)
	}
	return out
}

func createManualTLSRule(t *testing.T, handler *Handlers, domain, certPEM, keyPEM string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	payload, err := json.Marshal(map[string]any{
		"name": "tls-warn", "protocol": "http", "domain": domain,
		"listen_port": 8443, "enable_tls": true, "tls_source": "manual",
		"tls_cert": certPEM, "tls_key": keyPEM,
		"health_check_interval": 10, "health_check_timeout": 2, "health_check_unhealthy_threshold": 3, "health_check_healthy_threshold": 2,
		"upstreams": []map[string]any{{"host": "127.0.0.1", "port": 9000, "enabled": true}},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(string(payload)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// 保存手动 TLS 规则时，会让站点握手失败的证书警告（域名不匹配 / 证书链
// 不完整）必须进保存响应——面板据此弹框披露，否则用户只看到「创建成功」。
func TestCreateRule_manualTLSDomainMismatch_returnsWarningInResponse(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	certPEM, keyPEM, err := generateTestCert("other.example.test", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// When：证书签给别的域名
	response := createManualTLSRule(t, handler, "tls-warn.example.test", certPEM, keyPEM)

	// Then：保存成功（警告不阻断）且响应携带域名不匹配警告
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	warnings := responseWarnings(t, response.Body.Bytes())
	if !strings.Contains(strings.Join(warnings, "\n"), "证书域名与规则域名不匹配") {
		t.Fatalf("response warnings=%q, want domain-mismatch warning", warnings)
	}
}

// 有效期类警告（过期 / 未生效）属可轮换状态：仍随审计留痕，但不进保存响应。
func TestCreateRule_manualTLSExpired_keepsExpiryWarningOutOfResponse(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	certPEM, keyPEM, err := generateTestCert("tls-warn.example.test", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("generate expired cert: %v", err)
	}

	response := createManualTLSRule(t, handler, "tls-warn.example.test", certPEM, keyPEM)

	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	warnings := responseWarnings(t, response.Body.Bytes())
	// 自签单张证书同时带「链不完整」——它在响应里；「已过期」不在。
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "证书链可能不完整") {
		t.Fatalf("response warnings=%q, want incomplete-chain warning", warnings)
	}
	if strings.Contains(joined, "证书已过期") {
		t.Fatalf("response warnings=%q must not carry expiry warning", warnings)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='创建' AND resource='负载规则' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("query create audit: %v", err)
	}
	if !strings.Contains(detail, "证书已过期") {
		t.Fatalf("create audit detail=%q, want expiry warning kept in audit", detail)
	}
}

// 更新方向同口径：替换为域名不匹配的证书，响应携带该警告。
func TestUpdateRule_manualTLSDomainMismatch_returnsWarningInResponse(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	seedAuditRule(t, "lb_tls_warn", "before", "tls-warn.example.test", 8443, true, "manual", true)
	seedAuditUpstream(t, "lb_tls_warn")
	certPEM, keyPEM, err := generateTestCert("other.example.test", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	payload, err := json.Marshal(map[string]any{"name": "after", "tls_cert": certPEM, "tls_key": keyPEM})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_tls_warn", strings.NewReader(string(payload)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	warnings := responseWarnings(t, response.Body.Bytes())
	if !strings.Contains(strings.Join(warnings, "\n"), "证书域名与规则域名不匹配") {
		t.Fatalf("response warnings=%q, want domain-mismatch warning", warnings)
	}
}

// 回归形状：链可信且域名覆盖的证书不得让响应带出任何证书警告。
func TestUpdateRule_manualTLSClean_omitsWarningsInResponse(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	seedAuditRule(t, "lb_tls_warn", "before", "tls-ok.example.test", 8443, true, "manual", true)
	seedAuditUpstream(t, "lb_tls_warn")
	certPEM, keyPEM, roots := generateTestCAChain(t, []string{"tls-ok.example.test"})
	injectTestRoots(t, roots)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	payload, err := json.Marshal(map[string]any{"name": "after", "tls_cert": certPEM, "tls_key": keyPEM})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_tls_warn", strings.NewReader(string(payload)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if warnings := responseWarnings(t, response.Body.Bytes()); len(warnings) != 0 {
		t.Fatalf("response warnings=%q, trusted matching cert must not warn", warnings)
	}
}
