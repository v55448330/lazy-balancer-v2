package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// R52 F-1/F-3 公共种子：一条可用的 DNS 提供商配置。
func seedR52CertificateConfig(t *testing.T) int64 {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('r52-dns','dnspod','{"token":"x"}',1)`)
	if err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate config ID: %v", err)
	}
	return id
}

// R52 F-1 公共种子：当前启用的 CA 提供商 id。
func seedR52EnabledProviderID(t *testing.T) int {
	t.Helper()
	var providerID int
	if err := db.DB.QueryRow("SELECT id FROM ca_providers WHERE enabled=1 ORDER BY id LIMIT 1").Scan(&providerID); err != nil {
		t.Fatalf("read enabled CA provider: %v", err)
	}
	return providerID
}

// R52 F-1（写侧）：CreateRule 必须拒绝引用不存在/已禁用 CA 提供商的
// ca_provider_id——否则主节点静默回退到错误 CA 签发，从节点快照整包拒绝。
func TestCreateRule_rejects_dangling_ca_provider_id(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	dnsConfigID := seedR52CertificateConfig(t)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := fmt.Sprintf(`{"name":"dangling-ca","protocol":"http","domain":"dangling-ca.example.test","listen_port":8080,"enable_tls":true,"tls_source":"acme_dns","acme_config_id":%d,"ca_provider_id":999,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, dnsConfigID)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "CA 提供商") {
		t.Fatalf("create status=%d body=%s, want 400 点名 CA 提供商", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE domain='dangling-ca.example.test'").Scan(&count); err != nil {
		t.Fatalf("read rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("rejected rule persisted, count=%d", count)
	}
}

// R52 F-1（写侧）对照组：引用存在且启用的 CA 提供商必须放行并原样落库。
func TestCreateRule_allows_valid_ca_provider_id(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	dnsConfigID := seedR52CertificateConfig(t)
	providerID := seedR52EnabledProviderID(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	t.Cleanup(services.ResetCAQueueManagerForTest)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := fmt.Sprintf(`{"name":"valid-ca","protocol":"http","domain":"valid-ca.example.test","listen_port":8080,"enable_tls":true,"tls_source":"acme_dns","acme_config_id":%d,"ca_provider_id":%d,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, dnsConfigID, providerID)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var persisted int
	if err := db.DB.QueryRow("SELECT ca_provider_id FROM lb_rules WHERE domain='valid-ca.example.test'").Scan(&persisted); err != nil {
		t.Fatalf("read persisted CA provider: %v", err)
	}
	if persisted != providerID {
		t.Fatalf("persisted provider=%d, want %d", persisted, providerID)
	}
}

// R52 F-1（写侧）对照组：ca_provider_id=0（系统默认）语义不变，照常放行。
func TestCreateRule_allows_zero_ca_provider_id(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	dnsConfigID := seedR52CertificateConfig(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	t.Cleanup(services.ResetCAQueueManagerForTest)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := fmt.Sprintf(`{"name":"zero-ca","protocol":"http","domain":"zero-ca.example.test","listen_port":8080,"enable_tls":true,"tls_source":"acme_dns","acme_config_id":%d,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, dnsConfigID)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s, want 201（0=系统默认不得被误拒）", response.Code, response.Body.String())
	}
}

// R52 F-1（写侧）：UpdateRule 切换到 acme_dns 时同样拒绝悬挂 ca_provider_id。
func TestUpdateRule_rejects_dangling_ca_provider_id(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_upd_ca999", 0, false)
	seedAuditRule(t, "lb_upd_ca999", "before", "upd-ca999.example.test", 8080, false, "manual", false)
	seedAuditUpstream(t, "lb_upd_ca999")
	dnsConfigID := seedR52CertificateConfig(t)
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	body := fmt.Sprintf(`{"enable_tls":true,"tls_source":"acme_dns","acme_config_id":%d,"ca_provider_id":999}`, dnsConfigID)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_upd_ca999", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "CA 提供商") {
		t.Fatalf("update status=%d body=%s, want 400 点名 CA 提供商", response.Code, response.Body.String())
	}
}

// R52 F-1（写侧）对照组：UpdateRule 携带有效 ca_provider_id 必须放行。
func TestUpdateRule_allows_valid_ca_provider_id(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_upd_ca_valid", 0, false)
	seedAuditRule(t, "lb_upd_ca_valid", "before", "upd-ca-valid.example.test", 8080, false, "manual", false)
	seedAuditUpstream(t, "lb_upd_ca_valid")
	dnsConfigID := seedR52CertificateConfig(t)
	providerID := seedR52EnabledProviderID(t)
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	body := fmt.Sprintf(`{"enable_tls":true,"tls_source":"acme_dns","acme_config_id":%d,"ca_provider_id":%d}`, dnsConfigID, providerID)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_upd_ca_valid", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var persisted int
	if err := db.DB.QueryRow("SELECT ca_provider_id FROM lb_rules WHERE caddy_id='lb_upd_ca_valid'").Scan(&persisted); err != nil {
		t.Fatalf("read persisted CA provider: %v", err)
	}
	if persisted != providerID {
		t.Fatalf("persisted provider=%d, want %d", persisted, providerID)
	}
}

// R52 组合不变量：存量规则携带有效 ca_provider_id 时，省略该字段的更新
// （nil=保留现值）不得被 400——保留语义与新存在性校验必须兼容。
func TestUpdateRule_preserves_valid_ca_provider_when_omitted(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_upd_ca_keep", 0, false)
	seedAuditRule(t, "lb_upd_ca_keep", "before", "upd-ca-keep.example.test", 8080, false, "acme_dns", true)
	seedAuditUpstream(t, "lb_upd_ca_keep")
	dnsConfigID := seedR52CertificateConfig(t)
	providerID := seedR52EnabledProviderID(t)
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=?,ca_provider_id=? WHERE caddy_id='lb_upd_ca_keep'", dnsConfigID, providerID); err != nil {
		t.Fatalf("bind ACME state: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_upd_ca_keep", strings.NewReader(`{"name":"after"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200（保留现值合并不应被误拒）", response.Code, response.Body.String())
	}
	var persisted int
	if err := db.DB.QueryRow("SELECT ca_provider_id FROM lb_rules WHERE caddy_id='lb_upd_ca_keep'").Scan(&persisted); err != nil {
		t.Fatalf("read persisted CA provider: %v", err)
	}
	if persisted != providerID {
		t.Fatalf("persisted provider=%d, want preserved %d", persisted, providerID)
	}
}

// R52 F-2：EnableRule 不得把 enable_tls+acme_dns 且 acme_config_id=0 的
// 存量坏规则（导入残留）投入运行——与 R51 Create/Update 写侧 400 口径对齐。
func TestEnableRule_rejects_acme_dns_without_certificate_config(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_enable_no_config", "enable-no-config", "enable-no-config.example.test", 8080, false, "acme_dns", true)
	seedAuditUpstream(t, "lb_enable_no_config")
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_enable_no_config/enable", nil))

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "DNS 提供商配置") {
		t.Fatalf("enable status=%d body=%s, want 400 点名 DNS 提供商配置", response.Code, response.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_enable_no_config'").Scan(&enabled); err != nil {
		t.Fatalf("read enabled state: %v", err)
	}
	if enabled {
		t.Fatal("rejected rule stayed enabled")
	}
}

// R52 F-3：CreateRule 必须拒绝引用不存在 certificate_configs 行的
// acme_config_id（R51 门只挡 0 值，悬挂非 0 同样不得落库）。
func TestCreateRule_rejects_dangling_acme_config_id(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{"name":"dangling-cfg","protocol":"http","domain":"dangling-cfg.example.test","listen_port":8080,"enable_tls":true,"tls_source":"acme_dns","acme_config_id":999,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "DNS 提供商配置") {
		t.Fatalf("create status=%d body=%s, want 400 点名 DNS 提供商配置", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE domain='dangling-cfg.example.test'").Scan(&count); err != nil {
		t.Fatalf("read rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("rejected rule persisted, count=%d", count)
	}
}

// R52 F-3：manual 规则保留的存量 acme_config_id 若在 manual 期间被删除，
// 切换回 acme_dns（不带 acme_config_id，0=保留合并出悬挂 id）必须 400，
// 不得静默复用已删除的 DNS 配置。
func TestUpdateRule_rejects_dangling_acme_config_id_on_switch_back(t *testing.T) {
	// Given：manual 规则携带来自 acme_dns 时期的残留 acme_config_id，配置行已删除
	harness := newUpdateAuditRuleHandlers(t, "lb_stale_cfg", 0, false)
	seedAuditRule(t, "lb_stale_cfg", "before", "stale-cfg.example.test", 8080, false, "manual", false)
	seedAuditUpstream(t, "lb_stale_cfg")
	dnsConfigID := seedR52CertificateConfig(t)
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=? WHERE caddy_id='lb_stale_cfg'", dnsConfigID); err != nil {
		t.Fatalf("seed stale ACME config: %v", err)
	}
	if _, err := db.DB.Exec("DELETE FROM certificate_configs WHERE id=?", dnsConfigID); err != nil {
		t.Fatalf("delete certificate config: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_stale_cfg", strings.NewReader(`{"enable_tls":true,"tls_source":"acme_dns"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "DNS 提供商配置") {
		t.Fatalf("update status=%d body=%s, want 400 点名 DNS 提供商配置", response.Code, response.Body.String())
	}
}

// R52 F-3 对照组：切换到 acme_dns 且引用存在的配置必须放行。
func TestUpdateRule_allows_acme_dns_with_valid_config(t *testing.T) {
	// Given
	harness := newUpdateAuditRuleHandlers(t, "lb_valid_cfg", 0, false)
	seedAuditRule(t, "lb_valid_cfg", "before", "valid-cfg.example.test", 8080, false, "manual", false)
	seedAuditUpstream(t, "lb_valid_cfg")
	dnsConfigID := seedR52CertificateConfig(t)
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)
	body := fmt.Sprintf(`{"enable_tls":true,"tls_source":"acme_dns","acme_config_id":%d}`, dnsConfigID)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_valid_cfg", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
}
