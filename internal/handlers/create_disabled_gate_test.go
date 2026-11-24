package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// 创建即禁用：创建即禁用（enabled 显式 false）跳过冲突门——禁用规则不渲染、
// 零冲突（UI 复制向导按预览「禁用」态创建副本，旧码被域名/端口门恒 400）；
// 启用方向由 EnableRule 既有二次门把守（与 DuplicateRule 无门、UpdateRule
// 启用方向检查同构）。enabled=true/缺省的创建行为完全不变。
func TestCreateRule_disabled_create_skips_conflict_gates(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)

	seedEnabledHTTP := func(caddyID, domain string, port int) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress,enable_tls,tls_source,tls_cert,tls_key,tls_http_redirect)
			VALUES (?,?,?,'http',?,?,'weighted_round_robin',1,1,0,'manual','','',0)`, caddyID, caddyID, "", domain, port); err != nil {
			t.Fatalf("seed rule %s: %v", caddyID, err)
		}
		if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'http')`, caddyID); err != nil {
			t.Fatalf("seed upstream %s: %v", caddyID, err)
		}
	}
	seedEnabledTCP := func(caddyID string, port int) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress,enable_tls,tls_source,tls_cert,tls_key,tls_http_redirect)
			VALUES (?,?,?,'tcp','',?,'weighted_round_robin',1,1,0,'manual','','',0)`, caddyID, caddyID, "", port); err != nil {
			t.Fatalf("seed tcp rule %s: %v", caddyID, err)
		}
		if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9001,1,1,'tcp')`, caddyID); err != nil {
			t.Fatalf("seed tcp upstream %s: %v", caddyID, err)
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
	httpBody := func(name, domain string, port int, enabled string) string {
		return fmt.Sprintf(`{"name":%q,"protocol":"http","domain":%q,"listen_port":%d,"enabled":%s,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, name, domain, port, enabled)
	}
	tcpBody := func(name string, port int, enabled string) string {
		return fmt.Sprintf(`{"name":%q,"protocol":"tcp","listen_port":%d,"enabled":%s,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9001,"enabled":true}]}`, name, port, enabled)
	}

	t.Run("disabled copy with same domain and port passes conflict gates", func(t *testing.T) {
		seedEnabledHTTP("lb_cp_src1", "copy-a.test", 18080)
		response := create(httpBody("copy-a-disabled", "copy-a.test", 18080, "false"))
		if response.Code != http.StatusCreated {
			t.Fatalf("status=%d body=%s, want 201（禁用态共存允许，启用时把关）", response.Code, response.Body.String())
		}
	})

	t.Run("enabled create with same domain still rejected", func(t *testing.T) {
		response := create(httpBody("copy-a-enabled", "copy-a.test", 18080, "true"))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "域名已被其他 HTTP/HTTPS 规则使用") {
			t.Fatalf("status=%d body=%s, want 400 domain conflict（回归形状）", response.Code, response.Body.String())
		}
	})

	t.Run("enabled omitted defaults to enabled and still rejected", func(t *testing.T) {
		body := strings.Replace(httpBody("copy-a-default", "copy-a.test", 18080, "true"), `"enabled":true,`, "", 1)
		response := create(body)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "域名已被其他 HTTP/HTTPS 规则使用") {
			t.Fatalf("status=%d body=%s, want 400（缺省=创建即启用）", response.Code, response.Body.String())
		}
	})

	t.Run("disabled copy of TCP rule passes port gate", func(t *testing.T) {
		seedEnabledTCP("lb_cp_tcpsrc", 19001)
		response := create(tcpBody("copy-tcp-disabled", 19001, "false"))
		if response.Code != http.StatusCreated {
			t.Fatalf("status=%d body=%s, want 201（禁用 TCP 副本不占端口）", response.Code, response.Body.String())
		}
	})

	t.Run("enabled TCP create with same port still rejected", func(t *testing.T) {
		response := create(tcpBody("copy-tcp-enabled", 19001, "true"))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "端口 19001 已被其他规则占用") {
			t.Fatalf("status=%d body=%s, want 400 port conflict（回归形状）", response.Code, response.Body.String())
		}
	})

	t.Run("enable of disabled copy hits EnableRule second gate", func(t *testing.T) {
		// Given 禁用副本已存在（首个子测试创建，同域名同端口）
		var caddyID string
		if err := db.DB.QueryRow("SELECT caddy_id FROM lb_rules WHERE name='copy-a-disabled'").Scan(&caddyID); err != nil {
			t.Fatalf("query disabled copy: %v", err)
		}
		// When 直接启用
		request := httptest.NewRequest(http.MethodPost, "/rules/"+caddyID+"/enable", nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		// Then 启用方向二次门拒绝（冲突面不变）
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "已被其他启用中的规则使用") {
			t.Fatalf("status=%d body=%s, want 400 enable second gate", response.Code, response.Body.String())
		}
	})
}

// 「跟随默认」CA 提供商解析不到任何启用提供商（管理端删除/禁用全部 CA）
// 是可修复的配置状态，必须是 400 + 可操作文案，而不是 500 服务器故障——
// 后者会让用户以为服务损坏且刷新页面后无任何持久痕迹。
func TestCreateRule_acmeDnsWithoutEnabledCAProviderIsBadRequest(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	if _, err := db.DB.Exec(`UPDATE ca_providers SET enabled = 0`); err != nil {
		t.Fatalf("disable ca providers: %v", err)
	}
	dnsResult, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('dns','dnspod','{"token":"x"}',1)`)
	if err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	dnsConfigID, err := dnsResult.LastInsertId()
	if err != nil {
		t.Fatalf("certificate config id: %v", err)
	}

	body := fmt.Sprintf(`{"name":"no-ca","protocol":"http","domain":"no-ca.example.test","listen_port":18443,"enabled":true,"enable_tls":true,"tls_source":"acme_dns","acme_config_id":%d,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, dnsConfigID)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（无可用 CA 提供商是可修复配置状态）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "没有可用的 CA 提供商") {
		t.Fatalf("文案必须给出可操作指引: %s", response.Body.String())
	}
}
