package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// LB42-2/LB42-3(第 42 轮审计):存量规则启用门(validateStoredRuleConfig)与
// 启动聚合校验(validateEnabledStoredRuleConfigs)缺少保存门已有的 TCP 形态
// 校验——TCP+cookie 等 HTTP 专属策略、TCP+dynamic_dns(渲染整跳过)、同端口
// 双启用 TCP 规则均可经存量/直改 DB 进入启用态。

func seedTCPStoredRule(t *testing.T, id, name string, port int, enabled bool, strategy string, dynamicDNS bool) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_compress,tls_source,enable_tls,dynamic_dns)
		VALUES (?,?,?,'tcp','',?,?,'',?,1,'manual',0,?)`, id, name, "", port, strategy, enabled, dynamicDNS); err != nil {
		t.Fatalf("seed tcp rule %s: %v", id, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?, '127.0.0.1', 9000, 1, 1, 'tcp')`, id); err != nil {
		t.Fatalf("seed tcp upstream %s: %v", id, err)
	}
}

// LB42-2:存量 tcp+cookie 规则 EnableRule 期望 400(与保存门 rule_features.go
// 策略白名单同口径;现行 200 把 cookie 透传到 L4 渲染被静默忽略)。
func TestEnableRule_rejectsTCPRuleWithHTTPOnlyStrategy(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedTCPStoredRule(t, "lb_tcp_cookie", "tcp-cookie", 19090, false, "cookie", false)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_tcp_cookie/enable", nil))

	// Then:400 点名负载策略,且规则保持禁用
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "负载策略") {
		t.Fatalf("enable status=%d body=%s, want 400 点名负载策略", response.Code, response.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_tcp_cookie'").Scan(&enabled); err != nil {
		t.Fatalf("read enabled state: %v", err)
	}
	if enabled {
		t.Fatal("rejected rule stayed enabled")
	}
}

// LB42-3①:存量 tcp+dynamic_dns 规则(渲染整跳过形态)EnableRule 期望 400;
// 聚合校验同样点名。
func TestEnableRule_rejectsTCPRuleWithDynamicDNS(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedTCPStoredRule(t, "lb_tcp_ddns", "tcp-ddns", 19091, false, "weighted_round_robin", true)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_tcp_ddns/enable", nil))

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "动态上游") {
		t.Fatalf("enable status=%d body=%s, want 400 点名动态上游", response.Code, response.Body.String())
	}
}

// LB42-3②:存量两条同端口 TCP 均启用(兜 validatePortFromDB 之前的存量双
// 启用),聚合校验必须报错并点名全部冲突规则。
func TestValidateEnabledStoredRuleConfigs_namesDuplicateTCPPortRules(t *testing.T) {
	// Given
	initializeRuleFeatureTestDB(t)
	seedTCPStoredRule(t, "lb_tcp_dup_a", "tcp-dup-a", 19092, true, "weighted_round_robin", false)
	seedTCPStoredRule(t, "lb_tcp_dup_b", "tcp-dup-b", 19092, true, "least_conn", false)

	// When
	err := validateEnabledStoredRuleConfigs(context.Background())

	// Then:报错点名两条规则
	if err == nil {
		t.Fatal("duplicate enabled TCP port must be rejected by aggregate validation")
	}
	if !strings.Contains(err.Error(), "lb_tcp_dup_a") || !strings.Contains(err.Error(), "lb_tcp_dup_b") {
		t.Fatalf("aggregate error must name both conflicting rules, got: %v", err)
	}
}

// LB42-3① 聚合形态:tcp+dynamic_dns 启用存量在聚合校验点名。
func TestValidateEnabledStoredRuleConfigs_namesTCPDynamicDNS(t *testing.T) {
	// Given
	initializeRuleFeatureTestDB(t)
	seedTCPStoredRule(t, "lb_tcp_ddns_on", "tcp-ddns-on", 19093, true, "weighted_round_robin", true)

	// When
	err := validateEnabledStoredRuleConfigs(context.Background())

	// Then
	if err == nil || !strings.Contains(err.Error(), "lb_tcp_ddns_on") || !strings.Contains(err.Error(), "动态上游") {
		t.Fatalf("aggregate validation must name tcp+dynamic_dns rule, got: %v", err)
	}
}
