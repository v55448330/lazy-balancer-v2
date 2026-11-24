package handlers

// 同域名同端口冲突门、跳转遮蔽门与渲染层共用同一裁定：全部上游被禁用的规则
// 不产生 host 路由（渲染主循环直接跳过），不作为域名占用方。跳转遮蔽侧此前
// 已落该口径，创建/更新/启用三入口与聚合校验此前只按 enabled=1 判定——
// 「A 上游全禁用 + B 同域名同端口」形态下 B 被 400 误拦，而渲染层实际只有 B
// 生效。本文件钉住两侧同源（SQL EXISTS 与聚合归组都按启用上游存在性过滤）。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"lazy-balancer-v2/internal/db"
)

const zeroUpstreamCreateBody = `{"name":"zero-b","protocol":"http","domain":"zero.example.test","listen_port":8081,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`

func seedZeroUpstreamHTTPRule(t *testing.T, caddyID, name, domain string, port int, enabled bool, upstreamEnabled bool) {
	t.Helper()
	seedAuditRule(t, caddyID, name, domain, port, enabled, "manual", false)
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?, '127.0.0.1', 9000, 1, ?, 'http')`, caddyID, upstreamEnabled); err != nil {
		t.Fatalf("seed upstream for %s: %v", caddyID, err)
	}
}

func TestCreateRule_zeroEnabledUpstreamRuleDoesNotOccupyDomain(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	// A：启用中但上游全部禁用——不产生 host 路由。
	seedZeroUpstreamHTTPRule(t, "lb_zero_a", "zero-a", "zero.example.test", 8081, true, false)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(zeroUpstreamCreateBody))
	request.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201（零启用上游规则不占位）", response.Code, response.Body.String())
	}
}

func TestCreateRule_enabledUpstreamRuleStillBlocksSameDomain(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	seedZeroUpstreamHTTPRule(t, "lb_zero_c", "zero-c", "zero.example.test", 8081, true, true)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(zeroUpstreamCreateBody))
	request.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "域名已被") {
		t.Fatalf("status=%d body=%s, want 400 域名冲突（启用上游仍占位）", response.Code, response.Body.String())
	}
}

func TestEnableRule_zeroEnabledUpstreamRuleDoesNotOccupyDomain(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	seedZeroUpstreamHTTPRule(t, "lb_zero_d", "zero-d", "zero.example.test", 8081, true, false)
	seedZeroUpstreamHTTPRule(t, "lb_zero_e", "zero-e", "zero.example.test", 8081, false, true)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_zero_e/enable", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（启用方向同一口径）", response.Code, response.Body.String())
	}
}

func TestUpdateRule_zeroEnabledUpstreamRuleDoesNotOccupyDomain(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	seedZeroUpstreamHTTPRule(t, "lb_zero_f", "zero-f", "zero.example.test", 8081, true, false)
	seedZeroUpstreamHTTPRule(t, "lb_zero_g", "zero-g", "old.example.test", 8081, true, true)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_zero_g", strings.NewReader(`{"domain":"zero.example.test"}`))
	request.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（更新方向同一口径）", response.Code, response.Body.String())
	}
}

// 聚合校验同口径：零启用上游的重复域名规则不构成运行时冲突（渲染侧只有另一条
// 生效）；两侧都有启用上游时仍必须硬错。
func TestValidateEnabledStoredRuleConfigs_zeroEnabledUpstreamRuleNotAnOwner(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	seedZeroUpstreamHTTPRule(t, "lb_zero_h", "zero-h", "zero.example.test", 18083, true, false)
	seedZeroUpstreamHTTPRule(t, "lb_zero_i", "zero-i", "zero.example.test", 18083, true, true)

	if err := validateEnabledStoredRuleConfigs(context.Background()); err != nil {
		t.Fatalf("零启用上游规则不应作为域名占用方: %v", err)
	}
}

func TestValidateEnabledStoredRuleConfigs_enabledUpstreamsBothSidesStillConflict(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	seedZeroUpstreamHTTPRule(t, "lb_zero_j", "zero-j", "zero.example.test", 18084, true, true)
	seedZeroUpstreamHTTPRule(t, "lb_zero_k", "zero-k", "zero.example.test", 18084, true, true)

	err := validateEnabledStoredRuleConfigs(context.Background())
	if err == nil || !strings.Contains(err.Error(), "zero.example.test") {
		t.Fatalf("两侧都有启用上游时仍必须硬错，实际: %v", err)
	}
}
