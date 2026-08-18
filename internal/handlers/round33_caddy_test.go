package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// Round 33 N-3: 动态 DNS 多上游错误哨兵化后，预校验消费点（errors.Is）仍命中
// 明确的中文错误；不再依赖生成侧错误文案的字符串匹配。
func TestValidateRuleConfigGeneration_dynamicDNSMultiUpstream_hitsSentinel(t *testing.T) {
	// Given
	newBackupTestHandlers(t)
	rule := models.LbRule{
		CaddyID: "lb_dyn", Protocol: "http", Domain: "dyn.example.test", ListenPort: 80,
		DynamicDNS: true,
		Upstreams: []models.Upstream{
			{Host: "a.example.test", Port: 80, Enabled: true},
			{Host: "b.example.test", Port: 80, Enabled: true},
		},
	}

	// When 哨兵包装后经预校验判定
	config := services.GenerateSingleRuleCaddyConfig(services.SingleRuleConfig{
		CaddyID: rule.CaddyID, Protocol: rule.Protocol, Domain: rule.Domain, ListenPort: rule.ListenPort,
		Strategy: rule.Strategy, DynamicDNS: rule.DynamicDNS, Upstreams: []services.UpstreamConfig{
			{Host: "a.example.test", Port: 80, Weight: 1, Enabled: true},
			{Host: "b.example.test", Port: 80, Weight: 1, Enabled: true},
		},
	})
	genErr, isErr := config["error"].(error)
	if !isErr {
		t.Fatalf("error 键应为 error 类型，实际 %T", config["error"])
	}
	if !errors.Is(genErr, services.ErrDynamicDNSUpstreamCount) {
		t.Fatalf("哨兵必须可 errors.Is 命中，实际: %v", genErr)
	}

	// Then 消费点返回明确中文错误
	validationErr := validateRuleConfigGeneration(rule)
	if validationErr == nil {
		t.Fatal("动态 DNS 多上游应被预校验拒绝")
	}
	if validationErr.Error() != "动态 DNS 模式仅支持一个启用的上游" {
		t.Fatalf("预校验错误=%q，want 动态 DNS 模式仅支持一个启用的上游", validationErr.Error())
	}
}

// Round 33 N-5: audit_log_size_mb 超上限（512MB）被 UpdateConfig 拒绝（400）。
func TestUpdateConfig_rejectsAuditLogSizeAbove512MB(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)

	// When 超上限
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"source":"basic","audit_log_size_mb":600}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then 400 + 明确中文文案
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "审计日志轮转大小上限 512MB") {
		t.Fatalf("body=%s, want 审计日志轮转大小上限 512MB", response.Body.String())
	}
}
