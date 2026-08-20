package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// R46 C-B-1（v1 备份）: 禁用的 SSL 规则无内联证书时，导入归一为 enable_tls=0
// 并逐条告警——此前会原样落库 enable_tls=1 + tls_source='manual' + 空证书的非法
// 状态，且该状态随 v2 导出回流。
func TestImportV1Config_normalizes_disabled_ssl_rule_without_cert(t *testing.T) {
	// Given v1 备份中一条禁用（status=false）的 SSL 规则不带内联证书
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := `{
		"proxy_config":{"config":[
			{"pk":1,"fields":{"proxy_name":"ssl-disabled-nocert","protocol":true,"listen":8461,"server_name":"ssl-disabled-nocert.example.test","status":false,"ssl":true,"ssl_redirect_https":true,"upstream_list":[1]}}
		]},
		"upstream_config":{"config":[
			{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9001,"weight":100}}
		]}
	}`
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then 规则导入成功且归一为 enable_tls=0（tls_source 随之置空），并逐条告警
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "已按关闭 TLS 导入") {
		t.Fatalf("import response missing normalization warning: %s", response.Body.String())
	}
	var enableTLS int
	var tlsSource string
	var enabled int
	if err := db.DB.QueryRow("SELECT enable_tls, tls_source, enabled FROM lb_rules WHERE name='ssl-disabled-nocert'").Scan(&enableTLS, &tlsSource, &enabled); err != nil {
		t.Fatalf("read imported rule: %v", err)
	}
	if enableTLS != 0 || tlsSource != "" || enabled != 0 {
		t.Fatalf("imported rule enable_tls=%d tls_source=%q enabled=%d, want 0/''/0", enableTLS, tlsSource, enabled)
	}
}

// R46 C-B-1（v2 备份）: 启用手动 TLS 空证书行被拒绝时须点名违规规则，便于在
// 整包备份中定位（镜像保存/启用侧 validateStoredRuleConfig 口径）。
// R55 C-1：TLS 形态校验迁至 validateV2BackupTLSShape（冲突置禁用之后执行）。
func TestValidateV2BackupTLSShape_names_offending_rule(t *testing.T) {
	// Given 一条启用、手动 TLS、无证书的备份规则行
	rule := map[string]any{
		"caddy_id": "lb_named_nocert", "name": "named-nocert", "protocol": "http",
		"domain": "named.example.test", "listen_port": 8462,
		"enabled": 1, "enable_tls": 1, "tls_source": "manual",
	}

	// When
	err := validateV2BackupTLSShape(map[string][]map[string]any{"lb_rules": {rule}})

	// Then 拒绝且错误信息点名规则名
	if err == nil || !strings.Contains(err.Error(), "named-nocert") ||
		!strings.Contains(err.Error(), "手动证书模式下必须提供 TLS 证书和私钥") {
		t.Fatalf("validateV2BackupTLSShape err=%v, want naming the offending rule", err)
	}
}
