package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/mcpserver"
)

func TestGetMCPTools_returns_complete_public_registry(t *testing.T) {
	// Given
	gin.SetMode(gin.TestMode)
	handler := NewHandlers(Dependencies{})
	router := gin.New()
	router.GET("/api/v1/mcp/tools", handler.GetMCPTools)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools", nil)

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Code    int                  `json:"code"`
		Message string               `json:"message"`
		Data    []mcpserver.ToolSpec `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// 工具清单是 MCP 使用者可见的外部契约：期望值必须独立冻结，用
	// len(mcpserver.ListToolSpecs()) 作期望是回声——工具被整体删空也照样通过。
	wantTools := []string{
		"list_rules",
		"get_rule",
		"create_rule",
		"update_rule",
		"delete_rule",
		"enable_rule",
		"disable_rule",
		"duplicate_rule",
		"list_cert_jobs",
		"retry_cert_job",
		"delete_cert_job",
		"issue_certificate",
		"list_certificates",
		"get_config",
		"update_config",
		"reload_caddy",
		"export_config",
		"get_metrics_dashboard",
		"get_metrics_overview",
		"get_realtime_traffic",
		"get_upstream_health",
		"list_audit_logs",
		"get_system_info",
		"list_users",
		"list_api_keys",
		"get_cluster_status",
		"get_security_overview",
		"list_security_policies",
		"get_security_policy",
		"list_security_events",
		"list_security_bindings",
		"get_rule_security_policy",
		"list_custom_rules",
		"list_block_pages",
		"get_crs_info",
		"get_crs_update_status",
		"get_crs_update_logs",
		"list_crs_rules",
		"get_crs_rule",
		"get_crs_rule_index",
		"get_ip2region_info",
		"get_ip2region_regions",
		"get_ip2region_update_status",
		"get_ip2region_update_logs",
		"get_rule_stage_stats",
		"create_security_policy",
		"update_security_policy",
		"delete_security_policy",
		"bind_security_policy",
		"unbind_security_policy",
		"set_rule_security_policies",
		"create_custom_rule",
		"update_custom_rule",
		"delete_custom_rule",
		"create_block_page",
		"update_block_page",
		"delete_block_page",
		"list_ip_lists",
		"get_ip_list",
		"create_ip_list",
		"update_ip_list",
		"delete_ip_list",
		"add_ip_to_list",
		"remove_ip_from_list",
		"toggle_crs_auto_update",
		"trigger_crs_update",
		"toggle_ip2region_auto_update",
		"trigger_ip2region_update",
		"list_cluster_nodes",
		"create_register_token",
		"approve_cluster_node",
		"reject_cluster_node",
		"create_login_ticket",
		"update_node_access_url",
		"delete_cluster_node",
		"control_cluster_node_service",
		"forget_cluster_node_pin",
		"forget_cluster_pins",
		"set_cluster_mode",
		"promote_cluster",
		"pull_sync",
		"list_system_tasks",
		"get_system_task_logs",
		"get_system_task_history",
		"trigger_system_task",
		"toggle_system_task",
		"cancel_system_task",
		"control_system_task",
		"update_cluster_settings",
		"list_certificate_configs",
		"create_certificate_config",
		"update_certificate_config",
		"delete_certificate_config",
		"test_certificate_config",
		"list_dns_providers",
		"list_ca_providers",
		"get_ca_provider",
		"update_ca_provider",
		"test_ca_provider",
		"get_cert_job",
		"get_cert_job_logs",
		"parse_certificate",
		"create_user",
		"update_user",
		"toggle_user_status",
		"reset_user_password",
		"delete_user",
		"reset_user_mfa",
		"create_api_key",
		"update_api_key_status",
		"delete_api_key",
		"preview_config",
		"validate_config",
		"import_config",
		"validate_import",
		"import_v1_config",
		"get_rule_logs",
		"get_rule_caddy_config",
		"get_rule_metrics_history",
		"get_rule_cert_info",
		"get_caddy_status",
		"get_caddy_config",
		"get_caddy_logs",
		"update_caddy_config",
		"start_caddy",
		"stop_caddy",
		"restart_caddy",
		"get_admin_tls",
		"update_admin_tls",
		"inspect_admin_tls",
		"get_system_metrics",
		"get_system_logs",
		"restart_system",
		"get_rule_metrics",
		"get_metrics_history",
		"get_connections",
	}
	if body.Code != 0 || body.Message == "" {
		t.Fatalf("unexpected response: %+v", body)
	}
	gotTools := make([]string, 0, len(body.Data))
	for _, spec := range body.Data {
		gotTools = append(gotTools, spec.Name)
	}
	if !slices.Equal(gotTools, wantTools) {
		t.Fatalf("工具清单漂移（外部契约）：got %d 项 %v, want %d 项 %v", len(gotTools), gotTools, len(wantTools), wantTools)
	}
	var hasReadOnly, hasWrite bool
	for _, spec := range body.Data {
		hasReadOnly = hasReadOnly || spec.ReadOnly
		hasWrite = hasWrite || !spec.ReadOnly
	}
	if !hasReadOnly || !hasWrite {
		t.Fatalf("registry classifications read=%v write=%v", hasReadOnly, hasWrite)
	}
	if strings.Contains(response.Body.String(), "path_args") || strings.Contains(response.Body.String(), "query_args") {
		t.Fatalf("handler leaked internal path_args/query_args: %s", response.Body.String())
	}
}
