package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type toolSpec struct {
	name        string
	description string
	method      string
	path        string
	pathArgs    []string
	queryArgs   []string
	schema      string
}

var tools = []toolSpec{
	{"list_rules", "列出全部负载均衡规则", http.MethodGet, "/rules", nil, nil, emptySchema},
	{"get_rule", "获取指定负载均衡规则详情", http.MethodGet, "/rules/{caddy_id}", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"create_rule", "创建负载均衡规则", http.MethodPost, "/rules", nil, nil, createRuleSchema},
	{"update_rule", "更新指定负载均衡规则", http.MethodPut, "/rules/{caddy_id}", []string{"caddy_id"}, nil, updateRuleSchema},
	{"delete_rule", "删除指定负载均衡规则", http.MethodDelete, "/rules/{caddy_id}", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"enable_rule", "启用指定负载均衡规则", http.MethodPost, "/rules/{caddy_id}/enable", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"disable_rule", "禁用指定负载均衡规则", http.MethodPut, "/rules/{caddy_id}/disable", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"duplicate_rule", "复制指定负载均衡规则", http.MethodPost, "/rules/{caddy_id}/duplicate", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"update_rule_acl", "更新指定规则的 IP 访问控制", http.MethodPost, "/rules/{caddy_id}/acl", []string{"caddy_id"}, nil, aclSchema},
	{"list_cert_jobs", "列出证书签发任务", http.MethodGet, "/certificates/jobs", nil, []string{"rule_id"}, querySchema("rule_id", "按规则 ID 过滤", "string")},
	{"retry_cert_job", "重试指定证书签发任务", http.MethodPost, "/certificates/jobs/{id}/retry", []string{"id"}, nil, idSchema("id", "证书任务 ID", "integer")},
	{"delete_cert_job", "删除指定证书签发任务", http.MethodDelete, "/certificates/jobs/{id}", []string{"id"}, nil, idSchema("id", "证书任务 ID", "integer")},
	{"issue_certificate", "触发 ACME 证书签发", http.MethodPost, "/certificates/issue", nil, nil, issueCertificateSchema},
	{"list_certificates", "列出 Caddy 当前证书", http.MethodGet, "/certificates", nil, nil, emptySchema},
	{"get_config", "读取全局配置", http.MethodGet, "/config", nil, nil, emptySchema},
	{"update_config", "更新全局配置并应用 Caddy", http.MethodPut, "/config", nil, nil, updateConfigSchema},
	{"reload_caddy", "从数据库重新生成并加载 Caddy 配置", http.MethodPost, "/config/reload", nil, nil, emptySchema},
	{"export_config", "导出完整配置备份", http.MethodGet, "/config/export", nil, nil, emptySchema},
	{"get_metrics_overview", "获取指标总览", http.MethodGet, "/metrics/overview", nil, nil, emptySchema},
	{"get_realtime_traffic", "获取实时流量", http.MethodGet, "/metrics/realtime", nil, nil, emptySchema},
	{"get_upstream_health", "获取上游健康状态", http.MethodGet, "/config/health", nil, nil, emptySchema},
	{"list_audit_logs", "分页列出操作审计日志", http.MethodGet, "/audit-logs", nil, []string{"page", "page_size"}, auditLogsSchema},
	{"get_system_info", "获取系统信息", http.MethodGet, "/system/info", nil, nil, emptySchema},
	{"list_users", "列出用户", http.MethodGet, "/users", nil, nil, emptySchema},
	{"list_api_keys", "列出 API 密钥（不返回密钥明文）", http.MethodGet, "/api-keys", nil, nil, emptySchema},
	{"get_cluster_status", "获取当前节点集群状态", http.MethodGet, "/cluster/status", nil, nil, emptySchema},
}

const emptySchema = `{"type":"object","properties":{},"additionalProperties":false}`
const maxResponseSize = 4 << 20
const InternalAuthHeader = "X-Lazy-Balancer-Internal-MCP-Auth"

const createRuleSchema = `{"type":"object","required":["name","protocol","listen_port","upstreams"],"properties":{"name":{"type":"string"},"description":{"type":"string"},"protocol":{"type":"string","enum":["http","tcp"]},"domain":{"type":"string"},"listen_port":{"type":"integer","minimum":1,"maximum":65535},"strategy":{"type":"string"},"dynamic_dns":{"type":"boolean"},"enable_dns_server":{"type":"boolean"},"dns_server":{"type":"string"},"dns_family":{"type":"string","enum":["ipv4","ipv6","both"]},"health_check_path":{"type":"string"},"health_check_interval":{"type":"integer"},"health_check_timeout":{"type":"integer"},"health_check_unhealthy_threshold":{"type":"integer"},"health_check_healthy_threshold":{"type":"integer"},"enable_active_health_check":{"type":"boolean"},"tcp_health_check_port":{"type":"integer"},"tcp_proxy_protocol":{"type":"boolean"},"tcp_try_duration":{"type":"integer"},"tcp_try_interval":{"type":"integer"},"request_body_max_size_mb":{"type":"integer"},"upstream_keepalive_timeout":{"type":"integer"},"server_tokens_hidden":{"type":"integer"},"ip_acl_mode":{"type":"string","enum":["","allow","deny"]},"ip_acl_list":{"type":"array","items":{"type":"string"}},"custom_routes_enabled":{"type":"boolean"},"proxy_dial_timeout":{"type":"integer"},"proxy_response_header_timeout":{"type":"integer"},"proxy_read_timeout":{"type":"integer"},"proxy_write_timeout":{"type":"integer"},"proxy_stream_timeout":{"type":"integer"},"path_rules":{"type":"array","items":{"type":"object"}},"host_header":{"type":"string"},"upstreams":{"type":"array","items":{"type":"object","required":["host","port"],"properties":{"host":{"type":"string"},"port":{"type":"integer"},"weight":{"type":"integer"},"domain":{"type":"string"},"dynamic_dns":{"type":"boolean"},"enabled":{"type":"boolean"},"protocol":{"type":"string"},"dns_server":{"type":"string"},"max_connections":{"type":"integer"}}}},"enable_tls":{"type":"boolean"},"tls_source":{"type":"string"},"acme_config_id":{"type":"integer"},"ca_provider_id":{"type":"integer"},"tls_cert":{"type":"string"},"tls_key":{"type":"string"},"tls_http_redirect":{"type":"boolean"},"enable_compress":{"type":"boolean"},"compress_types":{"type":"string"},"log_enabled":{"type":"boolean"}},"additionalProperties":false}`

const updateRuleSchema = `{"type":"object","required":["caddy_id"],"properties":{"caddy_id":{"type":"string"},"name":{"type":"string"},"description":{"type":"string"},"protocol":{"type":"string"},"domain":{"type":"string"},"listen_port":{"type":"integer"},"strategy":{"type":"string"},"dynamic_dns":{"type":"boolean"},"enable_dns_server":{"type":"boolean"},"dns_server":{"type":"string"},"dns_family":{"type":"string"},"health_check_path":{"type":"string"},"health_check_interval":{"type":"integer"},"health_check_timeout":{"type":"integer"},"health_check_unhealthy_threshold":{"type":"integer"},"health_check_healthy_threshold":{"type":"integer"},"enable_active_health_check":{"type":"boolean"},"tcp_health_check_port":{"type":"integer"},"tcp_proxy_protocol":{"type":"boolean"},"tcp_try_duration":{"type":"integer"},"tcp_try_interval":{"type":"integer"},"request_body_max_size_mb":{"type":"integer"},"upstream_keepalive_timeout":{"type":"integer"},"server_tokens_hidden":{"type":"integer"},"ip_acl_mode":{"type":"string"},"ip_acl_list":{"type":"array","items":{"type":"string"}},"custom_routes_enabled":{"type":"boolean"},"proxy_dial_timeout":{"type":"integer"},"proxy_response_header_timeout":{"type":"integer"},"proxy_read_timeout":{"type":"integer"},"proxy_write_timeout":{"type":"integer"},"proxy_stream_timeout":{"type":"integer"},"path_rules":{"type":"array","items":{"type":"object"}},"host_header":{"type":"string"},"upstreams":{"type":"array","items":{"type":"object"}},"enable_tls":{"type":"boolean"},"tls_source":{"type":"string"},"acme_config_id":{"type":"integer"},"ca_provider_id":{"type":"integer"},"tls_cert":{"type":"string"},"tls_key":{"type":"string"},"tls_http_redirect":{"type":"boolean"},"enable_compress":{"type":"boolean"},"compress_types":{"type":"string"},"enabled":{"type":"boolean"},"log_enabled":{"type":"boolean"}},"additionalProperties":false}`

const aclSchema = `{"type":"object","required":["caddy_id","ip_acl_mode","ip_acl_list"],"properties":{"caddy_id":{"type":"string"},"ip_acl_mode":{"type":"string","enum":["","allow","deny"]},"ip_acl_list":{"type":"array","items":{"type":"string"}}},"additionalProperties":false}`
const issueCertificateSchema = `{"type":"object","properties":{"caddy_id":{"type":"string"},"domain":{"type":"string"}},"oneOf":[{"maxProperties":0},{"required":["caddy_id","domain"]}],"additionalProperties":false}`
const auditLogsSchema = `{"type":"object","properties":{"page":{"type":"integer","minimum":1,"default":1},"page_size":{"type":"integer","minimum":1,"maximum":100,"default":20}},"additionalProperties":false}`
const updateConfigSchema = `{"type":"object","properties":{"source":{"type":"string"},"dns_provider":{"type":"string"},"dns_credentials":{"type":"string"},"acme_email":{"type":"string"},"cert_expiry_days":{"type":"integer"},"cert_renewal_days":{"type":"integer"},"cert_renewal_attempts":{"type":"integer"},"log_level":{"type":"string"},"caddy_log_level":{"type":"string"},"caddy_log_size_mb":{"type":"integer"},"request_body_max_size_mb":{"type":"integer"},"http_read_timeout":{"type":"integer"},"http_write_timeout":{"type":"integer"},"http_idle_timeout":{"type":"integer"},"upstream_keepalive_timeout":{"type":"integer"},"proxy_dial_timeout":{"type":"integer"},"proxy_response_header_timeout":{"type":"integer"},"proxy_read_timeout":{"type":"integer"},"proxy_write_timeout":{"type":"integer"},"proxy_stream_timeout":{"type":"integer"},"server_tokens_hidden":{"type":"boolean"},"cert_job_log_size_mb":{"type":"integer"},"runtime_log_size_mb":{"type":"integer"},"access_log_json":{"type":"boolean"},"access_log_format":{"type":"string"},"audit_retention_months":{"type":"integer"},"jwt_expire_minutes":{"type":"integer"},"timezone":{"type":"string"},"default_ca_provider_id":{"type":"integer"}},"additionalProperties":false}`

func New(baseURL string, client *http.Client) http.Handler {
	return NewWithInternalAuth(baseURL, client, "")
}

func NewWithInternalAuth(baseURL string, client *http.Client, internalAuthSecret string) http.Handler {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	mcpServer := server.NewMCPServer("Lazy Balancer V2", "1.0.0", server.WithToolCapabilities(false))
	for _, spec := range tools {
		spec := spec
		mcpServer.AddTool(mcp.NewToolWithRawSchema(spec.name, spec.description, json.RawMessage(spec.schema)), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return forward(ctx, client, baseURL, internalAuthSecret, spec, request)
		})
	}
	return server.NewStreamableHTTPServer(mcpServer, server.WithStateLess(true), server.WithEndpointPath("/api/v1/mcp"))
}

func forward(ctx context.Context, client *http.Client, baseURL, internalAuthSecret string, spec toolSpec, call mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	arguments := call.GetArguments()
	path := spec.path
	for _, name := range spec.pathArgs {
		value, ok := arguments[name]
		if !ok {
			return nil, fmt.Errorf("缺少参数 %s", name)
		}
		path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(fmt.Sprint(value)))
	}
	endpoint, err := url.Parse(strings.TrimRight(baseURL, "/") + path)
	if err != nil {
		return nil, fmt.Errorf("构造内部 API 地址: %w", err)
	}
	query := endpoint.Query()
	for _, name := range spec.queryArgs {
		if value, ok := arguments[name]; ok && fmt.Sprint(value) != "" {
			query.Set(name, scalarString(value))
		}
	}
	endpoint.RawQuery = query.Encode()

	bodyArguments := make(map[string]any, len(arguments))
	for key, value := range arguments {
		bodyArguments[key] = value
	}
	if spec.name == "create_rule" {
		if upstreams, ok := bodyArguments["upstreams"].([]any); ok {
			for _, upstream := range upstreams {
				if fields, ok := upstream.(map[string]any); ok {
					if _, exists := fields["enabled"]; !exists {
						fields["enabled"] = true
					}
				}
			}
		}
	}
	for _, name := range append(append([]string{}, spec.pathArgs...), spec.queryArgs...) {
		delete(bodyArguments, name)
	}
	var bodyBytes []byte
	if spec.method == http.MethodPost || spec.method == http.MethodPut || spec.method == http.MethodPatch {
		if len(bodyArguments) > 0 {
			bodyBytes, err = json.Marshal(bodyArguments)
			if err != nil {
				return nil, fmt.Errorf("序列化工具参数: %w", err)
			}
		}
	}
	var body io.Reader
	if bodyBytes != nil {
		body = bytes.NewReader(bodyBytes)
	}
	request, err := http.NewRequestWithContext(ctx, spec.method, endpoint.String(), body)
	if err != nil {
		return nil, fmt.Errorf("创建内部 API 请求: %w", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if apiKey := extractAPIKey(call.Header); apiKey != "" {
		request.Header.Set("X-API-Key", apiKey)
	} else {
		return nil, fmt.Errorf("MCP 请求缺少 API 密钥")
	}
	if internalAuthSecret != "" {
		request.Header.Set(InternalAuthHeader, internalAuthSecret)
	}
	redirectlessClient := *client
	redirectlessClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := redirectlessClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("内部 API 请求失败: %w", err)
	}
	// 面板启用 HTTPS 时 HTTP 请求会收到 301；客户端不自动跟随（避免 POST 变 GET），
	// 这里按原方法原请求体重试一次重定向地址
	if response.StatusCode == http.StatusMovedPermanently || response.StatusCode == http.StatusTemporaryRedirect || response.StatusCode == http.StatusPermanentRedirect {
		location := response.Header.Get("Location")
		response.Body.Close()
		if location == "" {
			return nil, fmt.Errorf("内部 API 重定向缺少目标地址")
		}
		redirectURL, err := request.URL.Parse(location)
		if err != nil {
			return nil, fmt.Errorf("解析内部 API 重定向地址: %w", err)
		}
		if !isLoopbackHTTPURL(redirectURL) {
			return nil, fmt.Errorf("拒绝非回环内部 API 重定向地址")
		}
		var retryBody io.Reader
		if bodyBytes != nil {
			retryBody = bytes.NewReader(bodyBytes)
		}
		request, err = http.NewRequestWithContext(ctx, spec.method, redirectURL.String(), retryBody)
		if err != nil {
			return nil, fmt.Errorf("创建重定向请求失败: %w", err)
		}
		if retryBody != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		request.Header.Set("X-API-Key", extractAPIKey(call.Header))
		if internalAuthSecret != "" {
			request.Header.Set(InternalAuthHeader, internalAuthSecret)
		}
		response, err = redirectlessClient.Do(request)
		if err != nil {
			return nil, fmt.Errorf("内部 API 请求失败: %w", err)
		}
		if response.StatusCode == http.StatusMovedPermanently || response.StatusCode == http.StatusTemporaryRedirect || response.StatusCode == http.StatusPermanentRedirect {
			response.Body.Close()
			return nil, fmt.Errorf("内部 API 重定向次数超过限制")
		}
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("读取内部 API 响应: %w", err)
	}
	if len(responseBody) > maxResponseSize {
		result := mcp.NewToolResultText("内部 API 响应超过 4 MiB 上限，请改用分页或专用导出工具")
		result.IsError = true
		return result, nil
	}
	if len(responseBody) == 0 {
		responseBody = []byte(`{}`)
	}
	result := mcp.NewToolResultText(string(responseBody))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		result.IsError = true
	}
	return result, nil
}

func isLoopbackHTTPURL(target *url.URL) bool {
	if target.Scheme != "http" && target.Scheme != "https" {
		return false
	}
	hostname := target.Hostname()
	return hostname == "localhost" || net.ParseIP(hostname).IsLoopback()
}

func extractAPIKey(header http.Header) string {
	if apiKey := header.Get("X-API-Key"); apiKey != "" {
		return apiKey
	}
	authorization := header.Get("Authorization")
	if strings.HasPrefix(authorization, "Bearer lb_sk_") {
		return strings.TrimPrefix(authorization, "Bearer ")
	}
	return ""
}

func scalarString(value any) string {
	switch value := value.(type) {
	case float64:
		if value == float64(int64(value)) {
			return strconv.FormatInt(int64(value), 10)
		}
	}
	return fmt.Sprint(value)
}

func idSchema(name, description, valueType string) string {
	return fmt.Sprintf(`{"type":"object","required":[%q],"properties":{%q:{"type":%q,"description":%q}},"additionalProperties":false}`, name, name, valueType, description)
}

func querySchema(name, description, valueType string) string {
	return fmt.Sprintf(`{"type":"object","properties":{%q:{"type":%q,"description":%q}},"additionalProperties":false}`, name, valueType, description)
}
