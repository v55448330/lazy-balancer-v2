package mcpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/big"
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
	{"disable_rule", "禁用指定负载均衡规则", http.MethodPost, "/rules/{caddy_id}/disable", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"duplicate_rule", "复制指定负载均衡规则", http.MethodPost, "/rules/{caddy_id}/duplicate", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"list_cert_jobs", "列出证书签发任务", http.MethodGet, "/certificates/jobs", nil, []string{"rule_id", "page", "page_size"}, listCertJobsSchema},
	{"retry_cert_job", "重试指定证书签发任务", http.MethodPost, "/certificates/jobs/{id}/retry", []string{"id"}, nil, idSchema("id", "证书任务 ID", "integer")},
	{"delete_cert_job", "删除指定证书签发任务", http.MethodDelete, "/certificates/jobs/{id}", []string{"id"}, nil, idSchema("id", "证书任务 ID", "integer")},
	{"issue_certificate", "触发 ACME 证书签发", http.MethodPost, "/certificates/issue", nil, nil, issueCertificateSchema},
	{"list_certificates", "列出 Caddy 当前证书", http.MethodGet, "/certificates", nil, nil, emptySchema},
	{"get_config", "读取全局配置", http.MethodGet, "/config", nil, nil, emptySchema},
	{"update_config", "更新全局配置并应用 Caddy", http.MethodPut, "/config", nil, nil, updateConfigSchema},
	{"reload_caddy", "从数据库重新生成并加载 Caddy 配置", http.MethodPost, "/config/reload", nil, nil, emptySchema},
	{"export_config", "导出完整配置备份", http.MethodGet, "/config/export", nil, nil, emptySchema},
	{"get_metrics_dashboard", "获取聚合监控面板指标", http.MethodGet, "/metrics/dashboard", nil, nil, emptySchema},
	{"get_metrics_overview", "获取指标总览", http.MethodGet, "/metrics/overview", nil, nil, emptySchema},
	{"get_realtime_traffic", "获取实时流量", http.MethodGet, "/metrics/realtime", nil, nil, emptySchema},
	{"get_upstream_health", "获取上游健康状态", http.MethodGet, "/config/health", nil, nil, emptySchema},
	{"list_audit_logs", "分页列出操作审计日志", http.MethodGet, "/audit-logs", nil, []string{"page", "page_size", "username", "action", "resource", "ip", "keyword", "start_time", "end_time"}, auditLogsSchema},
	{"get_system_info", "获取系统信息", http.MethodGet, "/system/info", nil, nil, emptySchema},
	{"list_users", "列出用户", http.MethodGet, "/users", nil, nil, emptySchema},
	{"list_api_keys", "列出 API 密钥（不返回密钥明文）", http.MethodGet, "/api-keys", nil, nil, emptySchema},
	{"get_cluster_status", "获取当前节点集群状态", http.MethodGet, "/cluster/status", nil, nil, emptySchema},
	{"get_security_overview", "获取安全总览（今日拦截/检测、攻击类型 TOP、源 IP TOP）", http.MethodGet, "/security/overview", nil, nil, emptySchema},
	{"list_security_policies", "列出全部安全策略", http.MethodGet, "/security/policies", nil, nil, emptySchema},
	{"get_security_policy", "获取指定安全策略详情", http.MethodGet, "/security/policies/{id}", []string{"id"}, nil, idSchema("id", "策略 ID", "integer")},
	{"list_security_events", "分页列出安全事件（WAF 拦截/IP ACL 拒绝），可按负载规则/策略/触发规则/URI 过滤", http.MethodGet, "/security/events", nil, []string{"page", "page_size", "action", "ip", "rule_caddy_id", "rule_name", "policy_name", "rule_triggered", "uri", "start_time", "end_time"}, securityEventsSchema},
	{"list_security_bindings", "列出安全策略与规则的绑定关系", http.MethodGet, "/security/bindings", nil, nil, emptySchema},
	{"get_rule_security_policy", "获取指定规则绑定的安全策略（仅返回 enabled=1 的策略）", http.MethodGet, "/security/rules/{caddy_id}/policy", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"list_custom_rules", "列出全部自定义安全规则", http.MethodGet, "/security/custom-rules", nil, nil, emptySchema},
	{"list_block_pages", "列出全部拦截页面", http.MethodGet, "/security/block-pages", nil, nil, emptySchema},
	{"get_crs_info", "获取 CRS 规则库信息（版本/状态/自动更新）", http.MethodGet, "/security/crs", nil, nil, emptySchema},
	{"get_crs_update_status", "获取 CRS 更新进度状态", http.MethodGet, "/security/crs/update/status", nil, nil, emptySchema},
	{"get_crs_update_logs", "获取 CRS 更新日志", http.MethodGet, "/security/crs/update/logs", nil, nil, emptySchema},
	{"list_crs_rules", "分页浏览 CRS 规则文件", http.MethodGet, "/security/crs/rules", nil, []string{"search", "page", "page_size"}, listCRSRulesSchema},
	{"get_crs_rule", "查看指定 CRS 规则文件内容", http.MethodGet, "/security/crs/rules/{filename}", []string{"filename"}, nil, idSchema("filename", "规则文件名", "string")},
	{"get_ip2region_info", "获取 IP2Region 信息（版本/状态/自动更新）", http.MethodGet, "/security/ip2region", nil, nil, emptySchema},
	{"get_ip2region_regions", "获取可选区域列表", http.MethodGet, "/security/ip2region/regions", nil, nil, emptySchema},
	{"get_ip2region_update_status", "获取 IP2Region 更新进度状态", http.MethodGet, "/security/ip2region/update/status", nil, nil, emptySchema},
	{"get_ip2region_update_logs", "获取 IP2Region 更新日志", http.MethodGet, "/security/ip2region/update/logs", nil, nil, emptySchema},
	{"get_rate_limit_blocks", "获取限流拦截统计", http.MethodGet, "/security/rate-limit-blocks", nil, nil, emptySchema},
	{"create_security_policy", "创建安全策略（WAF 模式/CRS/IP ACL/GeoIP/限流/拦截页面）", http.MethodPost, "/security/policies", nil, nil, bodySchema},
	{"update_security_policy", "更新指定安全策略", http.MethodPut, "/security/policies/{id}", []string{"id"}, nil, bodySchema},
	{"delete_security_policy", "删除指定安全策略", http.MethodDelete, "/security/policies/{id}", []string{"id"}, nil, idSchema("id", "策略 ID", "integer")},
	{"bind_security_policy", "将安全策略绑定到指定规则", http.MethodPost, "/security/policies/{id}/bind", []string{"id"}, nil, bodySchema},
	{"unbind_security_policy", "解除安全策略与规则的绑定", http.MethodDelete, "/security/policies/{id}/bind/{caddy_id}", []string{"id", "caddy_id"}, nil, bodySchema},
	// v2.2.0 多策略绑定：原子替换规则绑定的策略集合（整体替换而非追加），
	// policy_ids maxItems=5 与后端「最多绑定 5 条策略」校验对齐。
	{"set_rule_security_policies", "原子设置规则的安全策略集合（按 policy_id ASC 顺序评估）", http.MethodPut, "/security/rules/{caddy_id}/policies", []string{"caddy_id"}, nil, setRuleSecurityPoliciesSchema},
	{"create_custom_rule", "创建自定义安全规则", http.MethodPost, "/security/custom-rules", nil, nil, bodySchema},
	{"update_custom_rule", "更新指定自定义安全规则", http.MethodPut, "/security/custom-rules/{id}", []string{"id"}, nil, bodySchema},
	{"delete_custom_rule", "删除指定自定义安全规则", http.MethodDelete, "/security/custom-rules/{id}", []string{"id"}, nil, idSchema("id", "规则 ID", "integer")},
	{"create_block_page", "创建拦截页面", http.MethodPost, "/security/block-pages", nil, nil, bodySchema},
	{"update_block_page", "更新指定拦截页面", http.MethodPut, "/security/block-pages/{id}", []string{"id"}, nil, bodySchema},
	{"delete_block_page", "删除指定拦截页面", http.MethodDelete, "/security/block-pages/{id}", []string{"id"}, nil, idSchema("id", "页面 ID", "integer")},
	{"toggle_crs_auto_update", "开关 CRS 自动更新", http.MethodPut, "/security/crs/auto-update", nil, nil, bodySchema},
	{"trigger_crs_update", "手动触发 CRS 规则库更新", http.MethodPost, "/security/crs/update", nil, nil, emptySchema},
	{"toggle_ip2region_auto_update", "开关 IP2Region 自动更新", http.MethodPut, "/security/ip2region/auto-update", nil, nil, bodySchema},
	{"trigger_ip2region_update", "手动触发 IP2Region 数据库更新", http.MethodPost, "/security/ip2region/update", nil, nil, emptySchema},
	{"list_cluster_nodes", "列出全部集群节点", http.MethodGet, "/cluster/nodes", nil, nil, emptySchema},
	{"create_register_token", "生成集群注册令牌", http.MethodPost, "/cluster/register-tokens", nil, nil, bodySchema},
	{"approve_cluster_node", "审批通过从节点注册", http.MethodPost, "/cluster/nodes/{id}/approve", []string{"id"}, nil, idSchema("id", "节点 ID", "integer")},
	{"reject_cluster_node", "拒绝从节点注册", http.MethodPost, "/cluster/nodes/{id}/reject", []string{"id"}, nil, idSchema("id", "节点 ID", "integer")},
	{"create_login_ticket", "为从节点生成登录票据（操作者账户必须已启用 MFA，否则 403；人类 JWT 路径还需 60 秒内通过 MFA 验证（428 step-up），API Key/MCP 路径仅豁免该验证窗口）", http.MethodPost, "/cluster/nodes/{id}/login-ticket", []string{"id"}, nil, idSchema("id", "节点 ID", "integer")},
	{"update_node_access_url", "更新从节点访问地址", http.MethodPut, "/cluster/nodes/{id}/access-url", []string{"id"}, nil, bodySchema},
	{"delete_cluster_node", "删除指定集群节点", http.MethodDelete, "/cluster/nodes/{id}", []string{"id"}, nil, idSchema("id", "节点 ID", "integer")},
	{"set_cluster_mode", "注册并切换为从节点（standalone/master → slave，需主节点审批）", http.MethodPost, "/cluster/mode", nil, nil, bodySchema},
	{"promote_cluster", "将从节点提升为主节点", http.MethodPost, "/cluster/promote", nil, nil, emptySchema},
	{"pull_sync", "手动触发从节点同步", http.MethodPost, "/cluster/sync/pull", nil, nil, emptySchema},
	{"update_cluster_settings", "更新集群同步设置", http.MethodPut, "/cluster/settings", nil, nil, bodySchema},
	{"list_certificate_configs", "列出全部 DNS 证书配置", http.MethodGet, "/certificate-configs", nil, nil, emptySchema},
	{"create_certificate_config", "创建 DNS 证书配置", http.MethodPost, "/certificate-configs", nil, nil, bodySchema},
	{"update_certificate_config", "更新指定 DNS 证书配置", http.MethodPut, "/certificate-configs/{id}", []string{"id"}, nil, bodySchema},
	{"delete_certificate_config", "删除指定 DNS 证书配置", http.MethodDelete, "/certificate-configs/{id}", []string{"id"}, nil, idSchema("id", "配置 ID", "integer")},
	// R72 二十八次审计 F2：handler 要求 body 携带 domain（测试用的域名）——此前
	// schema 只有 id（additionalProperties:false），经 MCP 调用恒 400「请求参数
	// 无效」。id 进路径、domain 进 body（转发器按 pathParams 分流）。
	{"test_certificate_config", "测试指定 DNS 证书配置", http.MethodPost, "/certificate-configs/{id}/test", []string{"id"}, nil, `{"type":"object","required":["id","domain"],"properties":{"id":{"type":"integer","description":"配置 ID"},"domain":{"type":"string","description":"用于测试的域名，如 example.com"}},"additionalProperties":false}`},
	{"list_dns_providers", "列出支持的 DNS 提供商", http.MethodGet, "/dns-providers", nil, nil, emptySchema},
	{"list_ca_providers", "列出全部 CA 提供商", http.MethodGet, "/ca-providers", nil, nil, emptySchema},
	{"get_ca_provider", "获取指定 CA 提供商详情", http.MethodGet, "/ca-providers/{id}", []string{"id"}, nil, idSchema("id", "CA ID", "integer")},
	{"update_ca_provider", "更新指定 CA 提供商", http.MethodPut, "/ca-providers/{id}", []string{"id"}, nil, bodySchema},
	{"test_ca_provider", "测试指定 CA 提供商连接", http.MethodPost, "/ca-providers/{id}/test", []string{"id"}, nil, idSchema("id", "CA ID", "integer")},
	{"get_cert_job", "获取指定证书签发任务详情", http.MethodGet, "/certificates/jobs/{id}", []string{"id"}, nil, idSchema("id", "任务 ID", "integer")},
	{"get_cert_job_logs", "获取指定证书签发任务日志", http.MethodGet, "/certificates/jobs/{id}/logs", []string{"id"}, nil, idSchema("id", "任务 ID", "integer")},
	{"parse_certificate", "解析上传的证书内容", http.MethodPost, "/certificates/parse", nil, nil, bodySchema},
	{"create_user", "创建用户", http.MethodPost, "/users", nil, nil, bodySchema},
	{"update_user", "更新指定用户", http.MethodPut, "/users/{id}", []string{"id"}, nil, bodySchema},
	{"toggle_user_status", "启用/禁用指定用户", http.MethodPut, "/users/{id}/status", []string{"id"}, nil, bodySchema},
	{"reset_user_password", "重置指定用户密码", http.MethodPost, "/users/{id}/reset-password", []string{"id"}, nil, idSchema("id", "用户 ID", "integer")},
	{"delete_user", "删除指定用户", http.MethodDelete, "/users/{id}", []string{"id"}, nil, idSchema("id", "用户 ID", "integer")},
	{"create_api_key", "创建 API 密钥", http.MethodPost, "/api-keys", nil, nil, bodySchema},
	{"update_api_key_status", "更新 API 密钥状态（启用/只读/MCP 开关）", http.MethodPatch, "/api-keys/{id}/status", []string{"id"}, nil, bodySchema},
	{"delete_api_key", "删除指定 API 密钥", http.MethodDelete, "/api-keys/{id}", []string{"id"}, nil, idSchema("id", "密钥 ID", "integer")},
	{"preview_config", "预览配置变更（不应用）", http.MethodPost, "/config/preview", nil, nil, bodySchema},
	{"validate_config", "验证配置文件有效性", http.MethodPost, "/config/validate", nil, nil, bodySchema},
	{"import_config", "导入 v2 配置备份", http.MethodPost, "/config/import", nil, nil, bodySchema},
	{"validate_import", "验证导入文件（不写入）", http.MethodPost, "/config/import/validate", nil, nil, bodySchema},
	{"import_v1_config", "导入 v1（nginx）配置", http.MethodPost, "/config/import/v1", nil, nil, bodySchema},
	{"get_rule_caddy_config", "获取指定规则的 Caddy 配置片段", http.MethodGet, "/rules/{caddy_id}/caddy-config", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"get_rule_metrics_history", "获取指定规则的历史指标", http.MethodGet, "/rules/{caddy_id}/metrics-history", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"get_rule_logs", "获取指定规则的访问日志", http.MethodGet, "/rules/{caddy_id}/logs", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"get_rule_cert_info", "获取指定规则的证书信息", http.MethodGet, "/rules/{caddy_id}/cert-info", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"get_caddy_status", "获取 Caddy 运行状态", http.MethodGet, "/caddy/status", nil, nil, emptySchema},
	{"get_caddy_config", "获取 Caddy 当前配置", http.MethodGet, "/caddy/config", nil, nil, emptySchema},
	{"get_caddy_logs", "获取 Caddy 日志", http.MethodGet, "/caddy/logs", nil, []string{"type"}, caddyLogsSchema},
	{"update_caddy_config", "直接更新 Caddy 配置", http.MethodPut, "/caddy/config", nil, nil, bodySchema},
	{"start_caddy", "启动 Caddy", http.MethodPost, "/caddy/start", nil, nil, emptySchema},
	{"stop_caddy", "停止 Caddy", http.MethodPost, "/caddy/stop", nil, nil, emptySchema},
	{"restart_caddy", "重启 Caddy", http.MethodPost, "/caddy/restart", nil, nil, emptySchema},
	{"get_admin_tls", "获取管理面板 HTTPS 配置", http.MethodGet, "/admin-tls", nil, nil, emptySchema},
	{"update_admin_tls", "更新管理面板 HTTPS 配置", http.MethodPut, "/admin-tls", nil, nil, bodySchema},
	{"inspect_admin_tls", "检查管理面板 HTTPS 证书", http.MethodPost, "/admin-tls/inspect", nil, nil, bodySchema},
	{"get_system_metrics", "获取系统资源指标（CPU/内存/磁盘）", http.MethodGet, "/system/metrics", nil, nil, emptySchema},
	{"get_system_logs", "获取应用日志", http.MethodGet, "/system/logs", nil, nil, emptySchema},
	{"restart_system", "重启应用服务", http.MethodPost, "/system/restart", nil, nil, emptySchema},
	{"get_rule_metrics", "获取指定规则的实时指标", http.MethodGet, "/metrics/rule/{caddy_id}", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"get_metrics_history", "获取历史指标趋势", http.MethodGet, "/metrics/history", nil, []string{"rule_id", "interval"}, metricsHistorySchema},
	{"get_connections", "获取当前连接统计", http.MethodGet, "/metrics/connections", nil, nil, emptySchema},
}

const emptySchema = `{"type":"object","properties":{},"additionalProperties":false}`
const bodySchema = `{"type":"object","additionalProperties":true}`
const maxResponseSize = 4 << 20
const InternalAuthHeader = "X-Lazy-Balancer-Internal-MCP-Auth"

// serverInstructions 随 initialize 响应下发给客户端，说明认证方式、权限范围与常用流程，
// 让 Agent 在首次选工具前就能选对路径、减少试错往返
const serverInstructions = `Lazy Balancer V2 负载均衡管理接口。认证：X-API-Key 头或 Authorization: Bearer lb_sk_...，Key 需开启 MCP 功能。

权限范围：
- 只读 Key（read_only）仅能调用 GET 查询类工具；写工具（POST/PUT/DELETE）需非只读 Key
- 写操作需要管理员权限（API Key 所属用户角色为 admin），非管理员 Key 调用写工具返回 403
- 写操作仅在主节点可用，从节点一律 403；所有写操作校验后即时生效（失败自动回滚），无需手动 reload
- 配置 IP 白名单的 Key 还需来源 IP 命中白名单（MCP 内部转发不受白名单影响）

常用流程：
- 新建 HTTP 代理：create_rule（protocol=http + domain + listen_port + upstreams）→ 需要免费证书时 issue_certificate 传 caddy_id
- 新建 TCP 代理：create_rule（protocol=tcp + listen_port + upstreams，不要填 domain）；后端需真实客户端 IP 时加 tcp_proxy_protocol=true
- 排查流量异常：get_upstream_health → get_metrics_dashboard → list_audit_logs（page/page_size 分页，page_size≤100）
- 快速看全局指标：get_metrics_overview（轻量）；get_metrics_dashboard 为全量聚合，数据量大，非必要不用
- 修改规则前先 get_rule 取完整现状；delete_rule 不可恢复，调用前必须确认

错误约定：401=密钥无效或未开启 MCP；403=只读 Key 调写工具/从节点写操作/IP 白名单拦截；-32602=参数不符合工具的 input_schema（先看 schema 再重试，不要猜测字段名）。

完整操作手册：resources/read 读取 lazy-balancer://docs/ops-playbook（接入/scope/工作流/排障/纪律/性能建议）。`

//go:embed playbook.md
var opsPlaybook string

const opsPlaybookURI = "lazy-balancer://docs/ops-playbook"

// OpsPlaybook 返回手册正文，供 MCP 资源与 REST 下载端点共用同一来源
func OpsPlaybook() string { return opsPlaybook }

// toolDescription 组合一句话描述与用法提示，随 tools/list 暴露给客户端
func toolDescription(spec toolSpec) string {
	if usage := toolUsage[spec.name]; usage != "" {
		return spec.description + "。用法：" + usage
	}
	return spec.description
}

const createRuleSchema = `{"type":"object","required":["name","protocol","listen_port","upstreams"],"properties":{"name":{"type":"string"},"description":{"type":"string"},"protocol":{"type":"string","enum":["http","tcp"]},"domain":{"type":"string"},"listen_port":{"type":"integer","minimum":1,"maximum":65535},"strategy":{"type":"string"},"dynamic_dns":{"type":"boolean"},"enable_dns_server":{"type":"boolean"},"dns_server":{"type":"string"},"dns_family":{"type":"string","enum":["ipv4","ipv6","both"]},"health_check_path":{"type":"string"},"health_check_interval":{"type":"integer"},"health_check_timeout":{"type":"integer"},"health_check_unhealthy_threshold":{"type":"integer"},"health_check_healthy_threshold":{"type":"integer"},"enable_active_health_check":{"type":"boolean"},"tcp_health_check_port":{"type":"integer"},"tcp_proxy_protocol":{"type":"boolean"},"tcp_try_duration":{"type":"integer"},"tcp_try_interval":{"type":"integer"},"request_body_max_size_mb":{"type":"integer"},"upstream_keepalive_timeout":{"type":"integer"},"server_tokens_hidden":{"type":"integer"},"custom_routes_enabled":{"type":"boolean"},"proxy_dial_timeout":{"type":"integer","minimum":0},"proxy_response_header_timeout":{"type":"integer","minimum":0},"proxy_read_timeout":{"type":"integer","minimum":0},"proxy_write_timeout":{"type":"integer","minimum":0},"proxy_stream_timeout":{"type":"integer","minimum":0},"proxy_flush_interval":{"type":"integer","minimum":-1},"proxy_stream_close_delay":{"type":"integer","minimum":0},"path_rules":{"type":"array","items":{"type":"object"}},"host_header":{"type":"string"},"upstreams":{"type":"array","items":{"type":"object","required":["host","port"],"properties":{"host":{"type":"string"},"port":{"type":"integer"},"weight":{"type":"integer"},"dynamic_dns":{"type":"boolean"},"enabled":{"type":"boolean"},"protocol":{"type":"string"},"max_connections":{"type":"integer"}}}},"enable_tls":{"type":"boolean"},"tls_source":{"type":"string"},"acme_config_id":{"type":"integer"},"ca_provider_id":{"type":"integer"},"tls_cert":{"type":"string"},"tls_key":{"type":"string"},"tls_http_redirect":{"type":"boolean"},"enable_compress":{"type":"boolean"},"compress_types":{"type":"string"},"log_enabled":{"type":"boolean"}},"additionalProperties":false}`

const updateRuleSchema = `{"type":"object","required":["caddy_id"],"properties":{"caddy_id":{"type":"string"},"name":{"type":"string"},"description":{"type":"string"},"protocol":{"type":"string"},"domain":{"type":"string"},"listen_port":{"type":"integer"},"strategy":{"type":"string"},"dynamic_dns":{"type":"boolean"},"enable_dns_server":{"type":"boolean"},"dns_server":{"type":"string"},"dns_family":{"type":"string"},"health_check_path":{"type":"string"},"health_check_interval":{"type":"integer"},"health_check_timeout":{"type":"integer"},"health_check_unhealthy_threshold":{"type":"integer"},"health_check_healthy_threshold":{"type":"integer"},"enable_active_health_check":{"type":"boolean"},"tcp_health_check_port":{"type":"integer"},"tcp_proxy_protocol":{"type":"boolean"},"tcp_try_duration":{"type":"integer"},"tcp_try_interval":{"type":"integer"},"request_body_max_size_mb":{"type":"integer"},"upstream_keepalive_timeout":{"type":"integer"},"server_tokens_hidden":{"type":"integer"},"custom_routes_enabled":{"type":"boolean"},"proxy_dial_timeout":{"type":"integer","minimum":0},"proxy_response_header_timeout":{"type":"integer","minimum":0},"proxy_read_timeout":{"type":"integer","minimum":0},"proxy_write_timeout":{"type":"integer","minimum":0},"proxy_stream_timeout":{"type":"integer","minimum":0},"proxy_flush_interval":{"type":"integer","minimum":-1},"proxy_stream_close_delay":{"type":"integer","minimum":0},"path_rules":{"type":"array","items":{"type":"object"}},"host_header":{"type":"string"},"upstreams":{"type":"array","items":{"type":"object"}},"enable_tls":{"type":"boolean"},"tls_source":{"type":"string"},"acme_config_id":{"type":"integer"},"ca_provider_id":{"type":"integer"},"tls_cert":{"type":"string"},"tls_key":{"type":"string"},"tls_http_redirect":{"type":"boolean"},"enable_compress":{"type":"boolean"},"compress_types":{"type":"string"},"enabled":{"type":"boolean"},"log_enabled":{"type":"boolean"}},"additionalProperties":false}`

const issueCertificateSchema = `{"type":"object","properties":{"caddy_id":{"type":"string"},"domain":{"type":"string"}},"oneOf":[{"maxProperties":0},{"required":["caddy_id"]}],"additionalProperties":false}`
const auditLogsSchema = `{"type":"object","properties":{"page":{"type":"integer","minimum":1,"default":1},"page_size":{"type":"integer","minimum":1,"maximum":100,"default":20},"username":{"type":"string","description":"操作人模糊筛选"},"action":{"type":"string","description":"操作模糊筛选"},"resource":{"type":"string","description":"对象模糊筛选"},"ip":{"type":"string","description":"IP 模糊筛选"},"keyword":{"type":"string","description":"详情关键词"},"start_time":{"type":"string","description":"开始时间（配置时区，YYYY-MM-DD[ HH:MM:SS]）"},"end_time":{"type":"string","description":"结束时间（配置时区，YYYY-MM-DD[ HH:MM:SS]）"}},"additionalProperties":false}`

// R68 B-F2：schema 必须覆盖 queryArgs 声明的全部参数——mcp-go 在工具处理器前
// 按 input_schema 强校验（additionalProperties:false），querySchema("search")
// 会把 Agent 按工具描述传的 page/page_size 以 -32602 拒绝，分页永远不可达。
// 边界与 REST clamp 对齐（ListCRSRules page_size≤100 默认 50；cert jobs
// page≤1000000、page_size≤200 默认 50——见 ListCertJobs maxCertJobPage）。
const listCRSRulesSchema = `{"type":"object","properties":{"search":{"type":"string","description":"搜索关键词"},"page":{"type":"integer","minimum":1,"default":1},"page_size":{"type":"integer","minimum":1,"maximum":100,"default":50}},"additionalProperties":false}`
const listCertJobsSchema = `{"type":"object","properties":{"rule_id":{"type":"string","description":"按规则 ID 过滤"},"page":{"type":"integer","minimum":1,"maximum":1000000,"default":1},"page_size":{"type":"integer","minimum":1,"maximum":200,"default":50}},"additionalProperties":false}`
const securityEventsSchema = `{"type":"object","properties":{"page":{"type":"integer","minimum":1,"default":1},"page_size":{"type":"integer","minimum":1,"maximum":100,"default":20},"action":{"type":"string"},"ip":{"type":"string"},"rule_caddy_id":{"type":"string"},"rule_name":{"type":"string","description":"按负载规则名称过滤（子串）"},"policy_name":{"type":"string","description":"按安全策略名称过滤（子串）"},"rule_triggered":{"type":"string","description":"按触发规则过滤（CRS 规则 ID，或 IP 访问控制/请求阻断评估/协议异常/协议攻击/自定义规则 家族标签）"},"uri":{"type":"string","description":"按请求 URI 过滤（子串）"},"start_time":{"type":"string","description":"开始时间（配置时区，YYYY-MM-DD[ HH:MM:SS]）"},"end_time":{"type":"string","description":"结束时间（配置时区，YYYY-MM-DD[ HH:MM:SS]）"}},"additionalProperties":false}`
const caddyLogsSchema = `{"type":"object","properties":{"type":{"type":"string","enum":["runtime","server","proxy","tls"]}},"additionalProperties":false}`
const metricsHistorySchema = `{"type":"object","properties":{"rule_id":{"type":"string","description":"可选规则 ID（Caddy ID），省略时返回全局聚合趋势"},"interval":{"type":"string","description":"时间范围（如 1h、24h、7d），默认 1h"}},"additionalProperties":false}`

// setRuleSecurityPoliciesSchema（v2.2.0 多策略绑定）：maxItems=5 与后端
// SetRuleSecurityPolicies 的「最多绑定 5 条策略」校验对齐，避免 MCP 放行后端拒绝的载荷。
const setRuleSecurityPoliciesSchema = `{"type":"object","required":["caddy_id","policy_ids"],"properties":{"caddy_id":{"type":"string","description":"规则 Caddy ID"},"policy_ids":{"type":"array","items":{"type":"integer"},"maxItems":5,"description":"策略 ID 列表（整体替换现有绑定，按 policy_id ASC 顺序评估）"}},"additionalProperties":false}`
const updateConfigSchema = `{"type":"object","properties":{"source":{"type":"string"},"dns_provider":{"type":"string"},"dns_credentials":{"type":"string"},"acme_email":{"type":"string"},"cert_expiry_days":{"type":"integer"},"cert_renewal_days":{"type":"integer"},"cert_renewal_attempts":{"type":"integer"},"log_level":{"type":"string"},"caddy_log_level":{"type":"string"},"caddy_log_size_mb":{"type":"integer"},"request_body_max_size_mb":{"type":"integer"},"http_read_timeout":{"type":"integer"},"http_write_timeout":{"type":"integer"},"http_idle_timeout":{"type":"integer"},"upstream_keepalive_timeout":{"type":"integer"},"proxy_dial_timeout":{"type":"integer","minimum":0},"proxy_response_header_timeout":{"type":"integer","minimum":0},"proxy_read_timeout":{"type":"integer","minimum":0},"proxy_write_timeout":{"type":"integer","minimum":0},"proxy_stream_timeout":{"type":"integer","minimum":0},"proxy_flush_interval":{"type":"integer","minimum":-1},"proxy_stream_close_delay":{"type":"integer","minimum":0},"server_tokens_hidden":{"type":"boolean"},"cert_job_log_size_mb":{"type":"integer"},"runtime_log_size_mb":{"type":"integer"},"access_log_json":{"type":"boolean"},"access_log_format":{"type":"string"},"audit_retention_months":{"type":"integer"},"jwt_expire_minutes":{"type":"integer"},"timezone":{"type":"string"},"default_ca_provider_id":{"type":"integer"},"audit_log_size_mb":{"type":"integer"},"mfa_write_guard":{"type":"boolean"},"mfa_lockout_enabled":{"type":"boolean"}},"additionalProperties":false}`

func New(baseURL string, client *http.Client) http.Handler {
	return NewWithInternalAuth(baseURL, client, "")
}

func NewWithInternalAuth(baseURL string, client *http.Client, internalAuthSecret string) http.Handler {
	return newWithReadOnlyResolver(baseURL, client, internalAuthSecret, resolveAPIKeyReadOnly)
}

func newWithReadOnlyResolver(baseURL string, client *http.Client, internalAuthSecret string, resolver readOnlyResolver) http.Handler {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	mcpServer := server.NewMCPServer("Lazy Balancer V2", "1.0.0", server.WithToolCapabilities(false), server.WithInstructions(serverInstructions))
	mcpServer.AddResource(
		mcp.NewResource(opsPlaybookURI, "ops-playbook", mcp.WithResourceDescription("Lazy Balancer V2 MCP 完整操作手册（接入/权限范围/工作流/排障/纪律/性能建议）"), mcp.WithMIMEType("text/markdown")),
		func(context.Context, mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return []mcp.ResourceContents{mcp.TextResourceContents{URI: opsPlaybookURI, MIMEType: "text/markdown", Text: opsPlaybook}}, nil
		},
	)
	for _, spec := range tools {
		mcpServer.AddTool(mcp.NewToolWithRawSchema(spec.name, toolDescription(spec), json.RawMessage(spec.schema)), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return forward(ctx, client, baseURL, internalAuthSecret, spec, request)
		})
	}
	streamable := server.NewStreamableHTTPServer(mcpServer, server.WithStateLess(true), server.WithEndpointPath("/api/v1/mcp"))
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		serveWithToolVisibility(writer, request, streamable, resolver)
	})
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
	maps.Copy(bodyArguments, arguments)
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
	// reset_user_password：后端必填 new_password，而工具 schema 只暴露 id（随机值语义），
	// 由 MCP 层生成随机密码注入请求体，成功后在结果文本中回显一次
	generatedPassword := ""
	if spec.name == "reset_user_password" {
		password, err := generateRandomPassword(16)
		if err != nil {
			return nil, fmt.Errorf("生成随机密码: %w", err)
		}
		generatedPassword = password
		bodyArguments["new_password"] = password
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
	} else if generatedPassword != "" {
		result = mcp.NewToolResultText(string(responseBody) + "\n（本次密码为系统生成：" + generatedPassword + "，请立即转交用户保存）")
	}
	return result, nil
}

const randomPasswordCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// generateRandomPassword 用 crypto/rand 生成无偏字母数字密码，供 reset_user_password 注入后端请求体
func generateRandomPassword(length int) (string, error) {
	buffer := make([]byte, length)
	for i := range buffer {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(randomPasswordCharset))))
		if err != nil {
			return "", fmt.Errorf("读取随机源: %w", err)
		}
		buffer[i] = randomPasswordCharset[index.Int64()]
	}
	return string(buffer), nil
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
