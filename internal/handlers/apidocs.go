package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type apiDocRoute struct {
	Method      string
	Path        string
	Tag         string
	Summary     string
	Request     string
	Response    string
	Errors      []string
	Description string
}

var apiDocRoutes = []apiDocRoute{
	{"POST", "/auth/login", "认证", "用户登录", `{"username":"admin","password":"..."}`, `{"token":"jwt","user":{},"node_mode":"master"}`, []string{"400 invalid_request", "401 invalid_credentials"}, "密码仅用于验证，不返回。"},
	{"POST", "/auth/ticket-login", "认证", "从节点票据登录", `{"ticket":"base64url(payload).base64url(signature)"}`, `{"token":"jwt","user":{},"node_mode":"slave"}`, []string{"400 invalid_request", "401 invalid_or_expired_ticket"}, "公开接口；仅从节点接受所属节点的一次性 60 秒登录票据。"},
	{"GET", "/auth/setup", "认证", "检查是否需要初始化", "", `{"needs_setup":true}`, []string{}, "用户表为空时返回 needs_setup=true，前端应引导创建首个管理员。"},
	{"POST", "/auth/setup", "认证", "创建首个管理员", `{"username":"admin","password":"...","display_name":""}`, `{"message":"管理员账号创建成功，请登录"}`, []string{"400 invalid_request", "403 already_initialized"}, "仅当用户表为空时可用。"},
	{"GET", "/branding", "系统", "品牌文案配置", "", `{"app_name":"Lazy Balancer","footer_text":"Copyright © ..."}`, []string{}, "公开接口；读取 data/branding.json，不存在时以默认值播种。"},
	{"POST", "/auth/logout", "认证", "用户登出", "", `{"code":0,"message":"Logged out"}`, nil, ""},
	{"POST", "/mcp", "MCP", "Model Context Protocol Streamable HTTP 端点", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"client","version":"1"}}}`, `{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"Lazy Balancer V2","version":"1.0.0"}}}`, []string{"401 api_key_required", "403 mcp_disabled_or_ip_denied"}, "仅接受 X-API-Key 或 Bearer lb_sk_；支持 initialize、ping、tools/list、tools/call。"},
	{"GET", "/users", "用户", "用户列表", "", `{"code":0,"data":[{"id":1,"username":"admin","role":"admin","display_name":null,"is_enabled":true}]}`, []string{"401 unauthenticated"}, "所有已登录用户可读。"},
	{"POST", "/users", "用户", "创建用户", `{"username":"viewer","password":"...","role":"user","display_name":"只读用户"}`, `{"code":0,"message":"User created","data":{"id":2}}`, []string{"400 invalid_request", "403 admin_required"}, "仅 admin。"},
	{"PUT", "/users/:id", "用户", "更新用户", `{"username":"viewer","role":"user","display_name":"观察员","password":"新密码(可选)"}`, `{"code":0,"message":"User updated"}`, []string{"400 invalid_request", "403 admin_required", "404 not_found"}, "仅 admin；省略字段时保留原值。"},
	{"PUT", "/users/:id/status", "用户", "启用或禁用用户", `{"is_enabled":false}`, `{"code":0,"message":"User status updated"}`, []string{"400 invalid_request", "403 admin_required"}, "仅 admin。"},
	{"POST", "/users/:id/reset-password", "用户", "重置用户密码", `{"new_password":"..."}`, `{"code":0,"message":"Password reset successfully"}`, []string{"400 invalid_request", "403 admin_required"}, "仅 admin。"},
	{"DELETE", "/users/:id", "用户", "删除用户", "", `{"code":0,"message":"User deleted"}`, []string{"400 cannot_delete_self", "403 admin_required", "404 not_found"}, "仅 admin。"},
	{"GET", "/users/me", "用户", "当前用户信息", "", `{"id":1,"username":"admin","role":"admin","display_name":null}`, []string{"401 unauthenticated"}, ""},
	{"PATCH", "/users/me", "用户", "更新当前用户", `{"display_name":"昵称","password":"新密码(可选)"}`, `{"id":1,"username":"admin","display_name":"昵称"}`, []string{"400 invalid_request", "401 unauthenticated"}, "密码只接受新值，不返回。"},
	{"GET", "/users/me/api-keys", "API密钥", "当前用户 API 密钥列表", "", `[{"id":1,"name":"ci","key_prefix":"lb_sk_abcd","last_used":null,"expires_at":null,"is_enabled":true,"mcp_enabled":true,"read_only":false,"mcp_ip_whitelist":["10.0.0.0/8"]}]`, []string{"401 unauthenticated"}, "不返回完整密钥。"},
	{"POST", "/users/me/api-keys", "API密钥", "创建当前用户 API 密钥", `{"name":"ci","expires_at":null,"mcp_enabled":true,"read_only":false,"mcp_ip_whitelist":["10.0.0.0/8","192.168.1.5"]}`, `{"id":1,"key":"lb_sk_...","message":"This key will only be shown once."}`, []string{"400 invalid_request", "401 unauthenticated"}, "完整密钥只在创建时返回一次；裸 IP 自动规范化为 /32 或 /128。"},
	{"PATCH", "/users/me/api-keys/:id", "API密钥", "更新当前用户 API 密钥", `{"is_enabled":true,"mcp_enabled":true,"read_only":false,"mcp_ip_whitelist":["10.0.0.0/8"]}`, `{"code":0,"message":"API key updated"}`, []string{"400 invalid_request", "404 not_found"}, "四个字段均可选，但至少提交一个。"},
	{"DELETE", "/users/me/api-keys/:id", "API密钥", "删除当前用户 API 密钥", "", `{"code":0,"message":"API key deleted"}`, []string{"404 not_found"}, ""},
	{"GET", "/api-keys", "API密钥", "API 密钥列表", "", `[{"id":1,"name":"ci","username":"admin","is_enabled":true,"mcp_enabled":true,"read_only":false,"mcp_ip_whitelist":[]}]`, []string{"401 unauthenticated"}, "所有已登录用户可读。"},
	{"POST", "/api-keys", "API密钥", "管理端创建 API 密钥", `{"name":"ci","expires_at":null,"mcp_enabled":true,"read_only":false,"mcp_ip_whitelist":[]}`, `{"id":1,"key":"lb_sk_..."}`, []string{"400 invalid_request", "403 admin_required"}, ""},
	{"PATCH", "/api-keys/:id/status", "API密钥", "管理端更新 API 密钥", `{"is_enabled":true,"mcp_enabled":true,"read_only":false,"mcp_ip_whitelist":[]}`, `{"code":0,"message":"API key updated"}`, []string{"400 invalid_request", "403 admin_required", "404 not_found"}, "四个字段均可选，但至少提交一个。"},
	{"DELETE", "/api-keys/:id", "API密钥", "管理端删除 API 密钥", "", `{"code":0,"message":"API key deleted"}`, []string{"403 admin_required", "404 not_found"}, ""},
	{"GET", "/config", "配置", "读取全局配置", "", `{"log_level":"info","timezone":"Asia/Shanghai","audit_retention_months":3,"proxy_dial_timeout":0,"proxy_response_header_timeout":0,"proxy_read_timeout":0,"proxy_write_timeout":0,"proxy_stream_timeout":0}`, []string{"401 unauthenticated"}, ""},
	{"PUT", "/config", "配置", "更新全局配置", `{"source":"caddy","proxy_dial_timeout":10,"proxy_response_header_timeout":30,"proxy_read_timeout":60,"proxy_write_timeout":60,"proxy_stream_timeout":0}`, `{"changed":true,"section":"Caddy全局配置","changes":["代理连接超时"]}`, []string{"400 validation_failed", "403 slave_or_admin_required"}, "只提交需要修改的字段；代理超时单位为秒，0 表示使用 Caddy 默认值；无修改不触发 Caddy 重载。"},
	{"GET", "/config/export", "配置", "导出全部配置备份", "", `{"meta":{},"config":{},"tables":{}}`, []string{"403 slave_or_admin_required"}, "仅主节点；下载 JSON 备份文件（含用户与密钥哈希、证书任务）。"},
	{"POST", "/config/import", "配置", "导入配置备份", `{"meta":{"app":"lazy-balancer-v2"},"config":{},"tables":{}}`, `{"message":"配置导入成功"}`, []string{"400 invalid_backup", "403 slave_or_admin_required", "500 rollback"}, "仅主节点；单事务全覆盖恢复，失败回滚并保留原配置。"},
	{"POST", "/config/import/validate", "配置", "校验配置备份", `{"meta":{"app":"lazy-balancer-v2","version":1},"tables":{"lb_rules":[],"users":[]}}`, `{"valid":true,"type":"v2"}`, []string{"400 invalid_request"}, "只校验备份格式和兼容性，不写数据库。"},
	{"POST", "/config/preview", "配置", "预览配置变更", `{"source":"basic","log_level":"debug"}`, `{"changed":true,"section":"基础设置","changes":["系统日志级别"]}`, []string{"400 invalid_request"}, "不写数据库，不触发 Caddy。"},
	{"POST", "/config/reload", "配置", "手动重载 Caddy", "", `{"code":0,"message":"Caddy config reloaded"}`, []string{"403 admin_required"}, ""},
	{"POST", "/config/validate", "配置", "验证 Caddy 配置", `{}`, `{"code":0,"message":"Config is valid"}`, []string{"400 config_invalid"}, ""},
	{"GET", "/config/health", "配置", "上游健康状态", "", `{"server":{"127.0.0.1:8080":{"healthy":true}}}`, []string{"401 unauthenticated"}, "所有已登录用户可读。"},
	{"GET", "/rules", "规则", "负载均衡规则列表", "", `[{"caddy_id":"lb_...","name":"example","protocol":"http","listen_port":80,"ip_acl_mode":"allow","ip_acl_list":["192.0.2.0/24"],"custom_routes_enabled":true,"proxy_dial_timeout":0,"proxy_response_header_timeout":0,"proxy_read_timeout":0,"proxy_write_timeout":0,"proxy_stream_timeout":0,"path_rules":[{"id":1,"match_type":"prefix","path":"/prometheus/","sort_order":0,"upstreams":null}],"enabled":true}]`, []string{"401 unauthenticated"}, "path_rules.upstreams 为 null 时继承父规则上游，否则使用 address、port、weight、protocol 对象数组；TCP 规则可用 tcp_proxy_protocol=true 向上游发送 PROXY v2 协议头传递真实客户端 IP。"},
	{"POST", "/rules", "规则", "创建负载均衡规则", `{"name":"example","protocol":"http","listen_port":8080,"ip_acl_mode":"allow","ip_acl_list":["192.0.2.0/24"],"custom_routes_enabled":true,"proxy_dial_timeout":5,"proxy_response_header_timeout":15,"proxy_read_timeout":30,"proxy_write_timeout":30,"proxy_stream_timeout":0,"path_rules":[{"match_type":"prefix","path":"/prometheus/","sort_order":0,"upstreams":[{"address":"127.0.0.1","port":9090,"weight":1,"protocol":"http"}]}],"upstreams":[{"host":"127.0.0.1","port":9000}]}`, `{"caddy_id":"lb_..."}`, []string{"400 validation_failed", "403 slave_mode"}, "ACL 列表仅接受 CIDR；路径必须以 / 开头，match_type 仅支持 prefix 或 exact；代理超时单位为秒，0 表示继承全局配置。"},
	{"GET", "/rules/:caddy_id", "规则", "规则详情", "", `{"caddy_id":"lb_...","name":"example","ip_acl_mode":"","ip_acl_list":[],"custom_routes_enabled":false,"proxy_dial_timeout":0,"proxy_response_header_timeout":0,"proxy_read_timeout":0,"proxy_write_timeout":0,"proxy_stream_timeout":0,"path_rules":[]}`, []string{"404 not_found"}, ""},
	{"GET", "/rules/:caddy_id/metrics-history", "指标", "规则历史指标", "", `{"code":0,"data":{"protocol":"http","supported":true,"rows":[{"timestamp":"2026-07-18 12:00:00","requests_total":10,"requests_2xx":9,"requests_3xx":0,"requests_4xx":1,"requests_5xx":0,"bytes_in":100,"bytes_out":1000}]}}`, []string{"404 not_found"}, "query: range（1h/6h/24h/7d，默认 24h）；TCP 规则返回 supported=false 和空 rows。"},
	{"PUT", "/rules/:caddy_id", "规则", "更新负载均衡规则", `{"ip_acl_mode":"deny","ip_acl_list":["198.51.100.0/24"],"custom_routes_enabled":true,"path_rules":[{"match_type":"exact","path":"/health","sort_order":0,"upstreams":null}]}`, `{"code":0,"message":"Rule updated"}`, []string{"400 validation_failed", "404 not_found", "409 cert_job_active", "500 caddy_apply_failed"}, "合并更新：指针字段省略时保留原值，显式 false、0 或空数组会写入；path_rules 仅在字段存在时整体替换；字符串空值保留原值。Caddy 应用失败返回 500。"},
	{"POST", "/rules/:caddy_id/acl", "规则", "更新规则访问控制", `{"ip_acl_mode":"allow","ip_acl_list":["192.0.2.0/24"]}`, `{"code":0,"message":"访问控制已保存"}`, []string{"400 validation_failed", "404 not_found", "500 caddy_apply_failed"}, "ACL 列表仅接受 CIDR；Caddy 应用失败时回滚数据库。"},
	{"DELETE", "/rules/:caddy_id", "规则", "删除负载均衡规则", "", `{"code":0,"message":"Rule deleted"}`, []string{"404 not_found"}, ""},
	{"POST", "/rules/:caddy_id/enable", "规则", "启用规则", "", `{"code":0,"message":"Rule enabled"}`, []string{"404 not_found", "500 caddy_apply_failed"}, "ACME 证书未过期且未到续期窗口时复用现有证书，不重新签发。"},
	{"PUT", "/rules/:caddy_id/disable", "规则", "禁用规则", "", `{"code":0,"message":"Rule disabled"}`, []string{"404 not_found", "500 caddy_apply_failed"}, "非终态证书任务会置为 disabled。"},
	{"POST", "/rules/:caddy_id/duplicate", "规则", "复制规则", "", `{"caddy_id":"lb_new..."}`, []string{"404 not_found"}, "不读取请求体；名称固定追加「（副本）」后缀。"},
	{"GET", "/certificate-configs", "证书", "DNS 提供商配置列表", "", `[{"id":1,"name":"dnspod","dns_provider":"dnspod","enabled":true}]`, []string{"401 unauthenticated"}, "凭证明文对所有登录用户可读，仅管理员可修改。"},
	{"GET", "/certificates", "证书", "Caddy 证书列表", "", `{"certificates":[]}`, []string{"500 caddy_unavailable"}, "读取 Caddy 当前证书数据。"},
	{"POST", "/certificate-configs", "证书", "创建 DNS 提供商配置", `{"name":"dnspod","dns_provider":"dnspod","dns_credentials":{"id":"...","token":"..."},"enabled":true}`, `{"id":1}`, []string{"400 invalid_request"}, "凭证保存后所有登录用户可读，仅管理员可修改。"},
	{"PUT", "/certificate-configs/:id", "证书", "更新 DNS 提供商配置", `{"name":"dnspod","enabled":true}`, `{"code":0,"message":"Config updated"}`, []string{"400 invalid_request", "404 not_found"}, ""},
	{"DELETE", "/certificate-configs/:id", "证书", "删除 DNS 提供商配置", "", `{"code":0,"message":"Config deleted"}`, []string{"404 not_found"}, ""},
	{"GET", "/dns-providers", "证书", "DNS 提供商能力列表", "", `{"code":0,"data":[{"code":"dnspod","name":"DNSPod","credential_fields":[]}]}`, []string{"401 unauthenticated"}, "所有已登录用户可读；返回提供商代码及凭证字段定义。"},
	{"POST", "/certificate-configs/test", "证书", "测试未保存的 DNS 提供商配置", `{"domain":"example.com","dns_provider":"dnspod","dns_credentials":{"id":"...","token":"..."}}`, `{"code":0,"message":"凭证有效"}`, []string{"400 invalid_credentials"}, "测试成功/失败都会记录操作日志，不记录凭证。"},
	{"POST", "/certificate-configs/:id/test", "证书", "测试 DNS 提供商配置", `{"domain":"example.com"}`, `{"code":0,"message":"凭证有效"}`, []string{"400 invalid_credentials", "404 not_found"}, "测试成功/失败都会记录操作日志，不记录凭证。"},
	{"GET", "/ca-providers", "证书", "CA 提供商列表", "", `[{"id":1,"name":"Let's Encrypt","provider":"letsencrypt","enabled":true}]`, []string{"401 unauthenticated"}, ""},
	{"GET", "/ca-providers/:id", "证书", "CA 提供商详情", "", `{"code":0,"data":{"id":1,"name":"Let's Encrypt","provider":"letsencrypt","enabled":true}}`, []string{"400 invalid_request", "404 not_found"}, "所有已登录用户可读。"},
	{"PUT", "/ca-providers/:id", "证书", "更新 CA 提供商", `{"name":"Let's Encrypt","enabled":true}`, `{"code":0,"message":"CA provider updated"}`, []string{"400 invalid_request", "404 not_found"}, ""},
	{"POST", "/ca-providers/:id/test", "证书", "测试 CA 提供商", "", `{"code":0,"message":"CA 提供商配置有效"}`, []string{"400 test_failed", "404 not_found"}, "测试成功/失败都会记录操作日志。"},
	{"GET", "/certificates/jobs", "证书", "证书签发任务列表", "", `[{"id":1,"rule_id":"lb_...","domain":"example.com","status":"issued","ca_provider_name":"Let's Encrypt"}]`, []string{"401 unauthenticated"}, "可用 query rule_id 过滤。"},
	{"POST", "/certificates/jobs/:id/retry", "证书", "重试证书签发任务", "", `{"code":0,"message":"Retry triggered"}`, []string{"404 not_found", "429 retry_guard", "500 queue_unavailable"}, ""},
	{"DELETE", "/certificates/jobs/:id", "证书", "删除证书签发任务", "", `{"code":0,"message":"Job deleted"}`, []string{"404 not_found"}, ""},
	{"POST", "/certificates/issue", "证书", "触发 ACME 签发流程", "", `{"code":0,"message":"Certificate issuance triggered"}`, []string{"401 unauthenticated"}, "该接口仅触发流程，不表示签发完成。"},
	{"POST", "/certificates/parse", "证书", "解析证书", `{"cert_pem":"...","key_pem":"..."}`, `{"domain":"example.com","valid":true}`, []string{"400 invalid_certificate"}, "证书材料不写入审计。"},
	{"GET", "/cluster/status", "集群", "当前节点集群状态", "", `{"code":0,"message":"查询成功","data":{"node_mode":"master","cluster_version":3,"master_url":"","sync_interval":60,"sync_caddy_config":false,"cluster_active":true,"applied_version":0,"last_sync_at":"","last_sync_error":"","pending_count":1,"approved_count":2}}`, []string{"401 未登录"}, "JWT 或 API Key。主节点返回待审批和已批准节点计数。"},
	{"GET", "/cluster/nodes", "集群", "主节点查看从节点", "", `{"code":0,"data":[{"id":2,"name":"slave-a","ip_address":"10.0.0.2","port":8000,"status":"online","is_approved":true,"reported_version":3,"current_version":3,"health":{"caddy_ok":true,"rules_count":5,"certs_expiring_30d":0,"last_sync_at":"2026-07-18T12:00:00Z","last_sync_error":"","uptime_sec":3600},"last_seen":"2026-07-18T12:00:00Z","created_at":"2026-07-18T11:00:00Z"}]}`, []string{"401 unauthenticated"}, "所有已认证用户可读；接受 JWT 或 API Key，仅主节点返回节点列表；离线状态按 last_seen 超过 2×sync_interval 在读取时计算。"},
	{"POST", "/cluster/register-tokens", "集群", "生成一次性注册令牌", "", `{"code":0,"message":"注册令牌已生成，仅显示一次","data":{"token":"...","expires_at":"2026-07-18T12:30:00Z"}}`, []string{"403 仅主节点管理员"}, "admin JWT 或管理员 API Key；明文仅返回一次，服务端仅保存 SHA-256 哈希，30 分钟过期。"},
	{"POST", "/cluster/register", "集群机器接口", "从节点注册", `{"token":"...","name":"slave-a","ip_address":"10.0.0.2","port":8000}`, `{"code":0,"message":"注册成功，等待主节点审批","data":{"registration_id":2,"registration_secret":"..."}}`, []string{"401 注册令牌无效或已过期"}, "不使用 JWT；注册令牌一次性。相同 IP+端口待审批注册幂等更新。"},
	{"GET", "/cluster/register/:id/status", "集群机器接口", "轮询注册审批状态", "", `{"code":0,"data":{"status":"approved","cluster_token":"lb_cluster_..."}}`, []string{"401 注册凭证无效"}, "X-Registration-Secret 或 Bearer registration_secret；cluster_token 仅在首次 approved 响应返回。"},
	{"POST", "/cluster/nodes/:id/approve", "集群", "批准待审批节点", "", `{"code":0,"message":"审批节点成功"}`, []string{"403 仅主节点管理员", "404 节点不存在"}, "admin JWT 或管理员 API Key；签发节点专属长期集群令牌，仅保存 SHA-256 哈希。"},
	{"POST", "/cluster/nodes/:id/reject", "集群", "拒绝待审批节点", "", `{"code":0,"message":"拒绝节点成功"}`, []string{"403 仅主节点管理员", "404 节点不存在"}, "admin JWT 或管理员 API Key；删除节点记录。"},
	{"POST", "/cluster/nodes/:id/login-ticket", "集群", "生成从节点登录票据", "", `{"ticket":"...","url":"https://10.0.0.2:8000"}`, []string{"403 仅主节点管理员", "409 节点不在线"}, "admin JWT 或管理员 API Key；票据 60 秒有效且只能使用一次。"},
	{"DELETE", "/cluster/nodes/:id", "集群", "移除集群节点", "", `{"code":0,"message":"删除节点成功"}`, []string{"403 仅主节点管理员", "404 节点不存在"}, "admin JWT 或管理员 API Key；删除节点及其长期令牌哈希。"},
	{"POST", "/cluster/mode", "集群", "主节点注册并切换为从节点", `{"mode":"slave","master_url":"https://master:8000","register_token":"...","node_name":"slave-a"}`, `{"code":0,"message":"已切换为从节点，等待主节点审批"}`, []string{"400 参数无效", "502 向目标主节点注册失败"}, "admin JWT 或管理员 API Key；仅在目标主节点注册成功后持久化 slave。http:// 地址成功但 message 包含明文传输警告。"},
	{"POST", "/cluster/promote", "集群", "从节点提升为主节点", "", `{"code":0,"message":"已提升为主节点"}`, []string{"500 提升失败"}, "admin JWT 或管理员 API Key；清空主节点地址和集群令牌、停止同步、启动 ACME 并递增版本。"},
	{"PUT", "/cluster/settings", "集群", "更新集群设置", `{"sync_interval":60,"sync_caddy_config":true}`, `{"code":0,"message":"集群设置已更新"}`, []string{"400 参数无效", "403 从节点不能修改 Caddy 同步开关"}, "admin JWT 或管理员 API Key；sync_interval 由主节点下发，sync_caddy_config 仅主节点可改，从节点均只读。"},
	{"GET", "/cluster/sync/snapshot", "集群机器接口", "拉取全量集群快照", "", `{"code":0,"data":{"schema_version":1,"min_reader_version":1,"version":3,"fingerprint":"sha256","signature":"hmac-sha256","rules":[],"users":[],"api_keys":[],"basic_settings":{},"certs":[]}}`, []string{"304 版本和指纹均未变化", "400 快照缺少签名", "401 集群凭证无效"}, "X-Cluster-Token 或 Bearer cluster token；query: since_version,fingerprint。schema_version 表示快照结构版本，min_reader_version 表示可读取该快照的最低实现版本；signature 为以节点令牌为键的 HMAC-SHA256（含版本号），从节点强制验签并拒绝版本回退。用户密码哈希、API key 哈希和证书私钥只通过此机器接口传输。"},
	{"POST", "/cluster/sync/pull", "集群", "从节点立即同步", "", `{"code":0,"message":"手动同步完成","data":{"applied_version":3,"changed":true}}`, []string{"500 同步失败"}, "admin JWT 或管理员 API Key；有变更记录应用版本，无变更记录「配置无变化」，均写入操作日志。"},
	{"POST", "/cluster/nodes/report", "集群机器接口", "从节点上报健康状态", `{"applied_version":3,"service_status":"ok","health":{"caddy_ok":true,"rules_count":5,"certs_expiring_30d":0,"last_sync_at":"2026-07-18T12:00:00Z","last_sync_error":"","uptime_sec":3600},"last_sync_at":"2026-07-18T12:00:00Z","last_sync_error":""}`, `{"code":0,"message":"节点状态已更新"}`, []string{"401 集群凭证无效"}, "X-Cluster-Token 或 Bearer cluster token。"},
	{"GET", "/caddy/status", "Caddy", "Caddy 状态", "", `{"status":"running"}`, []string{"500 caddy_unavailable"}, ""},
	{"GET", "/caddy/config", "Caddy", "当前 Caddy 配置", "", `{...}`, []string{"500 caddy_unavailable"}, ""},
	{"PUT", "/caddy/config", "Caddy", "直接更新 Caddy 配置", `{...}`, `{"code":0,"message":"Config saved"}`, []string{"400 config_invalid"}, ""},
	{"POST", "/caddy/start", "Caddy", "启动 Caddy", "", `{"code":0,"message":"Caddy started"}`, []string{"500 start_failed"}, ""},
	{"POST", "/caddy/stop", "Caddy", "停止 Caddy", "", `{"code":0,"message":"Caddy stopped"}`, []string{"500 stop_failed"}, ""},
	{"POST", "/caddy/restart", "Caddy", "重启 Caddy", "", `{"code":0,"message":"Caddy restarted"}`, []string{"500 restart_failed"}, ""},
	{"GET", "/admin-tls", "系统", "管理面板 HTTPS 配置", "", `{"enabled":true,"mode":"selfsigned","restart_hint":true}`, []string{"401 unauthenticated"}, "不返回证书内容。"},
	{"PUT", "/admin-tls", "系统", "启用/禁用管理面板 HTTPS", `{"enabled":true,"mode":"selfsigned"}`, `{"code":0,"message":"已保存，服务正在重启以应用 HTTPS 配置"}`, []string{"400 invalid_request", "403 admin_required"}, "multipart 表单；mode=selfsigned 或 upload（upload 需 cert_file/key_file 文件字段）。保存后服务自动重启，从节点同步后亦自动重启。"},
	{"POST", "/admin-tls/inspect", "系统", "解析上传证书信息（不保存）", `"multipart form: cert_file, key_file"`, `{"domain":"example.com","issuer":"Let's Encrypt","not_after":"2027-01-01 00:00:00","days_left":365}`, []string{"400 invalid_certificate"}, "仅解析并返回证书信息，供保存前展示。"},
	{"POST", "/system/restart", "系统", "重启服务", "", `{"code":0,"message":"服务正在重启"}`, []string{"403 admin_required"}, "进程退出后由容器重启策略拉起，用于应用进程级配置（如 Caddy 日志时区）。"},
	{"GET", "/system/logs", "系统", "读取应用运行日志", "", `{"content":"..."}`, []string{"401 unauthenticated"}, "需配置 LOG_FILE 环境变量。"},
	{"GET", "/rules/:caddy_id/logs", "规则", "规则访问日志（最近 1000 行）", "", `{"content":"...","offset":12345}`, []string{"404 not_found"}, "需规则开启访问日志；offset 为尾部结束位置，供 log-stream 续读。"},
	{"GET", "/rules/:caddy_id/log-stream", "规则", "规则日志增量流", "", `{"offset":12456,"lines":["{...}"]}`, []string{"404 not_found"}, "query: offset（字节偏移，上次返回值）。返回 offset 之后的新日志行与新 offset，供前端增量统计，无服务端状态。"},
	{"GET", "/rules/:caddy_id/caddy-config", "规则", "单规则 Caddy 配置预览", "", `{...}`, []string{"404 not_found"}, ""},
	{"POST", "/rules/cert-info", "规则", "批量查询规则证书信息", `{"caddy_ids":["lb_..."]}`, `{"lb_...":{"expires_at":"...","days_left":30}}`, []string{"401 unauthenticated"}, "只读，不写操作日志。"},
	{"GET", "/rules/:caddy_id/cert-info", "规则", "查询单规则证书信息", "", `{"expires_at":"...","days_left":30}`, []string{"404 not_found"}, "只读，不写操作日志。"},
	{"POST", "/config/import/v1", "配置", "导入 v1（nginx 版）备份", "v1 备份 JSON", `{"message":"已导入 26 条规则"}`, []string{"400 invalid_backup", "403 slave_or_admin_required", "500 rollback"}, "仅主节点；自动转换负载均衡规则（含内联证书），仅导入规则部分。"},
	{"GET", "/caddy/logs", "Caddy", "Caddy 日志", "", `{"content":"..."}`, []string{"401 unauthenticated"}, "query: type（server/proxy/tls/access）。"},
	{"GET", "/caddy/metrics", "Caddy", "Caddy 指标", "", `{"requests_total":0,"requests_in_flight":0}`, []string{"401 unauthenticated"}, "JWT 或 lb_sk_ API Key（供 Prometheus 抓取）。"},
	{"GET", "/caddy/host-metrics", "Caddy", "按域名统计指标", "", `[{"host":"example.com","requests_total":0}]`, []string{"401 unauthenticated"}, ""},
	{"GET", "/certificates/jobs/:id", "证书", "证书签发任务详情", "", `{"id":1,"rule_id":"lb_...","status":"issued"}`, []string{"404 not_found"}, ""},
	{"GET", "/certificates/jobs/:id/logs", "证书", "证书签发任务日志", "", `{"content":"..."}`, []string{"404 not_found"}, ""},
	{"GET", "/metrics/overview", "指标", "指标总览", "", `{"total_requests":0,"requests_per_sec":0}`, []string{"401 unauthenticated"}, ""},
	{"GET", "/metrics/rule/:caddy_id", "指标", "单规则指标", "", `{"requests_total":0,"bytes_in":0,"bytes_out":0}`, []string{"404 not_found"}, ""},
	{"GET", "/metrics/history", "指标", "历史指标", "", `[{"timestamp":"...","bytes_in":0,"bytes_out":0}]`, []string{"401 unauthenticated"}, ""},
	{"GET", "/metrics/realtime", "指标", "实时流量", "", `{"bytes_in":0,"bytes_out":0}`, []string{"401 unauthenticated"}, ""},
	{"GET", "/metrics/connections", "指标", "连接统计", "", `{"established":0,"time_wait":0}`, []string{"401 unauthenticated"}, ""},
	{"GET", "/system/info", "系统", "系统信息", "", `{"ip_address":"...","hostname":"..."}`, []string{"401 unauthenticated"}, ""},
	{"GET", "/system/metrics", "系统", "系统指标", "", `{"cpu_percent":0,"memory_percent":0}`, []string{"401 unauthenticated"}, ""},
	{"GET", "/audit-logs", "审计", "操作日志", "", `{"list":[],"total":0,"page":1,"page_size":20}`, []string{"401 unauthenticated"}, "query: page, page_size。"},
}

func buildOpenAPIYAML() string {
	var b strings.Builder
	b.WriteString("openapi: 3.1.0\ninfo:\n  title: Lazy Balancer API\n  version: 1.0.0\n")
	b.WriteString("  description: |\n    Lazy Balancer v1 REST API。管理接口使用 Authorization: Bearer <JWT 或 lb_sk_ API Key>。\n    集群机器接口使用 X-Cluster-Token 或 X-Registration-Secret；响应统一为 {code,message,data?}。\n    不返回用户密码；TLS 私钥、DNS 凭证及其他配置数据对所有已登录用户可读，仅管理员可修改。集群快照包含密码和密钥哈希及证书私钥，部署时建议使用 HTTPS。\nservers:\n  - url: /api/v1\npaths:\n")
	pathOrder := make([]string, 0)
	routesByPath := make(map[string][]apiDocRoute)
	for _, r := range apiDocRoutes {
		if _, exists := routesByPath[r.Path]; !exists {
			pathOrder = append(pathOrder, r.Path)
		}
		routesByPath[r.Path] = append(routesByPath[r.Path], r)
	}
	for _, path := range pathOrder {
		fmt.Fprintf(&b, "  %s:\n", path)
		for _, route := range routesByPath[path] {
			writeOpenAPIOperation(&b, route)
		}
	}
	b.WriteString("components:\n  securitySchemes:\n    bearerAuth:\n      type: http\n      scheme: bearer\n      description: JWT 或 lb_sk_ API Key\n    clusterToken:\n      type: apiKey\n      in: header\n      name: X-Cluster-Token\n    registrationSecret:\n      type: apiKey\n      in: header\n      name: X-Registration-Secret\nsecurity:\n  - bearerAuth: []\n")
	return b.String()
}

func writeOpenAPIOperation(b *strings.Builder, route apiDocRoute) {
	fmt.Fprintf(b, "    %s:\n      tags: [%s]\n      summary: %s\n", strings.ToLower(route.Method), route.Tag, route.Summary)
	if route.Path == "/cluster/register" {
		b.WriteString("      security: []\n")
	} else if route.Path == "/cluster/register/:id/status" {
		b.WriteString("      security:\n        - registrationSecret: []\n")
	} else if route.Tag == "集群机器接口" {
		b.WriteString("      security:\n        - clusterToken: []\n")
	}
	if route.Description != "" {
		fmt.Fprintf(b, "      description: %s\n", strconv.Quote(route.Description))
	}
	if route.Request != "" {
		fmt.Fprintf(b, "      requestBody:\n        required: true\n        content:\n          application/json:\n            example: %s\n", route.Request)
	}
	fmt.Fprintf(b, "      responses:\n        '200':\n          description: 成功\n          content:\n            application/json:\n              example: %s\n", route.Response)
	for _, routeError := range route.Errors {
		parts := strings.SplitN(routeError, " ", 2)
		description := "错误"
		if len(parts) == 2 {
			description = parts[1]
		}
		fmt.Fprintf(b, "        '%s':\n          description: %s\n          content:\n            application/json:\n              example: {\"code\":%s,\"message\":\"%s\"}\n", parts[0], description, parts[0], description)
	}
}

func (h *Handlers) GetOpenAPIYAML(c *gin.Context) {
	c.Data(http.StatusOK, "application/yaml; charset=utf-8", []byte(buildOpenAPIYAML()))
}

func (h *Handlers) GetAPIDocs(c *gin.Context) {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Lazy Balancer API 文档</title><style>body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f9fafb;color:#111827}main{max-width:1200px;margin:32px auto;padding:0 20px}.card{background:white;border-radius:12px;padding:24px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}code,pre{background:#f3f4f6;border-radius:6px;padding:2px 6px}pre{padding:12px;overflow:auto}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #e5e7eb;padding:8px;text-align:left;vertical-align:top}th{background:#f9fafb}.method{font-weight:700;color:#2563eb}</style></head><body><main><h1>Lazy Balancer API 文档</h1><div class="card"><p>Base URL：<code>/api/v1</code></p><p>认证：<code>Authorization: Bearer &lt;JWT 或 lb_sk_ API Key&gt;</code></p><p>统一响应：<code>{"code":0,"message":"...","data":...}</code>；错误使用相同结构并返回 4xx/5xx。</p><p>OpenAPI YAML：<a href="/api/v1/openapi.yaml">/api/v1/openapi.yaml</a></p></div>`)
	for _, r := range apiDocRoutes {
		fmt.Fprintf(&b, `<div class="card"><h2><span class="method">%s</span> <code>%s</code></h2><p><strong>%s</strong></p>`, r.Method, r.Path, r.Summary)
		if r.Description != "" {
			fmt.Fprintf(&b, `<p>%s</p>`, r.Description)
		}
		b.WriteString(`<table><tr><th>请求体</th><th>成功响应</th><th>错误</th></tr><tr>`)
		if r.Request == "" {
			b.WriteString(`<td>-</td>`)
		} else {
			fmt.Fprintf(&b, `<td><pre>%s</pre></td>`, r.Request)
		}
		fmt.Fprintf(&b, `<td><pre>%s</pre></td>`, r.Response)
		if len(r.Errors) == 0 {
			b.WriteString(`<td>-</td>`)
		} else {
			fmt.Fprintf(&b, `<td>%s</td>`, strings.Join(r.Errors, "<br>"))
		}
		b.WriteString(`</tr></table></div>`)
	}
	b.WriteString(`</main></body></html>`)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(b.String()))
}
