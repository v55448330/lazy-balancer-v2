package mcpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
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

	"lazy-balancer-v2/internal/apikey"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/netutil"
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

const controlTaskSchema = `{"type":"object","required":["id","action"],"properties":{"id":{"type":"string","description":"任务 ID（见 list_system_tasks）"},"action":{"type":"string","enum":["start","stop","restart"],"description":"启动/停止/重启"}}}`

// 单/少字段写工具的 input_schema 声明 properties/required
// （保留 additionalProperties:true 的向前兼容形态）——运行时未启用 input schema
// 校验，schema 是 Agent 唯一的构参契约，漏字段会让 Agent 只能凭描述猜名。
const toggleAutoUpdateSchema = `{"type":"object","required":["auto_update"],"properties":{"auto_update":{"type":"boolean","description":"true=启用自动更新，false=关闭"}},"additionalProperties":true}`

const toggleUserStatusSchema = `{"type":"object","required":["id","is_enabled"],"properties":{"id":{"type":"integer","description":"用户 ID"},"is_enabled":{"type":"boolean","description":"true=启用，false=禁用"}},"additionalProperties":true}`

const setClusterModeSchema = `{"type":"object","required":["mode","master_url","register_token"],"properties":{"mode":{"type":"string","enum":["slave"],"description":"目标模式（仅 slave；提升主节点用 promote_cluster）"},"master_url":{"type":"string","description":"目标主节点地址，如 https://master:8000（http:// 明文会记录警告）"},"register_token":{"type":"string","description":"目标主节点生成的一次性注册令牌"},"node_name":{"type":"string","description":"节点名称，省略=使用本机配置名"}},"additionalProperties":true}`

const updateClusterSettingsSchema = `{"type":"object","properties":{"sync_interval":{"type":"integer","minimum":10,"maximum":86400,"description":"同步间隔秒数（10-86400）"},"sync_users":{"type":"boolean","description":"同步系统数据（含全局配置，恒同步——提交 false 返回 400）"},"sync_rules":{"type":"boolean","description":"同步负载规则"},"sync_security":{"type":"boolean","description":"同步安全防护（含 CRS/IP2Region 规则库）"}},"additionalProperties":true}`

const parseCertificateSchema = `{"type":"object","required":["cert_pem","key_pem"],"properties":{"cert_pem":{"type":"string","description":"证书 PEM"},"key_pem":{"type":"string","description":"私钥 PEM"}},"additionalProperties":true}`

const updateNodeAccessURLSchema = `{"type":"object","required":["id","access_url"],"properties":{"id":{"type":"integer","description":"节点 ID"},"access_url":{"type":"string","description":"访问地址，允许空串（登录票据回退 protocol://ip:port）"}},"additionalProperties":true}`

const updateCAProviderSchema = `{"type":"object","required":["id"],"properties":{"id":{"type":"integer","description":"CA ID"},"name":{"type":"string","description":"名称（≤100 字符）"},"provider":{"type":"string","enum":["letsencrypt","zerossl"]},"credentials":{"type":"string","description":"凭证 JSON 字符串（Let's Encrypt 必须为空字符串）"},"max_concurrent":{"type":"integer","minimum":1,"maximum":100,"description":"最大并发（≤100）"},"min_interval_ms":{"type":"integer","minimum":0,"maximum":60000,"description":"最小间隔毫秒（≤60000）"},"enabled":{"type":"boolean"}},"additionalProperties":true}`

const updateAdminTLSSchema = `{"type":"object","properties":{"enabled":{"type":"boolean","description":"省略=保持现值；false=禁用"},"mode":{"type":"string","enum":["selfsigned","upload"],"description":"证书来源"},"cert_file":{"type":"string","description":"证书 PEM（JSON 通道；multipart 通道为文件字段）"},"key_file":{"type":"string","description":"私钥 PEM（JSON 通道；multipart 通道为文件字段）"}},"additionalProperties":true}`

const inspectAdminTLSSchema = `{"type":"object","required":["cert_file","key_file"],"properties":{"cert_file":{"type":"string","description":"证书 PEM（JSON 通道；multipart 通道为文件字段）"},"key_file":{"type":"string","description":"私钥 PEM（JSON 通道；multipart 通道为文件字段）"}},"additionalProperties":true}`

const toggleTaskSchema = `{"type":"object","required":["id","enabled"],"properties":{"id":{"type":"string","description":"任务 ID（见 list_system_tasks）"},"enabled":{"type":"boolean","description":"true=恢复 false=停止"}}}`

// —— 高风险写工具的 body 字段契约（与 REST 请求 struct 同字段名）——
// 运行时 input schema 校验刻意未启用，schema 是 Agent 唯一构参契约：
// 零字段契约只能靠工具描述猜字段名，错名由 REST 400 暴露。
// additionalProperties:true 保留向前兼容（低频/新增字段不被挡）。

// securityPolicyFieldsSchema 与 models.CreateSecurityPolicyRequest /
// UpdateSecurityPolicyRequest 字段集同名（创建必填 name，更新全可选）。
const securityPolicyFieldsSchema = `"name":{"type":"string","description":"策略名称"},"description":{"type":"string"},"mode":{"type":"string","enum":["off","detection","blocking","custom_only"],"description":"off=全关/detection=检测仅记录/blocking=拦截/custom_only=仅自定义规则"},"policy_type":{"type":"string","enum":["stage0","stage1","stage2","stage3"],"description":"缺省按内容自动推断；显式 mixed 拒绝（混合策略为存量兼容形态，请按阶段类型分别创建）；跨阶段内容推断为 mixed 同样 400"},"anomaly_threshold":{"type":"integer","description":"CRS 异常分阈值"},"trust_detection":{"type":"boolean","description":"仅 stage0 信任策略消费：false=直通上游零事件，true=保留检测记录"},"ip_acl_enabled":{"type":"boolean","description":"IP 访问控制开关"},"ip_acl_mode":{"type":"string","enum":["allow","deny"],"description":"IP 访问控制模式（缺省归一 deny）"},"ip_acl_list":{"type":"string","description":"内联 CIDR 数组 JSON 文本"},"ip_acl_list_refs":{"type":"string","description":"引用的 IP 地址列表 id 数组 JSON 文本"},"ip_whitelist_enabled":{"type":"boolean"},"ip_whitelist":{"type":"string","description":"IP 白名单（JSON 数组文本）"},"ip_whitelist_refs":{"type":"string","description":"引用的 IP 地址列表 id 数组 JSON 文本（白名单与内联 ip_whitelist 取并集）"},"ip_blacklist":{"type":"string","description":"IP 黑名单（JSON 数组文本）"},"rate_limit_enabled":{"type":"boolean"},"rate_limit_rps":{"type":"integer","description":"限流请求速率（次/秒）"},"rate_limit_burst":{"type":"integer","description":"限流突发容量"},"geoip_mode":{"type":"string","description":"地域拦截模式（off=关闭）"},"geoip_countries":{"type":"string","description":"地域名单（JSON 数组文本）"},"geoip_crawler_exempt":{"type":"boolean","description":"地域拦截对已知爬虫豁免"},"geoip_crawler_engines":{"type":"string","description":"参与豁免的爬虫引擎（JSON 数组文本）"},"crs_rule_groups":{"type":"string","description":"启用的 CRS 规则组（JSON 数组文本）"},"crs_excluded_rules":{"type":"string","description":"排除的 CRS 规则 ID（JSON 数组文本）"},"custom_rules":{"type":"string","description":"自定义规则 ID 数组 JSON 文本"},"block_page_id":{"type":"integer","description":"拦截页面 ID（0=默认页）"},"block_status_code":{"type":"integer","description":"拦截状态码（0=默认 403）"},"waf_check_response":{"type":"boolean","description":"WAF 检查响应体"},"log_request_body":{"type":"boolean","description":"记录请求体（审计体积换取证）"},"enabled":{"type":"boolean"}`

var createSecurityPolicySchema = `{"type":"object","required":["name"],"properties":{` + securityPolicyFieldsSchema + `},"additionalProperties":true}`
var updateSecurityPolicySchema = `{"type":"object","required":["id"],"properties":{"id":{"type":"integer","description":"策略 ID"},` + securityPolicyFieldsSchema + `},"additionalProperties":true}`

// customRuleFieldsSchema 与 validateSecurityCustomRule 校验同口径：
// condition_logic/action/score 与条件 target/operator 枚举均为后端硬校验（创建省略 condition_logic=and）。
const customRuleFieldsSchema = `"name":{"type":"string","description":"规则名称（≤100 字符，禁控制字符与双引号）"},"description":{"type":"string","description":"规则描述（≤500 字符）"},"conditions":{"type":"array","minItems":1,"items":{"type":"object","required":["target","operator","pattern"],"properties":{"target":{"type":"string","enum":["uri","args","body","headers","user_agent"]},"operator":{"type":"string","enum":["contains","regex","equals","starts_with"]},"pattern":{"type":"string","description":"匹配模式"}}},"description":"匹配条件（至少一条，关系由 condition_logic 决定）"},"condition_logic":{"type":"string","enum":["and","or"],"description":"条件关系：and=同时满足（缺省），or=任一满足；更新省略=保持现值"},"action":{"type":"string","enum":["block","log","pass"]},"score":{"type":"integer","enum":[1,3,5,10,20],"description":"异常分值"},"enabled":{"type":"boolean","description":"创建省略=启用，显式 false=禁用；更新省略=保持现值"}`

var createCustomRuleSchema = `{"type":"object","required":["name","conditions","action","score"],"properties":{` + customRuleFieldsSchema + `},"additionalProperties":true}`
var updateCustomRuleSchema = `{"type":"object","required":["id"],"properties":{"id":{"type":"integer","description":"规则 ID"},` + customRuleFieldsSchema + `},"additionalProperties":true}`

// blockPageFieldsSchema 与 validateBlockPagePayload 同口径（name/content
// 必填、content ≤64KB、content_type 四值白名单缺省 text/html）。
const blockPageFieldsSchema = `"name":{"type":"string","description":"拦截页名称（≤100 字符）"},"description":{"type":"string","description":"≤500 字符"},"content":{"type":"string","description":"拦截页内容（≤64KB）"},"content_type":{"type":"string","enum":["text/html; charset=utf-8","application/json; charset=utf-8","application/xml; charset=utf-8","text/plain; charset=utf-8"],"description":"缺省 text/html; charset=utf-8"}`

var createBlockPageSchema = `{"type":"object","required":["name","content"],"properties":{` + blockPageFieldsSchema + `},"additionalProperties":true}`
var updateBlockPageSchema = `{"type":"object","required":["id"],"properties":{"id":{"type":"integer","description":"页面 ID"},` + blockPageFieldsSchema + `},"additionalProperties":true}`

// ipListFieldsSchema：entries 为 {value, remark} 对象数组的 JSON 文本；
// 名称全局唯一（忽略大小写）、≤50 字符。
const ipListFieldsSchema = `"name":{"type":"string","description":"名单名称（≤50 字符，全局唯一忽略大小写）"},"description":{"type":"string"},"category":{"type":"string","description":"分类"},"entries":{"type":"string","description":"条目 JSON 文本：[{\"value\":\"10.0.0.0/8\",\"remark\":\"备注\"}]（创建/全量替换用；单条处置用 add_ip_to_list/remove_ip_from_list）"}`

var createIPListSchema = `{"type":"object","required":["name"],"properties":{` + ipListFieldsSchema + `},"additionalProperties":true}`
var updateIPListSchema = `{"type":"object","required":["id"],"properties":{"id":{"type":"integer","description":"列表 ID"},` + ipListFieldsSchema + `},"additionalProperties":true}`

// certificateConfigFieldsSchema 与 models.Create/UpdateCertificateConfigRequest
// 同字段名；dns_credentials 为字段名→值的映射（键面由 list_dns_providers 给出）。
const certificateConfigFieldsSchema = `"name":{"type":"string","description":"配置名称"},"dns_provider":{"type":"string","description":"DNS 提供商代码（见 list_dns_providers）"},"dns_credentials":{"type":"object","additionalProperties":{"type":"string"},"description":"凭证键值映射（更新时回传掩码串按未改动处理）"},"enabled":{"type":"boolean"}`

var createCertificateConfigSchema = `{"type":"object","required":["name","dns_provider"],"properties":{` + certificateConfigFieldsSchema + `},"additionalProperties":true}`
var updateCertificateConfigSchema = `{"type":"object","required":["id"],"properties":{"id":{"type":"integer","description":"配置 ID"},` + certificateConfigFieldsSchema + `},"additionalProperties":true}`

const createUserSchema = `{"type":"object","required":["username","password","role"],"properties":{"username":{"type":"string","description":"用户名：小写字母开头，仅小写字母/数字（3-50 字符，不接受大写、下划线、汉字）"},"password":{"type":"string","description":"初始密码：8-24 个可打印 ASCII 字符（数字/大小写字母/特殊字符，不强制四类全含）"},"role":{"type":"string","enum":["admin","user"]},"display_name":{"type":"string","description":"显示名（≤50 字符）"}},"additionalProperties":true}`
const updateUserSchema = `{"type":"object","required":["id"],"properties":{"id":{"type":"integer","description":"用户 ID"},"username":{"type":"string","description":"新用户名：小写字母开头，仅小写字母/数字（3-50 字符，不接受大写、下划线、汉字；省略=不修改）"},"role":{"type":"string","enum":["admin","user"]},"display_name":{"type":"string"},"password":{"type":"string","description":"新密码：8-24 个可打印 ASCII 字符（数字/大小写字母/特殊字符；省略=不修改）"}},"additionalProperties":true}`

const createAPIKeySchema = `{"type":"object","required":["name"],"properties":{"name":{"type":"string","description":"密钥名称"},"expires_at":{"type":["string","null"],"description":"过期时间（RFC3339），null=永不过期"},"mcp_enabled":{"type":"boolean","description":"允许该 Key 调 MCP"},"read_only":{"type":"boolean","description":"只读 Key（仅查询与读探测工具）"},"mcp_ip_whitelist":{"type":"array","items":{"type":"string"},"description":"来源 IP 白名单（CIDR，约束该 Key 的全部 REST 与 MCP 调用）"}},"additionalProperties":true}`
const updateAPIKeyStatusSchema = `{"type":"object","required":["id"],"properties":{"id":{"type":"integer","description":"密钥 ID"},"is_enabled":{"type":"boolean"},"mcp_enabled":{"type":"boolean"},"read_only":{"type":"boolean"},"mcp_ip_whitelist":{"type":"array","items":{"type":"string"},"description":"来源 IP 白名单（CIDR）"}},"additionalProperties":true,"description":"四个字段均可选但至少提交一个"}`

const previewConfigSchema = `{"type":"object","properties":{"source":{"type":"string","description":"配置分区标识（如 caddy/basic/security，分区字段清单同 update_config）"}},"additionalProperties":true,"description":"预览配置变更（不写库不触发 Caddy）；分区字段同 update_config 的 properties"}`
const validateConfigSchema = `{"type":"object","description":"完整 Caddy 配置 JSON 本体（无固定子集——校验目标是任意 Caddy 配置）","additionalProperties":true}`
const updateCaddyConfigSchema = `{"type":"object","description":"完整 Caddy 配置 JSON 本体（一次性逃生口：后续任何配置变更以数据库权威配置覆盖它）","additionalProperties":true}`
const configImportSchema = `{"type":"object","properties":{"meta":{"type":"object","description":"备份元信息（app/version）"},"config":{"type":"object","description":"全局配置段"},"tables":{"type":"object","description":"分表数据段"},"sections":{"type":"string","description":"可选导入分类子集（逗号分隔，等价 REST ?sections=；省略=按备份自身记录的分类全选）。注意：备份正文里的 sections 是打包时的分类记录并参与完整性校验和，本参数经 query 传输，不要写进备份正文"}},"additionalProperties":true,"description":"v2 配置备份 JSON；lbbak 二进制备份与超过 1 MiB 网关上限的备份请走 REST /config/import 或管理面板"}`
const importV1ConfigSchema = `{"type":"object","description":"v1（nginx 版）备份 JSON 整体作为请求体（仅导入负载规则部分；覆盖导入会清理旧规则及其安全策略绑定）","additionalProperties":true}`

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
	{"retry_cert_job", "重试指定证书签发任务", http.MethodPost, "/certificates/jobs/{id}/retry", []string{"id"}, []string{"force"}, retryCertJobSchema},
	{"delete_cert_job", "删除指定证书签发任务", http.MethodDelete, "/certificates/jobs/{id}", []string{"id"}, nil, idSchema("id", "证书任务 ID", "integer")},
	{"issue_certificate", "触发 ACME 证书签发", http.MethodPost, "/certificates/issue", nil, []string{"force"}, issueCertificateSchema},
	{"list_certificates", "列出证书任务清单（每规则每域名最新签发任务：状态/到期时间）", http.MethodGet, "/certificates", nil, []string{"rule_id", "page", "page_size"}, listCertificatesSchema},
	{"get_config", "读取全局配置", http.MethodGet, "/config", nil, nil, emptySchema},
	{"update_config", "更新全局配置并应用 Caddy", http.MethodPut, "/config", nil, nil, updateConfigSchema},
	{"reload_caddy", "从数据库重新生成并加载 Caddy 配置", http.MethodPost, "/config/reload", nil, nil, emptySchema},
	{"export_config", "导出完整配置备份（lbbak 二进制 tar.gz；MCP 通道不支持二进制下载，本工具恒返回面板/REST 下载指引）", http.MethodGet, "/config/export", nil, nil, emptySchema},
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
	{"list_security_events", "分页列出安全事件（WAF 拦截/IP ACL 拒绝），可按负载规则/策略/触发规则/URI 过滤", http.MethodGet, "/security/events", nil, []string{"page", "page_size", "action", "ip", "rule_caddy_id", "rule_name", "policy_name", "rule_triggered", "rule_triggered_exclude", "uri", "start_time", "end_time"}, securityEventsSchema},
	{"list_security_bindings", "列出安全策略与规则的绑定关系", http.MethodGet, "/security/bindings", nil, nil, emptySchema},
	{"get_rule_security_policy", "获取指定规则绑定的安全策略（仅返回 enabled=1 的策略）", http.MethodGet, "/security/rules/{caddy_id}/policy", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"list_custom_rules", "列出全部自定义安全规则", http.MethodGet, "/security/custom-rules", nil, nil, emptySchema},
	{"list_block_pages", "列出全部拦截页面", http.MethodGet, "/security/block-pages", nil, nil, emptySchema},
	{"get_crs_info", "获取 CRS 规则库信息（版本/状态/自动更新）", http.MethodGet, "/security/crs", nil, nil, emptySchema},
	{"get_crs_update_status", "获取 CRS 更新进度状态", http.MethodGet, "/security/crs/update/status", nil, nil, emptySchema},
	{"get_crs_update_logs", "获取 CRS 更新日志", http.MethodGet, "/security/crs/update/logs", nil, nil, emptySchema},
	{"list_crs_rules", "分页浏览 CRS 规则文件", http.MethodGet, "/security/crs/rules", nil, []string{"search", "page", "page_size"}, listCRSRulesSchema},
	{"get_crs_rule", "查看指定 CRS 规则文件内容", http.MethodGet, "/security/crs/rules/{filename}", []string{"filename"}, nil, idSchema("filename", "规则文件名", "string")},
	{"get_crs_rule_index", "获取 CRS 结构化规则索引（全部 6 位规则 ID/消息/文件/分类，按 ID 升序）", http.MethodGet, "/security/crs/rule-index", nil, nil, emptySchema},
	{"get_ip2region_info", "获取 IP2Region 信息（版本/状态/自动更新）", http.MethodGet, "/security/ip2region", nil, nil, emptySchema},
	{"get_ip2region_regions", "获取可选区域列表", http.MethodGet, "/security/ip2region/regions", nil, nil, emptySchema},
	{"get_ip2region_update_status", "获取 IP2Region 更新进度状态", http.MethodGet, "/security/ip2region/update/status", nil, nil, emptySchema},
	{"get_ip2region_update_logs", "获取 IP2Region 更新日志", http.MethodGet, "/security/ip2region/update/logs", nil, nil, emptySchema},
	{"get_rate_limit_blocks", "获取限流拦截统计", http.MethodGet, "/security/rate-limit-blocks", nil, nil, emptySchema},
	{"get_rule_stage_stats", "获取单规则三阶段安全统计（阶段 1/3 近 24h 拦截数+限流重载口径计数）", http.MethodGet, "/security/rules/{caddy_id}/stage-stats", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"create_security_policy", "创建安全策略（WAF 模式/CRS/IP ACL/GeoIP/限流/拦截页面）", http.MethodPost, "/security/policies", nil, nil, createSecurityPolicySchema},
	{"update_security_policy", "更新指定安全策略", http.MethodPut, "/security/policies/{id}", []string{"id"}, nil, updateSecurityPolicySchema},
	{"delete_security_policy", "删除指定安全策略", http.MethodDelete, "/security/policies/{id}", []string{"id"}, nil, idSchema("id", "策略 ID", "integer")},
	{"bind_security_policy", "将安全策略绑定到指定规则", http.MethodPost, "/security/policies/{id}/bind", []string{"id"}, nil, `{"type":"object","required":["id","rule_caddy_id"],"properties":{"id":{"type":"integer","description":"策略 ID"},"rule_caddy_id":{"type":"string","description":"规则 Caddy ID（additive 绑定，不覆盖已有绑定）"}},"additionalProperties":false}`},
	// DELETE 请求体恒被后端丢弃——宽松 body schema(任意字段放行)会误导
	// Agent 构造无效 body;换成路径参数契约形态(required id+caddy_id,
	// forward 按 pathArgs 从 arguments 取值)。
	{"unbind_security_policy", "解除安全策略与规则的绑定", http.MethodDelete, "/security/policies/{id}/bind/{caddy_id}", []string{"id", "caddy_id"}, nil, `{"type":"object","required":["id","caddy_id"],"properties":{"id":{"type":"integer","description":"策略 ID"},"caddy_id":{"type":"string","description":"规则 Caddy ID"}},"additionalProperties":false}`},
	// v2.2.0 多策略绑定：原子替换规则绑定的策略集合（整体替换而非追加），
	// policy_ids maxItems=8 与后端 maxBindingsPerRule 校验对齐。
	{"set_rule_security_policies", "原子设置规则的安全策略集合（按 policy_id ASC 顺序评估）", http.MethodPut, "/security/rules/{caddy_id}/policies", []string{"caddy_id"}, nil, setRuleSecurityPoliciesSchema},
	{"create_custom_rule", "创建自定义安全规则", http.MethodPost, "/security/custom-rules", nil, nil, createCustomRuleSchema},
	{"update_custom_rule", "更新指定自定义安全规则", http.MethodPut, "/security/custom-rules/{id}", []string{"id"}, nil, updateCustomRuleSchema},
	{"delete_custom_rule", "删除指定自定义安全规则", http.MethodDelete, "/security/custom-rules/{id}", []string{"id"}, nil, idSchema("id", "规则 ID", "integer")},
	{"create_block_page", "创建拦截页面", http.MethodPost, "/security/block-pages", nil, nil, createBlockPageSchema},
	{"update_block_page", "更新指定拦截页面", http.MethodPut, "/security/block-pages/{id}", []string{"id"}, nil, updateBlockPageSchema},
	{"delete_block_page", "删除指定拦截页面", http.MethodDelete, "/security/block-pages/{id}", []string{"id"}, nil, idSchema("id", "页面 ID", "integer")},
	{"list_ip_lists", "列出全部 IP 地址列表", http.MethodGet, "/security/ip-lists", nil, nil, emptySchema},
	// v2.3.2 名单瘦身后 list_ip_lists 仅含 entry_count，
	// 读条目唯一通道是 GET /security/ip-lists/:id——补工具覆盖，免豁免。
	{"get_ip_list", "获取指定 IP 地址列表详情（含全部条目）", http.MethodGet, "/security/ip-lists/{id}", []string{"id"}, nil, idSchema("id", "列表 ID", "integer")},
	{"create_ip_list", "创建 IP 地址列表", http.MethodPost, "/security/ip-lists", nil, nil, createIPListSchema},
	{"update_ip_list", "更新指定 IP 地址列表", http.MethodPut, "/security/ip-lists/{id}", []string{"id"}, nil, updateIPListSchema},
	{"delete_ip_list", "删除指定 IP 地址列表", http.MethodDelete, "/security/ip-lists/{id}", []string{"id"}, nil, idSchema("id", "列表 ID", "integer")},
	// （2026-09 审计）：安全事件处置工作流——单条追加幂等（已存在返回
	// added=false），免去 Agent 读全表-改-全量替换的竞态路径。
	{"add_ip_to_list", "向 IP 地址列表追加单条 IP/CIDR（安全事件处置用，幂等；内置威胁名单只读返回 400）", http.MethodPost, "/security/ip-lists/{id}/ips", []string{"id"}, nil, `{"type":"object","required":["id","value"],"properties":{"id":{"type":"integer","description":"列表 ID"},"value":{"type":"string","description":"IP 或 CIDR，如 203.0.113.7 或 10.0.0.0/8。remark 无需提交：自定义名单固定为「事件处置」，自动封禁预置名单固定为「手动封禁」（任务挤出豁免判据）"}},"additionalProperties":false}`},
	// 封禁处置闭环的解封原语：幂等单条移除（value 不在名单返回 removed=false）。
	// 不得用 get_ip_list+update_ip_list 读-改-全量写回替代——自动封禁任务并发
	// 向同一名单写入时全量回写会覆盖并发新增（丢失封禁条目）。
	{"remove_ip_from_list", "从 IP 地址列表移除单条 IP/CIDR（解封/误封处置，幂等；内置威胁名单只读返回 400）", http.MethodPost, "/security/ip-lists/{id}/remove-ip", []string{"id"}, nil, `{"type":"object","required":["id","value"],"properties":{"id":{"type":"integer","description":"列表 ID"},"value":{"type":"string","description":"要移除的 IP 或 CIDR，如 203.0.113.7 或 10.0.0.0/8"}},"additionalProperties":false}`},
	{"toggle_crs_auto_update", "开关 CRS 自动更新", http.MethodPut, "/security/crs/auto-update", nil, nil, toggleAutoUpdateSchema},
	{"trigger_crs_update", "手动触发 CRS 规则库更新", http.MethodPost, "/security/crs/update", nil, nil, emptySchema},
	{"toggle_ip2region_auto_update", "开关 IP2Region 自动更新", http.MethodPut, "/security/ip2region/auto-update", nil, nil, toggleAutoUpdateSchema},
	{"trigger_ip2region_update", "手动触发 IP2Region 数据库更新", http.MethodPost, "/security/ip2region/update", nil, nil, emptySchema},
	{"list_cluster_nodes", "列出全部集群节点", http.MethodGet, "/cluster/nodes", nil, nil, emptySchema},
	{"create_register_token", "生成集群注册令牌（无需请求体；明文仅返回一次，30 分钟过期）", http.MethodPost, "/cluster/register-tokens", nil, nil, emptySchema},
	{"approve_cluster_node", "审批通过从节点注册", http.MethodPost, "/cluster/nodes/{id}/approve", []string{"id"}, nil, idSchema("id", "节点 ID", "integer")},
	{"reject_cluster_node", "拒绝从节点注册", http.MethodPost, "/cluster/nodes/{id}/reject", []string{"id"}, nil, idSchema("id", "节点 ID", "integer")},
	{"create_login_ticket", "为从节点生成登录票据（操作者账户必须已启用 MFA，否则 403；人类 JWT 路径还需 60 秒内通过 MFA 验证（428 step-up），API Key/MCP 路径仅豁免该验证窗口）", http.MethodPost, "/cluster/nodes/{id}/login-ticket", []string{"id"}, nil, idSchema("id", "节点 ID", "integer")},
	{"update_node_access_url", "更新从节点访问地址", http.MethodPut, "/cluster/nodes/{id}/access-url", []string{"id"}, nil, updateNodeAccessURLSchema},
	{"delete_cluster_node", "删除指定集群节点", http.MethodDelete, "/cluster/nodes/{id}", []string{"id"}, nil, idSchema("id", "节点 ID", "integer")},
	{"control_cluster_node_service", "主节点遥控从节点服务（仅主节点管理员 Key 可用；从节点证书指纹不匹配时先 forget_cluster_node_pin）", http.MethodPost, "/cluster/nodes/{id}/service", []string{"id"}, nil, `{"type":"object","required":["id","action"],"properties":{"id":{"type":"integer","description":"节点 ID"},"action":{"type":"string","enum":["start_caddy","stop_caddy","restart_caddy","restart_app"],"description":"服务控制动作（与后端 IsValidClusterServiceAction 支持集一致）"}},"additionalProperties":false}`},
	{"forget_cluster_node_pin", "清除主节点对指定从节点的证书指纹钉（单节点重钉；无钉时幂等成功）", http.MethodPost, "/cluster/nodes/{id}/forget-pin", []string{"id"}, nil, idSchema("id", "节点 ID", "integer")},
	{"forget_cluster_pins", "清除本节点对主节点的全部证书指纹钉（从节点 PinMismatch 自救；主节点调用返回 400）", http.MethodPost, "/cluster/forget-pins", nil, nil, emptySchema},
	{"set_cluster_mode", "注册并切换为从节点（standalone/master → slave，需主节点审批）", http.MethodPost, "/cluster/mode", nil, nil, setClusterModeSchema},
	{"promote_cluster", "将从节点提升为主节点", http.MethodPost, "/cluster/promote", nil, nil, emptySchema},
	{"pull_sync", "手动触发从节点同步", http.MethodPost, "/cluster/sync/pull", nil, nil, emptySchema},
	// 任务监控（v2.3.4）：聚合视图 + 三操作
	{"list_system_tasks", "任务监控聚合视图（全部定时/后台任务族状态）", http.MethodGet, "/system/tasks", nil, nil, emptySchema},
	{"get_system_task_logs", "任务文本日志（尾部 256KB）", http.MethodGet, "/system/tasks/{id}/logs", []string{"id"}, nil, idSchema("id", "任务 ID", "string")},
	{"get_system_task_history", "任务运行历史（task_runs 时间倒序）", http.MethodGet, "/system/tasks/{id}/history", []string{"id"}, nil, idSchema("id", "任务 ID", "string")},
	{"trigger_system_task", "手动触发任务（全部非常驻任务族——以 GET /system/tasks 的 triggerable 字段为准；证书队列行用 cert-job:<job_id>）", http.MethodPost, "/system/tasks/{id}/trigger", []string{"id"}, nil, idSchema("id", "任务 ID（见 GET /system/tasks 的 triggerable 族）", "string")},
	{"toggle_system_task", "统一调度开关（定时/循环=停止/恢复调度、常驻=启停；触发类不可调度）", http.MethodPost, "/system/tasks/{id}/toggle", []string{"id"}, nil, toggleTaskSchema},
	{"cancel_system_task", "取消运行中任务（仅下载类）", http.MethodPost, "/system/tasks/{id}/cancel", []string{"id"}, nil, idSchema("id", "任务 ID", "string")},
	{"control_system_task", "常驻任务控制（action=start|stop|restart 均可用；常驻任务的启停也可经 toggle_system_task 的 enabled 实现，control 额外提供 restart 组合动作）", http.MethodPost, "/system/tasks/{id}/control", []string{"id"}, nil, controlTaskSchema},
	{"update_cluster_settings", "更新集群同步设置", http.MethodPut, "/cluster/settings", nil, nil, updateClusterSettingsSchema},
	{"list_certificate_configs", "列出全部 DNS 证书配置", http.MethodGet, "/certificate-configs", nil, nil, emptySchema},
	{"create_certificate_config", "创建 DNS 证书配置", http.MethodPost, "/certificate-configs", nil, nil, createCertificateConfigSchema},
	{"update_certificate_config", "更新指定 DNS 证书配置", http.MethodPut, "/certificate-configs/{id}", []string{"id"}, nil, updateCertificateConfigSchema},
	{"delete_certificate_config", "删除指定 DNS 证书配置", http.MethodDelete, "/certificate-configs/{id}", []string{"id"}, nil, idSchema("id", "配置 ID", "integer")},
	// handler 要求 body 携带 domain（测试用的域名）——此前
	// schema 只有 id（additionalProperties:false），经 MCP 调用恒 400「请求参数
	// 无效」。id 进路径、domain 进 body（转发器按 pathParams 分流）。
	{"test_certificate_config", "测试指定 DNS 证书配置", http.MethodPost, "/certificate-configs/{id}/test", []string{"id"}, nil, `{"type":"object","required":["id","domain"],"properties":{"id":{"type":"integer","description":"配置 ID"},"domain":{"type":"string","description":"用于测试的域名，如 example.com"}},"additionalProperties":false}`},
	{"list_dns_providers", "列出支持的 DNS 提供商", http.MethodGet, "/dns-providers", nil, nil, emptySchema},
	{"list_ca_providers", "列出全部 CA 提供商", http.MethodGet, "/ca-providers", nil, nil, emptySchema},
	{"get_ca_provider", "获取指定 CA 提供商详情", http.MethodGet, "/ca-providers/{id}", []string{"id"}, nil, idSchema("id", "CA ID", "integer")},
	{"update_ca_provider", "更新指定 CA 提供商", http.MethodPut, "/ca-providers/{id}", []string{"id"}, nil, updateCAProviderSchema},
	{"test_ca_provider", "测试指定 CA 提供商连接", http.MethodPost, "/ca-providers/{id}/test", []string{"id"}, nil, idSchema("id", "CA ID", "integer")},
	{"get_cert_job", "获取指定证书签发任务详情", http.MethodGet, "/certificates/jobs/{id}", []string{"id"}, nil, idSchema("id", "任务 ID", "integer")},
	{"get_cert_job_logs", "获取指定证书签发任务日志", http.MethodGet, "/certificates/jobs/{id}/logs", []string{"id"}, nil, idSchema("id", "任务 ID", "integer")},
	{"parse_certificate", "解析上传的证书内容", http.MethodPost, "/certificates/parse", nil, nil, parseCertificateSchema},
	{"create_user", "创建用户", http.MethodPost, "/users", nil, nil, createUserSchema},
	{"update_user", "更新指定用户（初始化管理员不可降级为普通用户——is_setup_admin=true 的行返回 400）", http.MethodPut, "/users/{id}", []string{"id"}, nil, updateUserSchema},
	{"toggle_user_status", "启用/禁用指定用户（初始化管理员不可禁用——is_setup_admin=true 的行返回 400）", http.MethodPut, "/users/{id}/status", []string{"id"}, nil, toggleUserStatusSchema},
	{"reset_user_password", "重置指定用户密码", http.MethodPost, "/users/{id}/reset-password", []string{"id"}, nil, idSchema("id", "用户 ID", "integer")},
	{"delete_user", "删除指定用户（初始化管理员不可删除——is_setup_admin=true 的行返回 400）", http.MethodDelete, "/users/{id}", []string{"id"}, nil, idSchema("id", "用户 ID", "integer")},
	{"reset_user_mfa", "重置用户 MFA（仅管理员；操作者已启用 MFA 时须提交本人 6 位动态验证码，未启用传空串——MCP/API Key 路径不走 428 step-up，直接在本接口验码）", http.MethodPost, "/users/{id}/mfa/reset", []string{"id"}, nil, `{"type":"object","required":["id","code"],"properties":{"id":{"type":"integer","description":"用户 ID"},"code":{"type":"string","description":"操作者自己的 6 位 MFA 动态验证码；操作者未启用 MFA 时传空串"}},"additionalProperties":false}`},
	{"create_api_key", "创建 API 密钥", http.MethodPost, "/api-keys", nil, nil, createAPIKeySchema},
	{"update_api_key_status", "更新 API 密钥状态（启用/只读/MCP 开关）", http.MethodPatch, "/api-keys/{id}/status", []string{"id"}, nil, updateAPIKeyStatusSchema},
	{"delete_api_key", "删除指定 API 密钥", http.MethodDelete, "/api-keys/{id}", []string{"id"}, nil, idSchema("id", "密钥 ID", "integer")},
	{"preview_config", "预览配置变更（不应用）", http.MethodPost, "/config/preview", nil, nil, previewConfigSchema},
	{"validate_config", "验证配置文件有效性", http.MethodPost, "/config/validate", nil, nil, validateConfigSchema},
	{"import_config", "导入 v2 配置备份", http.MethodPost, "/config/import", nil, []string{"sections"}, configImportSchema},
	{"validate_import", "验证导入文件（不写入）", http.MethodPost, "/config/import/validate", nil, []string{"sections"}, configImportSchema},
	{"import_v1_config", "导入 v1（nginx）配置", http.MethodPost, "/config/import/v1", nil, nil, importV1ConfigSchema},
	{"get_rule_logs", "获取指定规则的访问日志（最近 1000 行尾读，无 offset 续读）", http.MethodGet, "/rules/{caddy_id}/logs", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"get_rule_caddy_config", "获取指定规则的 Caddy 配置片段", http.MethodGet, "/rules/{caddy_id}/caddy-config", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"get_rule_metrics_history", "获取指定规则的历史指标（range 选窗 1h/6h/24h/7d；跨规则全局趋势用 get_metrics_history）", http.MethodGet, "/rules/{caddy_id}/metrics-history", []string{"caddy_id"}, []string{"range"}, ruleMetricsHistorySchema},
	{"get_rule_cert_info", "获取指定规则的证书信息", http.MethodGet, "/rules/{caddy_id}/cert-info", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"get_caddy_status", "获取 Caddy 运行状态", http.MethodGet, "/caddy/status", nil, nil, emptySchema},
	{"get_caddy_config", "获取 Caddy 当前配置", http.MethodGet, "/caddy/config", nil, nil, emptySchema},
	{"get_caddy_logs", "获取 Caddy 日志", http.MethodGet, "/caddy/logs", nil, []string{"type"}, caddyLogsSchema},
	{"update_caddy_config", "直接更新 Caddy 配置", http.MethodPut, "/caddy/config", nil, nil, updateCaddyConfigSchema},
	{"start_caddy", "启动 Caddy", http.MethodPost, "/caddy/start", nil, nil, emptySchema},
	{"stop_caddy", "停止 Caddy", http.MethodPost, "/caddy/stop", nil, nil, emptySchema},
	{"restart_caddy", "重启 Caddy", http.MethodPost, "/caddy/restart", nil, nil, emptySchema},
	{"get_admin_tls", "获取管理面板 HTTPS 配置", http.MethodGet, "/admin-tls", nil, nil, emptySchema},
	{"update_admin_tls", "更新管理面板 HTTPS 配置", http.MethodPut, "/admin-tls", nil, nil, updateAdminTLSSchema},
	{"inspect_admin_tls", "检查管理面板 HTTPS 证书", http.MethodPost, "/admin-tls/inspect", nil, nil, inspectAdminTLSSchema},
	{"get_system_metrics", "获取系统资源指标（CPU/内存/磁盘）", http.MethodGet, "/system/metrics", nil, nil, emptySchema},
	{"get_system_logs", "获取应用日志", http.MethodGet, "/system/logs", nil, nil, emptySchema},
	{"restart_system", "重启应用服务", http.MethodPost, "/system/restart", nil, nil, emptySchema},
	{"get_rule_metrics", "获取指定规则的实时指标", http.MethodGet, "/metrics/rule/{caddy_id}", []string{"caddy_id"}, nil, idSchema("caddy_id", "规则 Caddy ID", "string")},
	{"get_metrics_history", "获取历史指标趋势（interval 选窗，可按 rule_id 过滤；单规则固定窗口用 get_rule_metrics_history 的 range）", http.MethodGet, "/metrics/history", nil, []string{"rule_id", "interval"}, metricsHistorySchema},
	{"get_connections", "获取当前连接统计", http.MethodGet, "/metrics/connections", nil, nil, emptySchema},
}

const emptySchema = `{"type":"object","properties":{},"additionalProperties":false}`
const maxResponseSize = 4 << 20
const InternalAuthHeader = "X-Lazy-Balancer-Internal-MCP-Auth"

// noPaginationToolHints 是「整份返回、无分页参数」的工具在响应超限时的专用
// 指引。通用「改用分页或专用导出工具」对它们是死路：既没有分页参数，也没有
// 可直接换用的导出工具——必须给该工具真能走通的路径。
//   - export_config：lbbak 二进制包，MCP 通道本就不支持二进制下载；
//   - get_caddy_config：Caddy 完整 JSON，单条规则片段有 get_rule_caddy_config；
//   - get_metrics_history / get_rule_metrics_history：可选 queryArgs 只收窄维度
//     （rule_id/interval/range），没有 page/page_size，收敛范围靠选窗与单规则过滤；
//   - get_caddy_logs：可选 queryArgs 只有 type，尾部日志超限只能换专用读通道；
//   - preview_config：POST 整份预览（source 为配置分区），无分页参数；
//   - get_rule_logs：GET 尾读最近 1000 行，无分页参数——它本身就是该类单条工具，
//     通用文案「改用对应的单条查询工具」对它指向自己，只能给 REST 增量读通道。
//
// 新增此类工具时必须在此登记，否则会退回不可执行的通用文案。
var noPaginationToolHints = map[string]string{
	"export_config":            "配置过大：MCP 通道响应上限 4 MiB，请由管理员经管理面板或 REST /config/export 下载备份",
	"get_caddy_config":         "Caddy 完整配置超过 MCP 通道 4 MiB 上限：请在管理面板查看/导出，或改用 get_rule_caddy_config 按规则逐个查询",
	"get_metrics_history":      "历史指标超过 MCP 通道 4 MiB 上限：本工具无分页参数——请传 rule_id 收窄到单条规则（或改用 get_rule_metrics_history 的 range 选窗），或经管理面板查看趋势",
	"get_rule_metrics_history": "规则历史指标超过 MCP 通道 4 MiB 上限：本工具无分页参数——请缩短 range（1h/6h）后重试，或经管理面板查看趋势",
	"get_caddy_logs":           "Caddy 日志超过 MCP 通道 4 MiB 上限：本工具无分页参数——请改用 get_rule_logs 按规则查看（尾读最近 1000 行），或经管理面板查看完整日志",
	"preview_config":           "预览结果超过 MCP 通道 4 MiB 上限：本工具无分页参数——请拆小 source（按配置分区分批预览），或经管理面板预览完整差异",
	"get_rule_logs":            "规则日志超过 MCP 通道 4 MiB 上限：本工具无分页参数（尾读最近 1000 行）——请经 REST /rules/{caddy_id}/log-stream 增量续读，或经管理面板查看完整日志",
}

// schemaDeclaresPagination 报告工具的 input_schema 是否声明 page/page_size。
// 超大响应指引按「真实分页能力」判定——queryArgs 非空不代表有分页
// （get_caddy_logs 只有 type、get_metrics_history 只有 rule_id/interval）。
// 判据不看 HTTP 方法：POST 整份返回工具（preview_config/validate_config/
// issue_certificate 等）同样没有分页参数，「改用分页」对它们一律是死路。
func schemaDeclaresPagination(spec toolSpec) bool {
	var shape struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal([]byte(spec.schema), &shape) != nil {
		return false
	}
	_, hasPage := shape.Properties["page"]
	_, hasPageSize := shape.Properties["page_size"]
	return hasPage || hasPageSize
}

// oversizedResponseMessage 选择超大响应的处置指引：专用 hint 优先；其余工具
// 按「schema 是否声明 page/page_size」分流——无分页能力的整份返回工具给单条
// 查询/管理面板路径（「改用分页」对它们是死路），有分页的维持通用分页指引。
func oversizedResponseMessage(spec toolSpec) string {
	if hint, ok := noPaginationToolHints[spec.name]; ok {
		return hint
	}
	if !schemaDeclaresPagination(spec) {
		return "内部 API 响应超过 4 MiB 上限；本工具无分页参数——请改用对应的单条查询工具（get_* 系列）缩小范围，或经管理面板查看/导出"
	}
	return "内部 API 响应超过 4 MiB 上限，请改用分页或专用导出工具"
}

// 历史 MCP 工具调用经本机回环转发到内部 REST（源地址恒为
// 127.0.0.1），审计/安全记录会把全部 MCP 操作记成回环 IP。网关层把真实客户端
// IP 注入请求 context（WithClientIP），forward 再转写为内部头；接收端仅在内部
// 认证密钥匹配时采信该头（外部请求无法伪造审计源 IP）。
const InternalClientIPHeader = "X-Lazy-Balancer-Internal-MCP-Client-IP"

type clientIPContextKey struct{}

// WithClientIP 将 MCP 请求的真实客户端 IP 附加到 context（网关在进入 MCP
// 协议处理器前调用）。
func WithClientIP(ctx context.Context, clientIP string) context.Context {
	return context.WithValue(ctx, clientIPContextKey{}, clientIP)
}

// ClientIPFromContext 读取网关注入的真实客户端 IP（无注入时返回空串）。
func ClientIPFromContext(ctx context.Context) string {
	clientIP, _ := ctx.Value(clientIPContextKey{}).(string)
	return clientIP
}

// serverInstructions 随 initialize 响应下发给客户端，说明认证方式、权限范围与常用流程，
// 让 Agent 在首次选工具前就能选对路径、减少试错往返
const serverInstructions = `Lazy Balancer V2 负载均衡管理接口。认证：X-API-Key 头或 Authorization: Bearer lb_sk_...，Key 需开启 MCP 功能。

权限范围：
- 只读 Key（read_only）可调用 GET 查询类工具（export_config 与 get_caddy_config 除外——导出含用户/密钥哈希、原始 Caddy 配置可能含内联私钥，二者与写操作同级隐藏）及 3 个读探测 POST 工具；其中 parse_certificate 对非管理员开放，validate_import/preview_config 需 Key 属主为管理员（属 admin 组路由，非管理员调用恒 403 且 tools/list 不展示）；其余写工具（POST/PUT/PATCH/DELETE）需非只读 Key
- 写操作需要管理员权限（API Key 所属用户角色为 admin），非管理员 Key 调用写工具返回 403；tools/list 已按「read_only 轴 + admin 轴」双轴过滤——admin 轴覆盖 admin 组路由与 business 组写路由（只读探测 POST 除外），未列出的工具不是不存在，而是当前 Key 不可见/不可调用
- 从节点上仅 /cluster/ 前缀端点可过只读门，非从节点语义的集群操作由业务层拒绝（403/400），其余变更类写工具一律 403（预览/解析/只读查询类 POST 除外）——集群运维在目标节点本身调用，不要发往主节点；所有写操作校验后即时生效（失败自动回滚），无需手动 reload
- 配置 IP 白名单的 Key 还需来源 IP 命中白名单（白名单约束该 Key 的全部 REST 与 MCP 调用；MCP 内部转发不受白名单影响）

常用流程：
- 新建 HTTP 代理：create_rule（protocol=http + domain + listen_port + upstreams）→ 需要免费证书时 issue_certificate 传 caddy_id
- 新建 TCP 代理：create_rule（protocol=tcp + listen_port + upstreams，不要填 domain）；后端需真实客户端 IP 时加 tcp_proxy_protocol=true
- 排查流量异常：get_upstream_health → get_metrics_dashboard → list_audit_logs（page/page_size 分页，page_size≤100）
- 快速看全局指标：get_metrics_overview（轻量）；get_metrics_dashboard 为全量聚合，数据量大，非必要不用
- 修改规则前先 get_rule 取完整现状；delete_rule 不可恢复，调用前必须确认

错误约定：401=密钥无效/缺失或使用 JWT；403=未开启 MCP/IP 白名单拦截/只读 Key 越权/从节点非集群写工具；缺参/缺密钥/传输失败与 REST 业务错误均以 IsError+文本返回（含具体 message，读后修正重试）；协议层暂不启用 input_schema 校验（不产生 -32602），schema 仅作构参契约——先读 schema 再调用，不要猜测字段名。

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

const createRuleSchema = `{"type":"object","required":["name","protocol","listen_port","upstreams"],"properties":{"name":{"type":"string"},"description":{"type":"string"},"protocol":{"type":"string","enum":["http","tcp"]},"domain":{"type":"string"},"listen_port":{"type":"integer","minimum":1,"maximum":65535},"enabled":{"type":"boolean","description":"缺省=创建即启用；显式 false=创建为禁用"},"strategy":{"type":"string","enum":["weighted_round_robin","ip_hash","least_conn","random","first","cookie"],"description":"负载策略。HTTP 六值全集；TCP 规则不支持 cookie（后端将拒绝，保存前请改用其余五值）"},"ntlm_compatible":{"type":"integer","enum":[0,1],"description":"NTLM 兼容开关，仅 HTTP 规则可用；1=开启（要求 strategy=cookie，后端将拒绝其余策略；TCP 规则携带即拒），且须同时提交 tcp_try_duration=-1、upstream_force_http1=1、proxy_flush_interval=-1、upstream_keepalive_timeout=300（规则向导的 NTLM 开关整体落下这四列，缺一即 400）"},"upstream_force_http1":{"type":"integer","enum":[0,1],"description":"上游强制 HTTP/1.1（通用列，仅 HTTP 规则渲染生效；https 上游禁 ALPN h2）。后端不支持 HTTP/2 或使用 NTLM 认证时开启；更新时省略=保留原值"},"dynamic_dns":{"type":"boolean"},"enable_dns_server":{"type":"boolean"},"dns_server":{"type":"string"},"dns_family":{"type":"string","enum":["ipv4","ipv6","both"]},"health_check_path":{"type":"string"},"health_check_interval":{"type":"integer"},"health_check_timeout":{"type":"integer","minimum":0,"description":"健康检查超时秒数；须小于 health_check_interval（两者均 >0 时否则 400）"},"health_check_unhealthy_threshold":{"type":"integer"},"health_check_healthy_threshold":{"type":"integer"},"enable_active_health_check":{"type":"boolean"},"health_check_host":{"type":"string","description":"健康检查域名：主动健康检查请求的 Host 头（纯主机名不带端口）；空=跟随 host_header"},"tcp_health_check_port":{"type":"integer"},"tcp_proxy_protocol":{"type":"boolean"},"tcp_try_duration":{"type":"integer","minimum":-1,"maximum":60000,"description":"重试窗口毫秒：HTTP 规则 -1=禁用重试（0=缺省 5 秒窗口），TCP 规则须 ≥0；上界 60000"},"tcp_try_interval":{"type":"integer","minimum":0,"maximum":60000,"description":"重试间隔毫秒；重试窗口 >0 时必须 ≥1"},"request_body_max_size_mb":{"type":"integer"},"upstream_keepalive_timeout":{"type":"integer"},"server_tokens_hidden":{"type":"integer","enum":[0,1,2],"description":"Server 头隐藏覆盖（API/MCP 预留字段，无 UI 入口）：0=跟随全局设置（基础设置的全局开关）/1=隐藏响应 Server 头/2=显式显示（抵消全局隐藏）"},"custom_routes_enabled":{"type":"boolean"},"proxy_dial_timeout":{"type":"integer","minimum":0},"proxy_response_header_timeout":{"type":"integer","minimum":0},"proxy_read_timeout":{"type":"integer","minimum":0},"proxy_write_timeout":{"type":"integer","minimum":0},"proxy_stream_timeout":{"type":"integer","minimum":0},"proxy_flush_interval":{"type":"integer","minimum":-1},"proxy_stream_close_delay":{"type":"integer","minimum":0},"path_rules":{"type":"array","items":{"type":"object","required":["match_type","path"],"properties":{"id":{"type":"integer"},"sort_order":{"type":"integer"},"match_type":{"type":"string","enum":["prefix","exact"]},"path":{"type":"string"},"upstream_path":{"type":"string"},"response_mode":{"type":"string","enum":["","static","redirect"]},"response_status":{"type":"integer"},"response_body":{"type":"string","maxLength":64},"response_content_type":{"type":"string","enum":["","text/plain","application/json","text/html"]},"redirect_to":{"type":"string"},"upstreams":{"type":"array","items":{"type":"object","required":["address","port"],"properties":{"address":{"type":"string"},"port":{"type":"integer","minimum":1,"maximum":65535},"weight":{"type":"integer","minimum":1},"protocol":{"type":"string","description":"http 或 https；省略=http"}}}}},"description":"路径规则：match_type/path/upstream_path/upstreams；另支持 response_mode 直返/跳转（2026-10-10）——static=静态响应（response_status 常用码，0=缺省 200/response_body ≤64 字符/response_content_type text/plain|application/json|text/html，空=缺省 text/plain），redirect=301+redirect_to 目标（须 http(s):// 绝对地址或 / 开头路径，禁控制字符）；互斥：直返/跳转与 upstreams/upstream_path 互斥、static 与 redirect_to 互斥、redirect 与 response_body/response_content_type 互斥"}},"host_header":{"type":"string"},"upstreams":{"type":"array","items":{"type":"object","required":["host","port"],"properties":{"host":{"type":"string"},"port":{"type":"integer","minimum":1,"maximum":65535},"weight":{"type":"integer","minimum":1},"enabled":{"type":"boolean"},"protocol":{"type":"string"},"max_connections":{"type":"integer"},"origin_domain":{"type":"string","description":"该上游独立的回源 Host 头与 HTTPS SNI（纯主机名不带端口）；空=跟随规则 host_header；dynamic_dns 规则与 TCP 规则不支持"}}}},"enable_tls":{"type":"boolean"},"tls_source":{"type":"string","enum":["manual","acme_dns"],"description":"证书来源：manual=手动上传证书/私钥（tls_cert/tls_key），acme_dns=ACME DNS 验证签发（需 acme_config_id）"},"block_page_stage1_id":{"type":"integer","description":"阶段 1（IP 预检）拦截页面 ID，0=跟随全局/策略"},"block_page_stage1_status":{"type":"integer","description":"阶段 1 拦截状态码（0=默认 403）"},"block_page_stage3_id":{"type":"integer","description":"阶段 3（WAF）拦截页面 ID，0=跟随全局/策略"},"block_page_stage3_status":{"type":"integer","description":"阶段 3 拦截状态码（0=默认 403）"},"acme_config_id":{"type":"integer"},"ca_provider_id":{"type":"integer"},"tls_cert":{"type":"string"},"tls_key":{"type":"string"},"tls_http_redirect":{"type":"boolean"},"enable_compress":{"type":"boolean"},"compress_types":{"type":"string"},"log_enabled":{"type":"boolean"}},"additionalProperties":false}`

const updateRuleSchema = `{"type":"object","required":["caddy_id"],"properties":{"caddy_id":{"type":"string"},"expected_updated_at":{"type":"string","description":"可选版本前置条件（乐观并发）：回传打开表单/上次读取时看到的 updated_at（RFC3339 或 YYYY-MM-DD HH:MM:SS）；省略或空串=不校验（后写覆盖前写）；提供且与当前库值不一致时 REST 返回 409，请重新读取规则后再提交。保护粒度为秒"},"name":{"type":"string"},"description":{"type":"string"},"protocol":{"type":"string","enum":["http","tcp"]},"domain":{"type":"string"},"listen_port":{"type":"integer","minimum":1,"maximum":65535},"strategy":{"type":"string","enum":["weighted_round_robin","ip_hash","least_conn","random","first","cookie"],"description":"负载策略。HTTP 六值全集；TCP 规则不支持 cookie（后端将拒绝，保存前请改用其余五值）"},"ntlm_compatible":{"type":"integer","enum":[0,1],"description":"NTLM 兼容开关，仅 HTTP 规则可用；1=开启（要求 strategy=cookie，后端将拒绝其余策略；TCP 规则携带即拒），且须同时提交 tcp_try_duration=-1、upstream_force_http1=1、proxy_flush_interval=-1、upstream_keepalive_timeout=300（规则向导的 NTLM 开关整体落下这四列，缺一即 400）"},"upstream_force_http1":{"type":"integer","enum":[0,1],"description":"上游强制 HTTP/1.1（通用列，仅 HTTP 规则渲染生效）。省略=保留原值"},"dynamic_dns":{"type":"boolean"},"enable_dns_server":{"type":"boolean"},"dns_server":{"type":"string"},"dns_family":{"type":"string","enum":["ipv4","ipv6","both"]},"health_check_path":{"type":"string"},"health_check_interval":{"type":"integer"},"health_check_timeout":{"type":"integer","minimum":0,"description":"健康检查超时秒数；须小于 health_check_interval（两者均 >0 时否则 400）"},"health_check_unhealthy_threshold":{"type":"integer"},"health_check_healthy_threshold":{"type":"integer"},"enable_active_health_check":{"type":"boolean"},"health_check_host":{"type":"string","description":"健康检查域名：主动健康检查请求的 Host 头（纯主机名不带端口）；空=跟随 host_header；省略=保留原值"},"tcp_health_check_port":{"type":"integer"},"tcp_proxy_protocol":{"type":"boolean"},"tcp_try_duration":{"type":"integer","minimum":-1,"maximum":60000,"description":"重试窗口毫秒：HTTP 规则 -1=禁用重试（0=缺省 5 秒窗口），TCP 规则须 ≥0；上界 60000"},"tcp_try_interval":{"type":"integer","minimum":0,"maximum":60000,"description":"重试间隔毫秒；重试窗口 >0 时必须 ≥1"},"request_body_max_size_mb":{"type":"integer"},"upstream_keepalive_timeout":{"type":"integer"},"server_tokens_hidden":{"type":"integer","enum":[0,1,2],"description":"Server 头隐藏覆盖（API/MCP 预留字段，无 UI 入口）：0=跟随全局设置（基础设置的全局开关）/1=隐藏响应 Server 头/2=显式显示（抵消全局隐藏）"},"custom_routes_enabled":{"type":"boolean"},"proxy_dial_timeout":{"type":"integer","minimum":0},"proxy_response_header_timeout":{"type":"integer","minimum":0},"proxy_read_timeout":{"type":"integer","minimum":0},"proxy_write_timeout":{"type":"integer","minimum":0},"proxy_stream_timeout":{"type":"integer","minimum":0},"proxy_flush_interval":{"type":"integer","minimum":-1},"proxy_stream_close_delay":{"type":"integer","minimum":0},"path_rules":{"type":"array","items":{"type":"object","required":["match_type","path"],"properties":{"id":{"type":"integer"},"sort_order":{"type":"integer"},"match_type":{"type":"string","enum":["prefix","exact"]},"path":{"type":"string"},"upstream_path":{"type":"string"},"response_mode":{"type":"string","enum":["","static","redirect"]},"response_status":{"type":"integer"},"response_body":{"type":"string","maxLength":64},"response_content_type":{"type":"string","enum":["","text/plain","application/json","text/html"]},"redirect_to":{"type":"string"},"upstreams":{"type":"array","items":{"type":"object","required":["address","port"],"properties":{"address":{"type":"string"},"port":{"type":"integer","minimum":1,"maximum":65535},"weight":{"type":"integer","minimum":1},"protocol":{"type":"string","description":"http 或 https；省略=http"}}}}},"description":"路径规则：match_type/path/upstream_path/upstreams；另支持 response_mode 直返/跳转（2026-10-10）——static=静态响应（response_status 常用码，0=缺省 200/response_body ≤64 字符/response_content_type text/plain|application/json|text/html，空=缺省 text/plain），redirect=301+redirect_to 目标（须 http(s):// 绝对地址或 / 开头路径，禁控制字符）；互斥：直返/跳转与 upstreams/upstream_path 互斥、static 与 redirect_to 互斥、redirect 与 response_body/response_content_type 互斥"}},"host_header":{"type":"string"},"upstreams":{"type":"array","items":{"type":"object","required":["host","port"],"properties":{"host":{"type":"string"},"port":{"type":"integer","minimum":1,"maximum":65535},"weight":{"type":"integer","minimum":1},"enabled":{"type":"boolean"},"protocol":{"type":"string"},"max_connections":{"type":"integer"},"origin_domain":{"type":"string","description":"该上游独立的回源 Host 头与 HTTPS SNI（纯主机名不带端口）；空=跟随规则 host_header；dynamic_dns 规则与 TCP 规则不支持"}},"description":"上游条目（创建时整体提交，更新时整体替换）；支持 host/port/weight/enabled/protocol/max_connections/origin_domain（该上游独立的回源 Host 头与 HTTPS SNI，纯主机名不带端口）"}},"enable_tls":{"type":"boolean"},"tls_source":{"type":"string","enum":["manual","acme_dns"],"description":"证书来源：manual=手动证书（tls_cert/tls_key），acme_dns=ACME DNS 验证签发（需 acme_config_id）"},"block_page_stage1_id":{"type":"integer","description":"阶段 1（IP 预检）拦截页面 ID，0=跟随全局/策略"},"block_page_stage1_status":{"type":"integer","description":"阶段 1 拦截状态码（0=默认 403）"},"block_page_stage3_id":{"type":"integer","description":"阶段 3（WAF）拦截页面 ID，0=跟随全局/策略"},"block_page_stage3_status":{"type":"integer","description":"阶段 3 拦截状态码（0=默认 403）"},"acme_config_id":{"type":"integer"},"ca_provider_id":{"type":"integer"},"tls_cert":{"type":"string"},"tls_key":{"type":"string"},"tls_http_redirect":{"type":"boolean"},"enable_compress":{"type":"boolean"},"compress_types":{"type":"string"},"enabled":{"type":"boolean"},"log_enabled":{"type":"boolean"}},"additionalProperties":false}`

// 确认门（与 REST 侧 POST /certificates/issue 的 {"all":true} 同步）
// 空 body（全量重签）不再放行——批量必须显式 all:true（enum 锁死 true，防
// all:false 静默变空批量）；定向签发仍走 caddy_id（domain 可选）。
const issueCertificateSchema = `{"type":"object","properties":{"caddy_id":{"type":"string","description":"定向签发（domain 可选，须与规则域名集合一致）；与 all 同传时以 caddy_id 为准（REST 同口径）"},"domain":{"type":"string"},"all":{"type":"boolean","enum":[true],"description":"全量重签（含已签发任务，消耗 CA 配额并触发 DNS 变更）：单次最多匹配 500 个 ACME 规则，超出 REST 返回 400，请分批执行或改传 caddy_id 定向签发"},"force":{"type":"boolean","description":"显式越过目标任务的 CA 限流冷却；省略或 false 不越过"}},"anyOf":[{"required":["all"]},{"required":["caddy_id"]}],"additionalProperties":false}`
const retryCertJobSchema = `{"type":"object","required":["id"],"properties":{"id":{"type":"integer","description":"证书任务 ID"},"force":{"type":"boolean","description":"显式越过未到期的 CA 限流冷却；省略或 false 不越过"}},"additionalProperties":true}`
const auditLogsSchema = `{"type":"object","properties":{"page":{"type":"integer","minimum":1,"maximum":500,"default":1,"description":"页码；超过 500 页 REST 直接 400（深 OFFSET 全表扫描），请用时间/用户/动作筛选缩小范围"},"page_size":{"type":"integer","minimum":1,"maximum":100,"default":20},"username":{"type":"string","description":"操作人模糊筛选"},"action":{"type":"string","description":"操作模糊筛选"},"resource":{"type":"string","description":"对象模糊筛选"},"ip":{"type":"string","description":"IP 模糊筛选"},"keyword":{"type":"string","description":"详情关键词"},"start_time":{"type":"string","description":"开始时间（配置时区，YYYY-MM-DD[ HH:MM:SS]）"},"end_time":{"type":"string","description":"结束时间（配置时区，YYYY-MM-DD[ HH:MM:SS]）"}},"additionalProperties":false}`

// schema 必须覆盖 queryArgs 声明的全部
// 参数——运行时未启用 WithInputSchemaValidation（mcp-go v0.58.0 实证：不启用
// 则 inputValidator 为 nil，参数不校验、也不会产生 -32602），input_schema 仅
// 是 Agent 侧契约文档：Agent 按 tools/list 的 schema 构参，漏声明的参数（如
// page/page_size）在 schema 上不可见，Agent 只能漏传或凭工具描述臆测。刻意
// 不启用运行时校验——启用会把 schema 文档缺口升级为硬失败面，是否启用另行裁定。
// 边界与 REST clamp 对齐（ListCRSRules page_size≤50 默认 50——REST 侧钳位；cert jobs
// page≤1000、page_size≤200 默认 50——见 ListCertJobs maxCertJobPage）。
const listCRSRulesSchema = `{"type":"object","properties":{"search":{"type":"string","description":"搜索关键词"},"page":{"type":"integer","minimum":1,"maximum":100000,"default":1},"page_size":{"type":"integer","minimum":1,"maximum":50,"default":50}},"additionalProperties":false}`
const listCertJobsSchema = `{"type":"object","properties":{"rule_id":{"type":"string","description":"按规则 ID 过滤"},"page":{"type":"integer","minimum":1,"maximum":1000,"default":1},"page_size":{"type":"integer","minimum":1,"maximum":200,"default":50}},"additionalProperties":false}`

// list_certificates 与 REST ListCertificates 的分页钳位同值（page/page_size
// 上限均 maxCertJobPage=1000，默认 1/1000）：此前 schema 为 emptySchema，
// 端点在获得 LIMIT/OFFSET 后 Agent 在 >1000 行部署上只能拿到前 1000 行，
// 响应 total 可见却无续页参数可跟随。rule_id 与 REST 的可选过滤同口径
// （精确匹配规则 Caddy ID）——转发层只按 queryArgs 构造查询串，漏登记会让
// Agent 的过滤意图被静默丢弃、退化为全局首页。
const listCertificatesSchema = `{"type":"object","properties":{"rule_id":{"type":"string","description":"按规则 Caddy ID 精确过滤（缺省=全部规则）"},"page":{"type":"integer","minimum":1,"maximum":1000,"default":1,"description":"页码；与 REST 同口径，page_size 默认 1000（等价原全量返回）"},"page_size":{"type":"integer","minimum":1,"maximum":1000,"default":1000,"description":"每页条数；响应 data.total 为匹配总数，超过本页条数时按 page 续取"}},"additionalProperties":false}`
const securityEventsSchema = `{"type":"object","properties":{"page":{"type":"integer","minimum":1,"maximum":1000,"default":1,"description":"页码；REST 侧超过 1000 会静默钳位（深 OFFSET 保护），更深历史请用筛选条件"},"page_size":{"type":"integer","minimum":1,"maximum":100,"default":20},"action":{"type":"string"},"ip":{"type":"string"},"rule_caddy_id":{"type":"string"},"rule_name":{"type":"string","description":"按负载规则名称过滤（子串）"},"policy_name":{"type":"string","description":"按安全策略名称过滤（子串）"},"rule_triggered":{"type":"string","description":"按触发规则过滤（类别：IP 访问控制/地域拦截/WAF 规则（CRS）含全部 6 位规则 ID/自定义规则；也可输细标签（评分拦截/协议异常/协议攻击）或 CRS 规则 ID/消息关键词）"},"rule_triggered_exclude":{"type":"string","description":"按触发规则反向过滤（同 rule_triggered 的类别/细标签/ID，整体取反——筛掉该类型看其余）"},"uri":{"type":"string","description":"按请求 URI 过滤（子串）"},"start_time":{"type":"string","description":"开始时间（配置时区，YYYY-MM-DD[ HH:MM:SS]）"},"end_time":{"type":"string","description":"结束时间（配置时区，YYYY-MM-DD[ HH:MM:SS]）"}},"additionalProperties":false}`
const caddyLogsSchema = `{"type":"object","properties":{"type":{"type":"string","enum":["runtime","server","proxy","tls"]}},"additionalProperties":false}`
const metricsHistorySchema = `{"type":"object","properties":{"rule_id":{"type":"string","description":"可选规则 ID（Caddy ID），省略时返回全局聚合趋势"},"interval":{"type":"string","description":"时间范围（如 1h、24h、7d），默认 1h"}},"additionalProperties":false}`

// setRuleSecurityPoliciesSchema（v2.2.0 多策略绑定）：maxItems 与后端
// SetRuleSecurityPolicies 的 maxBindingsPerRule=8 校验对齐，避免 MCP 放行后端拒绝的载荷。
const setRuleSecurityPoliciesSchema = `{"type":"object","required":["caddy_id","policy_ids"],"properties":{"caddy_id":{"type":"string","description":"规则 Caddy ID"},"policy_ids":{"type":"array","items":{"type":"integer"},"maxItems":8,"description":"策略 ID 列表（整体替换现有绑定，按 policy_id ASC 顺序评估）"}},"additionalProperties":false}`

// ruleMetricsHistorySchema（2026-09 审计）：range 的 enum 与 REST 侧
// metricsHistoryRange 支持集逐项一致（1h/6h/24h/7d，缺省走 REST 默认 24h），
// 避免工具层出现后端会拒绝或静默回退的取值。
const ruleMetricsHistorySchema = `{"type":"object","required":["caddy_id"],"properties":{"caddy_id":{"type":"string","description":"规则 Caddy ID"},"range":{"type":"string","enum":["1h","6h","24h","7d"],"default":"24h","description":"时间范围，默认 24h"}},"additionalProperties":false}`

// dns_provider/dns_credentials 是全局配置遗留字段——证书签发链
// 实际消费 certificate_configs 表的 DNS 凭证,标注防 Agent 误把凭证写进全局配置。
const updateConfigSchemaTemplate = `{"type":"object","properties":{"source":{"type":"string"},"dns_provider":{"type":"string","description":"遗留字段，签发链不消费；DNS 凭证配置请用 certificate_configs 系列"},"dns_credentials":{"type":"string","description":"遗留字段，签发链不消费；DNS 凭证配置请用 certificate_configs 系列"},"acme_email":{"type":"string"},"cert_expiry_days":{"type":"integer"},"cert_renewal_days":{"type":"integer"},"cert_renewal_attempts":{"type":"integer"},"server_map_lat":{"type":"number","minimum":-90,"maximum":90,"description":"威胁大屏本站纬度（-90~90，0=未设置）"},"server_map_lon":{"type":"number","minimum":-180,"maximum":180,"description":"威胁大屏本站经度（-180~180，0=未设置）"},"threat_screen_mode":{"type":"string","enum":["map","globe"],"description":"威胁大屏模式：map=平面地图，globe=三维地球"},"threat_traffic_sample_n":{"type":"integer","enum":[-1,0],"description":"大屏光流采样：-1=自适应（低流量等价全量），0=关闭"},"security_events_retention_days":{"type":"integer","minimum":1,"maximum":%[1]d,"description":"安全事件保留天数（1-%[1]d）"},"security_events_row_cap":{"type":"integer","minimum":1,"maximum":%[2]d,"description":"安全事件最大行数（1-%[2]d 行）"},"log_level":{"type":"string"},"caddy_log_level":{"type":"string"},"caddy_log_size_mb":{"type":"integer"},"request_body_max_size_mb":{"type":"integer"},"http_read_timeout":{"type":"integer"},"http_write_timeout":{"type":"integer"},"http_idle_timeout":{"type":"integer"},"upstream_keepalive_timeout":{"type":"integer"},"proxy_dial_timeout":{"type":"integer","minimum":0},"proxy_response_header_timeout":{"type":"integer","minimum":0},"proxy_read_timeout":{"type":"integer","minimum":0},"proxy_write_timeout":{"type":"integer","minimum":0},"proxy_stream_timeout":{"type":"integer","minimum":0},"proxy_flush_interval":{"type":"integer","minimum":-1},"proxy_stream_close_delay":{"type":"integer","minimum":0},"server_tokens_hidden":{"type":"boolean"},"trusted_proxy_enabled":{"type":"boolean","description":"受信代理（CDN 真实 IP 还原）总开关"},"trusted_proxy_ranges":{"type":"string","description":"受信代理网段（JSON 字符串数组文本，如 [\"203.0.113.0/24\"]；裸 IP 自动补 /32 或 /128；仅这些来源的 X-Forwarded-For 被采信）"},"trusted_proxy_range_refs":{"type":"string","description":"受信代理引用的 IP 地址列表 id（JSON 整数数组文本，如 [3,7]；与 trusted_proxy_ranges 合并生效）"},"trusted_proxy_headers":{"type":"string","description":"真实 IP 取值头（JSON 字符串数组文本，如 [\"X-Forwarded-For\",\"X-Real-IP\"]；按数组顺序取值）"},"trusted_proxy_strict":{"type":"boolean","description":"严格模式：非受信来源的伪造头一律拒绝"},"task_log_size_mb":{"type":"integer"},"runtime_log_size_mb":{"type":"integer"},"access_log_json":{"type":"boolean"},"access_log_format":{"type":"string"},"audit_retention_months":{"type":"integer"},"jwt_expire_minutes":{"type":"integer"},"timezone":{"type":"string"},"default_ca_provider_id":{"type":"integer"},"audit_log_size_mb":{"type":"integer"},"mfa_write_guard":{"type":"boolean"},"mfa_lockout_enabled":{"type":"boolean"},"github_proxy_url":{"type":"string","enum":["https://v4.gh-proxy.org/","https://axisnow.gh-proxy.org/","https://cdn.gh-proxy.org/"]},"github_token":{"type":"string","description":"可选 GITHUB_TOKEN（认证后 GitHub API 限流 60→5000 次/小时）；空串=清除已配置令牌，非空=覆盖，省略=保持现值；响应面仅以 has_github_token 显隐"}},"additionalProperties":false}`

// updateConfigSchema 的安全事件保留边界由 db.Max* 常量直接注入（上限单源：
// 写侧校验 caddy.go / 导入钳制 config_backup.go / 从端 apply 归一
// cluster_apply.go 同族引用）。模板用序号占位而非「字面量原文作查找键」——
// 后者一旦模板描述被润色就静默 no-op，此后上调 db.Max* 会让 schema 停在旧上限。
var updateConfigSchema = fmt.Sprintf(updateConfigSchemaTemplate, db.MaxSecurityEventsRetentionDays, db.MaxSecurityEventsRowCap)

// NewForTest 无内部鉴权密钥的装配入口，仅供测试夹具使用。
// 生产装配唯一走 NewWithInternalAuth（网关注入内部鉴权密钥）。名字显式带
// Test 后缀：旧名 New 看起来像生产入口，无编译期约束阻止误用；缺内部头时
// 接收端不采信客户端 IP 头（真实兜底仍在），但误接入生产会丢掉审计源 IP。
func NewForTest(baseURL string, client *http.Client) http.Handler {
	return NewWithInternalAuth(baseURL, client, "")
}

func NewWithInternalAuth(baseURL string, client *http.Client, internalAuthSecret string) http.Handler {
	return newWithVisibilityResolver(baseURL, client, internalAuthSecret, resolveAPIKeyVisibility)
}

func newWithVisibilityResolver(baseURL string, client *http.Client, internalAuthSecret string, resolver visibilityResolver) http.Handler {
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
		// 显式 JSON null 等价于未提供：客户端（尤其 LLM/Agent）常用 null 表示
		// 「可选字段不填」，若照 scalarString 拼进路径会得到 /rules/%3Cnil%3E
		// → REST 404，错误信息反而不指向真正的缺少参数。
		if !ok || value == nil {
			return toolCallError("缺少参数 %s", name)
		}
		path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(scalarString(value)))
	}
	endpoint, err := url.Parse(strings.TrimRight(baseURL, "/") + path)
	if err != nil {
		return nil, fmt.Errorf("构造内部 API 地址: %w", err)
	}
	query := endpoint.Query()
	for _, name := range spec.queryArgs {
		value, ok := arguments[name]
		// 显式 null 视为「未提供」：否则 scalarString(nil) 得到 "<nil>" 被当成
		// 真实过滤值转发（分页参数 → 400；ip/client_ip → 按字面过滤后静默
		// 空结果，比 400 更危险）。空字符串同样丢弃（REST 侧按缺省处理）。
		if !ok || value == nil || scalarString(value) == "" {
			continue
		}
		query.Set(name, scalarString(value))
	}
	endpoint.RawQuery = query.Encode()

	bodyArguments := make(map[string]any, len(arguments))
	maps.Copy(bodyArguments, arguments)
	// create_rule/update_rule 共用同一 upstreams 全量替换语义（REST 侧 enabled
	// 为非指针布尔，缺省即落 false 静默禁用全部上游）——MCP 层对两个入口同样
	// 注入缺省 enabled=true（显式 false 保留），使 Agent 按工具描述的「部分
	// 更新」心智调整上游列表不会踩坑（2026-09 审计）。
	if spec.name == "create_rule" || spec.name == "update_rule" {
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
	if apiKey := apikey.FromHeader(call.Header); apiKey != "" {
		request.Header.Set("X-API-Key", apiKey)
	} else {
		return toolCallError("MCP 请求缺少 API 密钥")
	}
	if internalAuthSecret != "" {
		request.Header.Set(InternalAuthHeader, internalAuthSecret)
	}
	if clientIP := ClientIPFromContext(ctx); clientIP != "" {
		request.Header.Set(InternalClientIPHeader, clientIP)
	}
	redirectlessClient := *client
	redirectlessClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := redirectlessClient.Do(request)
	if err != nil {
		return transportToolError(err, generatedPassword)
	}
	// 面板启用 HTTPS 时明文请求命中 TLS 嗅探层收到 302（cmd/server
	// http_redirect_mux.go）；客户端不自动跟随（避免 POST 变 GET），
	// 这里按原方法原请求体重试一次重定向地址
	if isReplayableRedirectStatus(response.StatusCode) {
		location := response.Header.Get("Location")
		response.Body.Close()
		if location == "" {
			return toolCallError("内部 API 重定向缺少目标地址")
		}
		redirectURL, err := request.URL.Parse(location)
		if err != nil {
			return toolCallError("解析内部 API 重定向地址: %v", err)
		}
		if !isLoopbackHTTPURL(redirectURL) {
			return toolCallError("拒绝非回环内部 API 重定向地址")
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
		request.Header.Set("X-API-Key", apikey.FromHeader(call.Header))
		if internalAuthSecret != "" {
			request.Header.Set(InternalAuthHeader, internalAuthSecret)
		}
		if clientIP := ClientIPFromContext(ctx); clientIP != "" {
			request.Header.Set(InternalClientIPHeader, clientIP)
		}
		response, err = redirectlessClient.Do(request)
		if err != nil {
			return transportToolError(err, generatedPassword)
		}
		if isReplayableRedirectStatus(response.StatusCode) {
			response.Body.Close()
			return toolCallError("内部 API 重定向次数超过限制")
		}
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("读取内部 API 响应: %w", err)
	}
	if len(responseBody) > maxResponseSize {
		// 指引选择单源在 oversizedResponseMessage（专用 hint 优先，其余按
		// 「schema 是否声明 page/page_size」分流）。
		result := mcp.NewToolResultText(oversizedResponseMessage(spec))
		result.IsError = true
		return result, nil
	}
	// v2.3.0 导出恒为 lbbak 二进制 tar.gz(application/gzip)。
	// gzip 字节经 NewToolResultText 会以文本形态静默损坏(UTF-8 替换/截断),
	// 4 MiB 内也必须拒收——给可行动指引而非损坏数据。
	if spec.name == "export_config" && !strings.HasPrefix(strings.TrimSpace(strings.ToLower(response.Header.Get("Content-Type"))), "application/json") {
		result := mcp.NewToolResultText("配置备份为 lbbak 二进制压缩包（tar.gz），MCP 通道不支持二进制下载，请经管理面板或 REST /config/export 下载")
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

func transportToolError(err error, generatedPassword string) (*mcp.CallToolResult, error) {
	// 超时只代表客户端没有等到响应；首跳与 TLS 重放必须使用同一分类，
	// 防止 Agent 在写操作可能已提交时盲目重试。
	var netErr net.Error
	if (errors.As(err, &netErr) && netErr.Timeout()) || errors.Is(err, context.DeadlineExceeded) {
		message := fmt.Sprintf("内部 API 请求超时: %v（操作可能已在服务端生效,请先用查询类工具核对状态再重试）", err)
		if generatedPassword != "" {
			// 同一调用方在成功响应中本就会收到该密码；不确定态交付候选值
			// 同时覆盖「已提交」与「未提交」两种终态，不扩大权限。
			message += fmt.Sprintf("\n（本次候选密码为系统生成：%s；密码重置可能已生效，若未生效请继续使用旧密码）", generatedPassword)
		}
		return mcp.NewToolResultError(message), nil
	}
	return toolCallError("内部 API 请求失败: %v", err)
}

const randomPasswordCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// toolCallError 把可恢复的调用层错误（缺参/缺 Key/传输失败/重定向异常）以
// IsError 工具结果返回——文档承诺 Agent 只需处理 IsError 分支；仅内部不变量
// 破坏（地址构造/序列化失败等）才走 handler error（mcp-go 包成 -32603）。
func toolCallError(format string, args ...any) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultError(fmt.Sprintf(format, args...)), nil
}

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

// isReplayableRedirectStatus 判定可按原方法/原请求体重放的重定向状态码
// 面板 TLS 嗅探层对明文请求回 302，兼容 301/307/308。
// 集合单源化到 netutil.IsTLSUpgradeRedirect——此前 MCP
// 转发与 services 同主机升级客户端各写一份 301/302/307/308 字面量，一侧新增
// 状态码即静默分叉。重放目标仍由 isLoopbackHTTPURL 约束（凭证不出回环）。
func isReplayableRedirectStatus(code int) bool {
	return netutil.IsTLSUpgradeRedirect(code)
}

func isLoopbackHTTPURL(target *url.URL) bool {
	if target.Scheme != "http" && target.Scheme != "https" {
		return false
	}
	hostname := target.Hostname()
	return hostname == "localhost" || net.ParseIP(hostname).IsLoopback()
}

// scalarString 把 JSON 标量转成字符串形态。
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
