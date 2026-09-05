package mcpserver

import (
	"encoding/json"
	"net/http"
)

const restAPIPathPrefix = "/api/v1"

type ToolSpec struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	ReadOnly    bool            `json:"read_only"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
	Usage       string          `json:"usage,omitempty"`
}

func ListToolSpecs() []ToolSpec {
	result := make([]ToolSpec, len(tools))
	for index, spec := range tools {
		item := ToolSpec{
			Name:        spec.name,
			Description: spec.description,
			Method:      spec.method,
			Path:        restAPIPathPrefix + spec.path,
			ReadOnly:    spec.method == http.MethodGet,
			Usage:       toolUsage[spec.name],
		}
		if spec.schema != "" && spec.schema != emptySchema {
			item.InputSchema = json.RawMessage(spec.schema)
		}
		result[index] = item
	}
	return result
}

var toolUsage = map[string]string{
	"list_rules":                   "先了解当前规则全貌（域名/端口/上游/启用状态），所有变更前的现状盘点入口",
	"get_rule":                     "在修改某条规则前获取其完整配置（上游/证书/路径路由/超时）",
	"create_rule":                  "新建 HTTP/TCP 代理规则。必填 name/protocol/listen_port/upstreams[{host,port}]；创建即重载生效，失败自动回滚",
	"update_rule":                  "修改现有规则的任意字段（部分更新）。协议切换会自动迁移上游协议并清理对侧字段",
	"delete_rule":                  "删除规则并清理关联上游/证书任务/证书文件。不可恢复，先 get_rule 确认。有 worker 正在执行签发时秒回 409（queued/冷却中不拦，稍后重试即可）",
	"enable_rule":                  "恢复被禁用规则的流量；ACME 规则会按需恢复/重排证书任务",
	"disable_rule":                 "临时下线规则但保留配置与证书；非终态证书任务置为 disabled。有 worker 正在执行签发时秒回 409（queued/冷却中不拦，稍后重试即可）",
	"duplicate_rule":               "以现有规则为模板快速克隆（新副本默认禁用，需再 enable）",
	"list_cert_jobs":               "查看 ACME 签发/续签任务进度与失败原因，可按 rule_id 过滤",
	"retry_cert_job":               "手动重试失败的签发任务（自动冷却期外的任务）",
	"delete_cert_job":              "删除证书任务记录（已签发证书文件不受影响）",
	"issue_certificate":            "触发 ACME 证书签发：传 caddy_id 定向签发单条规则，空对象则为全部启用 ACME 的规则批量签发",
	"list_certificates":            "查看 Caddy 当前加载的全部证书及到期时间",
	"get_config":                   "读取全局配置（时区/日志级别/超时/续签策略等）",
	"update_config":                "修改全局配置并即时应用（如时区、日志级别、代理超时）",
	"reload_caddy":                 "从数据库重新生成并加载 Caddy 配置，用于配置异常时强制收敛",
	"get_metrics_dashboard":        "一次获取全局+全部规则的聚合监控指标（请求数/状态码/流量/健康），Dashboard 数据源",
	"get_metrics_overview":         "获取轻量级指标总览（累计请求/字节/延迟分位数）",
	"get_realtime_traffic":         "获取实时出入站速率（网卡计数器差分）",
	"get_upstream_health":          "查看全部上游的三态健康（正常/异常/不健康），故障排查入口",
	"list_audit_logs":              "分页查询操作审计（谁/何时/对什么/做了什么），支持 page/page_size/username/action/resource/ip/keyword/start_time/end_time",
	"get_system_info":              "查看版本/运行时间/主机/系统信息",
	"list_users":                   "列出用户（角色/启用状态），判断操作者权限",
	"list_api_keys":                "列出 API 密钥（不含明文），核对 MCP 启用与只读属性",
	"get_cluster_status":           "查看本节点主/从角色、主节点地址、最近同步状态与错误",
	"get_security_overview":        "安全总览：今日拦截/检测计数、攻击类型 TOP10、源 IP TOP10、事件趋势",
	"list_security_policies":       "列出全部安全策略及其 WAF/CRS/IP ACL/GeoIP/限流配置",
	"get_security_policy":          "获取指定策略完整配置（含自定义规则和绑定关系）",
	"list_security_events":         "分页查询安全事件（WAF 拦截/IP ACL 拒绝），支持 page/page_size/action/ip/rule_caddy_id/rule_name/policy_name/rule_triggered/uri/start_time/end_time",
	"list_security_bindings":       "查看策略-规则绑定映射（规则可绑定多条安全策略），了解哪些规则启用了安全防护",
	"get_rule_security_policy":     "查看指定规则绑定的安全策略列表（数组，按 policy_id ASC 有序；仅含 enabled=1 的策略）",
	"list_custom_rules":            "列出全部自定义安全规则（多条件链式匹配）",
	"list_block_pages":             "列出全部拦截页面（含默认页和自定义页）",
	"get_crs_info":                 "查看 CRS 规则库版本、更新状态、自动更新开关",
	"get_crs_update_status":        "查看 CRS 正在进行的更新进度（检查/下载/安装/重载）",
	"get_crs_update_logs":          "查看 CRS 最近一次更新的详细日志",
	"list_crs_rules":               "分页浏览 CRS 规则文件列表，支持搜索",
	"get_crs_rule":                 "查看指定 CRS 规则文件的完整内容",
	"get_ip2region_info":           "查看 IP2Region 版本、更新状态、自动更新开关",
	"get_ip2region_regions":        "获取可选的区域列表（中国省份+海外）",
	"get_ip2region_update_status":  "查看 IP2Region 正在进行的更新进度",
	"get_ip2region_update_logs":    "查看 IP2Region 最近一次更新的详细日志",
	"get_rate_limit_blocks":        "查看限流拦截统计（按规则/时段聚合）",
	"create_security_policy":       "创建安全策略：配置 WAF 模式/异常阈值/CRS 规则组/IP ACL/GeoIP 区域控制/限流/拦截页面；custom_rules 为 JSON 数组字符串",
	"update_security_policy":       "更新策略任意字段（如调整 WAF 模式、增减区域、修改阈值）",
	"delete_security_policy":       "删除策略（绑定关系自动解除）",
	"bind_security_policy":         "将策略绑定到规则（rule_caddy_id）；规则可绑定多条安全策略（按 policy_id ASC 顺序评估，最多 5 条；超限时请使用 set_rule_security_policies 整体替换）",
	"unbind_security_policy":       "解除策略与规则的绑定（仅解除该策略，同规则的其他策略绑定保留）",
	"set_rule_security_policies":   "原子设置规则的安全策略集合（最多 5 条，按 policy_id ASC 顺序评估，整体替换现有绑定；policy_ids 为空数组 [] = 解除该规则全部绑定）",
	"create_custom_rule":           "创建自定义安全规则（URI/参数/请求头/User-Agent 多条件匹配）",
	"update_custom_rule":           "更新自定义规则的条件或动作",
	"delete_custom_rule":           "删除自定义规则",
	"create_block_page":            "创建自定义拦截页面 HTML",
	"update_block_page":            "更新拦截页面内容",
	"delete_block_page":            "删除拦截页面（默认页面不可删除）",
	"list_ip_lists":                "列出全部 IP 地址列表（名称/分类/条目数/引用该列表的安全策略）",
	"create_ip_list":               "创建 IP 地址列表：entries 为 {value, remark} 对象数组的 JSON 文本（IP/CIDR+备注）；名称全局唯一（忽略大小写）",
	"update_ip_list":               "更新 IP 地址列表（entries 为 {value, remark} 对象数组的 JSON 文本，全量替换；名称全局唯一）；省略的字段保持现值",
	"delete_ip_list":               "删除 IP 地址列表；被安全策略引用时返回 409，需先解除引用",
	"toggle_crs_auto_update":       "开启/关闭 CRS 每日自动更新",
	"trigger_crs_update":           "手动触发 CRS 规则库在线更新（检查→下载→安装→重载）",
	"toggle_ip2region_auto_update": "开启/关闭 IP2Region 每日自动更新",
	"trigger_ip2region_update":     "手动触发 IP2Region 数据库在线更新",
	"list_cluster_nodes":           "列出全部集群节点（主/从/待审批）及其同步状态",
	"create_register_token":        "生成一次性集群注册令牌（30 分钟有效），用于新从节点注册",
	"approve_cluster_node":         "审批通过从节点注册申请",
	"reject_cluster_node":          "拒绝从节点注册申请",
	"create_login_ticket":          "为已审批的从节点生成登录票据",
	"update_node_access_url":       "更新从节点的访问地址",
	"delete_cluster_node":          "删除集群节点记录",
	"set_cluster_mode":             "将本节点注册到主节点并切换为从节点，等待审批后开始同步；提升为主节点请使用 promote_cluster",
	"promote_cluster":              "将从节点提升为独立主节点（脱离集群）",
	"pull_sync":                    "手动触发从节点立即拉取主节点快照",
	"update_cluster_settings":      "更新集群同步间隔等设置",
	"list_certificate_configs":     "列出全部 DNS 证书配置（DNS 提供商/域名/凭证）",
	"create_certificate_config":    "创建 DNS 证书配置（选择 DNS 提供商+填写 API 凭证）",
	"update_certificate_config":    "更新 DNS 证书配置的凭证或域名",
	"delete_certificate_config":    "删除 DNS 证书配置",
	"test_certificate_config":      "测试 DNS 证书配置的凭证是否有效",
	"list_dns_providers":           "列出支持的 DNS 提供商类型",
	"list_ca_providers":            "列出全部 CA 提供商（Let's Encrypt/ZeroSSL/自定义）",
	"get_ca_provider":              "获取指定 CA 提供商详情（含 EAB 凭证）",
	"update_ca_provider":           "更新 CA 提供商配置（目录 URL/EAB 凭证/限流）",
	"test_ca_provider":             "测试 CA 提供商连接是否正常",
	"get_cert_job":                 "获取指定证书签发任务的详细状态",
	"get_cert_job_logs":            "查看指定证书任务的签发/续签日志",
	"parse_certificate":            "解析上传的证书内容（域名/有效期/颁发者）",
	"create_user":                  "创建用户（管理员/只读）",
	"update_user":                  "更新用户信息（显示名/角色）",
	"toggle_user_status":           "启用或禁用用户",
	"reset_user_password":          "重置用户密码为随机值",
	"delete_user":                  "删除用户",
	"create_api_key":               "创建 API 密钥（可配置 MCP/只读/IP 白名单）",
	"update_api_key_status":        "更新密钥状态（启用/MCP 开关/只读开关/IP 白名单）",
	"delete_api_key":               "删除 API 密钥",
	"preview_config":               "预览配置变更效果（不实际应用）",
	"validate_config":              "验证配置文件是否有效",
	"import_config":                "导入 v2 配置备份（覆盖式，先验证后写入）",
	"validate_import":              "验证导入文件是否有效（不写入）",
	"import_v1_config":             "导入 v1（nginx 版）配置，自动转换为 v2 规则",
	"get_rule_caddy_config":        "查看指定规则生成的 Caddy JSON 配置片段",
	"get_rule_metrics_history":     "查看指定规则的历史请求数/状态码/流量趋势",
	"get_rule_logs":                "查看指定规则最近的访问日志",
	"get_rule_cert_info":           "查看指定规则的证书信息（域名/到期/来源）",
	"get_caddy_status":             "查看 Caddy 进程运行状态",
	"get_caddy_config":             "查看 Caddy 当前加载的完整 JSON 配置",
	"get_caddy_logs":               "查看 Caddy 运行日志（runtime/server/proxy/tls，按类型过滤）",
	"update_caddy_config":          "直接更新 Caddy 配置（高级操作，慎用）",
	"start_caddy":                  "启动 Caddy 进程",
	"stop_caddy":                   "停止 Caddy 进程",
	"restart_caddy":                "重启 Caddy 进程",
	"get_admin_tls":                "查看管理面板 HTTPS 配置（证书/端口/模式）",
	"update_admin_tls":             "更新管理面板 HTTPS 配置",
	"inspect_admin_tls":            "检查管理面板 HTTPS 证书有效性",
	"get_system_metrics":           "查看系统资源使用（CPU/内存/磁盘/网络）",
	"get_system_logs":              "查看应用运行日志",
	"restart_system":               "重启应用服务（更新配置后生效）",
	"get_rule_metrics":             "查看指定规则的实时指标（请求数/状态码/连接数）",
	"get_metrics_history":          "查看历史指标趋势（按小时/天聚合，可按 rule_id 过滤单规则）",
	"get_connections":              "查看当前连接统计（按规则/上游分布）",
}
