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
	"list_rules":            "先了解当前规则全貌（域名/端口/上游/启用状态），所有变更前的现状盘点入口",
	"get_rule":              "在修改某条规则前获取其完整配置（上游/证书/路径路由/超时）",
	"create_rule":           "新建 HTTP/TCP 代理规则。必填 name/protocol/listen_port/upstreams[{host,port}]；创建即重载生效，失败自动回滚",
	"update_rule":           "修改现有规则的任意字段（部分更新）。协议切换会自动迁移上游协议并清理对侧字段",
	"delete_rule":           "删除规则并清理关联上游/证书任务/证书文件。不可恢复，先 get_rule 确认",
	"enable_rule":           "恢复被禁用规则的流量；ACME 规则会按需恢复/重排证书任务",
	"disable_rule":          "临时下线规则但保留配置与证书；进行中的签发任务会暂停",
	"duplicate_rule":        "以现有规则为模板快速克隆（新副本默认禁用，需再 enable）",
	"list_cert_jobs":        "查看 ACME 签发/续签任务进度与失败原因，可按 rule_id 过滤",
	"retry_cert_job":        "手动重试失败的签发任务（自动冷却期外的任务）",
	"delete_cert_job":       "删除证书任务记录（已签发证书文件不受影响）",
	"issue_certificate":     "触发 ACME 证书签发：传 caddy_id 定向签发单条规则，空对象则为全部启用 ACME 的规则批量签发",
	"list_certificates":     "查看 Caddy 当前加载的全部证书及到期时间",
	"get_config":            "读取全局配置（时区/日志级别/超时/续签策略等）",
	"update_config":         "修改全局配置并即时应用（如时区、日志级别、代理超时）",
	"reload_caddy":          "从数据库重新生成并加载 Caddy 配置，用于配置异常时强制收敛",
	"export_config":         "导出完整配置备份 JSON（含规则/用户/密钥/证书任务），用于迁移或存档",
	"get_metrics_dashboard": "一次获取全局+全部规则的聚合监控指标（请求数/状态码/流量/健康），Dashboard 数据源",
	"get_metrics_overview":  "获取轻量级指标总览（累计请求/字节/延迟分位数）",
	"get_realtime_traffic":  "获取实时出入站速率（网卡计数器差分）",
	"get_upstream_health":   "查看全部上游的三态健康（正常/异常/不健康），故障排查入口",
	"list_audit_logs":       "分页查询操作审计（谁/何时/对什么/做了什么），支持 page/page_size",
	"get_system_info":       "查看版本/运行时间/主机/系统信息",
	"list_users":            "列出用户（角色/启用状态），判断操作者权限",
	"list_api_keys":         "列出 API 密钥（不含明文），核对 MCP 启用与只读属性",
	"get_cluster_status":    "查看本节点主/从角色、主节点地址、最近同步状态与错误",
}
