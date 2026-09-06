package mcpserver_test

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/mcpserver"
)

// TestMCPToolSpecs_cover_registeredGinRoutes MCP 工具↔路由对照绊线（R68 B-F7）：
// 每个工具的 (method, path) 必须命中 SetupRouter 注册的真实路由——工具指向已
// 改名/删除的路由只会在 Agent 调用时 404，编译期与既有测试均不可见（OpenAPI
// 侧有同款绊线，MCP 侧此前为空白）。{param} 形态经 ginPathToOpenAPI 反向
// 归一为 Gin 的 :param 后比对。
func TestMCPToolSpecs_cover_registeredGinRoutes(t *testing.T) {
	router := newAPIDocTestRouter(t)
	registered := make(map[string]struct{}, len(router.Routes()))
	for _, route := range router.Routes() {
		registered[route.Method+" "+route.Path] = struct{}{}
	}
	missing := 0
	specs := mcpserver.ListToolSpecs()
	for _, spec := range specs {
		ginPath := openAPIToGinPath(spec.Path)
		if _, ok := registered[spec.Method+" "+ginPath]; !ok {
			t.Errorf("工具 %s 指向未注册路由 %s %s——REST 路由已改名/删除而工具规格未同步", spec.Name, spec.Method, spec.Path)
			missing++
		}
	}
	if missing == 0 && len(specs) == 0 {
		t.Fatal("工具清单为空——ListToolSpecs 可能已重构，请同步更新本绊线")
	}
}

// openAPIToGinPath 将 {param} 形态还原为 Gin 的 :param（ginPathToOpenAPI 反函数）。
func openAPIToGinPath(path string) string {
	var b strings.Builder
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '{':
			b.WriteByte(':')
		case '}':
		default:
			b.WriteByte(path[i])
		}
	}
	return b.String()
}

// mcpUncoveredRoutes：注册但无 MCP 工具覆盖的路由的显式豁免清单（F12-b，
// 2026-09 审计）。此前 parity 绊线只验「工具→路由」单向，新 REST 路由落地时
// 无机制迫使决策者考虑 MCP 暴露——本清单 + 双向断言补上：新增无工具路由必须
// 在此登记豁免理由（或补工具）；清单项不再注册时测试同样报错，防清单腐化。
var mcpUncoveredRoutes = map[string]string{
	// —— 认证 / 会话 / MFA（JWT 会话专属；MCP 仅 API Key，无用户会话概念）——
	"GET /api/v1/auth/setup":               "首次初始化探测：用户表为空时返回 needs_setup=true，前端引导创建首个管理员",
	"POST /api/v1/auth/setup":              "首次初始化：创建首个管理员账号，用户表非空后 403",
	"POST /api/v1/auth/login":              "JWT 会话专属：密码+MFA 登录签发会话令牌，MCP 仅 API Key 认证",
	"POST /api/v1/auth/logout":             "JWT 会话专属：吊销当前会话 jti；API Key 无会话可吊销（直接 404）",
	"POST /api/v1/auth/ticket-login":       "一次性票据登录：SSO/跨节点票据换 JWT，Agent 无票据来源",
	"GET /api/v1/auth/mfa/status":          "JWT 会话专属：当前会话用户的 MFA 绑定状态",
	"POST /api/v1/auth/mfa/setup":          "JWT 会话专属：生成 MFA 绑定密钥（pending），绑定当前会话用户",
	"POST /api/v1/auth/mfa/activate":       "JWT 会话专属：激活 pending MFA 绑定并一次性返回恢复码",
	"POST /api/v1/auth/mfa/disable":        "JWT 会话专属：禁用当前会话用户的 MFA（双重确认）",
	"POST /api/v1/auth/mfa/verify":         "JWT 会话专属：登录流程第二步 MFA 动态码验证",
	"POST /api/v1/auth/mfa/verify-step":    "JWT 会话专属：写操作 428 step-up 换发刷新 mfa_ts 的新 JWT；MCP/API Key 路径不走 428",
	"POST /api/v1/auth/mfa/recovery-codes": "JWT 会话专属：重生成当前会话用户的恢复码",
	// —— 用户自助端点（JWT 会话专属：me 系列操作的是当前会话用户）——
	"GET /api/v1/users/me":                 "JWT 会话专属：当前会话用户档案自助查询",
	"PATCH /api/v1/users/me":               "JWT 会话专属：当前会话用户自助更新档案",
	"GET /api/v1/users/me/api-keys":        "JWT 会话专属：当前会话用户名下 API Key 列表",
	"POST /api/v1/users/me/api-keys":       "JWT 会话专属：为当前会话用户创建 API Key",
	"PATCH /api/v1/users/me/api-keys/:id":  "JWT 会话专属：当前会话用户自助变更自己的 API Key 状态",
	"DELETE /api/v1/users/me/api-keys/:id": "JWT 会话专属：当前会话用户自助删除自己的 API Key",
	// —— 集群机器接口（注册密钥 / 集群令牌 / HMAC 票据认证，非 API Key 路径）——
	"POST /api/v1/cluster/register":             "集群机器接口：从节点发起注册（注册密钥随请求体提交，公开路由）",
	"GET /api/v1/cluster/register/:id/status":   "集群机器接口：从节点轮询自身注册审批状态（注册密钥认证）",
	"POST /api/v1/cluster/registration/confirm": "集群机器接口：主节点钉扎从节点证书指纹后确认注册（集群令牌认证）",
	"GET /api/v1/cluster/sync/snapshot":         "集群机器接口：从节点拉取全量同步快照（集群令牌认证；MB 级批量数据，支持 since_version/304）",
	"GET /api/v1/cluster/sync/waf-files":        "集群机器接口：从节点按哈希差量拉取完整 CRS 规则树与 GeoIP 数据库（集群令牌认证；MB 级 tar/xdb）",
	"POST /api/v1/cluster/nodes/report":         "集群机器接口：从节点上报健康状态（集群令牌认证；定时上报非人工操作）",
	"POST /api/v1/cluster/service-control":      "集群机器接口：主节点签发的一次性 HMAC 票据在从节点侧的服务控制入口（control_cluster_node_service 工具是主节点侧遥控入口，二者为同一条控制链的两端）",
	// —— 流式端点（MCP 无流式语义）——
	"GET /api/v1/rules/:caddy_id/log-stream": "SSE 流式推送规则访问日志（长连接增量事件）；MCP 工具为一次性请求-响应，无流式语义，Agent 用 get_rule_logs 查最近日志",
	// —— 批量便捷端点（面向面板列表轮询的批量形态；Agent 用单条工具）——
	"POST /api/v1/rules/cert-info":           "批量便捷端点：一次查最多 200 个 caddy_id 的证书信息，供面板规则列表轮询；Agent 用 get_rule_cert_info 按单条查",
	"POST /api/v1/certificates/jobs/current": "批量便捷端点：一次查最多 200 个 rule_id 的当前任务，供面板规则列表轮询任务状态；Agent 用 list_cert_jobs 按 rule_id 过滤",
	// —— 面板表单流程专属 ——
	"POST /api/v1/certificate-configs/test": "面板「先测后存」表单流程：测试尚未保存的 DNS 配置（凭证随请求体内联提交）；Agent 流程中配置已落库，用 test_certificate_config（/certificate-configs/:id/test）",
	// —— 面板展示 / 监控抓取（REST 专用只读数据）——
	"GET /api/v1/branding":           "面板前端品牌文案渲染（app_name/页脚/版本），公开只读；运维对象是 Caddy 而非面板 UI，Agent 无消费场景",
	"GET /api/v1/caddy/metrics":      "Caddy 原始指标（请求总量/在途计数），供 Prometheus 抓取与面板展示；Agent 监控走 get_metrics_dashboard/get_metrics_overview 聚合工具",
	"GET /api/v1/caddy/host-metrics": "Caddy 按域名粒度的指标统计，面板主机视图数据源；Agent 监控走 get_metrics_dashboard 聚合工具",
	"GET /api/v1/audit-logs/options": "审计日志页筛选下拉选项（操作人/操作/对象去重值+频次），面板 UI 辅助数据；Agent 直接用 get_audit_logs 的筛选参数查询",
	"GET /api/v1/logs/stats":         "9 类日志的存储大小/轮转/保留策略状态，面板日志页展示用；不涉及 Agent 的排障操作路径",
	"GET /api/v1/security/crs/setup": "CRS setup.conf 配置文件原文查看，面板 CRS 配置展示用；Agent 排查规则走 get_crs_rule/get_crs_rule_index",
	// —— MCP 自身镜像端点 ——
	"POST /api/v1/mcp":             "MCP Streamable HTTP JSON-RPC 端点本身：工具调用的入口即 MCP 协议，不是可经 MCP 转发的 REST 操作",
	"GET /api/v1/mcp/tools":        "MCP 自身镜像端点：OpenAPI 形态的工具清单，供外部集成方发现工具",
	"GET /api/v1/mcp/ops-playbook": "MCP 自身镜像端点：注入 MCP system prompt 的运维手册文本",
}

func TestMCPUncoveredRoutes_areExplicitlyExempted(t *testing.T) {
	router := newAPIDocTestRouter(t)
	covered := make(map[string]struct{})
	for _, spec := range mcpserver.ListToolSpecs() {
		covered[spec.Method+" "+openAPIToGinPath(spec.Path)] = struct{}{}
	}
	registered := make(map[string]struct{}, len(router.Routes()))
	for _, route := range router.Routes() {
		if !strings.HasPrefix(route.Path, "/api/v1/") ||
			route.Path == "/api/v1/docs" || route.Path == "/api/v1/openapi.yaml" {
			continue
		}
		key := route.Method + " " + route.Path
		registered[key] = struct{}{}
		if _, hasTool := covered[key]; hasTool {
			continue
		}
		if _, exempted := mcpUncoveredRoutes[key]; !exempted {
			t.Errorf("路由 %s 无 MCP 工具覆盖且未登记豁免——请补工具或在 mcpUncoveredRoutes 登记理由", key)
		}
	}
	for key := range mcpUncoveredRoutes {
		if _, ok := registered[key]; !ok {
			t.Errorf("豁免清单项 %s 不是已注册路由——路由已删除/改名，清单需同步", key)
		}
	}
}
