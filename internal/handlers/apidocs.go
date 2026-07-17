package handlers

import (
	"fmt"
	"net/http"
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
	{"POST", "/auth/logout", "认证", "用户登出", "", `{"code":0,"message":"Logged out"}`, nil, ""},
	{"GET", "/users/me", "用户", "当前用户信息", "", `{"id":1,"username":"admin","role":"admin","display_name":null}`, []string{"401 unauthenticated"}, ""},
	{"PATCH", "/users/me", "用户", "更新当前用户", `{"display_name":"昵称","password":"新密码(可选)"}`, `{"id":1,"username":"admin","display_name":"昵称"}`, []string{"400 invalid_request", "401 unauthenticated"}, "密码只接受新值，不返回。"},
	{"GET", "/users/me/api-keys", "API密钥", "当前用户 API 密钥列表", "", `[{"id":1,"name":"ci","key_prefix":"lb_sk_abcd","last_used":null,"expires_at":null,"is_enabled":true}]`, []string{"401 unauthenticated"}, "不返回完整密钥。"},
	{"POST", "/users/me/api-keys", "API密钥", "创建当前用户 API 密钥", `{"name":"ci","expires_at":null}`, `{"id":1,"key":"lb_sk_...","message":"This key will only be shown once."}`, []string{"400 invalid_request", "401 unauthenticated"}, "完整密钥只在创建时返回一次。"},
	{"PATCH", "/users/me/api-keys/:id", "API密钥", "启用或禁用当前用户 API 密钥", `{"is_enabled":false}`, `{"code":0,"message":"API key status updated"}`, []string{"400 invalid_request", "404 not_found"}, ""},
	{"DELETE", "/users/me/api-keys/:id", "API密钥", "删除当前用户 API 密钥", "", `{"code":0,"message":"API key deleted"}`, []string{"404 not_found"}, ""},
	{"GET", "/api-keys", "API密钥", "管理端 API 密钥列表", "", `[{"id":1,"name":"ci","username":"admin","is_enabled":true}]`, []string{"403 admin_required"}, "仅 admin。"},
	{"POST", "/api-keys", "API密钥", "管理端创建 API 密钥", `{"name":"ci","expires_at":null}`, `{"id":1,"key":"lb_sk_..."}`, []string{"400 invalid_request", "403 admin_required"}, ""},
	{"PATCH", "/api-keys/:id/status", "API密钥", "管理端启用或禁用 API 密钥", `{"is_enabled":true}`, `{"code":0,"message":"API key status updated"}`, []string{"403 admin_required", "404 not_found"}, ""},
	{"DELETE", "/api-keys/:id", "API密钥", "管理端删除 API 密钥", "", `{"code":0,"message":"API key deleted"}`, []string{"403 admin_required", "404 not_found"}, ""},
	{"GET", "/config", "配置", "读取全局配置", "", `{"log_level":"info","timezone":"Asia/Shanghai","audit_retention_months":3}`, []string{"401 unauthenticated"}, ""},
	{"PUT", "/config", "配置", "更新全局配置", `{"source":"basic","log_level":"debug","audit_retention_months":3}`, `{"changed":true,"section":"基础设置","changes":["系统日志级别"]}`, []string{"400 validation_failed", "403 slave_or_admin_required"}, "只提交需要修改的字段；无修改不触发 Caddy 重载。"},
	{"POST", "/config/preview", "配置", "预览配置变更", `{"source":"basic","log_level":"debug"}`, `{"changed":true,"section":"基础设置","changes":["系统日志级别"]}`, []string{"400 invalid_request"}, "不写数据库，不触发 Caddy。"},
	{"POST", "/config/reload", "配置", "手动重载 Caddy", "", `{"code":0,"message":"Caddy config reloaded"}`, []string{"403 admin_required"}, ""},
	{"POST", "/config/validate", "配置", "验证 Caddy 配置", `{}`, `{"code":0,"message":"Config is valid"}`, []string{"400 config_invalid"}, ""},
	{"GET", "/config/health", "配置", "上游健康状态", "", `{"server":{"127.0.0.1:8080":{"healthy":true}}}`, []string{"403 admin_required"}, ""},
	{"GET", "/rules", "规则", "负载均衡规则列表", "", `[{"caddy_id":"lb_...","name":"example","protocol":"http","listen_port":80,"enabled":true}]`, []string{"401 unauthenticated"}, ""},
	{"POST", "/rules", "规则", "创建负载均衡规则", `{"name":"example","protocol":"http","listen_port":8080,"upstreams":[{"host":"127.0.0.1","port":9000}]}`, `{"caddy_id":"lb_..."}`, []string{"400 validation_failed", "403 slave_mode"}, ""},
	{"GET", "/rules/:caddy_id", "规则", "规则详情", "", `{"caddy_id":"lb_...","name":"example"}`, []string{"404 not_found"}, ""},
	{"PUT", "/rules/:caddy_id", "规则", "更新负载均衡规则", `{"name":"example","enable_tls":true}`, `{"code":0,"message":"Rule updated"}`, []string{"400 validation_failed", "404 not_found", "409 cert_job_active"}, ""},
	{"DELETE", "/rules/:caddy_id", "规则", "删除负载均衡规则", "", `{"code":0,"message":"Rule deleted"}`, []string{"404 not_found"}, ""},
	{"POST", "/rules/:caddy_id/enable", "规则", "启用规则", "", `{"code":0,"message":"Rule enabled"}`, []string{"404 not_found", "500 caddy_apply_failed"}, "ACME 证书未过期且未到续期窗口时复用现有证书，不重新签发。"},
	{"PUT", "/rules/:caddy_id/disable", "规则", "禁用规则", "", `{"code":0,"message":"Rule disabled"}`, []string{"404 not_found", "500 caddy_apply_failed"}, "非终态证书任务会置为 disabled。"},
	{"POST", "/rules/:caddy_id/duplicate", "规则", "复制规则", `{"name":"copy-name"}`, `{"caddy_id":"lb_new..."}`, []string{"404 not_found"}, ""},
	{"GET", "/certificate-configs", "证书", "DNS 提供商配置列表", "", `[{"id":1,"name":"dnspod","dns_provider":"dnspod","enabled":true}]`, []string{"401 unauthenticated"}, "不返回凭证明文。"},
	{"POST", "/certificate-configs", "证书", "创建 DNS 提供商配置", `{"name":"dnspod","dns_provider":"dnspod","dns_credentials":{"id":"...","token":"..."},"enabled":true}`, `{"id":1}`, []string{"400 invalid_request"}, "凭证只保存，不返回。"},
	{"PUT", "/certificate-configs/:id", "证书", "更新 DNS 提供商配置", `{"name":"dnspod","enabled":true}`, `{"code":0,"message":"Config updated"}`, []string{"400 invalid_request", "404 not_found"}, ""},
	{"DELETE", "/certificate-configs/:id", "证书", "删除 DNS 提供商配置", "", `{"code":0,"message":"Config deleted"}`, []string{"404 not_found"}, ""},
	{"POST", "/certificate-configs/:id/test", "证书", "测试 DNS 提供商配置", `{"domain":"example.com"}`, `{"code":0,"message":"凭证有效"}`, []string{"400 invalid_credentials", "404 not_found"}, "测试成功/失败都会记录操作日志，不记录凭证。"},
	{"GET", "/ca-providers", "证书", "CA 提供商列表", "", `[{"id":1,"name":"Let's Encrypt","provider":"letsencrypt","enabled":true}]`, []string{"401 unauthenticated"}, ""},
	{"PUT", "/ca-providers/:id", "证书", "更新 CA 提供商", `{"name":"Let's Encrypt","enabled":true}`, `{"code":0,"message":"CA provider updated"}`, []string{"400 invalid_request", "404 not_found"}, ""},
	{"POST", "/ca-providers/:id/test", "证书", "测试 CA 提供商", "", `{"code":0,"message":"CA 提供商配置有效"}`, []string{"400 test_failed", "404 not_found"}, "测试成功/失败都会记录操作日志。"},
	{"GET", "/certificates/jobs", "证书", "证书签发任务列表", "", `[{"id":1,"rule_id":"lb_...","domain":"example.com","status":"issued","ca_provider_name":"Let's Encrypt"}]`, []string{"401 unauthenticated"}, "可用 query rule_id 过滤。"},
	{"POST", "/certificates/jobs/:id/retry", "证书", "重试证书签发任务", "", `{"code":0,"message":"Retry triggered"}`, []string{"404 not_found", "429 retry_guard", "500 queue_unavailable"}, ""},
	{"DELETE", "/certificates/jobs/:id", "证书", "删除证书签发任务", "", `{"code":0,"message":"Job deleted"}`, []string{"404 not_found"}, ""},
	{"POST", "/certificates/issue", "证书", "触发 ACME 签发流程", "", `{"code":0,"message":"Certificate issuance triggered"}`, []string{"401 unauthenticated"}, "该接口仅触发流程，不表示签发完成。"},
	{"POST", "/certificates/parse", "证书", "解析证书", `{"cert_pem":"...","key_pem":"..."}`, `{"domain":"example.com","valid":true}`, []string{"400 invalid_certificate"}, "证书材料不写入审计。"},
	{"GET", "/nodes", "集群", "节点列表", "", `[{"id":1,"name":"node-1","status":"online"}]`, []string{"403 admin_required"}, ""},
	{"POST", "/nodes/register", "集群", "节点注册", `{"name":"node-1","ip_address":"10.0.0.2","port":8000}`, `{"id":2}`, []string{"400 no_master"}, ""},
	{"PUT", "/nodes/:id", "集群", "更新节点", `{"name":"node-1","sync_enabled":true}`, `{"code":0,"message":"Node updated"}`, []string{"404 not_found"}, ""},
	{"PUT", "/nodes/:id/approve", "集群", "审批节点", "", `{"code":0,"message":"Node approved"}`, []string{"404 not_found"}, ""},
	{"PUT", "/nodes/:id/reject", "集群", "拒绝节点", "", `{"code":0,"message":"Node rejected"}`, []string{"404 not_found"}, ""},
	{"DELETE", "/nodes/:id", "集群", "删除节点", "", `{"code":0,"message":"Node deleted"}`, []string{"404 not_found"}, ""},
	{"POST", "/nodes/:id/heartbeat", "集群", "节点心跳", "", `{"code":0,"message":"Heartbeat received"}`, nil, "不记录操作日志。"},
	{"GET", "/sync/status", "同步", "同步状态", "", `{"last_sync":null,"pending_nodes":0,"node_mode":"master"}`, []string{"401 unauthenticated"}, ""},
	{"POST", "/sync/pull", "同步", "手动同步", "", `{"code":0,"message":"Sync completed"}`, []string{"500 sync_failed"}, ""},
	{"GET", "/caddy/status", "Caddy", "Caddy 状态", "", `{"status":"running"}`, []string{"500 caddy_unavailable"}, ""},
	{"GET", "/caddy/config", "Caddy", "当前 Caddy 配置", "", `{...}`, []string{"500 caddy_unavailable"}, ""},
	{"PUT", "/caddy/config", "Caddy", "直接更新 Caddy 配置", `{...}`, `{"code":0,"message":"Config saved"}`, []string{"400 config_invalid"}, ""},
	{"POST", "/caddy/start", "Caddy", "启动 Caddy", "", `{"code":0,"message":"Caddy started"}`, []string{"500 start_failed"}, ""},
	{"POST", "/caddy/stop", "Caddy", "停止 Caddy", "", `{"code":0,"message":"Caddy stopped"}`, []string{"500 stop_failed"}, ""},
	{"POST", "/caddy/restart", "Caddy", "重启 Caddy", "", `{"code":0,"message":"Caddy restarted"}`, []string{"500 restart_failed"}, ""},
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
	b.WriteString("  description: |\n    Lazy Balancer v1 REST API。认证使用 Authorization: Bearer <JWT 或 lb_sk_ API Key>。\n    响应统一为 {code,message,data?}；敏感字段（密码、密钥、凭证、私钥）不会返回。\nservers:\n  - url: /api/v1\npaths:\n")
	for _, r := range apiDocRoutes {
		fmt.Fprintf(&b, "  %s:\n    %s:\n      tags: [%s]\n      summary: %s\n", r.Path, strings.ToLower(r.Method), r.Tag, r.Summary)
		if r.Description != "" {
			fmt.Fprintf(&b, "      description: %s\n", r.Description)
		}
		if r.Request != "" {
			fmt.Fprintf(&b, "      requestBody:\n        required: true\n        content:\n          application/json:\n            example: %s\n", r.Request)
		}
		fmt.Fprintf(&b, "      responses:\n        '200':\n          description: 成功\n          content:\n            application/json:\n              example: %s\n", r.Response)
		for _, e := range r.Errors {
			parts := strings.SplitN(e, " ", 2)
			desc := "错误"
			if len(parts) == 2 {
				desc = parts[1]
			}
			fmt.Fprintf(&b, "        '%s':\n          description: %s\n          content:\n            application/json:\n              example: {\"code\":%s,\"message\":\"%s\"}\n", parts[0], desc, parts[0], desc)
		}
	}
	b.WriteString("components:\n  securitySchemes:\n    bearerAuth:\n      type: http\n      scheme: bearer\n      description: JWT 或 lb_sk_ API Key\nsecurity:\n  - bearerAuth: []\n")
	return b.String()
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
