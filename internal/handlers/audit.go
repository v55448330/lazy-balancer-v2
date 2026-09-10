package handlers

import (
	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

func recordAudit(c *gin.Context, action, resource, detail string) {
	username, _ := c.Get("username")
	usernameStr, _ := username.(string)
	if c.GetString("auth_type") == "api_key" {
		detail = services.AppendAPIKeyAuditDetail(detail, c.GetInt("api_key_id"), c.GetString("api_key_name"))
	}
	// A-1(2026-09-10 审计):优先读中间件注入的 audit_ip(内部 MCP 转发经
	// constant-time 采信的真实客户端 IP;第 15 轮 K-1 只覆盖了 3 条中间件审计
	// 路由,本函数是全部 Explicit 审计路径的最大消费方)。
	ip := c.GetString("audit_ip")
	if ip == "" {
		ip = c.ClientIP()
	}
	services.RecordAuditLog(usernameStr, action, resource, detail, ip)
}
