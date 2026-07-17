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
	services.RecordAuditLog(usernameStr, action, resource, detail, c.ClientIP())
}
