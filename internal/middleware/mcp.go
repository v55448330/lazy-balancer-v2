package middleware

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
)

func mcpAccessGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("auth_type") != "api_key" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "MCP 仅支持 API 密钥认证"})
			return
		}
		if !c.GetBool("api_key_mcp_enabled") {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "MCP 功能未开启"})
			return
		}
		encoded := c.GetString("api_key_mcp_ip_whitelist")
		if encoded == "" {
			c.Next()
			return
		}
		var whitelist []string
		if err := json.Unmarshal([]byte(encoded), &whitelist); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "MCP IP 白名单配置无效"})
			return
		}
		clientIP := net.ParseIP(c.ClientIP())
		for _, cidr := range whitelist {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "MCP IP 白名单配置无效"})
				return
			}
			if network.Contains(clientIP) {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "来源 IP 不在白名单"})
	}
}
