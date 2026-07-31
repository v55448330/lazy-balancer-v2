package middleware

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"time"

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

// loopbackAPIClient 是 MCP 工具内部转发专用的本机回环客户端；
// 面板强制 HTTPS 使用自签证书，回环自调用跳过证书校验；
// 不自动跟随重定向，由转发层按原方法重试（Go 的 301 会把 POST 变 GET）
func loopbackAPIClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
