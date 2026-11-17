package middleware

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/mcpserver"
)

// mcpGlobalSwitchGuard MCP 全局开关门（notify_settings 键 notify.mcp_enabled，
// 缺行/读失败按启用）：停用时 /mcp 全链路 503——认证与 Key 级 mcp_enabled 判
// 定已在前序守卫完成（401/403 优先于 503，拒绝真因不因全局停用被遮蔽）。
func mcpGlobalSwitchGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if mcpserver.MCPSwitchEnabled() {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"code": http.StatusServiceUnavailable, "message": apimsg.T(c, "k_963a42ce"), "message_key": "k_963a42ce"})
	}
}

func mcpAccessGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("auth_type") != "api_key" {
			recordAuthenticationRejection(c, "mcp_auth_rejected")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "MCP 仅支持 API 密钥认证"})
			return
		}
		if !c.GetBool("api_key_mcp_enabled") {
			recordAuthenticationRejection(c, "mcp_disabled")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "MCP 功能未开启"})
			return
		}
		c.Next()
	}
}

// LoopbackAPIClient 是 MCP 工具内部转发专用的本机回环客户端。转发 base URL
// 恒为明文 http://127.0.0.1:<port>/api/v1（见 SetupRouter）；面板启用 HTTPS
// 后该明文请求由 TLS 嗅探层回 302（cmd/server/http_redirect_mux.go），
// mcpserver 侧按原方法/原请求体重放到 https 回环地址。同一次升级换来的
// 证书可能是管理员选定的自签形态（selfsigned），因此这条专用链路必须信任
// 面板自身证书：InsecureSkipVerify 只允许存在于本客户端，不得扩散到任何
// 通用客户端。
//
// 凭证不出回环由两处共同保证：base URL 在这里固定为回环地址，重放目标另由
// mcpserver.isLoopbackHTTPURL 限制为 localhost/回环 IP。
// 重定向在 mcpserver 侧统一关闭（redirectlessClient），此处不重复配置。
func LoopbackAPIClient() *http.Client {
	return &http.Client{Timeout: 60 * time.Second, Transport: loopbackAPITransport()}
}

// loopbackAPITransport 只服务回环内部转发：显式跳过自签证书校验（面板
// selfsigned 形态），其余传输参数与默认传输保持同口径。
func loopbackAPITransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	return transport
}
