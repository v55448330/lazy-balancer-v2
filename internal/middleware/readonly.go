package middleware

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func readOnlyGuard(database *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		routePath := c.FullPath()
		if routePath == "" {
			routePath = path
		}
		switch c.Request.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			c.Next()
			return
		}
		if services.IsReadOnlyWriteRoute(c.Request.Method, routePath) {
			c.Next()
			return
		}
		var isMaster bool
		if err := database.QueryRowContext(c.Request.Context(), "SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "节点角色查询失败"})
			return
		}
		if !isMaster {
			// 从节点仅放行集群管理与认证路径
			if isReadOnlyGuardWhitelisted(path) {
				c.Next()
				return
			}
			recordAuthenticationRejection(c, "slave_write_denied")
			c.AbortWithStatusJSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "从节点只读，请在主节点操作"})
			return
		}
		if c.GetString("role") != "admin" {
			// 主节点非管理员仅放行自管理（个人资料、自己的 API 密钥）
			if isSelfServicePath(path) {
				c.Next()
				return
			}
			recordAuthenticationRejection(c, "slave_write_denied")
			c.AbortWithStatusJSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "非管理员用户只读"})
			return
		}
		c.Next()
	}
}

func isReadOnlyGuardWhitelisted(path string) bool {
	return path == "/api/v1/auth/login" ||
		path == "/api/v1/auth/logout" ||
		path == "/api/v1/cluster" ||
		strings.HasPrefix(path, "/api/v1/cluster/")
}

// isSelfServicePath 是主节点上非管理员用户可自助维护资源的路径
func isSelfServicePath(path string) bool {
	return path == "/api/v1/users/me" ||
		path == "/api/v1/users/me/api-keys" ||
		strings.HasPrefix(path, "/api/v1/users/me/api-keys/")
}
