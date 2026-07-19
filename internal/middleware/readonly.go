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
		if isReadOnlyGuardWhitelisted(path) {
			c.Next()
			return
		}
		routePath := c.FullPath()
		if routePath == "" {
			routePath = path
		}
		if !services.IsAuditedWriteRoute(c.Request.Method, routePath) || services.ClassifyAuditRoute(c.Request.Method, routePath) == services.AuditPolicySkip {
			c.Next()
			return
		}
		var isMaster bool
		if err := database.QueryRowContext(c.Request.Context(), "SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
			c.Next()
			return
		}
		if !isMaster {
			c.AbortWithStatusJSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "从节点只读，请在主节点操作"})
			return
		}
		if c.GetString("role") != "admin" {
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
		strings.HasPrefix(path, "/api/v1/cluster/") ||
		path == "/api/v1/users/me" ||
		strings.HasPrefix(path, "/api/v1/users/me/")
}
