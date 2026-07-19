package middleware

import (
	"database/sql"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

func clusterVersionMiddleware(database *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if c.Writer.Status() >= http.StatusBadRequest || !isSynchronizedWrite(c.Request.Method, c.FullPath()) {
			return
		}
		var isMaster bool
		if err := database.QueryRowContext(c.Request.Context(), "SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
			return
		}
		if err := services.BumpClusterVersion(c.Request.Context(), database); err != nil {
			log.Printf("cluster version bump failed for %s %s: %v", c.Request.Method, c.FullPath(), err)
		}
	}
}

func isSynchronizedWrite(method, path string) bool {
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete {
		return false
	}
	if method == http.MethodPut && (path == "/api/v1/config" || path == "/api/v1/caddy/config") {
		return true
	}
	if path == "/api/v1/rules/cert-info" {
		return false
	}
	for _, prefix := range []string{"/api/v1/rules", "/api/v1/users", "/api/v1/api-keys"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
