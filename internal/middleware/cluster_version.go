package middleware

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func clusterVersionMiddleware(database *sql.DB) gin.HandlerFunc {
	installErr := installClusterVersionTriggers(database)
	return func(c *gin.Context) {
		if !isSynchronizedWrite(c.Request.Method, c.FullPath()) {
			c.Next()
			return
		}
		if installErr != nil {
			_ = c.Error(installErr)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "cluster version trigger unavailable"})
			return
		}
		c.Next()
	}
}

func installClusterVersionTriggers(database *sql.DB) error {
	for _, table := range []string{"lb_rules", "upstreams", "path_rules", "users", "api_keys", "cert_jobs"} {
		for _, operation := range []string{"INSERT", "UPDATE", "DELETE"} {
			statement := fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS cluster_version_%s_%s
				AFTER %s ON %s
				WHEN (SELECT COALESCE(is_master,0) FROM global_config WHERE id=1)=1
				BEGIN
					UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1;
				END`, table, strings.ToLower(operation), operation, table)
			if _, err := database.Exec(statement); err != nil {
				return fmt.Errorf("install cluster version trigger for %s %s: %w", operation, table, err)
			}
		}
	}
	if _, err := database.Exec(`CREATE TRIGGER IF NOT EXISTS cluster_version_global_config_update
		AFTER UPDATE ON global_config
		WHEN OLD.cluster_version IS NEW.cluster_version AND COALESCE(NEW.is_master,0)=1
		BEGIN
			UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1;
		END`); err != nil {
		return fmt.Errorf("install cluster version trigger for global_config UPDATE: %w", err)
	}
	return nil
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
