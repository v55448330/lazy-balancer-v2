package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
)

func SetupRouter(h *handlers.Handlers, cfg *config.Config) *gin.Engine {
	if cfg.LogLevel == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()

	// CORS
	r.Use(corsMiddleware())
	r.Use(auditMiddleware())

	// Serve static files
	r.Static("/assets", cfg.StaticDir+"/assets")
	r.GET("/", func(c *gin.Context) {
		c.File(cfg.StaticDir + "/index.html")
	})
	r.Static("/ui", cfg.StaticDir)

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// API routes
	v1 := r.Group("/api/v1")
	{
		v1.GET("/openapi.yaml", h.GetOpenAPIYAML)
		v1.GET("/docs", h.GetAPIDocs)
		v1.POST("/auth/login", h.Login)

		v1.Use(apiKeyAuth(cfg))
		v1.GET("/caddy/metrics", h.GetCaddyMetrics)

		v1.Use(jwtAuth(cfg))
		{
			v1.POST("/auth/logout", h.Logout)
			// User management (admin only)
			admin := v1.Group("")
			admin.Use(adminOnly())
			{
				admin.GET("/users", h.ListUsers)
				admin.POST("/users", h.CreateUser)
				admin.PUT("/users/:id", h.UpdateUser)
				admin.PUT("/users/:id/status", h.ToggleUserStatus)
				admin.POST("/users/:id/reset-password", h.ResetUserPassword)
				admin.DELETE("/users/:id", h.DeleteUser)

				// API Keys
				admin.GET("/api-keys", h.ListAPIKeys)
				admin.POST("/api-keys", h.CreateAPIKey)
				admin.PATCH("/api-keys/:id/status", h.UpdateAPIKeyStatus)
				admin.DELETE("/api-keys/:id", h.DeleteAPIKey)

				// CA Providers (admin only for update/test)
				admin.PUT("/ca-providers/:id", h.UpdateCAProvider)
				admin.POST("/ca-providers/:id/test", h.TestCAProvider)

				// Nodes
				admin.GET("/nodes", h.ListNodes)
				admin.GET("/nodes/pending", h.ListPendingNodes)
				admin.PUT("/nodes/:id/approve", h.ApproveNode)
				admin.PUT("/nodes/:id/reject", h.RejectNode)
				admin.DELETE("/nodes/:id", h.DeleteNode)

				// Config
				admin.POST("/config/preview", h.PreviewConfigUpdate)
				admin.PUT("/config", h.UpdateConfig)
				admin.POST("/config/reload", h.ReloadCaddy)
				admin.POST("/config/validate", h.ValidateConfig)
				admin.GET("/config/health", h.GetUpstreamHealth)

				// Sync
				admin.GET("/sync/config", h.GetSyncConfig)
				admin.POST("/sync/pull", h.ManualSync)
			}

			// User + Admin
			{
				// Current user (self)
				v1.GET("/users/me", h.GetCurrentUser)
				v1.PATCH("/users/me", h.UpdateCurrentUser)
				v1.GET("/users/me/api-keys", h.ListCurrentUserAPIKeys)
				v1.POST("/users/me/api-keys", h.CreateCurrentUserAPIKey)
				v1.PATCH("/users/me/api-keys/:id", h.UpdateCurrentUserAPIKeyStatus)
				v1.DELETE("/users/me/api-keys/:id", h.DeleteCurrentUserAPIKey)

				// Rules
				v1.GET("/rules", h.ListRules)
				v1.GET("/rules/:caddy_id", h.GetRule)
				v1.GET("/rules/:caddy_id/caddy-config", h.GetRuleCaddyConfig)
				v1.GET("/rules/:caddy_id/logs", h.GetRuleLogs)
				v1.GET("/rules/:caddy_id/cert-info", h.GetRuleCertInfo)
				v1.POST("/rules/cert-info", h.GetRulesCertInfo)
				v1.POST("/rules", h.CreateRule)
				v1.PUT("/rules/:caddy_id", h.UpdateRule)
				v1.DELETE("/rules/:caddy_id", h.DeleteRule)
				v1.POST("/rules/:caddy_id/enable", h.EnableRule)
				v1.PUT("/rules/:caddy_id/disable", h.DisableRule)
				v1.POST("/rules/:caddy_id/duplicate", h.DuplicateRule)

				// Certificate Configs
				v1.GET("/certificate-configs", h.ListCertificateConfigs)
				v1.POST("/certificate-configs", h.CreateCertificateConfig)
				v1.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)
				v1.DELETE("/certificate-configs/:id", h.DeleteCertificateConfig)
				v1.GET("/dns-providers", h.ListDNSProviders)
				v1.GET("/ca-providers", h.ListCAProviders)
				v1.GET("/ca-providers/:id", h.GetCAProvider)
				v1.POST("/certificate-configs/test", h.TestCertificateConfig)
				v1.POST("/certificate-configs/:id/test", h.TestCertificateConfig)

				// Config (read only for non-admin)
				v1.GET("/config", h.GetConfig)

				// Metrics
				v1.GET("/metrics/overview", h.GetMetricsOverview)
				v1.GET("/metrics/rule/:caddy_id", h.GetRuleMetrics)
				v1.GET("/metrics/history", h.GetMetricsHistory)
				v1.GET("/metrics/realtime", h.GetRealtimeTraffic)
				v1.GET("/metrics/connections", h.GetConnectionStats)

				// System
				v1.GET("/system/info", h.GetSystemInfo)
				v1.GET("/system/metrics", h.GetSystemMetrics)

				// Caddy
				v1.GET("/caddy/status", h.GetCaddyStatus)
				v1.GET("/caddy/config", h.GetCaddyConfig)
				v1.GET("/caddy/logs", h.GetCaddyLogs)
				v1.PUT("/caddy/config", h.PutCaddyConfig)
				v1.GET("/caddy/host-metrics", h.GetHostMetrics)
				v1.POST("/caddy/start", h.StartCaddy)
				v1.POST("/caddy/stop", h.StopCaddy)
				v1.POST("/caddy/restart", h.RestartCaddy)

				// Sync
				v1.GET("/sync/status", h.GetSyncStatus)

				// Nodes
				v1.POST("/nodes/register", h.RegisterNode)
				v1.POST("/nodes/:id/heartbeat", h.NodeHeartbeat)
				v1.PUT("/nodes/:id", h.UpdateNode)

				// Certificates
				v1.GET("/certificates", h.ListCertificates)
				v1.POST("/certificates/issue", h.IssueCertificate)
				v1.POST("/certificates/parse", h.ParseCertificate)
				v1.GET("/certificates/jobs", h.ListCertJobs)
				v1.GET("/certificates/jobs/:id", h.GetCertJob)
				v1.GET("/certificates/jobs/:id/logs", h.GetCertJobLogs)
				v1.POST("/certificates/jobs/:id/retry", h.RetryCertJob)
				v1.DELETE("/certificates/jobs/:id", h.DeleteCertJob)

				v1.GET("/audit-logs", h.GetAuditLogs)
			}
		}
	}

	services.StartAuditCleanup()

	return r
}

func auditMiddleware() gin.HandlerFunc {
	writeMethods := map[string]bool{"POST": true, "PUT": true, "DELETE": true}
	return func(c *gin.Context) {
		c.Next()

		if !writeMethods[c.Request.Method] {
			return
		}
		path := c.FullPath()
		policy := services.ClassifyAuditRoute(c.Request.Method, path)
		if policy == services.AuditPolicySkip || services.HasExplicitAuditEvent(c.Request.Method, path) {
			return
		}
		if c.Writer.Status() >= 400 {
			return
		}

		action, resource, detail := services.FormatAuditAction(c.Request.Method, path)
		if action == "" {
			return
		}

		username, _ := c.Get("username")
		usernameStr, _ := username.(string)
		if c.GetString("auth_type") == "api_key" {
			detail = services.AppendAPIKeyAuditDetail(detail, c.GetInt("api_key_id"), c.GetString("api_key_name"))
		}

		services.RecordAuditLog(usernameStr, action, resource, detail, c.ClientIP())
	}
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func jwtAuth(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("auth_type") == "api_key" {
			c.Next()
			return
		}
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Missing authorization header"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Invalid authorization format"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Set("user_id", claims["user_id"])
		c.Set("username", claims["username"])
		c.Set("role", claims["role"])

		c.Next()
	}
}

func apiKeyAuth(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip if already authenticated via JWT
		if userID, exists := c.Get("user_id"); exists && userID != nil {
			c.Next()
			return
		}

		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer lb_sk_") {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}
		if apiKey == "" {
			c.Next()
			return
		}
		if len(apiKey) < 13 {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Invalid API key"})
			c.Abort()
			return
		}
		prefix := apiKey[:12]
		hash := sha256.Sum256([]byte(apiKey))
		keyHash := hex.EncodeToString(hash[:])

		var keyID, userID int
		var keyName, username, role string
		err := db.DB.QueryRow(`
			SELECT k.id, k.name, u.id, u.username, u.role
			FROM api_keys k
			JOIN users u ON u.id = k.created_by
			WHERE k.key_prefix = ? AND k.key_hash = ?
			  AND k.is_enabled = 1
			  AND u.is_enabled = 1
			  AND (k.expires_at IS NULL OR datetime(k.expires_at) > datetime('now'))
		`, prefix, keyHash).Scan(&keyID, &keyName, &userID, &username, &role)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Invalid API key"})
			c.Abort()
			return
		}

		db.DB.Exec("UPDATE api_keys SET last_used = datetime('now') WHERE id = ?", keyID)
		c.Set("user_id", userID)
		c.Set("username", username)
		c.Set("role", role)
		c.Set("auth_type", "api_key")
		c.Set("api_key_id", keyID)
		c.Set("api_key_name", keyName)

		c.Next()
	}
}

func adminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists || role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"code": 403, "message": "Admin access required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// GetNodeMode returns the current node mode
func GetNodeMode(c *gin.Context) string {
	mode, _ := c.Get("node_mode")
	if mode == nil {
		return "master"
	}
	return mode.(string)
}

// GetUserRole returns the current user role
func GetUserRole(c *gin.Context) string {
	role, _ := c.Get("role")
	if role == nil {
		return ""
	}
	return role.(string)
}

// IsReadOnly returns true if the current node is a slave
func IsReadOnly(c *gin.Context) bool {
	mode, _ := c.Get("node_mode")
	if mode == nil {
		return false
	}
	return mode.(string) == "slave"
}
