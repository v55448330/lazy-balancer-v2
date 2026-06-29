package middleware

import (
	"net/http"
	"strings"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
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
	api := r.Group("/api")
	{
		// Auth (public)
		api.POST("/auth/login", h.Login)

		// API Key auth (public)
		api.Use(apiKeyAuth(cfg))
		{
			api.POST("/auth/logout", h.Logout)
		}

		api.GET("/caddy/metrics", h.GetCaddyMetrics)

		// Protected routes
		api.Use(jwtAuth(cfg))
		{
			// User management (admin only)
			admin := api.Group("")
			admin.Use(adminOnly())
			{
				admin.GET("/users", h.ListUsers)
				admin.POST("/users", h.CreateUser)
				admin.PUT("/users/:id", h.UpdateUser)
				admin.PUT("/users/:id/status", h.ToggleUserStatus)
				admin.POST("/users/:id/reset-password", h.ResetUserPassword)
				admin.DELETE("/users/:id", h.DeleteUser)

				// API Keys
				admin.GET("/keys", h.ListAPIKeys)
				admin.POST("/keys", h.CreateAPIKey)
				admin.DELETE("/keys/:id", h.DeleteAPIKey)

				// Nodes
				admin.GET("/nodes", h.ListNodes)
				admin.GET("/nodes/pending", h.ListPendingNodes)
				admin.PUT("/nodes/:id/approve", h.ApproveNode)
				admin.PUT("/nodes/:id/reject", h.RejectNode)
				admin.DELETE("/nodes/:id", h.DeleteNode)

				// Config
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
				api.GET("/users/me", h.GetCurrentUser)
				api.PUT("/users/me", h.UpdateCurrentUser)

				// Rules
				api.GET("/rules", h.ListRules)
				api.GET("/rules/:caddy_id", h.GetRule)
				api.GET("/rules/:caddy_id/caddy-config", h.GetRuleCaddyConfig)
				api.GET("/rules/:caddy_id/cert-info", h.GetRuleCertInfo)
				api.POST("/rules/cert-info", h.GetRulesCertInfo)
				api.POST("/rules", h.CreateRule)
				api.PUT("/rules/:caddy_id", h.UpdateRule)
				api.DELETE("/rules/:caddy_id", h.DeleteRule)
				api.POST("/rules/:caddy_id/enable", h.EnableRule)
				api.PUT("/rules/:caddy_id/disable", h.DisableRule)
				api.POST("/rules/:caddy_id/duplicate", h.DuplicateRule)

				// Certificate Configs
				api.GET("/certificate-configs", h.ListCertificateConfigs)
				api.POST("/certificate-configs", h.CreateCertificateConfig)
				api.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)
				api.DELETE("/certificate-configs/:id", h.DeleteCertificateConfig)
				api.GET("/dns-providers", h.ListDNSProviders)
				api.POST("/certificate-configs/test", h.TestCertificateConfig)
				api.POST("/certificate-configs/:id/test", h.TestCertificateConfig)

				// Config (read only for non-admin)
				api.GET("/config", h.GetConfig)

				// Metrics
				api.GET("/metrics/overview", h.GetMetricsOverview)
				api.GET("/metrics/rule/:caddy_id", h.GetRuleMetrics)
				api.GET("/metrics/history", h.GetMetricsHistory)
				api.GET("/metrics/realtime", h.GetRealtimeTraffic)
				api.GET("/metrics/connections", h.GetConnectionStats)

				// System
				api.GET("/system/info", h.GetSystemInfo)
				api.GET("/system/metrics", h.GetSystemMetrics)

				// Caddy
				api.GET("/caddy/status", h.GetCaddyStatus)
				api.GET("/caddy/config", h.GetCaddyConfig)
				api.PUT("/caddy/config", h.PutCaddyConfig)
				api.GET("/caddy/host-metrics", h.GetHostMetrics)
				api.POST("/caddy/start", h.StartCaddy)
				api.POST("/caddy/stop", h.StopCaddy)
				api.POST("/caddy/restart", h.RestartCaddy)

				// Sync
				api.GET("/sync/status", h.GetSyncStatus)

				// Nodes
				api.POST("/nodes/register", h.RegisterNode)
				api.POST("/nodes/:id/heartbeat", h.NodeHeartbeat)
				api.PUT("/nodes/:id", h.UpdateNode)

				// Certificates
				api.GET("/certificates", h.ListCertificates)
				api.POST("/certificates/issue", h.IssueCertificate)
				api.POST("/certificates/parse", h.ParseCertificate)
				api.GET("/certificates/jobs", h.ListCertJobs)
				api.POST("/certificates/jobs/:id/retry", h.RetryCertJob)
				api.DELETE("/certificates/jobs/:id", h.DeleteCertJob)
			}
		}
	}

	return r
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
			c.Next()
			return
		}

		// Validate API key
		var keyHash string
		err := db.DB.QueryRow("SELECT key_hash FROM api_keys WHERE key_prefix = ?",
			apiKey[:12]).Scan(&keyHash)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Invalid API key"})
			c.Abort()
			return
		}

		// Verify key
		if err := bcrypt.CompareHashAndPassword([]byte(keyHash), []byte(apiKey)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Invalid API key"})
			c.Abort()
			return
		}

		// Update last used
		db.DB.Exec("UPDATE api_keys SET last_used = datetime('now') WHERE key_prefix = ?", apiKey[:12])

		// Set admin role for API key
		c.Set("user_id", 0)
		c.Set("role", "admin")

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
