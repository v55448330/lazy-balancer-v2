package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
)

func SetupRouter(h *handlers.Handlers, cfg *config.Config) *gin.Engine {
	services.ApplyLogLevel()

	r := gin.New()
	r.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("[%s] %s | %3d | %13v | %15s | %-7s %#v\n",
			param.TimeStamp.In(services.CurrentLocation()).Format("2006/01/02 15:04:05"),
			param.Method, param.StatusCode, param.Latency, param.ClientIP, param.Method, param.Path)
	}), gin.Recovery())

	// CORS
	r.Use(corsMiddleware())
	r.Use(gzip.Gzip(gzip.DefaultCompression))
	r.Use(auditMiddleware())
	r.Use(clusterVersionMiddleware(db.DB))

	// Serve static files
	r.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/assets/") {
			// Vite 产物文件名带内容哈希，可长期缓存
			c.Header("Cache-Control", "public, max-age=31536000, immutable")
		}
		c.Next()
	})
	r.Static("/assets", cfg.StaticDir+"/assets")
	r.GET("/", func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache")
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
		v1.GET("/auth/setup", h.GetSetupStatus)
		v1.POST("/auth/setup", h.SetupAdmin)
		v1.GET("/branding", h.GetBranding)
		v1.POST("/cluster/register", h.RegisterClusterNode)
		v1.GET("/cluster/register/:id/status", registrationAuth(db.DB), h.GetClusterRegistrationStatus)
		v1.GET("/cluster/sync/snapshot", clusterTokenAuth(db.DB), h.GetClusterSnapshot)
		v1.POST("/cluster/nodes/report", clusterTokenAuth(db.DB), h.ReportClusterNode)

		v1.Use(apiKeyAuth(cfg))
		v1.Use(jwtAuth(cfg))
		{
			v1.GET("/caddy/metrics", h.GetCaddyMetrics)
			v1.POST("/auth/logout", h.Logout)
			// User management (admin only)
			admin := v1.Group("")
			admin.Use(adminOnly(), readOnlyGuard(db.DB))
			{
				admin.POST("/users", h.CreateUser)
				admin.PUT("/users/:id", h.UpdateUser)
				admin.PUT("/users/:id/status", h.ToggleUserStatus)
				admin.POST("/users/:id/reset-password", h.ResetUserPassword)
				admin.DELETE("/users/:id", h.DeleteUser)

				// API Keys
				admin.POST("/api-keys", h.CreateAPIKey)
				admin.PATCH("/api-keys/:id/status", h.UpdateAPIKeyStatus)
				admin.DELETE("/api-keys/:id", h.DeleteAPIKey)

				// CA Providers (admin only for update/test)
				admin.PUT("/ca-providers/:id", h.UpdateCAProvider)
				admin.POST("/ca-providers/:id/test", h.TestCAProvider)

				admin.POST("/cluster/register-tokens", h.GenerateClusterRegisterToken)
				admin.POST("/cluster/nodes/:id/approve", h.ApproveClusterNode)
				admin.POST("/cluster/nodes/:id/reject", h.RejectClusterNode)
				admin.DELETE("/cluster/nodes/:id", h.DeleteClusterNode)
				admin.POST("/cluster/mode", h.SetClusterMode)
				admin.POST("/cluster/promote", h.PromoteClusterNode)
				admin.POST("/cluster/sync/pull", h.PullClusterSnapshot)
				admin.PUT("/cluster/settings", h.UpdateClusterSettings)

				// Config
				admin.POST("/config/preview", h.PreviewConfigUpdate)
				admin.PUT("/config", h.UpdateConfig)
				admin.POST("/config/reload", h.ReloadCaddy)
				admin.POST("/config/validate", h.ValidateConfig)
				admin.GET("/config/export", h.ExportConfigBackup)
				admin.POST("/config/import", h.ImportConfigBackup)
				admin.POST("/config/import/validate", h.ValidateConfigImport)
				admin.POST("/config/import/v1", h.ImportV1Config)

			}

			// User + Admin
			business := v1.Group("")
			business.Use(readOnlyGuard(db.DB))
			{
				// Current user (self)
				business.GET("/users/me", h.GetCurrentUser)
				business.PATCH("/users/me", h.UpdateCurrentUser)
				business.GET("/users/me/api-keys", h.ListCurrentUserAPIKeys)
				business.POST("/users/me/api-keys", h.CreateCurrentUserAPIKey)
				business.PATCH("/users/me/api-keys/:id", h.UpdateCurrentUserAPIKeyStatus)
				business.DELETE("/users/me/api-keys/:id", h.DeleteCurrentUserAPIKey)

				// Read-only lists (all authenticated users)
				business.GET("/users", h.ListUsers)
				business.GET("/api-keys", h.ListAPIKeys)
				business.GET("/cluster/nodes", h.ListClusterNodes)
				business.GET("/config/health", h.GetUpstreamHealth)

				// Rules
				business.GET("/rules", h.ListRules)
				business.GET("/rules/:caddy_id", h.GetRule)
				business.GET("/rules/:caddy_id/caddy-config", h.GetRuleCaddyConfig)
				business.GET("/rules/:caddy_id/metrics-history", h.GetRuleMetricsHistory)
				business.GET("/rules/:caddy_id/log-stream", h.GetRuleLogStream)
				business.GET("/rules/:caddy_id/logs", h.GetRuleLogs)
				business.GET("/rules/:caddy_id/cert-info", h.GetRuleCertInfo)
				business.POST("/rules/cert-info", h.GetRulesCertInfo)
				business.POST("/rules", h.CreateRule)
				business.PUT("/rules/:caddy_id", h.UpdateRule)
				business.POST("/rules/:caddy_id/acl", h.UpdateRuleACL)
				business.DELETE("/rules/:caddy_id", h.DeleteRule)
				business.POST("/rules/:caddy_id/enable", h.EnableRule)
				business.PUT("/rules/:caddy_id/disable", h.DisableRule)
				business.POST("/rules/:caddy_id/duplicate", h.DuplicateRule)

				// Certificate Configs
				business.GET("/certificate-configs", h.ListCertificateConfigs)
				business.POST("/certificate-configs", h.CreateCertificateConfig)
				business.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)
				business.DELETE("/certificate-configs/:id", h.DeleteCertificateConfig)
				business.GET("/dns-providers", h.ListDNSProviders)
				business.GET("/ca-providers", h.ListCAProviders)
				business.GET("/ca-providers/:id", h.GetCAProvider)
				business.POST("/certificate-configs/test", h.TestCertificateConfig)
				business.POST("/certificate-configs/:id/test", h.TestCertificateConfig)

				// Config (read only for non-admin)
				business.GET("/config", h.GetConfig)
				business.GET("/cluster/status", h.GetClusterStatus)

				// Metrics
				business.GET("/metrics/overview", h.GetMetricsOverview)
				business.GET("/metrics/rule/:caddy_id", h.GetRuleMetrics)
				business.GET("/metrics/history", h.GetMetricsHistory)
				business.GET("/metrics/realtime", h.GetRealtimeTraffic)
				business.GET("/metrics/connections", h.GetConnectionStats)

				// System
				business.GET("/system/info", h.GetSystemInfo)
				business.GET("/admin-tls", h.GetAdminTLS)
				business.PUT("/admin-tls", h.UpdateAdminTLS)
				business.POST("/admin-tls/inspect", h.InspectAdminTLSCert)
				business.GET("/system/metrics", h.GetSystemMetrics)
				business.GET("/system/logs", h.GetAppLogs)
				business.POST("/system/restart", h.RestartService)

				// Caddy
				business.GET("/caddy/status", h.GetCaddyStatus)
				business.GET("/caddy/config", h.GetCaddyConfig)
				business.GET("/caddy/logs", h.GetCaddyLogs)
				business.PUT("/caddy/config", h.PutCaddyConfig)
				business.GET("/caddy/host-metrics", h.GetHostMetrics)
				business.POST("/caddy/start", h.StartCaddy)
				business.POST("/caddy/stop", h.StopCaddy)
				business.POST("/caddy/restart", h.RestartCaddy)

				// Certificates
				business.GET("/certificates", h.ListCertificates)
				business.POST("/certificates/issue", h.IssueCertificate)
				business.POST("/certificates/parse", h.ParseCertificate)
				business.GET("/certificates/jobs", h.ListCertJobs)
				business.GET("/certificates/jobs/:id", h.GetCertJob)
				business.GET("/certificates/jobs/:id/logs", h.GetCertJobLogs)
				business.POST("/certificates/jobs/:id/retry", h.RetryCertJob)
				business.DELETE("/certificates/jobs/:id", h.DeleteCertJob)

				business.GET("/audit-logs", h.GetAuditLogs)
			}
		}
	}

	services.StartAuditCleanup()

	return r
}

func auditMiddleware() gin.HandlerFunc {
	writeMethods := map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}
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
		if c.Writer.Status() >= 400 && c.Writer.Status() < 500 {
			return
		}

		action, resource, detail := services.FormatAuditAction(c.Request.Method, path)
		if action == "" {
			return
		}
		if c.Writer.Status() >= 500 {
			detail = detail + "；结果：失败"
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
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Cluster-Token, X-Registration-Secret")

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
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "缺少认证信息"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "认证格式无效"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录状态已过期，请重新登录"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录凭证无效"})
			c.Abort()
			return
		}

		// Resolve the current role and enabled state from the database so that
		// demotion or disabling takes effect immediately, not at token expiry.
		userIDFloat, ok := claims["user_id"].(float64)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录凭证无效"})
			c.Abort()
			return
		}
		var dbRole string
		var dbEnabled bool
		var passwordVersion int64
		if err := db.DB.QueryRow("SELECT role, COALESCE(is_enabled,1), password_version FROM users WHERE id = ?", int64(userIDFloat)).Scan(&dbRole, &dbEnabled, &passwordVersion); err != nil || !dbEnabled {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "用户不存在或已禁用"})
			c.Abort()
			return
		}
		if claim, exists := claims["pwd_ver"]; exists {
			claimVersion, valid := claim.(float64)
			if !valid || claimVersion != float64(passwordVersion) {
				c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "密码已修改，请重新登录"})
				c.Abort()
				return
			}
		} else if passwordVersion != 0 {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "密码已修改，请重新登录"})
			c.Abort()
			return
		}

		c.Set("user_id", claims["user_id"])
		c.Set("username", claims["username"])
		c.Set("role", dbRole)

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
			if hasJWTBearer(c) {
				c.Next()
				return
			}
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
			if hasJWTBearer(c) {
				c.Next()
				return
			}
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

func hasJWTBearer(c *gin.Context) bool {
	authHeader := c.GetHeader("Authorization")
	return strings.HasPrefix(authHeader, "Bearer ") && !strings.HasPrefix(authHeader, "Bearer lb_sk_")
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
