package middleware

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/mcpserver"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
)

var internalMCPAuthSecret = rand.Text()
var jwtAuthenticationQuery = func(query string, args ...any) *sql.Row {
	return db.DB.QueryRow(query, args...)
}

const revokedTokenTimeFormat = "2006-01-02T15:04:05Z"

var recordAuthenticationSecurityAudit = services.RecordAuditLog
var authenticationSecurityAuditNow = time.Now

var securityAuditLimiter = authenticationAuditLimiter{events: make(map[string]time.Time)}

type authenticationAuditLimiter struct {
	mu     sync.Mutex
	events map[string]time.Time
}

func (limiter *authenticationAuditLimiter) allow(key string, now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if last, exists := limiter.events[key]; exists && now.Sub(last) < time.Minute {
		return false
	}
	for eventKey, last := range limiter.events {
		if now.Sub(last) >= 2*time.Minute {
			delete(limiter.events, eventKey)
		}
	}
	limiter.events[key] = now
	return true
}

func (limiter *authenticationAuditLimiter) reset() {
	limiter.mu.Lock()
	limiter.events = make(map[string]time.Time)
	limiter.mu.Unlock()
}

func recordAuthenticationRejection(c *gin.Context, reason string) {
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}
	ipAddress := c.ClientIP()
	if !securityAuditLimiter.allow(reason+"\x00"+path+"\x00"+ipAddress, authenticationSecurityAuditNow()) {
		return
	}
	detail := services.FormatAuditDetail("路径："+path, "原因类别："+reason)
	recordAuthenticationSecurityAudit("system", "认证拒绝", "安全审计", detail, ipAddress)
}

type revokedJTICleanup struct {
	mu      sync.Mutex
	lastRun time.Time
}

func (cleanup *revokedJTICleanup) run(database *sql.DB, now time.Time) error {
	cleanup.mu.Lock()
	defer cleanup.mu.Unlock()
	if !cleanup.lastRun.IsZero() && now.Sub(cleanup.lastRun) < time.Hour {
		return nil
	}
	if _, err := database.Exec("DELETE FROM revoked_jti WHERE expires_at<=?", now.UTC().Format(revokedTokenTimeFormat)); err != nil {
		return fmt.Errorf("cleanup revoked JWT IDs: %w", err)
	}
	cleanup.lastRun = now
	return nil
}

func SetupRouter(h *handlers.Handlers, cfg *config.Config) *gin.Engine {
	services.ApplyLogLevel()

	r := gin.New()
	r.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		if !shouldLogRequest(param.StatusCode, param.Latency) {
			return ""
		}
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
		mcpHandler := mcpserver.NewWithInternalAuth(fmt.Sprintf("http://127.0.0.1:%d/api/v1", cfg.Port), loopbackAPIClient(), internalMCPAuthSecret)
		v1.POST("/mcp", apiKeyAuth(cfg), mcpAccessGuard(), func(c *gin.Context) {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
			body, err := io.ReadAll(c.Request.Body)
			if err != nil {
				var maxBytesError *http.MaxBytesError
				if errors.As(err, &maxBytesError) {
					c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"code": http.StatusRequestEntityTooLarge, "message": "Request body too large"})
					return
				}
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"code": http.StatusBadRequest, "message": "Invalid request body"})
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewReader(body))
			gin.WrapH(mcpHandler)(c)
		})
		v1.GET("/openapi.yaml", h.GetOpenAPIYAML)
		v1.GET("/docs", h.GetAPIDocs)
		v1.POST("/auth/login", h.Login)
		v1.POST("/auth/ticket-login", h.TicketLogin)
		v1.GET("/auth/setup", h.GetSetupStatus)
		v1.POST("/auth/setup", h.SetupAdmin)
		v1.GET("/branding", h.GetBranding)
		v1.POST("/cluster/register", h.RegisterClusterNode)
		v1.GET("/cluster/register/:id/status", registrationAuth(db.DB), h.GetClusterRegistrationStatus)
		v1.GET("/cluster/sync/snapshot", clusterTokenAuth(db.DB), h.GetClusterSnapshot)
		v1.POST("/cluster/registration/confirm", clusterTokenAuth(db.DB), h.ConfirmClusterRegistration)
		v1.POST("/cluster/nodes/report", clusterTokenAuth(db.DB), h.ReportClusterNode)

		v1.Use(apiKeyAuth(cfg))
		v1.Use(jwtAuth(cfg))
		v1.Use(apiKeyReadOnlyGuard())
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
				admin.POST("/cluster/nodes/:id/login-ticket", h.GenerateClusterLoginTicket)
				admin.PUT("/cluster/nodes/:id/access-url", h.UpdateClusterNodeAccessURL)
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

				// Security (admin write)
				admin.POST("/security/policies", h.CreateSecurityPolicy)
				admin.PUT("/security/policies/:id", h.UpdateSecurityPolicy)
				admin.DELETE("/security/policies/:id", h.DeleteSecurityPolicy)
				admin.POST("/security/policies/:id/bind", h.BindRuleToPolicy)
				admin.DELETE("/security/policies/:id/bind/:caddy_id", h.UnbindRuleFromPolicy)
				admin.PUT("/security/crs/auto-update", h.UpdateCRSAutoUpdate)
				admin.POST("/security/crs/update", h.StartCRSUpdate)
				admin.PUT("/security/ip2region/auto-update", h.UpdateIP2RegionAutoUpdate)
				admin.POST("/security/ip2region/update", h.StartIP2RegionUpdate)
				admin.POST("/security/custom-rules", h.CreateSecurityCustomRule)
				admin.PUT("/security/custom-rules/:id", h.UpdateSecurityCustomRule)
				admin.DELETE("/security/custom-rules/:id", h.DeleteSecurityCustomRule)
				admin.POST("/security/block-pages", h.CreateSecurityBlockPage)
				admin.PUT("/security/block-pages/:id", h.UpdateSecurityBlockPage)
				admin.DELETE("/security/block-pages/:id", h.DeleteSecurityBlockPage)

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
				business.GET("/mcp/tools", h.GetMCPTools)
				business.GET("/mcp/ops-playbook", h.GetMCPOpsPlaybook)
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

				// Security (read for all, write for admin)
				business.GET("/security/policies", h.ListSecurityPolicies)
				business.GET("/security/policies/:id", h.GetSecurityPolicy)
				business.GET("/security/overview", h.GetSecurityOverview)
				business.GET("/security/rate-limit-blocks", h.GetSecurityRateLimitBlocks)
				business.GET("/security/events", h.ListSecurityEvents)
				business.GET("/security/crs", h.GetCRSInfo)
				business.GET("/security/crs/update/status", h.GetCRSUpdateStatus)
				business.GET("/security/crs/update/logs", h.GetCRSUpdateLogs)
				business.GET("/security/ip2region", h.GetIP2RegionInfo)
				business.GET("/security/ip2region/regions", h.GetIP2RegionRegions)
				business.GET("/security/ip2region/update/status", h.GetIP2RegionUpdateStatus)
				business.GET("/security/ip2region/update/logs", h.GetIP2RegionUpdateLogs)
				business.GET("/security/rules/:caddy_id/policy", h.GetSecurityPolicyBindings)
				business.GET("/security/bindings", h.GetAllSecurityBindings)
				business.GET("/security/custom-rules", h.ListSecurityCustomRules)
				business.GET("/security/block-pages", h.ListSecurityBlockPages)
				business.GET("/security/crs/rules", h.ListCRSRules)
				business.GET("/security/crs/rules/:filename", h.GetCRSRuleContent)
				business.GET("/security/crs/setup", h.GetCRSSetupConfig)

				// Config (read only for non-admin)
				business.GET("/config", h.GetConfig)
				business.GET("/cluster/status", h.GetClusterStatus)

				// Metrics
				business.GET("/metrics/dashboard", h.GetMetricsDashboard)
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
				business.POST("/certificates/jobs/current", h.GetCurrentCertJobs)
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

func shouldLogRequest(statusCode int, latency time.Duration) bool {
	switch services.CurrentLogLevel() {
	case "warn":
		return statusCode >= http.StatusBadRequest || latency >= time.Second
	case "error":
		return statusCode >= http.StatusInternalServerError
	default:
		return true
	}
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
			recordAuthenticationRejection(c, "jwt_missing")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "缺少认证信息"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			recordAuthenticationRejection(c, "jwt_format_invalid")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "认证格式无效"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWTSecret), nil
		}, jwt.WithExpirationRequired(), jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

		if err != nil || !token.Valid {
			recordAuthenticationRejection(c, "jwt_expired_or_invalid")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录状态已过期，请重新登录"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			recordAuthenticationRejection(c, "jwt_claims_invalid")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录凭证无效"})
			c.Abort()
			return
		}
		now := time.Now().UTC()
		revocationSource := tokenString
		if jti, exists := claims["jti"].(string); exists && jti != "" {
			revocationSource = jti
			c.Set("token_jti", jti)
		}
		revocationHash := sha256.Sum256([]byte(revocationSource))
		encodedRevocationHash := hex.EncodeToString(revocationHash[:])
		if exp, valid := claims["exp"].(float64); valid {
			c.Set("token_revocation_hash", encodedRevocationHash)
			c.Set("token_expires_at", time.Unix(int64(exp), 0).UTC())
		}

		// Resolve the current role and enabled state from the database so that
		// demotion or disabling takes effect immediately, not at token expiry.
		userIDFloat, ok := claims["user_id"].(float64)
		if !ok {
			recordAuthenticationRejection(c, "jwt_subject_invalid")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录凭证无效"})
			c.Abort()
			return
		}
		var dbUsername, dbRole sql.NullString
		var dbEnabled sql.NullBool
		var passwordVersion sql.NullInt64
		var revoked bool
		queryErr := jwtAuthenticationQuery(`WITH auth_state AS (
			SELECT EXISTS(SELECT 1 FROM revoked_jti WHERE jti_hash=? AND expires_at>?) AS revoked
		)
		SELECT auth_state.revoked, u.username, u.role, COALESCE(u.is_enabled,0), u.password_version
		FROM auth_state LEFT JOIN users u ON u.id=?`, encodedRevocationHash, now.Format(revokedTokenTimeFormat), int64(userIDFloat)).Scan(&revoked, &dbUsername, &dbRole, &dbEnabled, &passwordVersion)
		if queryErr == nil && revoked {
			recordAuthenticationRejection(c, "jwt_revoked")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录状态已失效，请重新登录"})
			c.Abort()
			return
		}
		if queryErr != nil || !dbUsername.Valid || !dbRole.Valid || !dbEnabled.Valid || !dbEnabled.Bool || !passwordVersion.Valid {
			recordAuthenticationRejection(c, "jwt_user_unavailable")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "用户不存在或已禁用"})
			c.Abort()
			return
		}
		claimUsername, valid := claims["username"].(string)
		if !valid || claimUsername != dbUsername.String {
			recordAuthenticationRejection(c, "jwt_identity_mismatch")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录凭证无效"})
			c.Abort()
			return
		}
		if claim, exists := claims["pwd_ver"]; exists {
			claimVersion, valid := claim.(float64)
			if !valid || claimVersion != float64(passwordVersion.Int64) {
				recordAuthenticationRejection(c, "jwt_password_changed")
				c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "密码已修改，请重新登录"})
				c.Abort()
				return
			}
		} else if passwordVersion.Int64 != 0 {
			recordAuthenticationRejection(c, "jwt_password_changed")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "密码已修改，请重新登录"})
			c.Abort()
			return
		}

		c.Set("user_id", claims["user_id"])
		c.Set("username", claims["username"])
		c.Set("role", dbRole.String)

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
			recordAuthenticationRejection(c, "api_key_invalid")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Invalid API key"})
			c.Abort()
			return
		}
		prefix := apiKey[:12]
		hash := sha256.Sum256([]byte(apiKey))
		keyHash := hex.EncodeToString(hash[:])

		var keyID, userID int
		var keyName, username, role string
		var mcpEnabled, readOnly bool
		var mcpIPWhitelist string
		err := db.DB.QueryRow(`
			SELECT k.id, k.name, u.id, u.username, u.role,
			       COALESCE(k.mcp_enabled,0), COALESCE(k.read_only,0), COALESCE(k.mcp_ip_whitelist,'')
			FROM api_keys k
			JOIN users u ON u.id = k.created_by
			WHERE k.key_prefix = ? AND k.key_hash = ?
			  AND k.is_enabled = 1
			  AND u.is_enabled = 1
			  AND (k.expires_at IS NULL OR datetime(k.expires_at) > datetime('now'))
		`, prefix, keyHash).Scan(&keyID, &keyName, &userID, &username, &role, &mcpEnabled, &readOnly, &mcpIPWhitelist)
		if err != nil {
			if hasJWTBearer(c) {
				c.Next()
				return
			}
			recordAuthenticationRejection(c, "api_key_invalid")
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "Invalid API key"})
			c.Abort()
			return
		}
		trustedInternalMCP := subtle.ConstantTimeCompare([]byte(c.GetHeader(mcpserver.InternalAuthHeader)), []byte(internalMCPAuthSecret)) == 1
		if mcpIPWhitelist != "" && !trustedInternalMCP {
			var whitelist []string
			if err := json.Unmarshal([]byte(mcpIPWhitelist), &whitelist); err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "API Key IP 白名单配置无效"})
				return
			}
			clientIP := net.ParseIP(c.ClientIP())
			allowed := false
			for _, cidr := range whitelist {
				_, network, err := net.ParseCIDR(cidr)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "API Key IP 白名单配置无效"})
					return
				}
				if network.Contains(clientIP) {
					allowed = true
					break
				}
			}
			if !allowed {
				recordAuthenticationRejection(c, "api_key_ip_denied")
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "来源 IP 不在白名单"})
				return
			}
		}

		db.MarkAPIKeyUsed(keyID)
		c.Set("user_id", userID)
		c.Set("username", username)
		c.Set("role", role)
		c.Set("auth_type", "api_key")
		c.Set("api_key_id", keyID)
		c.Set("api_key_name", keyName)
		c.Set("api_key_mcp_enabled", mcpEnabled)
		c.Set("api_key_read_only", readOnly)
		c.Set("api_key_mcp_ip_whitelist", mcpIPWhitelist)

		c.Next()
	}
}

func apiKeyReadOnlyGuard() gin.HandlerFunc {
	writeMethods := map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}
	return func(c *gin.Context) {
		if c.GetString("auth_type") != "api_key" || !c.GetBool("api_key_read_only") || !writeMethods[c.Request.Method] {
			c.Next()
			return
		}
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		if services.IsReadOnlyWriteRoute(c.Request.Method, path) {
			c.Next()
			return
		}
		recordAuthenticationRejection(c, "api_key_read_only")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "只读 API 密钥禁止写操作"})
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
			recordAuthenticationRejection(c, "admin_required")
			c.JSON(http.StatusForbidden, gin.H{"code": 403, "message": "Admin access required"})
			c.Abort()
			return
		}
		c.Next()
	}
}
