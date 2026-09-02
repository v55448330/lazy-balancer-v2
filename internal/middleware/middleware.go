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
	"strconv"
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

// mfaUserEnabledCheck：MFA 启用态查询的测试注入点（与 jwtAuthenticationQuery 同模式）——
// 第 15 轮审计 I-J 的 fail-closed 回归测试需要模拟「瞬时 DB 失败」，真实关闭 DB 会
// 连带让 jwtAuth 的会话校验先失败（401），无法单独触发守卫分支。
var mfaUserEnabledCheck = services.MFAUserEnabled

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

// auditClientIP 审计源 IP（第 15 轮审计 K-1）：内部 MCP 转发请求（本机回环
// 自调用）携带网关注入的真实客户端 IP 头；仅当内部认证密钥匹配（与
// apiKeyAuth 的 trustedInternalMCP 判定同口径）时采信，外部请求伪造该头不
// 产生任何效果，其余请求沿用 gin ClientIP。
func auditClientIP(c *gin.Context) string {
	if secret := c.GetHeader(mcpserver.InternalAuthHeader); secret != "" &&
		subtle.ConstantTimeCompare([]byte(secret), []byte(internalMCPAuthSecret)) == 1 {
		if clientIP := c.GetHeader(mcpserver.InternalClientIPHeader); clientIP != "" {
			return clientIP
		}
	}
	return c.ClientIP()
}

func recordAuthenticationRejection(c *gin.Context, reason string) {
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}
	ipAddress := auditClientIP(c)
	if !securityAuditLimiter.allow(reason+"\x00"+path+"\x00"+ipAddress, authenticationSecurityAuditNow()) {
		return
	}
	detail := services.FormatAuditDetail("路径："+path, "原因类别："+reason)
	recordAuthenticationSecurityAudit("system", "认证拒绝", "安全审计", detail, ipAddress)
}

type loginRateBucket struct {
	mu    sync.Mutex
	count int
	until time.Time
}

var loginRateBuckets = struct {
	sync.Mutex
	entries map[string]*loginRateBucket
}{entries: make(map[string]*loginRateBucket)}

func loginRateLimit() gin.HandlerFunc {
	const limit = 10
	return func(c *gin.Context) {
		now := time.Now()
		ip := c.ClientIP()

		loginRateBuckets.Lock()
		bucket, ok := loginRateBuckets.entries[ip]
		if !ok {
			bucket = &loginRateBucket{until: now.Add(time.Minute)}
			loginRateBuckets.entries[ip] = bucket
		}
		loginRateBuckets.Unlock()

		bucket.mu.Lock()
		if now.After(bucket.until) {
			bucket.count = 0
			bucket.until = now.Add(time.Minute)
		}
		bucket.count++
		exceeded := bucket.count > limit
		bucket.mu.Unlock()

		if exceeded {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"code": http.StatusTooManyRequests, "message": "登录尝试过于频繁，请稍后再试"})
			return
		}
		c.Next()
	}
}

var loginRateLimitCleanupOnce sync.Once

func startLoginRateLimitCleanup() {
	loginRateLimitCleanupOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				loginRateBuckets.Lock()
				for ip, bucket := range loginRateBuckets.entries {
					bucket.mu.Lock()
					if now.After(bucket.until) {
						delete(loginRateBuckets.entries, ip)
					}
					bucket.mu.Unlock()
				}
				loginRateBuckets.Unlock()
			}
		}()
	})
}

func SetupRouter(h *handlers.Handlers, cfg *config.Config) *gin.Engine {
	startLoginRateLimitCleanup()
	services.ApplyLogLevel()

	r := gin.New()
	r.SetTrustedProxies(nil)
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
					c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"code": http.StatusRequestEntityTooLarge, "message": "请求体过大"})
					return
				}
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"code": http.StatusBadRequest, "message": "请求体无效"})
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewReader(body))
			// 第 15 轮审计 K-1：把真实客户端 IP 注入 MCP 转发 context——内部
			// 转发是本机回环自调用，不注入则 MCP 操作的审计源 IP 恒为
			// 127.0.0.1（接收端 auditClientIP 凭内部认证密钥采信）。
			c.Request = c.Request.WithContext(mcpserver.WithClientIP(c.Request.Context(), c.ClientIP()))
			gin.WrapH(mcpHandler)(c)
		})
		v1.GET("/openapi.yaml", h.GetOpenAPIYAML)
		v1.GET("/docs", h.GetAPIDocs)
		v1.POST("/auth/login", loginRateLimit(), h.Login)
		v1.POST("/auth/ticket-login", loginRateLimit(), h.TicketLogin)
		v1.POST("/auth/mfa/verify", loginRateLimit(), h.MFAVerifyLogin)
		v1.GET("/auth/setup", loginRateLimit(), h.GetSetupStatus)
		v1.POST("/auth/setup", loginRateLimit(), h.SetupAdmin)
		v1.GET("/branding", h.GetBranding)
		v1.POST("/cluster/register", h.RegisterClusterNode)
		v1.GET("/cluster/register/:id/status", registrationAuth(db.DB), h.GetClusterRegistrationStatus)
		v1.GET("/cluster/sync/snapshot", clusterTokenAuth(db.DB), h.GetClusterSnapshot)
		v1.GET("/cluster/sync/waf-files", clusterTokenAuth(db.DB), h.GetClusterWafFiles)
		v1.POST("/cluster/registration/confirm", clusterTokenAuth(db.DB), h.ConfirmClusterRegistration)
		v1.POST("/cluster/nodes/report", clusterTokenAuth(db.DB), h.ReportClusterNode)
		// 从节点服务控制：票据即凭证（主节点签发的一次性 HMAC，与登录票据同
		// 机制），不走 clusterTokenAuth——主节点无法取回令牌明文（仅存哈希）。
		v1.POST("/cluster/service-control", h.ClusterServiceControl)

		v1.Use(apiKeyAuth(cfg))
		v1.Use(jwtAuth(cfg))
		v1.Use(apiKeyReadOnlyGuard())
		v1.Use(mfaStepUpGuard())
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
				admin.POST("/users/:id/mfa/reset", h.MFAResetByAdmin)

				// R72 二十六次 W1-3：管理语义端点收紧至 admin 组——服务重启/管理面板
				// TLS/原始 Caddy 配置覆写/Caddy 进程启停均为管理员级操作；此前挂在
				// business 组（仅 readOnlyGuard），apidocs 承诺的 403 admin_required
				// 实际不存在（PutCaddyConfig/StartCaddy/RestartService/UpdateAdminTLS
				// handler 内部均无角色检查）。读取类端点（GET/inspect）保留 business。
				admin.PUT("/admin-tls", h.UpdateAdminTLS)
				admin.POST("/system/restart", h.RestartService)
				admin.PUT("/caddy/config", h.PutCaddyConfig)
				admin.POST("/caddy/start", h.StartCaddy)
				admin.POST("/caddy/stop", h.StopCaddy)
				admin.POST("/caddy/restart", h.RestartCaddy)

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
				admin.POST("/cluster/nodes/:id/service", h.ControlClusterNodeService)
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
				admin.PUT("/security/rules/:caddy_id/policies", h.SetRuleSecurityPolicies)
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
				admin.POST("/security/ip-lists", h.CreateIPList)
				admin.PUT("/security/ip-lists/:id", h.UpdateIPList)
				admin.DELETE("/security/ip-lists/:id", h.DeleteIPList)
				admin.POST("/security/ip-lists/:id/ips", h.AddIPToList)

			}

			// User + Admin
			business := v1.Group("")
			business.Use(readOnlyGuard(db.DB))
			{
				// Current user (self)
				business.GET("/users/me", h.GetCurrentUser)
				business.PATCH("/users/me", h.UpdateCurrentUser)
				// v2.1.8 MFA 自助端点（JWT 用户）
				business.GET("/auth/mfa/status", h.MFAStatus)
				business.POST("/auth/mfa/setup", h.MFASetup)
				business.POST("/auth/mfa/activate", h.MFAActivate)
				business.POST("/auth/mfa/disable", h.MFADisable)
				business.POST("/auth/mfa/recovery-codes", h.MFARecoveryCodes)
				business.POST("/auth/mfa/verify-step", h.MFAVerifyStep)
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
				business.GET("/logs/stats", h.GetLogStats)
				business.GET("/rules/:caddy_id/cert-info", h.GetRuleCertInfo)
				business.POST("/rules/cert-info", h.GetRulesCertInfo)
				business.POST("/rules", h.CreateRule)
				business.PUT("/rules/:caddy_id", h.UpdateRule)
				business.DELETE("/rules/:caddy_id", h.DeleteRule)
				business.POST("/rules/:caddy_id/enable", h.EnableRule)
				business.POST("/rules/:caddy_id/disable", h.DisableRule)
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
				business.GET("/security/ip-lists", h.ListIPLists)
				business.GET("/security/crs/rules", h.ListCRSRules)
				business.GET("/security/crs/rule-index", h.GetCRSRuleIndex)
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
				business.POST("/admin-tls/inspect", h.InspectAdminTLSCert)
				business.GET("/system/metrics", h.GetSystemMetrics)
				business.GET("/system/logs", h.GetAppLogs)

				// Caddy
				business.GET("/caddy/status", h.GetCaddyStatus)
				business.GET("/caddy/config", h.GetCaddyConfig)
				business.GET("/caddy/logs", h.GetCaddyLogs)
				business.GET("/caddy/host-metrics", h.GetHostMetrics)

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
				business.GET("/audit-logs/options", h.GetAuditLogOptions)
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

		services.RecordAuditLog(usernameStr, action, resource, detail, auditClientIP(c))
	}
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if origin := c.Request.Header.Get("Origin"); origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
		}
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
			// 第 15 轮审计 S-2：过期与无效分判——过期是自然态（重登即可），签名
			// 无效/格式损坏是凭证问题；旧代码两类同发「登录状态已过期」，把无效
			// 凭证误导成「重新登录就能好」。401 状态码不变，仅消息分语义。
			if errors.Is(err, jwt.ErrTokenExpired) {
				recordAuthenticationRejection(c, "jwt_expired")
				c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录状态已过期，请重新登录"})
			} else {
				recordAuthenticationRejection(c, "jwt_invalid")
				c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "登录凭证无效"})
			}
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
		// R72 B-1：JWT 成功路径补 auth_type——全仓此前只有 apiKeyAuth 设置该值，
		// mfaStepUpGuard 的 != "jwt" 对 JWT 用户恒真（守卫整体死代码）。
		c.Set("auth_type", "jwt")
		// v2.1.8 MFA step-up：mfa_ts 声明透传（无声明=0，guard 视为过期）
		if ts, ok := claims["mfa_ts"].(float64); ok {
			c.Set("mfa_ts", ts)
		}

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
			// 第 15 轮审计 K-2：MCP/Key 认证链的通用 401 消息此前为英文
			// "Invalid API key"，与本认证链其余消息（缺少认证信息/认证格式无效/
			// 登录状态已过期等）及 serverInstructions 的中文错误约定不一致——
			// Agent 与前端按中文解析。
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "API 密钥无效"})
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
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "API 密钥无效"})
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

// mfaStepUpGuard v2.1.8：MFA 写操作验证（全局开关，默认关；R72 五次：60 秒窗）。开启时，启用 MFA
// 的 JWT 用户执行写操作（readOnlyWriteRoutes 判定源——与只读密钥同一事实源，契约
// 绊线自动覆盖两侧）且 mfa_ts 距今超过 10 分钟 → 428，前端全局弹码验证后携新
// JWT 重试。API Key/MCP 认证豁免（机器身份无 MFA 概念）。
func mfaStepUpGuard() gin.HandlerFunc {
	writeMethods := map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}
	return func(c *gin.Context) {
		if !writeMethods[c.Request.Method] || c.GetString("auth_type") != "jwt" {
			c.Next()
			return
		}
		if !services.MFAWriteGuardEnabled() {
			c.Next()
			return
		}
		// R72 C-I-1：step-up 机制本体必须永可达——豁免 verify-step 自身（POST，
		// 位于本守卫之下），否则守卫生效后「弹码→verify-step→再 428」无限循环，
		// 全员写操作死锁；/auth/logout 同理（登出不该要求验证码）。
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		if path == "/api/v1/auth/mfa/verify-step" || path == "/api/v1/auth/logout" {
			c.Next()
			return
		}
		// R72 十六次（用户反馈）：豁免只读语义 POST（readOnlyWriteRoutes——批量
		// 证书状态查询 cert-info/jobs/current、测试连接、预览/解析等）——它们
		// 用 POST 承载查询/预览载荷，语义是读，不该触发 step-up（用户打开规则
		// 列表页就被弹码）。与只读 API Key 的写操作判定同一事实源。
		if services.IsReadOnlyWriteRoute(c.Request.Method, path) {
			c.Next()
			return
		}
		// R72 B-1（缺陷二）：jwtAuth 将 user_id 以 float64 存入（JWT JSON 数字），
		// gin GetString 对非 string 断言失败恒返回 ""——改类型化取值（与
		// getContextUserIDInt 同口径）。
		var userID int
		switch v := c.MustGet("user_id").(type) {
		case float64:
			userID = int(v)
		case int:
			userID = v
		case int64:
			userID = int(v)
		case string:
			parsed, err := strconv.Atoi(v)
			if err != nil {
				c.Next()
				return
			}
			userID = parsed
		default:
			c.Next()
			return
		}
		// 第 15 轮审计 I-J（R72 C-I-3）：DB 错误与「MFA 未启用」必须分判——未启用
		// 是合理直通（该用户未启用 MFA，守卫不适用）；DB 错误必须 fail-closed
		// （与本文件同类守卫的基建错误 500 中止同口径，如 apiKeyAuth 的白名单
		// 解析失败）：瞬时 DB 失败落穿此处会让已启用 MFA 的用户整体绕过
		// step-up（fail-open），等同二因子静默旁路。
		mfaEnabled, err := mfaUserEnabledCheck(userID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "MFA 状态查询失败"})
			return
		}
		if !mfaEnabled {
			c.Next()
			return
		}
		// R72 五次（用户裁决：开关开启后立即生效）：宽限窗 10 分钟 → 60 秒。
		// 不能是 0——TOTP 码以 30 秒时间片为单位且重放防护拒绝同片重用：零窗
		// 口意味着每个写操作都必须是不同的时间片（两次写操作间隔 <30s 时第二
		// 次无码可用，必须干等下一片），向导多步连存等流程不可用。60 秒窗的
		// 语义：距上次 MFA 验证超过 1 分钟的写操作都要求验码（「立即生效」的
		// 观感），紧邻的连续操作（428→弹码→重试→顺手再存一步）不重复骚扰。
		mfaTs := c.GetFloat64("mfa_ts")
		if elapsed := time.Since(time.Unix(int64(mfaTs), 0)); mfaTs > 0 && elapsed < 60*time.Second {
			// R72 八次（用户裁决）：宽限窗内静默放行时告知用户——响应头携带距上次
			// 验证的秒数（TOTP 同片不可重用，窗口内的操作没有可用码也照常执行），
			// 前端据此提示「xx 秒内已验证，本次无需验证」。
			c.Header("X-Mfa-Verified-Seconds-Ago", strconv.FormatInt(int64(elapsed.Seconds()), 10))
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusPreconditionRequired, gin.H{"code": 428, "message": "MFA_STEP_UP_REQUIRED", "detail": "此操作需要 MFA 验证"})
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
			c.JSON(http.StatusForbidden, gin.H{"code": 403, "message": "需要管理员权限"})
			c.Abort()
			return
		}
		c.Next()
	}
}
