package handlers

// OIDC 集成(2026-09-17 v2.3.0,用户裁定方案):
//   · 单提供商,4 项配置(issuer/client_id/client_secret/enabled)——端点经
//     OIDC Discovery 自动获取,用户零高级配置
//   · OIDC 用户不绑定本地账号:每次首登独立 JIT 开户(auth_provider='oidc',
//     默认普通角色),重复登录按 (issuer, subject) 命中
//   · 双通道保底:OIDC 启用时本地账号永远可登(登录框默认 OIDC+折叠本地)
//   · 写保护矩阵:绑本地 MFA→TOTP 弹码;未绑 OIDC 会话→IdP 重新认证
//     (prompt=login,回调刷新 mfa_ts);锁定仅密码路径(OIDC 失败不计入,
//     防「伪造回调锁死账号」DoS)
//   · 登录从节点:保持本地 MFA 硬门槛(选项 A)
//   · 配置随 global_config 集群快照自动同步;从节点回调独立闭环→只读 JWT

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// OIDCConfig 存 global_config.oidc_config(JSON 列)。
type OIDCConfig struct {
	Enabled      bool   `json:"enabled"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	DisplayName  string `json:"display_name"`
}

// oidcStateEntry 登录跳转与回调之间的一次性状态(state 防 CSRF,nonce 防
// 重放,PKCE verifier 防授权码拦截;reauth=prompt=login 的 IdP 重认证请求)。
type oidcStateEntry struct {
	nonce    string
	verifier string
	returnTo string
	created  time.Time
}

var (
	oidcStates   sync.Map // state -> oidcStateEntry
	oidcProvMu   sync.Mutex
	oidcProvCach = map[string]*oidc.Provider{} // issuer -> provider(discovery 产物)
)

const oidcStateTTL = 10 * time.Minute

// ── 配置读写 ──

func loadOIDCConfig() (OIDCConfig, bool) {
	var raw string
	if err := db.DB.QueryRow("SELECT COALESCE(oidc_config,'') FROM global_config WHERE id=1").Scan(&raw); err != nil || raw == "" {
		return OIDCConfig{}, false
	}
	var cfg OIDCConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return OIDCConfig{}, false
	}
	return cfg, true
}

func saveOIDCConfig(cfg OIDCConfig) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = db.DB.Exec("UPDATE global_config SET oidc_config=? WHERE id=1", string(raw))
	return err
}

// oidcProvider 按 issuer 获取(带缓存的 discovery)。
// normalizeOIDCIssuer 通用规范化(2026-09-17):去尾斜杠;对 login.microsoftonline.com
// (Microsoft Entra)自动补 /v2.0——v1 端点无 OIDC 发现文档,漏写是最高频配置错误;
// 其他提供商逐字保留。以标准 OIDC 为准,不针对特定厂商做分支逻辑。
func normalizeOIDCIssuer(raw string) string {
	issuer := strings.TrimRight(strings.TrimSpace(raw), "/")
	if u, err := url.Parse(issuer); err == nil && u.Host == "login.microsoftonline.com" && !strings.HasSuffix(issuer, "/v2.0") {
		issuer += "/v2.0"
	}
	return issuer
}

func oidcProvider(issuer string) (*oidc.Provider, error) {
	oidcProvMu.Lock()
	defer oidcProvMu.Unlock()
	if p, ok := oidcProvCach[issuer]; ok {
		return p, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC 发现失败(检查服务地址可达性与 .well-known 配置): %w", err)
	}
	oidcProvCach[issuer] = p
	return p, nil
}

func oidcProviderInvalidate(issuer string) {
	oidcProvMu.Lock()
	delete(oidcProvCach, issuer)
	oidcProvMu.Unlock()
}

func oidcOAuthConfig(cfg OIDCConfig, p *oidc.Provider, callbackURL string) oauth2.Config {
	return oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  callbackURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

// ── 公开端点 ──

// OIDCStatus GET /auth/oidc/status(公开):登录页按钮显隐与展示名。
func (h *Handlers) OIDCStatus(c *gin.Context) {
	cfg, ok := loadOIDCConfig()
	if !ok || !cfg.Enabled || cfg.Issuer == "" {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"enabled": false}})
		return
	}
	name := cfg.DisplayName
	if name == "" {
		if u, err := url.Parse(cfg.Issuer); err == nil {
			name = u.Host
		} else {
			name = "OIDC"
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"enabled": true, "display_name": name}})
}

// requestOrigin 推导回调基址(反向代理场景尊重 X-Forwarded-Proto/Host)。
func requestOrigin(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	host := c.GetHeader("X-Forwarded-Host")
	if host == "" {
		host = c.Request.Host
	}
	return scheme + "://" + host
}

func oidcCallbackURL(c *gin.Context) string {
	return requestOrigin(c) + "/api/v1/auth/oidc/callback"
}

// OIDCLogin GET /auth/oidc/login?prompt=login&return_to=...
// 生成 state/nonce/PKCE 后跳转提供商授权页。prompt=login 用于写保护的
// IdP 重新认证(强制重登,回调侧刷新 mfa_ts)。
func (h *Handlers) OIDCLogin(c *gin.Context) {
	cfg, ok := loadOIDCConfig()
	if !ok || !cfg.Enabled || cfg.Issuer == "" {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "OIDC 未启用"})
		return
	}
	p, err := oidcProvider(cfg.Issuer)
	if err != nil {
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: err.Error()})
		return
	}
	stateRaw := make([]byte, 16)
	nonceRaw := make([]byte, 16)
	verifierRaw := make([]byte, 32)
	if _, err := rand.Read(stateRaw); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成状态失败"})
		return
	}
	if _, err := rand.Read(nonceRaw); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成 nonce 失败"})
		return
	}
	if _, err := rand.Read(verifierRaw); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成 PKCE 失败"})
		return
	}
	state := hex.EncodeToString(stateRaw)
	nonce := hex.EncodeToString(nonceRaw)
	verifier := oauth2.GenerateVerifier()
	returnTo := c.Query("return_to")
	if returnTo != "" && !strings.HasPrefix(returnTo, "/") {
		returnTo = "" // 仅允许站内相对路径,防开放重定向
	}
	oidcStates.Store(state, oidcStateEntry{nonce: nonce, verifier: verifier, returnTo: returnTo, created: time.Now()})
	// 顺手清理过期状态(单机内存态,量级=未完成登录数,遍历可忽略)
	oidcStates.Range(func(k, v any) bool {
		if e, ok := v.(oidcStateEntry); ok && time.Since(e.created) > oidcStateTTL {
			oidcStates.Delete(k)
		}
		return true
	})

	oauthCfg := oidcOAuthConfig(cfg, p, oidcCallbackURL(c))
	authURL := oauthCfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	c.Redirect(http.StatusFound, authURL)
}

// OIDCCallback GET /auth/oidc/callback——授权码换令牌→ID Token 验签→
// 用户命中/禁用检查/JIT 开户→签发本站 JWT(与密码登录同构,auth_method=oidc)。
func (h *Handlers) OIDCCallback(c *gin.Context) {
	cfg, ok := loadOIDCConfig()
	if !ok || !cfg.Enabled || cfg.Issuer == "" {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "OIDC 未启用"})
		return
	}
	fail := func(status int, msg, auditDetail string) {
		if auditDetail != "" {
			services.RecordAuditLog(c.Query("state")[:0]+"oidc-user", "认证拒绝", "用户认证", services.FormatAuditDetail(auditDetail, services.AuditResultPart("failure")), c.ClientIP())
		}
		c.JSON(status, models.APIResponse{Code: status, Message: msg})
	}
	stateEntryRaw, ok := oidcStates.LoadAndDelete(c.Query("state"))
	if !ok {
		fail(http.StatusBadRequest, "登录状态无效或已过期,请重新登录", "")
		return
	}
	entry := stateEntryRaw.(oidcStateEntry)
	if time.Since(entry.created) > oidcStateTTL {
		fail(http.StatusBadRequest, "登录状态已过期,请重新登录", "")
		return
	}
	if errParam := c.Query("error"); errParam != "" {
		fail(http.StatusUnauthorized, "提供商拒绝授权: "+errParam+" "+c.Query("error_description"), "OIDC 提供商拒绝授权")
		return
	}
	p, err := oidcProvider(cfg.Issuer)
	if err != nil {
		fail(http.StatusBadGateway, err.Error(), "")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	oauthCfg := oidcOAuthConfig(cfg, p, oidcCallbackURL(c))
	oauth2Token, err := oauthCfg.Exchange(ctx, c.Query("code"),
		oauth2.SetAuthURLParam("code_verifier", entry.verifier))
	if err != nil {
		fail(http.StatusBadGateway, "令牌交换失败: "+err.Error(), "OIDC 令牌交换失败")
		return
	}
	rawIDToken, _ := oauth2Token.Extra("id_token").(string)
	if rawIDToken == "" {
		fail(http.StatusBadGateway, "提供商未返回 id_token", "OIDC 缺少 id_token")
		return
	}
	verifier := p.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		fail(http.StatusUnauthorized, "ID Token 校验失败: "+err.Error(), "OIDC id_token 校验失败")
		return
	}
	var claims struct {
		Sub               string `json:"sub"`
		Nonce             string `json:"nonce"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		fail(http.StatusBadGateway, "解析用户信息失败", "OIDC claims 解析失败")
		return
	}
	if claims.Nonce != entry.nonce {
		fail(http.StatusUnauthorized, "nonce 不匹配(疑似重放)", "OIDC nonce 不匹配")
		return
	}

	// 用户命中:OIDC 用户独立行(不绑定本地账号),按 (issuer, subject) 定位。
	var userID int
	var username, role string
	var isEnabled int
	err = db.DB.QueryRow("SELECT id, username, role, COALESCE(is_enabled,1) FROM users WHERE auth_provider='oidc' AND oidc_issuer=? AND oidc_subject=?", cfg.Issuer, claims.Sub).
		Scan(&userID, &username, &role, &isEnabled)
	switch {
	case errors.Is(err, nil):
		if isEnabled != 1 {
			services.RecordAuditLog(username, "登录失败", "用户认证", services.FormatAuditDetail("OIDC 登录(账号已禁用)", services.AuditResultPart("failure")), c.ClientIP())
			fail(http.StatusForbidden, "账号已被禁用", "")
			return
		}
	case errors.Is(err, sql.ErrNoRows):
		// JIT 开户:默认普通角色;用户名取 preferred_username→email 本地部分→sub,
		// 冲突时后缀去重(不绑定本地账号,同名共存)。
		base := claims.PreferredUsername
		if base == "" && claims.Email != "" {
			base = strings.SplitN(claims.Email, "@", 2)[0]
		}
		if base == "" {
			base = "oidc-" + claims.Sub
		}
		base = strings.TrimSpace(base)
		if len(base) > 50 {
			base = base[:50]
		}
		displayName := claims.Name
		if displayName == "" {
			displayName = base
		}
		candidate := base
		for i := 2; ; i++ {
			var exists int
			if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username=?", candidate).Scan(&exists); err != nil {
				fail(http.StatusInternalServerError, "查询用户失败", "")
				return
			}
			if exists == 0 {
				break
			}
			suffix := fmt.Sprintf("-%d", i)
			if len(base)+len(suffix) > 50 {
				candidate = base[:50-len(suffix)] + suffix
			} else {
				candidate = base + suffix
			}
		}
		// password_hash 置空:bcrypt 对空哈希恒败,OIDC 用户密码登录天然不可用。
		res, err := db.DB.Exec("INSERT INTO users (username, password_hash, role, display_name, is_enabled, auth_provider, oidc_subject, oidc_issuer) VALUES (?, '', 'user', ?, 1, 'oidc', ?, ?)",
			candidate, displayName, claims.Sub, cfg.Issuer)
		if err != nil {
			fail(http.StatusInternalServerError, "创建 OIDC 用户失败", "OIDC JIT 开户失败")
			return
		}
		newID, _ := res.LastInsertId()
		userID = int(newID)
		username = candidate
		role = "user"
		services.RecordAuditLog(username, "创建", "用户认证", services.FormatAuditDetail(fmt.Sprintf("OIDC 首次登录自动开户(%s)", cfg.Issuer), services.AuditResultPart("success")), c.ClientIP())
	default:
		fail(http.StatusInternalServerError, "查询用户失败", "")
		return
	}

	// 签发本站 JWT(与密码登录同构;auth_method=oidc 标记会话来源——本地
	// MFA 族功能对 OIDC 用户整体豁免,v2.3.0 用户裁定)。
	token, expiresAt, err := h.issueOIDCJWT(userID, username, role, 0)
	if err != nil {
		fail(http.StatusInternalServerError, "签发登录令牌失败", "")
		return
	}
	services.RecordAuditLog(username, "登录成功", "用户认证", services.FormatAuditDetail("OIDC 登录", services.AuditResultPart("success")), c.ClientIP())
	_, _ = db.DB.Exec("UPDATE users SET last_login=datetime('now') WHERE id=?", userID)

	// 回跳前端:令牌走 URL fragment(不发给服务器),前端路由接收后入会话。
	returnTo := entry.returnTo
	if returnTo == "" {
		returnTo = "/"
	}
	front := requestOrigin(c)
	c.Redirect(http.StatusFound, front+"/#/oidc/callback?token="+url.QueryEscape(token)+"&expires_at="+fmt.Sprintf("%d", expiresAt.Unix())+"&return_to="+url.QueryEscape(returnTo))
}

// issueOIDCJWT 与密码登录的令牌同构(auth.go:198 口径),附加 auth_method=oidc。
func (h *Handlers) issueOIDCJWT(userID int, username, role string, mfaTs float64) (string, time.Time, error) {
	expireMinutes := 720
	if err := db.DB.QueryRow("SELECT COALESCE(jwt_expire_minutes,20) FROM global_config WHERE id=1").Scan(&expireMinutes); err != nil || expireMinutes <= 0 || expireMinutes > 1440 {
		expireMinutes = 20
	}
	now := time.Now()
	jtiBytes := make([]byte, 32)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", time.Time{}, err
	}
	nodeMode := "master"
	if h.clusterService != nil {
		if isMaster, err := h.clusterService.IsMaster(context.Background()); err == nil && !isMaster {
			nodeMode = "slave"
		}
	} else {
		// 单测路径(无集群服务注入):直读全局 is_master,缺省主节点
		var isMasterVal int
		_ = db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMasterVal)
		if isMasterVal == 0 {
			nodeMode = "slave"
		}
	}
	tokenClaims := map[string]interface{}{
		"user_id":     userID,
		"username":    username,
		"role":        role,
		"node_mode":   nodeMode,
		"auth_method": "oidc",
		"jti":         hex.EncodeToString(jtiBytes),
		"iat":         now.Unix(),
		"exp":         now.Add(time.Duration(expireMinutes) * time.Minute).Unix(),
	}
	if mfaTs > 0 {
		tokenClaims["mfa_ts"] = mfaTs
	}
	b, _ := json.Marshal(tokenClaims)
	var cm jwt.MapClaims
	_ = json.Unmarshal(b, &cm)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cm)
	tokenString, err := token.SignedString([]byte(h.cfg.JWTSecret))
	if err != nil {
		return "", time.Time{}, err
	}
	return tokenString, now.Add(time.Duration(expireMinutes) * time.Minute), nil
}

// ── 管理端点(显示/测试/修改/删除) ──

// OIDCSettings GET /settings/oidc(admin)——secret 掩码返回。
func (h *Handlers) OIDCSettings(c *gin.Context) {
	cfg, _ := loadOIDCConfig()
	masked := cfg.ClientSecret
	if masked != "" {
		if len(masked) > 4 {
			masked = masked[:2] + "****" + masked[len(masked)-2:]
		} else {
			masked = "****"
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"enabled": cfg.Enabled, "issuer": cfg.Issuer, "client_id": cfg.ClientID,
		"client_secret_masked": masked, "has_secret": cfg.ClientSecret != "",
		"display_name":  cfg.DisplayName,
		"callback_hint": "/api/v1/auth/oidc/callback",
	}})
}

// OIDCSettingsUpdate PUT /settings/oidc(admin)。
// 空 client_secret=保持现值(掩码回显不应逼用户重填)。
func (h *Handlers) OIDCSettingsUpdate(c *gin.Context) {
	var req struct {
		Enabled      *bool   `json:"enabled"`
		Issuer       *string `json:"issuer"`
		ClientID     *string `json:"client_id"`
		ClientSecret *string `json:"client_secret"`
		DisplayName  *string `json:"display_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	cfg, _ := loadOIDCConfig()
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}
	if req.Issuer != nil {
		issuer := normalizeOIDCIssuer(*req.Issuer)
		if *req.Issuer != "" && (issuer == "" || !strings.HasPrefix(issuer, "http")) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "服务地址须为 http(s) URL"})
			return
		}
		if issuer != cfg.Issuer {
			oidcProviderInvalidate(cfg.Issuer)
		}
		cfg.Issuer = issuer
	}
	if req.ClientID != nil {
		cfg.ClientID = strings.TrimSpace(*req.ClientID)
	}
	if req.ClientSecret != nil && *req.ClientSecret != "" {
		cfg.ClientSecret = strings.TrimSpace(*req.ClientSecret)
	}
	if req.DisplayName != nil {
		cfg.DisplayName = strings.TrimSpace(*req.DisplayName)
	}
	// 启用前置门:issuer+client_id+secret 三者齐备才允许 enabled=true。
	if cfg.Enabled && (cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "") {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "启用前需完整配置服务地址、Client ID 与 Client Secret"})
		return
	}
	if err := saveOIDCConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 OIDC 配置失败"})
		return
	}
	recordAudit(c, "更新", "OIDC 配置", services.FormatAuditDetail("认证集成", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "OIDC 配置已保存"})
}

// OIDCSettingsTest POST /settings/oidc/test(admin)——完整发现+JWKS 探测。
func (h *Handlers) OIDCSettingsTest(c *gin.Context) {
	var req struct {
		Issuer      string `json:"issuer"`
		DiscoveryOK bool   `json:"-"`
	}
	_ = c.ShouldBindJSON(&req)
	issuer := normalizeOIDCIssuer(req.Issuer)
	if issuer == "" {
		cfg, _ := loadOIDCConfig()
		issuer = cfg.Issuer
	}
	if issuer == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请提供服务地址"})
		return
	}
	oidcProviderInvalidate(issuer) // 测试总是新鲜发现,不喂缓存
	p, err := oidcProvider(issuer)
	if err != nil {
		recordAudit(c, "测试失败", "OIDC 配置", services.FormatAuditDetail(issuer, services.AuditResultPart("failure")))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"ok": false, "error": err.Error()}})
		return
	}
	// JWKS 可达性:验证器远端密钥拉取(一次签验失败即证可达性/格式)。
	var providerClaims struct {
		Issuer string   `json:"issuer"`
		Name   string   `json:"name"`
		Scopes []string `json:"scopes_supported"`
	}
	_ = p.Claims(&providerClaims)
	name := providerClaims.Name
	if name == "" {
		if u, err := url.Parse(issuer); err == nil {
			name = u.Host
		}
	}
	recordAudit(c, "测试成功", "OIDC 配置", services.FormatAuditDetail(fmt.Sprintf("%s(%s)", name, issuer), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"ok": true, "issuer": providerClaims.Issuer, "provider_name": name,
		"authorization_endpoint": p.Endpoint().AuthURL,
		"token_endpoint":         p.Endpoint().TokenURL,
		"scopes":                 providerClaims.Scopes,
	}})
}

// OIDCSettingsDelete DELETE /settings/oidc(admin)——清空配置(等效禁用+抹除)。
func (h *Handlers) OIDCSettingsDelete(c *gin.Context) {
	cfg, _ := loadOIDCConfig()
	oidcProviderInvalidate(cfg.Issuer)
	if err := saveOIDCConfig(OIDCConfig{}); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除 OIDC 配置失败"})
		return
	}
	recordAudit(c, "删除", "OIDC 配置", services.FormatAuditDetail("认证集成", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "OIDC 配置已删除"})
}
