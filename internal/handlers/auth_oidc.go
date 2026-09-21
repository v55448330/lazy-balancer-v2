package handlers

// OIDC 集成(2026-09-17 v2.3.0,用户裁定方案):
//   · 单提供商,4 项配置(issuer/client_id/client_secret/enabled)——端点经
//     OIDC Discovery 自动获取,用户零高级配置
//   · OIDC 用户不绑定本地账号:每次首登独立 JIT 开户(auth_provider='oidc',
//     默认普通角色),重复登录按 (issuer, subject) 命中
//   · 写保护矩阵:绑本地 MFA→TOTP 弹码;OIDC 会话(auth_method=oidc)与本地
//     MFA 体系完全解耦,经 mfaStepUpGuard 显式直通(v2.3.0 用户裁定);
//     锁定仅密码路径(OIDC 失败不计入,防「伪造回调锁死账号」DoS)
//   · 配置随 global_config 集群快照自动同步;从节点回调独立闭环→只读 JWT

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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
// 重放,PKCE verifier 防授权码拦截)。
type oidcStateEntry struct {
	nonce    string
	verifier string
	returnTo string
	created  time.Time
}

var (
	oidcStates   sync.Map // state -> oidcStateEntry
	oidcProvMu   sync.Mutex
	oidcProvCach = map[string]oidcProvEntry{} // issuer -> discovery 产物(含短 TTL 负缓存)
	// oidcStateCount 在册 state 条目计数(R39-3:未认证泛洪封顶,计数与
	// Store/Delete/TTL 清理同点维护)
	oidcStateCount atomic.Int32
)

// oidcProvEntry:成功缓存 provider;失败缓存 err+failedAt(负缓存,短 TTL——
// R39-4:IdP 故障时不逐请求回源放大,恢复后 5s 内自动重试)。
type oidcProvEntry struct {
	provider *oidc.Provider
	err      error
	failedAt time.Time
}

const (
	oidcStateTTL    = 10 * time.Minute
	oidcNegCacheTTL = 5 * time.Second // discovery 失败负缓存 TTL
)

// oidcStateMaxEntries 在册 state 条目上限(R39-3:未认证泛洪内存封顶;
// var 供测试收窄)。
var oidcStateMaxEntries = 4096

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

// oidcProvider 按 issuer 获取(带缓存的 discovery;R39-4:网络发现移出全局锁,
// 失败负缓存 oidcNegCacheTTL——IdP 故障时不再持锁串行 8s 逐请求回源)。
func oidcProvider(issuer string) (*oidc.Provider, error) {
	oidcProvMu.Lock()
	e, ok := oidcProvCach[issuer]
	oidcProvMu.Unlock()
	if ok {
		if e.provider != nil {
			return e.provider, nil
		}
		if time.Since(e.failedAt) < oidcNegCacheTTL {
			return nil, e.err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, issuer)
	oidcProvMu.Lock()
	if err != nil {
		werr := fmt.Errorf("OIDC 发现失败(检查服务地址可达性与 .well-known 配置): %w", err)
		oidcProvCach[issuer] = oidcProvEntry{err: werr, failedAt: time.Now()}
		oidcProvMu.Unlock()
		return nil, werr
	}
	oidcProvCach[issuer] = oidcProvEntry{provider: p}
	oidcProvMu.Unlock()
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

// trustedProxyRemoteAddr(APIMCP41-5,第 41 轮审计,2026-09-19 用户裁定按建议收窄):
// 仅当直连对端为回环/私网(RFC1918+ULA+链路本地,即可信反代)时才采信
// X-Forwarded-Proto/Host。解析失败(畸形/空)一律 false——宁可回退请求自身
// 基址也不采信可疑来源。
func trustedProxyRemoteAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr // 容忍无端口形态(测试构造/非 TCP  listener)
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// requestOrigin 推导回调基址(反向代理场景尊重 X-Forwarded-Proto/Host)。
// APIMCP41-5:转发头仅当直连对端可信时采信——路由器 SetTrustedProxies(nil)
// 意味着任何公网客户端都能伪造 X-Forwarded-Host,无来源校验会把回调
// redirect_uri 与成功回跳基址(令牌走 fragment)指向攻击者域。
func requestOrigin(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	host := c.Request.Host
	if trustedProxyRemoteAddr(c.Request.RemoteAddr) {
		if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		}
		if fwdHost := c.GetHeader("X-Forwarded-Host"); fwdHost != "" {
			host = fwdHost
		}
	}
	return scheme + "://" + host
}

func oidcCallbackURL(c *gin.Context) string {
	return requestOrigin(c) + "/api/v1/auth/oidc/callback"
}

// oidcStandardErrorCodes OAuth2/OIDC 规范错误码全集(RFC 6749 §5.2 + OIDC
// Core §3.1.2.6)——回调 error 参数白名单。
var oidcStandardErrorCodes = map[string]struct{}{
	"invalid_request":            {},
	"unauthorized_client":        {},
	"access_denied":              {},
	"unsupported_response_type":  {},
	"invalid_scope":              {},
	"server_error":               {},
	"temporarily_unavailable":    {},
	"interaction_required":       {},
	"login_required":             {},
	"account_selection_required": {},
	"consent_required":           {},
	"invalid_request_uri":        {},
	"invalid_request_object":     {},
	"invalid_client":             {},
	"invalid_grant":              {},
	"unsupported_grant_type":     {},
	"unsupported_token_type":     {},
	"expired_token":              {},
}

// sanitizeOIDCErrorParam(A40-1-4):回调 error 参数仅放行标准错误码(大小写
// 不敏感,保留原形回显);超长或非白名单值返回空串——外部可控文本不得经
// 前端错误页当系统提示渲染。
func sanitizeOIDCErrorParam(raw string) string {
	code := strings.TrimSpace(raw)
	if len(code) > 64 {
		return ""
	}
	if _, ok := oidcStandardErrorCodes[strings.ToLower(code)]; !ok {
		return ""
	}
	return code
}

// OIDCLogin GET /auth/oidc/login?return_to=...
// 生成 state/nonce/PKCE 后跳转提供商授权页。
func (h *Handlers) OIDCLogin(c *gin.Context) {
	// A40-1-2:login 是浏览器整页导航(登录页按钮/链接触发)——失败一律 302
	// 回前端登录页错误位(oidc_error 经 URL fragment 携带,不发给服务器),
	// 与回调 C2-7 同型,不渲染裸 JSON。
	fail := func(msg string) {
		c.Redirect(http.StatusFound, requestOrigin(c)+"/#/login?oidc_error="+url.QueryEscape(msg))
	}
	cfg, ok := loadOIDCConfig()
	if !ok || !cfg.Enabled || cfg.Issuer == "" {
		fail("OIDC 未启用")
		return
	}
	// 过期清理先行(R39-3 P1 复审修正):封顶判定必须在自愈清理之后——
	// 否则死条目(未被回调消费的过期 state)永无清理机会,4096 次未完成
	// 登录即可把 OIDC 登录永久 429 直至重启(防护自身被武器化)。
	oidcStates.Range(func(k, v any) bool {
		if e, ok := v.(oidcStateEntry); ok && time.Since(e.created) > oidcStateTTL {
			// SEC-1:LoadAndDelete 原子扣减——与回调消费方竞争同键时恰好一个
			// 赢家,计数不向负漂移(封顶判定因此不被侵蚀)。
			if _, loaded := oidcStates.LoadAndDelete(k); loaded {
				oidcStateCount.Add(-1)
			}
		}
		return true
	})
	// R39-3:在册 state 条目封顶——未认证泛洪不得无限放大内存(上限远高于
	// 正常未完成登录量级;到达即拒绝,不影响「回调失败不计锁定」裁定)。
	if oidcStateCount.Load() >= int32(oidcStateMaxEntries) {
		fail("登录请求过于频繁，请稍后再试")
		return
	}
	p, err := oidcProvider(cfg.Issuer)
	if err != nil {
		fail(err.Error())
		return
	}
	stateRaw := make([]byte, 16)
	nonceRaw := make([]byte, 16)
	verifierRaw := make([]byte, 32)
	if _, err := rand.Read(stateRaw); err != nil {
		fail("生成状态失败")
		return
	}
	if _, err := rand.Read(nonceRaw); err != nil {
		fail("生成 nonce 失败")
		return
	}
	if _, err := rand.Read(verifierRaw); err != nil {
		fail("生成 PKCE 失败")
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
	oidcStateCount.Add(1)

	oauthCfg := oidcOAuthConfig(cfg, p, oidcCallbackURL(c))
	authURL := oauthCfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	c.Redirect(http.StatusFound, authURL)
}

// isUniqueConstraintError 判定 SQLite 唯一约束冲突（modernc 驱动错误文本口径，
// 与 users.go 用户名 409 分支同源）。
func isUniqueConstraintError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// OIDCCallback GET /auth/oidc/callback——授权码换令牌→ID Token 验签→
// 用户命中/禁用检查/JIT 开户→签发本站 JWT(与密码登录同构,auth_method=oidc)。
func (h *Handlers) OIDCCallback(c *gin.Context) {
	cfg, ok := loadOIDCConfig()
	if !ok || !cfg.Enabled || cfg.Issuer == "" {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "OIDC 未启用"})
		return
	}
	// C2-7:回调是浏览器整页导航——失败一律 302 回前端错误页(error 经 URL
	// fragment 携带,不渲染裸 JSON)。审计归因用占位用户名:失败路径身份尚未
	// 验证,不落请求方可控的用户名。
	fail := func(msg, auditDetail string) {
		if auditDetail != "" {
			services.RecordAuditLog("oidc-user", "认证拒绝", "用户认证", services.FormatAuditDetail(auditDetail, services.AuditResultPart("failure")), c.ClientIP())
		}
		c.Redirect(http.StatusFound, requestOrigin(c)+"/#/oidc/callback?error="+url.QueryEscape(msg))
	}
	stateEntryRaw, ok := oidcStates.LoadAndDelete(c.Query("state"))
	if ok {
		oidcStateCount.Add(-1)
	}
	if !ok {
		fail("登录状态无效或已过期,请重新登录", "")
		return
	}
	entry := stateEntryRaw.(oidcStateEntry)
	if time.Since(entry.created) > oidcStateTTL {
		fail("登录状态已过期,请重新登录", "")
		return
	}
	if errParam := c.Query("error"); errParam != "" {
		// SEC-3+A40-1-4:仅回显 OAuth2/OIDC 标准错误码——description 与自造
		// error 值均为外部可控文本,回显会被登录页当系统提示渲染(社工文案
		// 注入面);非白名单短码一律吞掉,只保留「提供商拒绝授权」事实。
		msg := "提供商拒绝授权"
		if code := sanitizeOIDCErrorParam(errParam); code != "" {
			msg += ": " + code
		}
		fail(msg, "OIDC 提供商拒绝授权")
		return
	}
	p, err := oidcProvider(cfg.Issuer)
	if err != nil {
		fail(err.Error(), "")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	oauthCfg := oidcOAuthConfig(cfg, p, oidcCallbackURL(c))
	oauth2Token, err := oauthCfg.Exchange(ctx, c.Query("code"),
		oauth2.SetAuthURLParam("code_verifier", entry.verifier))
	if err != nil {
		fail("令牌交换失败: "+err.Error(), "OIDC 令牌交换失败")
		return
	}
	rawIDToken, _ := oauth2Token.Extra("id_token").(string)
	if rawIDToken == "" {
		fail("提供商未返回 id_token", "OIDC 缺少 id_token")
		return
	}
	verifier := p.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		fail("ID Token 校验失败: "+err.Error(), "OIDC id_token 校验失败")
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
		fail("解析用户信息失败", "OIDC claims 解析失败")
		return
	}
	if claims.Nonce != entry.nonce {
		fail("nonce 不匹配(疑似重放)", "OIDC nonce 不匹配")
		return
	}

	// 用户命中:OIDC 用户独立行(不绑定本地账号),按 (issuer, subject) 定位。
	// R39-2:同查 password_version——OIDC JWT 携带 pwd_ver,与本地会话同构,
	// 配置导入的版本递增不再把 OIDC 会话打入永久 401 死循环。
	var userID int
	var username, role string
	var isEnabled int
	var passwordVersion int64
	err = db.DB.QueryRow("SELECT id, username, role, COALESCE(is_enabled,1), COALESCE(password_version,0) FROM users WHERE auth_provider='oidc' AND oidc_issuer=? AND oidc_subject=?", cfg.Issuer, claims.Sub).
		Scan(&userID, &username, &role, &isEnabled, &passwordVersion)
	switch {
	case errors.Is(err, nil):
		if isEnabled != 1 {
			services.RecordAuditLog(username, "登录失败", "用户认证", services.FormatAuditDetail(fmt.Sprintf("OIDC 登录 %s(账号已禁用)", services.AuditUserPart(userID, username)), services.AuditResultPart("failure")), c.ClientIP())
			fail("账号已被禁用", "")
			return
		}
	case errors.Is(err, sql.ErrNoRows):
		// JIT 开户:默认普通角色;用户名取 preferred_username→email 本地部分→sub,
		// 冲突时后缀去重(不绑定本地账号,同名共存)。TrimSpace 先于空值兜底
		// (OIDC-5:纯空白 preferred_username 不得穿过兜底产出空用户名)。
		base := strings.TrimSpace(claims.PreferredUsername)
		if base == "" && claims.Email != "" {
			base = strings.TrimSpace(strings.SplitN(claims.Email, "@", 2)[0])
		}
		if base == "" {
			base = "oidc-" + claims.Sub
		}
		// A40-1-3:截断按 rune 计数——byte 截断会把中文/emoji 切成无效 UTF-8
		// 落库(前端展示乱码);列宽 VARCHAR(50) 的语义单位是字符不是字节。
		if runes := []rune(base); len(runes) > 50 {
			base = string(runes[:50])
		}
		displayName := claims.Name
		if displayName == "" {
			displayName = base
		}
		candidate := base
		for i := 2; ; i++ {
			var exists int
			if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username=?", candidate).Scan(&exists); err != nil {
				fail("查询用户失败", "")
				return
			}
			if exists == 0 {
				break
			}
			suffix := fmt.Sprintf("-%d", i)
			// 后缀去重同按 rune 预算(后缀为 ASCII,字节数=rune 数)
			baseRunes := []rune(base)
			if len(baseRunes)+len(suffix) > 50 {
				budget := 50 - len(suffix)
				if budget < 0 {
					budget = 0
				}
				candidate = string(baseRunes[:budget]) + suffix
			} else {
				candidate = base + suffix
			}
		}
		// password_hash 置空:bcrypt 对空哈希恒败,OIDC 用户密码登录天然不可用。
		res, err := db.DB.Exec("INSERT INTO users (username, password_hash, role, display_name, is_enabled, auth_provider, oidc_subject, oidc_issuer) VALUES (?, '', 'user', ?, 1, 'oidc', ?, ?)",
			candidate, displayName, claims.Sub, cfg.Issuer)
		fellBack := false
		if err != nil && isUniqueConstraintError(err) {
			// U6a-1（第 45 轮审计）：JIT 开户与并发回调竞态——两请求同窗口双双
			// 走 no-rows 分支，后到的 INSERT 撞 u_oidc_identity 唯一索引。按既有
			// 命中分支收口：重 SELECT 对端已建行，命中即沿用其账号状态（禁用态
			// 同口径拒绝）；不补「创建」审计——行非本请求所建。身份行不存在
			// （冲突发生在 username 等其他唯一键）则维持原失败路径。
			err = db.DB.QueryRow("SELECT id, username, role, COALESCE(is_enabled,1), COALESCE(password_version,0) FROM users WHERE auth_provider='oidc' AND oidc_issuer=? AND oidc_subject=?", cfg.Issuer, claims.Sub).
				Scan(&userID, &username, &role, &isEnabled, &passwordVersion)
			fellBack = err == nil
			if fellBack && isEnabled != 1 {
				services.RecordAuditLog(username, "登录失败", "用户认证", services.FormatAuditDetail(fmt.Sprintf("OIDC 登录 %s(账号已禁用)", services.AuditUserPart(userID, username)), services.AuditResultPart("failure")), c.ClientIP())
				fail("账号已被禁用", "")
				return
			}
		}
		if err != nil {
			fail("创建 OIDC 用户失败", "OIDC JIT 开户失败")
			return
		}
		if !fellBack {
			newID, _ := res.LastInsertId()
			userID = int(newID)
			username = candidate
			role = "user"
			services.RecordAuditLog(username, "创建", "用户认证", services.FormatAuditDetail(fmt.Sprintf("OIDC 首次登录自动开户(%s)", cfg.Issuer), services.AuditResultPart("success")), c.ClientIP())
		}
	default:
		fail("查询用户失败", "")
		return
	}

	// 签发本站 JWT(与密码登录同构;auth_method=oidc 标记会话来源——本地
	// MFA 族功能对 OIDC 用户整体豁免,v2.3.0 用户裁定)。
	token, expiresAt, err := h.issueOIDCJWT(userID, username, role, passwordVersion, 0)
	if err != nil {
		fail("签发登录令牌失败", "")
		return
	}
	services.RecordAuditLog(username, "登录成功", "用户认证", services.FormatAuditDetail(fmt.Sprintf("OIDC 登录 %s", services.AuditUserPart(userID, username)), services.AuditResultPart("success")), c.ClientIP())
	_, _ = db.DB.Exec("UPDATE users SET last_login=datetime('now') WHERE id=?", userID)

	// 回跳前端:令牌走 URL fragment(不发给服务器),前端路由接收后入会话。
	returnTo := entry.returnTo
	if returnTo == "" {
		returnTo = "/"
	}
	front := requestOrigin(c)
	c.Redirect(http.StatusFound, front+"/#/oidc/callback?token="+url.QueryEscape(token)+"&expires_at="+fmt.Sprintf("%d", expiresAt.Unix())+"&return_to="+url.QueryEscape(returnTo))
}

// issueOIDCJWT 与密码登录的令牌同构(auth.go respondLoginWithMFA 口径),
// 附加 auth_method=oidc 与 pwd_ver(R39-2:jwtAuth 对缺 pwd_ver 且 DB 版本
// ≠0 的令牌恒拒——无该声明的 OIDC 会话在导入 bump 后永久 401)。
func (h *Handlers) issueOIDCJWT(userID int, username, role string, passwordVersion int64, mfaTs float64) (string, time.Time, error) {
	expireMinutes := 20
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
		"pwd_ver":     passwordVersion,
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
	if !guardConfiguredJSONBody(c) {
		return
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
		// SYS42-4:url.Parse + scheme 白名单——HasPrefix("http") 放行
		// 「httpxy://…」类伪 scheme。空 issuer 保留清除语义。
		if *req.Issuer != "" {
			u, perr := url.Parse(issuer)
			if issuer == "" || perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "服务地址须为 http(s) URL"})
				return
			}
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
		Issuer       string `json:"issuer"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if !guardConfiguredJSONBody(c) {
		return
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
	// SEC-2:机器身份(API Key/MCP)不开放「任指 URL」探测——issuer 须与已
	// 保存配置一致(先例端点探测的都是已存实体);管理员 JWT 面板编辑流不受限。
	if c.GetString("auth_type") == "api_key" {
		if stored, _ := loadOIDCConfig(); normalizeOIDCIssuer(req.Issuer) != "" && issuer != stored.Issuer {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "API Key 仅支持测试已保存的 OIDC 配置"})
			return
		}
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
	// 凭证离线校验:client_credentials 探测——invalid_client 即凭证错(secret
	// 值/ID 混淆等),在「测试」阶段暴露而非登录才炸;其余错误(unsupported_grant_type
	// /invalid_scope 等)=客户端认证已过或该服务不支持离线探测,降级为可达性通过。
	clientID, clientSecret := strings.TrimSpace(req.ClientID), strings.TrimSpace(req.ClientSecret)
	if clientID == "" || clientSecret == "" {
		if cfg, _ := loadOIDCConfig(); cfg.Issuer == issuer {
			if clientID == "" {
				clientID = cfg.ClientID
			}
			if clientSecret == "" {
				clientSecret = cfg.ClientSecret
			}
		}
	}
	credentialsChecked, credErr := probeClientCredentials(p.Endpoint().TokenURL, clientID, clientSecret)
	if credErr != nil {
		recordAudit(c, "测试失败", "OIDC 配置", services.FormatAuditDetail(fmt.Sprintf("%s(%s)", name, issuer), services.AuditResultPart("failure")))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"ok": false, "error": credErr.Error()}})
		return
	}
	detail := name + "(" + issuer + ")"
	if credentialsChecked {
		detail += " 凭证校验通过"
	}
	recordAudit(c, "测试成功", "OIDC 配置", services.FormatAuditDetail(detail, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"ok": true, "issuer": providerClaims.Issuer, "provider_name": name,
		"authorization_endpoint": p.Endpoint().AuthURL,
		"token_endpoint":         p.Endpoint().TokenURL,
		"scopes":                 providerClaims.Scopes,
		"credentials_checked":    credentialsChecked,
	}})
}

// oidcProbeClient 凭证探测专用客户端:出站请求必须有界(挂起的 token 端点
// 不得挂起 handler goroutine),与 discovery 8s 口径同族。
var oidcProbeClient = &http.Client{Timeout: 10 * time.Second}

// probeClientCredentials 用 client_credentials 向令牌端点探测凭证:
//   - 200:凭证正确(checked=true)
//   - 401/400 且 error=invalid_client:凭证错误(返回 err,含提供商描述)
//   - 其余错误(unsupported_grant_type/invalid_scope…):客户端认证未拒绝,
//     该服务不支持离线凭证探测(checked=false,可达性仍算通过)
//   - 网络/解析失败:返回 err(测试失败)
func probeClientCredentials(tokenURL, clientID, clientSecret string) (bool, error) {
	if clientID == "" || clientSecret == "" {
		return false, nil // 无凭证可验(仅探测发现可达性)
	}
	// scope 候选:①api://<client_id>/.default(Entra 等先验 scope 后验 secret 的
	// 提供商——实测 openid 会被 AADSTS1002012 拒而漏检 invalid_client);②openid(常规)。
	// 任一候选 invalid_client 即凭证错;全部非 invalid_client 错误=不支持离线探测。
	scopes := []string{"api://" + clientID + "/.default", "openid"}
	for _, scope := range scopes {
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {clientID},
			"client_secret": {clientSecret},
			"scope":         {scope},
		}
		resp, err := oidcProbeClient.PostForm(tokenURL, form)
		if err != nil {
			return false, fmt.Errorf("凭证探测请求失败: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return true, nil
		}
		var e struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "invalid_client" {
			msg := e.ErrorDescription
			if msg == "" {
				msg = e.Error
			}
			return false, fmt.Errorf("Client ID/Secret 被提供商拒绝(%s): %s", e.Error, msg)
		}
	}
	return false, nil // 无候选触达客户端认证:不支持离线探测,可达性通过
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
