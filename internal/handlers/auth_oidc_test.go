package handlers

// OIDC 集成行为测试(v2.3.0):httptest 模拟 IdP(发现/授权/令牌/JWKS 全链),
// 验证:配置 CRUD 掩码/测试探测/JIT 开户(独立用户不绑定本地)/重复登录命中/
// 禁用拒绝/同邮箱不绑定/JWT auth_method/写保护 OIDC_REAUTH 矩阵。

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// mockIdP 完整模拟 OIDC 提供商:发现文档+JWKS+授权端点(直接发码)+令牌端点
// (RSA 签发 id_token,含可配置 sub/email/preferred_username/nonce)。
type mockIdP struct {
	server    *httptest.Server
	key       *rsa.PrivateKey
	issuer    string
	lastNonce atomic.Value
	lastState atomic.Value
	// client_credentials 探测行为:ccUnsupported=400 unsupported_grant_type;
	// ccRejectClient=401 invalid_client;默认=200(凭证正确)
	ccUnsupported  bool
	ccRejectClient bool
}

func newMockIdP(t *testing.T) *mockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                m.issuer,
			"authorization_endpoint":                m.issuer + "/authorize",
			"token_endpoint":                        m.issuer + "/token",
			"jwks_uri":                              m.issuer + "/jwks.json",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"scopes_supported":                      []string{"openid", "profile", "email"},
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		pub := key.Public().(*rsa.PublicKey)
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}), // 65537
			}},
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		m.lastState.Store(q.Get("state"))
		m.lastNonce.Store(q.Get("nonce"))
		if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
			http.Error(w, "PKCE required", http.StatusBadRequest)
			return
		}
		redirect, _ := url.Parse(q.Get("redirect_uri"))
		rq := redirect.Query()
		rq.Set("code", "mock-code-1")
		rq.Set("state", q.Get("state"))
		redirect.RawQuery = rq.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json") // oauth2 库按 content-type 判定 JSON 解密
		_ = r.ParseForm()
		if r.FormValue("grant_type") == "client_credentials" {
			// 镜像 Entra 真实行为:scope 不带 /.default 先拒 invalid_scope(AADSTS1002012),
			// 带 /.default 才进入客户端认证(invalid_client)
			switch {
			case m.ccUnsupported:
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
			case !strings.Contains(r.FormValue("scope"), "/.default"):
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_scope", "error_description": "AADSTS1002012: Client credential flows must have a scope value with /.default suffixed."})
			case m.ccRejectClient || r.FormValue("client_secret") != "super-secret-123":
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided."})
			default:
				json.NewEncoder(w).Encode(map[string]string{"access_token": "at", "token_type": "Bearer"})
			}
			return
		}
		nonce, _ := m.lastNonce.Load().(string)
		now := time.Now()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": m.issuer, "aud": "test-client", "sub": "user-sub-1",
			"email": "oidc@example.com", "preferred_username": "oidcalice",
			"nonce": nonce, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		})
		signed, _ := tok.SignedString(key)
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer",
			"id_token": signed,
		})
	})
	m.server = httptest.NewServer(mux)
	m.issuer = m.server.URL
	t.Cleanup(m.server.Close)
	return m
}

// simulateIdPIssuesCode 对 mock authorize 发真实 HTTP,解析 302 回调地址中的 code。
func simulateIdPIssuesCode(t *testing.T, authURL string) string {
	t.Helper()
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // 不跟随(example.com 不可路由),直接读 302 Location
	}}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize expected 302, got %d", resp.StatusCode)
	}
	loc, _ := resp.Location()
	if code := loc.Query().Get("code"); code != "" {
		return code
	}
	t.Fatalf("authorize did not issue code: %v %s", resp.StatusCode, loc)
	return ""
}

func setupOIDCTest(t *testing.T, idp *mockIdP) (*gin.Engine, *Handlers) {
	t.Helper()
	dir := t.TempDir()
	if err := db.Initialize(dir); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{JWTSecret: "test-secret", DataDir: dir}
	h := &Handlers{cfg: cfg}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/auth/oidc/status", h.OIDCStatus)
	router.GET("/api/v1/auth/oidc/login", h.OIDCLogin)
	router.GET("/api/v1/auth/oidc/callback", h.OIDCCallback)
	router.GET("/api/v1/settings/oidc", h.OIDCSettings)
	router.PUT("/api/v1/settings/oidc", h.OIDCSettingsUpdate)
	router.POST("/api/v1/settings/oidc/test", h.OIDCSettingsTest)
	router.DELETE("/api/v1/settings/oidc", h.OIDCSettingsDelete)
	return router, h
}

func putOIDCConfig(t *testing.T, router *gin.Engine, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("save oidc config: %d %s", rec.Code, rec.Body.String())
	}
}

// 场景 1:配置 CRUD——保存/掩码回显/删除。
func TestOIDCSettings_crud_masks_secret(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"super-secret-123","enabled":true}`)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/settings/oidc", nil))
	var resp struct {
		Data struct {
			ClientSecretMasked string `json:"client_secret_masked"`
			HasSecret          bool   `json:"has_secret"`
			Enabled            bool   `json:"enabled"`
		} `json:"data"`
	}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Data.ClientSecretMasked == "super-secret-123" || !strings.Contains(resp.Data.ClientSecretMasked, "****") {
		t.Fatalf("secret must be masked, got %q", resp.Data.ClientSecretMasked)
	}
	if !resp.Data.HasSecret || !resp.Data.Enabled {
		t.Fatalf("has_secret/enabled should be true")
	}
	// 空 secret 更新=保持现值
	putOIDCConfig(t, router, `{"client_secret":""}`)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/settings/oidc", nil))
	if !strings.Contains(rec.Body.String(), `"has_secret":true`) {
		t.Fatalf("empty secret update must keep existing secret")
	}
	// 删除
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/settings/oidc", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/settings/oidc", nil))
	if strings.Contains(rec.Body.String(), `"issuer":"`+idp.issuer) {
		t.Fatalf("config should be cleared after delete")
	}
}

// 场景 2:测试端点——真实发现成功/不可达失败。
func TestOIDCSettingsTest_discovery_probe(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/oidc/test", strings.NewReader(`{"issuer":"`+idp.issuer+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"ok":true`) || !strings.Contains(rec.Body.String(), "token_endpoint") {
		t.Fatalf("discovery probe should succeed: %s", rec.Body.String())
	}
	// 不可达 issuer
	req = httptest.NewRequest(http.MethodPost, "/api/v1/settings/oidc/test", strings.NewReader(`{"issuer":"http://127.0.0.1:1/"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"ok":false`) {
		t.Fatalf("unreachable issuer should report ok=false: %s", rec.Body.String())
	}
}

// 场景 3:全链登录——JIT 开户为独立 OIDC 用户(默认普通角色),JWT 含 auth_method。
func TestOIDCCallback_full_flow_jit(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	// 本地同名/同邮箱用户存在——OIDC 必须不绑定,独立开户
	if _, err := db.DB.Exec("INSERT INTO users (username, password_hash, role, is_enabled) VALUES ('oidcalice', 'x', 'admin', 1)"); err != nil {
		t.Fatal(err)
	}
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	// 第一步:login 跳转(提取 state)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login should redirect, got %d %s", rec.Code, rec.Body.String())
	}
	authURL := rec.Header().Get("Location")
	u, _ := url.Parse(authURL)
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("authorize url missing state")
	}

	// 第二步:真实 HTTP 打 mock authorize,取 302 回调地址中的 code
	code := simulateIdPIssuesCode(t, authURL)

	// 第三步:callback
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code="+code+"&state="+state, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback should redirect with token, got %d body=%s", rec.Code, rec.Body.String())
	}
	front := rec.Header().Get("Location")
	if !strings.Contains(front, "#/oidc/callback?token=") {
		t.Fatalf("redirect missing token fragment: %s", front)
	}

	// 断言用户:独立行,auth_provider=oidc,role=user,用户名去重
	var provider, role, username string
	var cnt int
	db.DB.QueryRow("SELECT auth_provider, role, username FROM users WHERE auth_provider='oidc'").Scan(&provider, &role, &username)
	db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username IN ('oidcalice','oidcalice-2')").Scan(&cnt)
	if provider != "oidc" || role != "user" {
		t.Fatalf("JIT user must be independent oidc row with default role, got provider=%q role=%q", provider, role)
	}
	if username != "oidcalice-2" || cnt != 2 {
		t.Fatalf("username dedup expected oidcalice-2 + original local coexist, got %q cnt=%d", username, cnt)
	}
	// 本地用户未被污染(仍 admin,无 oidc 关联)
	var localRole, localProvider string
	db.DB.QueryRow("SELECT role, COALESCE(auth_provider,'local') FROM users WHERE username='oidcalice' AND auth_provider!='oidc'").Scan(&localRole, &localProvider)
	if localRole != "admin" || localProvider != "local" {
		t.Fatalf("local user must be untouched: role=%q provider=%q", localRole, localProvider)
	}
	// JWT auth_method=oidc
	tokStart := strings.Index(front, "token=") + len("token=")
	tokEnd := strings.Index(front[tokStart:], "&")
	if tokEnd < 0 {
		tokEnd = len(front) - tokStart
	}
	rawTok, _ := url.QueryUnescape(front[tokStart : tokStart+tokEnd])
	p2, err2 := jwt.NewParser().Parse(rawTok, func(tk *jwt.Token) (interface{}, error) { return []byte("test-secret"), nil })
	if err2 != nil || !p2.Valid {
		t.Fatalf("issued jwt should verify: %v", err2)
	}
	claims := p2.Claims.(jwt.MapClaims)
	if claims["auth_method"] != "oidc" {
		t.Fatalf("jwt must carry auth_method=oidc, got %v", claims["auth_method"])
	}
}

// 场景 4:重复登录命中既有 OIDC 用户;禁用后拒绝。
func TestOIDCCallback_repeat_and_disabled(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	doLogin := func() int {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
		u, _ := url.Parse(rec.Header().Get("Location"))
		code := simulateIdPIssuesCode(t, u.String())
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code="+code+"&state="+u.Query().Get("state"), nil))
		return rec.Code
	}
	if c := doLogin(); c != http.StatusFound {
		t.Fatalf("first login failed: %d", c)
	}
	var cnt int
	db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE auth_provider='oidc'").Scan(&cnt)
	if cnt != 1 {
		t.Fatalf("repeat setup: expected 1 oidc user, got %d", cnt)
	}
	// 提权为 admin 后重复登录——角色保持
	db.DB.Exec("UPDATE users SET role='admin' WHERE auth_provider='oidc'")
	if c := doLogin(); c != http.StatusFound {
		t.Fatalf("second login failed: %d", c)
	}
	var role string
	db.DB.QueryRow("SELECT role FROM users WHERE auth_provider='oidc'").Scan(&role)
	if role != "admin" {
		t.Fatalf("role must persist across logins, got %q", role)
	}
	// 禁用后拒绝
	db.DB.Exec("UPDATE users SET is_enabled=0 WHERE auth_provider='oidc'")
	if c := doLogin(); c != http.StatusForbidden {
		t.Fatalf("disabled user must be rejected, got %d", c)
	}
}

// 场景 5:未启用时 status 关闭、login 404。
func TestOIDC_disabled_state(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/status", nil))
	if !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("status should be disabled: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("login when disabled should 404, got %d", rec.Code)
	}
}

// 场景 6:回调伪造 state 拒绝(不计锁定——锁定列不动)。
func TestOIDCCallback_bad_state_rejected(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code=x&state=forged", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("forged state must be rejected, got %d", rec.Code)
	}
	var attempts int
	db.DB.QueryRow("SELECT COALESCE(login_failed_attempts,0) FROM users WHERE auth_provider='oidc'").Scan(&attempts)
	if attempts != 0 {
		t.Fatalf("oidc failures must not feed lockout counter, got %d", attempts)
	}
}

// 场景 7:OAuth 配置组装(回调 URL 反代头尊重)。
func TestOIDC_requestOrigin_forwarded(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "lb.example.com")
	router.ServeHTTP(rec, req)
	if !strings.Contains(rec.Header().Get("Location"), url.QueryEscape("https://lb.example.com/api/v1/auth/oidc/callback")) {
		t.Fatalf("redirect_uri must honor forwarded host/proto: %s", rec.Header().Get("Location"))
	}
}

// 场景 8:issuer 规范化——Entra 缺 /v2.0 自动补全;其他提供商逐字保留。
func TestOIDC_normalize_issuer(t *testing.T) {
	cases := map[string]string{
		"https://login.microsoftonline.com/tenant-id":      "https://login.microsoftonline.com/tenant-id/v2.0",
		"https://login.microsoftonline.com/tenant-id/":     "https://login.microsoftonline.com/tenant-id/v2.0",
		"https://login.microsoftonline.com/tenant-id/v2.0": "https://login.microsoftonline.com/tenant-id/v2.0",
		"https://sso.example.com/realms/master":            "https://sso.example.com/realms/master",
		"https://sso.example.com/realms/master/":           "https://sso.example.com/realms/master",
	}
	for in, want := range cases {
		if got := normalizeOIDCIssuer(in); got != want {
			t.Fatalf("normalize(%q)=%q, want %q", in, got, want)
		}
	}
}

// 场景 9(v2.3.0 裁定):OIDC 用户与本地 MFA 完全解耦——
// 启用/禁用/激活/管理员重置全 403;登录从节点两道 MFA 门豁免。
func TestOIDCUser_mfa_decoupled(t *testing.T) {
	dir := t.TempDir()
	if err := db.Initialize(dir); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{JWTSecret: "test-secret", DataDir: dir}
	h := &Handlers{cfg: cfg}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// OIDC 目标用户 + 本地操作者(admin)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider,oidc_subject,oidc_issuer) VALUES (9,'oidcu','','user',1,'oidc','sub9','https://x')"); err != nil {
		t.Fatal(err)
	}
	router.POST("/users/:id/mfa/reset", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("auth_type", "jwt")
		c.Set("auth_method", "local")
		h.MFAResetByAdmin(c)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/users/9/mfa/reset", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "不支持本地 MFA") {
		t.Fatalf("admin reset on oidc user must 403, got %d %s", rec.Code, rec.Body.String())
	}
	// 自助端点:OIDC 用户自己 MFASetup → 403
	router2 := gin.New()
	router2.POST("/auth/mfa/setup", func(c *gin.Context) {
		c.Set("user_id", 9)
		c.Set("auth_type", "jwt")
		c.Set("auth_method", "oidc")
		h.MFASetup(c)
	})
	rec = httptest.NewRecorder()
	router2.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/mfa/setup", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("oidc self mfa setup must 403, got %d %s", rec.Code, rec.Body.String())
	}
}

// 场景 10:登录从节点 MFA 门对 OIDC 会话豁免(本地用户仍要求)。
func TestOIDCUser_slave_login_gate_exempt(t *testing.T) {
	dir := t.TempDir()
	if err := db.Initialize(dir); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{JWTSecret: "test-secret", DataDir: dir}
	h := &Handlers{cfg: cfg, clusterService: services.NewClusterService(db.DB, nil, dir)}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/cluster/nodes/:id/login-ticket", func(c *gin.Context) {
		c.Set("user_id", 9)
		c.Set("auth_type", "jwt")
		c.Set("auth_method", "oidc")
		h.GenerateClusterLoginTicket(c)
	})
	// OIDC 用户(未绑 MFA)——门应豁免,进入后续(节点不存在 → 409,而非 403 MFA)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/cluster/nodes/999/login-ticket", nil)
	router.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "MFA") {
		t.Fatalf("oidc session must bypass mfa gate, got 403: %s", rec.Body.String())
	}
	h2 := &Handlers{cfg: cfg, clusterService: services.NewClusterService(db.DB, nil, dir)}
	// 本地用户(未绑 MFA)——门应生效 403
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'localadmin','x','admin',1)"); err != nil {
		t.Fatal(err)
	}
	router2 := gin.New()
	router2.POST("/cluster/nodes/:id/login-ticket", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("auth_type", "jwt")
		c.Set("auth_method", "local")
		h2.GenerateClusterLoginTicket(c)
	})
	rec = httptest.NewRecorder()
	router2.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/cluster/nodes/999/login-ticket", nil))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "MFA") {
		t.Fatalf("local user without mfa must hit gate, got %d %s", rec.Code, rec.Body.String())
	}
}

// 测试连接须做 client_credentials 凭证校验(不止 Discovery)——
// AADSTS7000215(secret ID/值混淆)必须在「测试」阶段暴露,不能等登录才炸。
func TestOIDCSettingsTest_verifiesClientCredentials(t *testing.T) {
	post := func(router *gin.Engine, body string) (bool, bool, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/oidc/test", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		var resp struct {
			Data struct {
				OK                 bool   `json:"ok"`
				CredentialsChecked bool   `json:"credentials_checked"`
				Error              string `json:"error"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v (%s)", err, rec.Body.String())
		}
		return resp.Data.OK, resp.Data.CredentialsChecked, resp.Data.Error
	}

	t.Run("凭证正确-校验通过", func(t *testing.T) {
		idp := newMockIdP(t)
		router, _ := setupOIDCTest(t, idp)
		ok, checked, errMsg := post(router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"super-secret-123"}`)
		if !ok || !checked {
			t.Fatalf("expect ok+credentials_checked, got ok=%v checked=%v err=%q", ok, checked, errMsg)
		}
	})
	t.Run("secret错误-测试失败且含提供商错误", func(t *testing.T) {
		idp := newMockIdP(t)
		router, _ := setupOIDCTest(t, idp)
		ok, _, errMsg := post(router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"wrong-secret"}`)
		if ok {
			t.Fatal("invalid client secret must fail the test")
		}
		if !strings.Contains(errMsg, "invalid_client") && !strings.Contains(errMsg, "AADSTS7000215") {
			t.Fatalf("error must surface provider message, got %q", errMsg)
		}
	})
	t.Run("IdP不支持cc-降级为可达性通过", func(t *testing.T) {
		idp := newMockIdP(t)
		idp.ccUnsupported = true
		router, _ := setupOIDCTest(t, idp)
		ok, checked, _ := post(router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"super-secret-123"}`)
		if !ok || checked {
			t.Fatalf("unsupported cc: expect ok+unchecked, got ok=%v checked=%v", ok, checked)
		}
	})
}
