package handlers

// OIDC 集成行为测试(v2.3.0):httptest 模拟 IdP(发现/授权/令牌/JWKS 全链),
// 验证:配置 CRUD 掩码/测试探测/JIT 开户(独立用户不绑定本地)/重复登录命中/
// 禁用拒绝/同邮箱不绑定/JWT auth_method+pwd_ver/MFA 解耦守卫矩阵。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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
	// usePref/prefUsername:覆盖 id_token 的 preferred_username(测空白用户名形状)
	usePref      bool
	prefUsername string
	// nonceByChallenge:PKCE challenge → nonce——并发双登录各自 authorize 后,
	// 令牌交换按 code_verifier 派生 challenge 回查本登录的 nonce(单登录场景
	// lastNonce 兜底同值)。
	nonceMu          sync.Mutex
	nonceByChallenge map[string]string
}

func newMockIdP(t *testing.T) *mockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockIdP{key: key, nonceByChallenge: map[string]string{}}
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
		m.nonceMu.Lock()
		m.nonceByChallenge[q.Get("code_challenge")] = q.Get("nonce")
		m.nonceMu.Unlock()
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
		// 并发登录配对:按 code_verifier 派生 S256 challenge 回查本登录的 nonce,
		// 未命中(单登录)时 lastNonce 兜底同值。
		if verifier := r.FormValue("code_verifier"); verifier != "" {
			sum := sha256.Sum256([]byte(verifier))
			m.nonceMu.Lock()
			if keyed, ok := m.nonceByChallenge[base64.RawURLEncoding.EncodeToString(sum[:])]; ok {
				nonce = keyed
			}
			m.nonceMu.Unlock()
		}
		pref := "oidcalice"
		if m.usePref {
			pref = m.prefUsername
		}
		now := time.Now()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": m.issuer, "aud": "test-client", "sub": "user-sub-1",
			"email": "oidc@example.com", "preferred_username": pref,
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
	// 禁用后拒绝(C2-7:浏览器导航形态,失败 302 回前端错误页)
	db.DB.Exec("UPDATE users SET is_enabled=0 WHERE auth_provider='oidc'")
	if c := doLogin(); c != http.StatusFound {
		t.Fatalf("disabled user must be rejected via error redirect, got %d", c)
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
	// A40-1-2:未启用也是浏览器导航形态——302 回登录页错误位,不渲染 404 JSON
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "#/login?oidc_error=") {
		t.Fatalf("login when disabled must 302 to login error page, got %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

// 场景 6:回调伪造 state 拒绝(不计锁定——锁定列不动)。
func TestOIDCCallback_bad_state_rejected(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code=x&state=forged", nil))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "#/oidc/callback?error=") {
		t.Fatalf("forged state must redirect to frontend error page, got %d %s", rec.Code, rec.Header().Get("Location"))
	}
	var attempts int
	db.DB.QueryRow("SELECT COALESCE(login_failed_attempts,0) FROM users WHERE auth_provider='oidc'").Scan(&attempts)
	if attempts != 0 {
		t.Fatalf("oidc failures must not feed lockout counter, got %d", attempts)
	}
}

// 场景 7:OAuth 配置组装(回调 URL 反代头尊重)。APIMCP41-5 后采信前提=直连
// 对端为回环/私网可信反代,故 RemoteAddr 置 RFC1918 地址。
func TestOIDC_requestOrigin_forwarded(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil)
	req.RemoteAddr = "10.0.0.1:44300"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "lb.example.com")
	router.ServeHTTP(rec, req)
	if !strings.Contains(rec.Header().Get("Location"), url.QueryEscape("https://lb.example.com/api/v1/auth/oidc/callback")) {
		t.Fatalf("redirect_uri must honor forwarded host/proto: %s", rec.Header().Get("Location"))
	}
}

// APIMCP41-5(第 41 轮审计,2026-09-19 用户裁定按建议收窄):X-Forwarded-Proto/Host
// 仅当直连对端为回环/私网(RFC1918+ULA+链路本地)时采信;公网直连一律忽略转发
// 头——路由器 SetTrustedProxies(nil) 意味着任何客户端都能伪造 X-Forwarded-Host,
// 无来源校验会把回调 redirect_uri 与成功回跳基址(令牌走 fragment)指向攻击者域。
func TestOIDC_requestOrigin_trustedProxyGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	origin := func(remoteAddr, fwdProto, fwdHost string) string {
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		req := httptest.NewRequest(http.MethodGet, "http://self.example.com/api/v1/auth/oidc/login", nil)
		req.RemoteAddr = remoteAddr
		if fwdProto != "" {
			req.Header.Set("X-Forwarded-Proto", fwdProto)
		}
		if fwdHost != "" {
			req.Header.Set("X-Forwarded-Host", fwdHost)
		}
		ctx.Request = req
		return requestOrigin(ctx)
	}
	// 可信:回环 + RFC1918 三段(含 172.31 上界)+ ULA + 链路本地(v4/v6) → 采信转发头。
	for _, ra := range []string{"127.0.0.1:9000", "[::1]:9000", "10.1.2.3:9000", "172.16.0.9:9000", "172.31.255.254:9000", "192.168.1.10:9000", "[fd00::5]:9000", "[fe80::1%eth0]:9000", "169.254.1.1:9000"} {
		if got := origin(ra, "https", "lb.example.com"); got != "https://lb.example.com" {
			t.Fatalf("trusted %s: origin=%q, want https://lb.example.com", ra, got)
		}
	}
	// 不可信:公网 v4/v6、172.32 出界、畸形、空 → 忽略转发头,用请求自身 scheme/host。
	for _, ra := range []string{"203.0.113.10:9000", "8.8.8.8:9000", "[2001:db8::1]:9000", "172.32.0.1:9000", "garbage", ""} {
		if got := origin(ra, "https", "evil.example.com"); got != "http://self.example.com" {
			t.Fatalf("untrusted %q: origin=%q, want http://self.example.com", ra, got)
		}
	}
	// 无转发头时行为与现状一致(任意对端都用请求自身基址)。
	if got := origin("203.0.113.10:9000", "", ""); got != "http://self.example.com" {
		t.Fatalf("origin=%q, want http://self.example.com", got)
	}
}

// APIMCP41-5 端到端:公网直连伪造 X-Forwarded-Host 不得污染 OIDC redirect_uri。
func TestOIDC_login_redirectURI_ignoresForwardedFromPublicRemote(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil)
	req.RemoteAddr = "203.0.113.10:9000"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "evil.example.com")
	router.ServeHTTP(rec, req)
	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "evil.example.com") {
		t.Fatalf("公网直连的转发头必须被忽略: %s", loc)
	}
	if !strings.Contains(loc, url.QueryEscape("http://example.com/api/v1/auth/oidc/callback")) {
		t.Fatalf("redirect_uri 应回退请求自身 host: %s", loc)
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

// 场景 11(U6a-1 第 45 轮审计):JIT 开户并发回调竞态——双请求同窗口双双走
// no-rows 分支,u_oidc_identity 唯一索引保证至多一行;后到的 INSERT 撞索引后
// 回退重 SELECT 命中既有行:两个回调都成功签发,最终恰一个身份行。
func TestOIDCCallback_jit_race_conflict_falls_back_to_existing_row(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	loginOnce := func() (code, state string) {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
		u, _ := url.Parse(rec.Header().Get("Location"))
		return simulateIdPIssuesCode(t, u.String()), u.Query().Get("state")
	}
	codeA, stateA := loginOnce()
	codeB, stateB := loginOnce()

	type callbackResult struct {
		code     int
		location string
	}
	results := make([]callbackResult, 2)
	ready := make(chan struct{}, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ready <- struct{}{}
		<-start
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code="+codeA+"&state="+stateA, nil))
		results[0] = callbackResult{rec.Code, rec.Header().Get("Location")}
	}()
	go func() {
		defer wg.Done()
		ready <- struct{}{}
		<-start
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code="+codeB+"&state="+stateB, nil))
		results[1] = callbackResult{rec.Code, rec.Header().Get("Location")}
	}()
	<-ready
	<-ready
	close(start)
	wg.Wait()

	var cnt int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE auth_provider='oidc' AND oidc_subject='user-sub-1'").Scan(&cnt); err != nil {
		t.Fatalf("count identity rows: %v", err)
	}
	if cnt != 1 {
		t.Fatalf("concurrent JIT must yield exactly 1 identity row, got %d", cnt)
	}
	for i, r := range results {
		if r.code != http.StatusFound {
			t.Fatalf("callback #%d code=%d body=%s, want 302", i, r.code, r.location)
		}
		if !strings.Contains(r.location, "#/oidc/callback?token=") {
			t.Fatalf("callback #%d must redirect with token (UNIQUE loser must fall back to existing row), got %s", i, r.location)
		}
	}
	var username string
	if err := db.DB.QueryRow("SELECT username FROM users WHERE auth_provider='oidc' AND oidc_subject='user-sub-1'").Scan(&username); err != nil || username == "" {
		t.Fatalf("identity row must exist with username, got %q err=%v", username, err)
	}
}
