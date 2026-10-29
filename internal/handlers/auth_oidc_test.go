package handlers

// OIDC 集成行为测试(v2.3.0):httptest 模拟 IdP(发现/授权/令牌/JWKS 全链),
// 验证:配置 CRUD 掩码/测试探测/JIT 开户(独立用户不绑定本地)/重复登录命中/
// 禁用拒绝/同邮箱不绑定/JWT auth_method+pwd_ver/MFA 解耦守卫矩阵。

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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
	// claimName:覆盖 id_token 的 name
	claimName atomic.Value
	// emailVerifiedMode 控制 id_token 的 email_verified 声明形态：
	// 缺省（未设置）="true"；"false"=显式 false；"absent"=不返回该声明。
	// 域白名单要求已验证邮箱，测试据此覆盖三种形态。
	emailVerifiedMode atomic.Value
	// groupsClaim 以原始 JSON 覆盖 id_token 的 groups 声明（未设置=不返回）：
	// 覆盖数组、分隔字符串、不可解析形态三种 IdP 风格。
	groupsClaim atomic.Value
	// nonceByChallenge:PKCE challenge → nonce——并发双登录各自 authorize 后,
	// 令牌交换按 code_verifier 派生 challenge 回查本登录的 nonce(单登录场景
	// lastNonce 兜底同值)。
	nonceMu          sync.Mutex
	nonceByChallenge map[string]string
	// requests 出站请求计数：任何打到本 IdP 的请求都 +1（含 discovery）。
	// 用于钉「启用门拒绝时一次出站都没有」——只看 302 目标无法区
	// 「拦在门前」与「跳转后才发现配置不全」。
	requests atomic.Int64
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
		name, _ := m.claimName.Load().(string)
		idClaims := jwt.MapClaims{
			"iss": m.issuer, "aud": "test-client", "sub": "user-sub-1",
			"email": "oidc@example.com", "preferred_username": pref, "name": name,
			"nonce": nonce, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		}
		switch mode, _ := m.emailVerifiedMode.Load().(string); mode {
		case "absent":
			// 不返回 email_verified（部分 IdP 形态）
		case "false":
			idClaims["email_verified"] = false
		default:
			idClaims["email_verified"] = true
		}
		if raw, _ := m.groupsClaim.Load().(string); raw != "" {
			var groupsClaim any
			if err := json.Unmarshal([]byte(raw), &groupsClaim); err == nil {
				idClaims["groups"] = groupsClaim
			}
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
		signed, _ := tok.SignedString(key)
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer",
			"id_token": signed,
		})
	})
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.requests.Add(1)
		mux.ServeHTTP(w, r)
	}))
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
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	dir := t.TempDir()
	if err := db.Initialize(dir); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{JWTSecret: "test-secret", DataDir: dir}
	h := &Handlers{cfg: cfg}
	// 流程测试无 cookie 容器，关闭 state↔浏览器绑定；绑定行为由
	// TestOIDCCallback_stateBoundToBrowser 专题覆盖。
	oldBinding := oidcStateBindingEnabled
	oidcStateBindingEnabled = false
	t.Cleanup(func() {
		oidcStateBindingEnabled = oldBinding
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
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
	if err := db.DB.QueryRow("SELECT auth_provider, role, username FROM users WHERE auth_provider='oidc'").Scan(&provider, &role, &username); err != nil {
		t.Fatalf("read oidc user row: %v", err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username IN ('oidcalice','oidcalice-2')").Scan(&cnt); err != nil {
		t.Fatalf("count oidcalice rows: %v", err)
	}
	if provider != "oidc" || role != "user" {
		t.Fatalf("JIT user must be independent oidc row with default role, got provider=%q role=%q", provider, role)
	}
	if username != "oidcalice-2" || cnt != 2 {
		t.Fatalf("username dedup expected oidcalice-2 + original local coexist, got %q cnt=%d", username, cnt)
	}
	// 本地用户未被污染(仍 admin,无 oidc 关联)
	var localRole, localProvider string
	if err := db.DB.QueryRow("SELECT role, COALESCE(auth_provider,'local') FROM users WHERE username='oidcalice' AND auth_provider!='oidc'").Scan(&localRole, &localProvider); err != nil {
		t.Fatalf("read local user row: %v", err)
	}
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

// 回跳前 last_login 记账写失败：登录已成功（JWT 已签发）——不得 500/不得
// 撤销登录（与密码登录「清零失败计数失败仅留痕」同族口径），但必须 warn
// 留痕便于排障（此前静默吞错）。
func TestOIDCCallback_lastLoginWriteFailureLoggedButLoginSucceeds(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	if _, err := db.DB.Exec("ALTER TABLE users RENAME COLUMN last_login TO last_login_unwritable"); err != nil {
		t.Fatalf("break last_login column: %v", err)
	}
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
	u, _ := url.Parse(rec.Header().Get("Location"))
	code := simulateIdPIssuesCode(t, u.String())
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code="+code+"&state="+u.Query().Get("state"), nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s, want 302（last_login 记账失败不得撤销已签发登录）", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "token=") {
		t.Fatalf("Location=%q, want 携带 token 的成功回跳", loc)
	}
	if !strings.Contains(logBuf.String(), "last_login") {
		t.Fatalf("last_login 写失败必须 warn 留痕, captured log=%q", logBuf.String())
	}
}

// 场景 4:重复登录命中既有 OIDC 用户;禁用后拒绝。
func TestOIDCCallback_repeat_and_disabled(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	doLoginRec := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
		u, _ := url.Parse(rec.Header().Get("Location"))
		code := simulateIdPIssuesCode(t, u.String())
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code="+code+"&state="+u.Query().Get("state"), nil))
		return rec
	}
	doLogin := func() int { return doLoginRec().Code }
	if c := doLogin(); c != http.StatusFound {
		t.Fatalf("first login failed: %d", c)
	}
	var cnt int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE auth_provider='oidc'").Scan(&cnt); err != nil {
		t.Fatalf("count oidc users: %v", err)
	}
	if cnt != 1 {
		t.Fatalf("repeat setup: expected 1 oidc user, got %d", cnt)
	}
	// 提权为 admin 后重复登录——角色保持
	db.DB.Exec("UPDATE users SET role='admin' WHERE auth_provider='oidc'")
	if c := doLogin(); c != http.StatusFound {
		t.Fatalf("second login failed: %d", c)
	}
	var role string
	if err := db.DB.QueryRow("SELECT role FROM users WHERE auth_provider='oidc'").Scan(&role); err != nil {
		t.Fatalf("read oidc role: %v", err)
	}
	if role != "admin" {
		t.Fatalf("role must persist across logins, got %q", role)
	}
	// 禁用后拒绝（浏览器导航形态,失败 302 回前端错误页；不得带 token)
	db.DB.Exec("UPDATE users SET is_enabled=0 WHERE auth_provider='oidc'")
	rec := doLoginRec()
	if rec.Code != http.StatusFound {
		t.Fatalf("disabled user must be rejected via error redirect, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	decoded, _ := url.QueryUnescape(loc)
	if !strings.Contains(loc, "error=") || strings.Contains(loc, "token=") || !strings.Contains(decoded, "账号已被禁用") {
		t.Fatalf("disabled callback Location=%q, want error=账号已被禁用 without token", loc)
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
	// 未启用也是浏览器导航形态——302 回登录页错误位,不渲染 404 JSON
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "#/login?oidc_error=") {
		t.Fatalf("login when disabled must 302 to login error page, got %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

// 公开 OIDC 状态端点在配置持续损坏时不得每请求写一条 warn；
// 响应仍按未启用 fail-closed。
func TestOIDCStatus_failureWarningIsThrottled(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	resetWarningWindow := func() {
		oidcStatusFailureLog.Lock()
		oidcStatusFailureLog.at = time.Time{}
		oidcStatusFailureLog.Unlock()
	}
	resetWarningWindow()
	t.Cleanup(resetWarningWindow)
	if _, err := db.DB.Exec(`UPDATE global_config SET oidc_config='{' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	for range 2 {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/status", nil))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"enabled":false`) {
			t.Fatalf("status=%d body=%s, want disabled 200", response.Code, response.Body.String())
		}
	}
	if got := strings.Count(logs.String(), "读取 OIDC 状态失败"); got != 1 {
		t.Fatalf("warning count=%d, want 1 within throttle window; logs=%s", got, logs.String())
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
	// 伪造 state 拒绝后 OIDC 用户尚不存在——SUM 聚合恒返回一行（无行=0），
	// 语义等价于原吞错零值，但查询故障不再静默。
	if err := db.DB.QueryRow("SELECT COALESCE(SUM(login_failed_attempts),0) FROM users WHERE auth_provider='oidc'").Scan(&attempts); err != nil {
		t.Fatalf("read lockout counter: %v", err)
	}
	if attempts != 0 {
		t.Fatalf("oidc failures must not feed lockout counter, got %d", attempts)
	}
}

// 场景 7:OAuth 配置组装(回调 URL 反代头尊重)。后采信前提=直连
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

// （2026-09-19 用户裁定按建议收窄):X-Forwarded-Proto/Host
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

// 受信反代头的 scheme 取值同样必须过白名单：X-Forwarded-Proto 只采信
// http/https（与 oidcCookieSecure 同判据），其余取值（javascript:/data:/
// 大小写变体之外的任意串）回退请求自身 scheme——否则回调基址与成功回跳
// 可被拼成非 HTTP(S) scheme 的攻击面。
func TestOIDC_requestOrigin_forwardedProtoSchemeWhitelist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	origin := func(fwdProto string) string {
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		req := httptest.NewRequest(http.MethodGet, "http://self.example.com/api/v1/auth/oidc/login", nil)
		req.RemoteAddr = "127.0.0.1:9000" // 回环=可信反代
		if fwdProto != "" {
			req.Header.Set("X-Forwarded-Proto", fwdProto)
		}
		ctx.Request = req
		return requestOrigin(ctx)
	}
	// 白名单取值照常采信。
	if got := origin("https"); got != "https://self.example.com" {
		t.Fatalf("https: origin=%q, want https://self.example.com", got)
	}
	if got := origin("http"); got != "http://self.example.com" {
		t.Fatalf("http: origin=%q, want http://self.example.com", got)
	}
	// 非白名单取值一律回退默认 scheme（不采信、不拼入）。
	for _, proto := range []string{"javascript", "javascript:alert(1)", "data", "file", "gopher", "https://evil"} {
		if got := origin(proto); got != "http://self.example.com" {
			t.Fatalf("proto=%q: origin=%q, want 回退 http://self.example.com", proto, got)
		}
	}
}

// 端到端:公网直连伪造 X-Forwarded-Host 不得污染 OIDC redirect_uri。
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

// 场景 9(v2.3.0 裁定):OIDC 用户与本地 MFA 完全解耦——五个入口
// （自助 setup/activate/disable/recovery-codes + 管理员 reset）全 403;登录从
// 节点两道 MFA 门豁免。rejectOIDCUserMFAOperation 是每个入口的首道门，逐个
// 入口钉住才能防止某一条被删（注释曾声称「全 403」而函数体只覆盖两个入口）。
func TestOIDCUser_mfa_decoupled(t *testing.T) {
	// 初始化临时库必须完整快照并在 cleanup 恢复
	// 三个全局句柄（同 setupOIDCTest）——否则后续用例踩已关闭的临时库。
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	dir := t.TempDir()
	if err := db.Initialize(dir); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{JWTSecret: "test-secret", DataDir: dir}
	h := &Handlers{cfg: cfg}
	// 流程测试无 cookie 容器，关闭 state↔浏览器绑定；绑定行为由
	// TestOIDCCallback_stateBoundToBrowser 专题覆盖。
	oldBinding := oidcStateBindingEnabled
	oidcStateBindingEnabled = false
	t.Cleanup(func() {
		oidcStateBindingEnabled = oldBinding
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	gin.SetMode(gin.TestMode)
	// OIDC 目标用户（id=9）+ 本地操作者（id=1，管理员）
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider,oidc_subject,oidc_issuer) VALUES (9,'oidcu','','user',1,'oidc','sub9','https://x')"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		path    string
		handler gin.HandlerFunc
		actorID int
		method  string
	}{
		{name: "自助 setup", path: "/auth/mfa/setup", handler: h.MFASetup, actorID: 9, method: "oidc"},
		{name: "自助 activate", path: "/auth/mfa/activate", handler: h.MFAActivate, actorID: 9, method: "oidc"},
		{name: "自助 disable", path: "/auth/mfa/disable", handler: h.MFADisable, actorID: 9, method: "oidc"},
		{name: "自助 recovery-codes", path: "/auth/mfa/recovery-codes", handler: h.MFARecoveryCodes, actorID: 9, method: "oidc"},
		{name: "管理员 reset", path: "/users/:id/mfa/reset", handler: h.MFAResetByAdmin, actorID: 1, method: "local"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			actorID, actorMethod := tc.actorID, tc.method
			router.POST(tc.path, func(c *gin.Context) {
				c.Set("user_id", actorID)
				c.Set("auth_type", "jwt")
				c.Set("auth_method", actorMethod)
				tc.handler(c)
			})
			requestPath := tc.path
			if tc.path == "/users/:id/mfa/reset" {
				requestPath = "/users/9/mfa/reset"
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, requestPath, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "不支持本地 MFA") {
				t.Fatalf("%s 对 OIDC 用户必须 403 不支持本地 MFA, got %d %s", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// 场景 10:登录从节点 MFA 门对 OIDC 会话豁免(本地用户仍要求)。
func TestOIDCUser_slave_login_gate_exempt(t *testing.T) {
	// 完整快照/恢复全局 DB 句柄（同 setupOIDCTest）。
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	dir := t.TempDir()
	if err := db.Initialize(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	cfg := &config.Config{JWTSecret: "test-secret", DataDir: dir}
	h := &Handlers{cfg: cfg, clusterService: services.NewClusterService(db.DB, dir)}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/cluster/nodes/:id/login-ticket", func(c *gin.Context) {
		c.Set("user_id", 9)
		c.Set("auth_type", "jwt")
		c.Set("auth_method", "oidc")
		h.GenerateClusterLoginTicket(c)
	})
	// OIDC 用户(未绑 MFA)——门应豁免,进入后续(节点不存在 → 404,而非 403 MFA)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/cluster/nodes/999/login-ticket", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "MFA") {
		t.Fatalf("oidc session must 绕过 mfa gate and reach node lookup (404), got %d: %s", rec.Code, rec.Body.String())
	}
	h2 := &Handlers{cfg: cfg, clusterService: services.NewClusterService(db.DB, dir)}
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

// 场景 11:JIT 开户并发回调竞态——双请求同窗口双双走
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

func TestIsUniqueConstraintError_coversDriverDialects(t *testing.T) {
	// users.go 两处 409 分支的双段判定（modernc「UNIQUE
	// constraint failed」+ 历史驱动兼容段「already exists」）并入本 helper——
	// 钉住两口径，防单侧回归。
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"modernc 唯一约束", errors.New("constraint failed: UNIQUE constraint failed: users.username (1555)"), true},
		{"历史驱动兼容段", errors.New("constraint failed: already exists"), true},
		{"无关错误", errors.New("database is locked"), false},
	}
	for _, c := range cases {
		if got := isUniqueConstraintError(c.err); got != c.want {
			t.Errorf("%s: isUniqueConstraintError=%v, want %v", c.name, got, c.want)
		}
	}
}

// 正式路径（绑定开启）下 state 必须与发起登录的浏览器绑定。
// 无 cookie / 另一 jar 的 cookie 交叉提交 code+state 都必须失败（302 error=，
// 不含 token）；同 jar 正常流程成功。
func TestOIDCCallback_stateBoundToBrowser(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	oidcStateBindingEnabled = true // setupOIDCTest 默认关闭，本测试显式开启
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	login := func() (state, code string, cookie *http.Cookie) {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("login status=%d body=%s", rec.Code, rec.Body.String())
		}
		authURL := rec.Header().Get("Location")
		u, _ := url.Parse(authURL)
		for _, c := range rec.Result().Cookies() {
			if c.Name == oidcStateCookieName {
				cookie = c
			}
		}
		if cookie == nil {
			t.Fatal("login must set the oidc_state binding cookie")
		}
		return u.Query().Get("state"), simulateIdPIssuesCode(t, authURL), cookie
	}
	callback := func(state, code string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code="+code+"&state="+state, nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	assertRejected := func(name string, rec *httptest.ResponseRecorder) {
		t.Helper()
		loc := rec.Header().Get("Location")
		if !strings.Contains(loc, "error=") || strings.Contains(loc, "token=") {
			t.Fatalf("%s: location=%q, want error= and no token", name, loc)
		}
	}

	stateA, codeA, cookieA := login()
	// 形状 1：无 cookie → 拒绝
	assertRejected("missing cookie", callback(stateA, codeA, nil))

	// 形状 2：另一浏览器的 cookie（不同 state 的绑定值）→ 拒绝
	stateB, codeB, cookieB := login()
	_ = stateB
	assertRejected("cross-jar cookie", callback(stateA, codeA, cookieB))

	// 形状 3：同 jar 正常流程 → token
	rec := callback(stateA, codeA, cookieA)
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "token=") || strings.Contains(loc, "error=") {
		t.Fatalf("same jar callback must succeed, location=%q", loc)
	}
	// B 的 state 未被 A 的失败消费破坏（各自独立）——用 B 的正常 cookie 完成
	rec = callback(stateB, codeB, cookieB)
	if !strings.Contains(rec.Header().Get("Location"), "token=") {
		t.Fatalf("second jar callback must succeed, location=%q", rec.Header().Get("Location"))
	}
}

func TestOIDCCookieSecure_forwardedProtoOnlyFromTrustedProxy(t *testing.T) {
	makeCtx := func(remote string) *gin.Context {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.RemoteAddr = remote
		c.Request.Header.Set("X-Forwarded-Proto", "https")
		return c
	}
	if oidcCookieSecure(makeCtx("203.0.113.9:443")) {
		t.Fatal("untrusted client must not force Secure cookie via X-Forwarded-Proto")
	}
	if !oidcCookieSecure(makeCtx("127.0.0.1:443")) {
		t.Fatal("trusted proxy https declaration must set Secure cookie")
	}
}

// OIDC 配置读失败/损坏时更新端点必须整体拒绝——
// 旧实现以零值 cfg 继续合并并整体写回，会清空 issuer/client_id/secret。
func TestOIDCSettingsUpdate_readFailureDoesNotOverwriteConfig(t *testing.T) {
	router, _ := setupOIDCTest(t, newMockIdP(t))
	if _, err := db.DB.Exec(`UPDATE global_config SET oidc_config='{broken' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(`{"display_name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "读取 OIDC 配置失败") {
		t.Fatalf("status=%d body=%s, want 500 读取失败", rec.Code, rec.Body.String())
	}
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(oidc_config,'') FROM global_config WHERE id=1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != "{broken" {
		t.Fatalf("oidc_config=%q, want untouched corrupt value", raw)
	}
}

// OIDC 配置更新/删除审计必须带字段级 delta，
// secret 只记「已更换/已清除」不落值。
func TestOIDCSettings_auditFieldDelta(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"client-a","client_secret":"secret-before","enabled":true}`)
	helperSuccess := func(body string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("update body=%s status=%d resp=%s", body, rec.Code, rec.Body.String())
		}
	}
	helperSuccess(`{"display_name":"SSO 登录","client_secret":"secret-after"}`)
	helperSuccess(`{"enabled":false}`)

	rows, err := db.AuditDB.Query(`SELECT detail FROM audit_log WHERE action='更新' AND resource='OIDC 配置' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var details []string
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(details, "\n")
	for _, fragment := range []string{"展示名称：（空）→SSO 登录", "Client Secret：已更换", "启用状态：启用→禁用"} {
		if !strings.Contains(joined, fragment) {
			t.Errorf("audit details=%v, want contains %q", details, fragment)
		}
	}
	if strings.Contains(joined, "secret-after") || strings.Contains(joined, "secret-before") {
		t.Fatalf("audit details leak secret value: %v", details)
	}

	// 删除留痕删除前字段值（secret 仅记已配置）。
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/settings/oidc", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", rec.Code, rec.Body.String())
	}
	var deleteDetail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='删除' AND resource='OIDC 配置' ORDER BY id DESC LIMIT 1`).Scan(&deleteDetail); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"删除前", idp.issuer, "Client ID client-a", "Client Secret 已配置", "启用状态 禁用"} {
		if !strings.Contains(deleteDetail, fragment) {
			t.Errorf("delete audit=%q, want contains %q", deleteDetail, fragment)
		}
	}
	if strings.Contains(deleteDetail, "secret-after") {
		t.Fatalf("delete audit leaks secret: %q", deleteDetail)
	}
}

// 冷缓存并发 discovery 必须合并（per-issuer singleflight）：登录风暴/公开端点
// 打点不得逐请求放大出站连接。
func TestOIDCProvider_coalescesConcurrentDiscovery(t *testing.T) {
	var hits atomic.Int32
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		time.Sleep(200 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks.json",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer server.Close()
	issuer = server.URL
	oidcProvMu.Lock()
	delete(oidcProvCach, issuer)
	oidcProvMu.Unlock()

	const callers = 6
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := oidcProvider(issuer); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("并发 discovery 失败: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("discovery 命中 %d 次, want 1（并发请求必须合并为一次出站）", got)
	}
}

// 库内 issuer 不合规时公开状态端点按未启用呈现（fail-closed），但降级必须
// 60s 节流留痕——管理员可修复的配置错误不能只靠手工 GET 端点发现。
func TestOIDCStatus_invalidStoredIssuerLogsAndDisables(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	if _, err := db.DB.Exec(`UPDATE global_config SET oidc_config=? WHERE id=1`,
		`{"enabled":true,"issuer":"ftp://bad.example","client_id":"c","client_secret":"s"}`); err != nil {
		t.Fatal(err)
	}
	oidcStatusIssuerLog.Lock()
	oidcStatusIssuerLog.at = time.Time{}
	oidcStatusIssuerLog.Unlock()
	logs := captureLog(t)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/status", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("status=%d body=%s, want 200 disabled", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logs.String(), "issuer 不合规") {
		t.Fatalf("降级必须留痕, logs=%q", logs.String())
	}
}

// 带外 NULL is_enabled 必须与 jwtAuth 同向 fail-closed：不得先签发一个随后
// 每次请求都 401 的会话。视图只替换本次查询的列，模拟迁移前/畸形快照的 NULL 形状。
func TestOIDCCallback_nullEnabledIdentityFailsClosed(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	if _, err := db.DB.Exec(`
		ALTER TABLE users RENAME TO users_rows;
		CREATE VIEW users AS
		SELECT id,username,role,NULL AS is_enabled,password_version,auth_provider,oidc_subject,oidc_issuer FROM users_rows;
		INSERT INTO users_rows (username,password_hash,role,is_enabled,auth_provider,oidc_subject,oidc_issuer)
		VALUES ('null-enabled','','admin',1,'oidc','user-sub-1',?)`, idp.issuer); err != nil {
		t.Fatalf("seed nullable identity shape: %v", err)
	}

	front := runOIDCLoginFlow(t, router)
	decoded, _ := url.QueryUnescape(front)
	if strings.Contains(front, "token=") || !strings.Contains(decoded, "账号已被禁用") {
		t.Fatalf("NULL is_enabled 必须拒登且不签发 token，got redirect: %s", front)
	}
}

// 导入/快照可绕过面板保存门带入 enabled=true 但凭证不全的配置；公开状态端点
// 不得展示必然失败的登录按钮，降级原因按既有 60s 窗口留痕一次。
func TestOIDCStatus_incompleteStoredCredentialsLogAndDisable(t *testing.T) {
	for _, tc := range []struct {
		name         string
		clientID     string
		clientSecret string
	}{
		{name: "missing client id", clientID: "", clientSecret: "s"},
		{name: "missing client secret", clientID: "c", clientSecret: ""},
		{name: "whitespace client secret", clientID: "c", clientSecret: "   "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newMockIdP(t)
			router, _ := setupOIDCTest(t, idp)
			if _, err := db.DB.Exec(`UPDATE global_config SET oidc_config=? WHERE id=1`,
				`{"enabled":true,"issuer":"`+idp.issuer+`","client_id":"`+tc.clientID+`","client_secret":"`+tc.clientSecret+`"}`); err != nil {
				t.Fatal(err)
			}
			oidcStatusIssuerLog.Lock()
			oidcStatusIssuerLog.at = time.Time{}
			oidcStatusIssuerLog.Unlock()
			t.Cleanup(func() {
				oidcStatusIssuerLog.Lock()
				oidcStatusIssuerLog.at = time.Time{}
				oidcStatusIssuerLog.Unlock()
			})
			logs := captureLog(t)

			for range 2 {
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/status", nil))
				if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) {
					t.Fatalf("status=%d body=%s, want 200 disabled", rec.Code, rec.Body.String())
				}
			}
			if got := strings.Count(logs.String(), "OIDC 配置不完整"); got != 1 {
				t.Fatalf("incomplete-config warning count=%d, want 1; logs=%s", got, logs.String())
			}
		})
	}
}
