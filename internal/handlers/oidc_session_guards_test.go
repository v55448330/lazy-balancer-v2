package handlers

// (/4）的行为规格
// OIDC 令牌 pwd_ver、state 容量上限、discovery 负缓存、JIT 空白用户名兜底、
// OIDC 用户 username 不可改、初始管理员不可降级、回调失败 302 回前端。

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/db"
)

// oidcLoginAndGetClaims 驱动完整登录链(login→authorize→callback),解析签发 JWT。
func oidcLoginAndGetClaims(t *testing.T, router *gin.Engine) jwt.MapClaims {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login redirect: got %d body=%s", rec.Code, rec.Body.String())
	}
	authURL := rec.Header().Get("Location")
	u, _ := url.Parse(authURL)
	code := simulateIdPIssuesCode(t, authURL)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code="+code+"&state="+u.Query().Get("state"), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback: got %d body=%s", rec.Code, rec.Body.String())
	}
	front := rec.Header().Get("Location")
	tokStart := strings.Index(front, "token=") + len("token=")
	tokEnd := strings.Index(front[tokStart:], "&")
	if tokEnd < 0 {
		tokEnd = len(front) - tokStart
	}
	rawTok, _ := url.QueryUnescape(front[tokStart : tokStart+tokEnd])
	parsed, err := jwt.NewParser().Parse(rawTok, func(tk *jwt.Token) (interface{}, error) { return []byte("test-secret"), nil })
	if err != nil || !parsed.Valid {
		t.Fatalf("issued jwt should verify: %v", err)
	}
	return parsed.Claims.(jwt.MapClaims)
}

// OIDC JWT 必须携带 pwd_ver 且随 DB password_version 变化——否则任何
// 配置导入(password_version+1)后 OIDC 会话永久 401 死循环(jwtAuth 对缺
// pwd_ver 且 DB 版本≠0 的令牌恒拒)。
func TestOIDCCallback_token_carries_pwd_ver(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	// Given:首次登录(password_version=0)——claim 必须存在且等于 0
	claims := oidcLoginAndGetClaims(t, router)
	v, ok := claims["pwd_ver"]
	if !ok || v != float64(0) {
		t.Fatalf("first login jwt must carry pwd_ver=0, got present=%v value=%v", ok, v)
	}

	// When:配置导入语义的 password_version bump(0→3)后再次登录
	if _, err := db.DB.Exec("UPDATE users SET password_version=3 WHERE auth_provider='oidc'"); err != nil {
		t.Fatal(err)
	}
	claims = oidcLoginAndGetClaims(t, router)
	v, ok = claims["pwd_ver"]
	if !ok || v != float64(3) {
		t.Fatalf("post-bump jwt must carry pwd_ver=3, got present=%v value=%v", ok, v)
	}
}

// 密码登录与 OIDC 回调必须签发同一组会话声明；只有认证来源与本地 MFA 时间
// 戳允许不同。该基线同时守住后续签发单源化的等价行为。
func TestSessionJWT_passwordAndOIDCClaimSetsMatch(t *testing.T) {
	idp := newMockIdP(t)
	router, h := setupOIDCTest(t, idp)
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('root',?,'admin',1)`, string(hash)); err != nil {
		t.Fatal(err)
	}
	router.POST("/auth/login", h.Login)
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("password login status=%d body=%s", loginRec.Code, loginRec.Body.String())
	}
	var loginBody struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginBody); err != nil {
		t.Fatal(err)
	}
	localToken, err := jwt.Parse(loginBody.Token, func(*jwt.Token) (any, error) { return []byte("test-secret"), nil })
	if err != nil {
		t.Fatalf("parse password token: %v", err)
	}
	localClaims := localToken.Claims.(jwt.MapClaims)

	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	oidcClaims := oidcLoginAndGetClaims(t, router)
	keySet := func(claims jwt.MapClaims) map[string]struct{} {
		keys := make(map[string]struct{}, len(claims))
		for key := range claims {
			if key != "auth_method" && key != "mfa_ts" {
				keys[key] = struct{}{}
			}
		}
		return keys
	}
	want := map[string]struct{}{"user_id": {}, "username": {}, "role": {}, "pwd_ver": {}, "jti": {}, "iat": {}, "exp": {}}
	if got := keySet(localClaims); !maps.Equal(got, want) {
		t.Fatalf("password session claim keys=%v, want %v", got, want)
	}
	if got := keySet(oidcClaims); !maps.Equal(got, want) {
		t.Fatalf("OIDC session claim keys=%v, want %v", got, want)
	}
	if _, ok := localClaims["auth_method"]; ok || oidcClaims["auth_method"] != "oidc" {
		t.Fatalf("auth_method local=%v OIDC=%v, want absent/oidc", localClaims["auth_method"], oidcClaims["auth_method"])
	}
}

func TestOIDCUserStatusToggle_bumpsSessionVersionAcrossReenable(t *testing.T) {
	idp := newMockIdP(t)
	router, h := setupOIDCTest(t, idp)
	seedUserAuditTest(t, 999, "status-admin", "admin", true)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	claims := oidcLoginAndGetClaims(t, router)
	if got := claims["pwd_ver"]; got != float64(0) {
		t.Fatalf("initial pwd_ver=%v, want 0", got)
	}
	var userID int
	if err := db.DB.QueryRow("SELECT id FROM users WHERE auth_provider='oidc'").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	path := "/users/" + strconv.Itoa(userID)
	for _, body := range []string{`{"is_enabled":false}`, `{"is_enabled":true}`} {
		response := serveUserMutation(h, http.MethodPut, path, body, 999, h.ToggleUserStatus)
		if response.Code != http.StatusOK {
			t.Fatalf("toggle %s: status=%d body=%s", body, response.Code, response.Body.String())
		}
	}

	claims = oidcLoginAndGetClaims(t, router)
	if got := claims["pwd_ver"]; got != float64(2) {
		t.Fatalf("new OIDC login pwd_ver=%v, want 2 after disable+enable", got)
	}
}

func TestOIDCLogin_state_entries_capped(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	// 隔离:清空全局在册状态(其他场景可能遗留未回调的 login state)
	oidcStates.Range(func(k, _ any) bool { oidcStates.Delete(k); return true })
	oidcStateCount.Store(0)
	old := oidcStateMaxEntries
	oidcStateMaxEntries = 2
	t.Cleanup(func() {
		oidcStateMaxEntries = old
		oidcStates.Range(func(k, _ any) bool { oidcStates.Delete(k); return true })
		oidcStateCount.Store(0)
	})

	// Given:两次未完成登录(state 留存在册)
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("login %d should pass under cap, got %d", i+1, rec.Code)
		}
	}
	// When:第三次 login(在册已达上限)→ 302 登录页错误位
	// 浏览器导航形态,失败不渲染 429 JSON)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "#/login?oidc_error=") {
		t.Fatalf("login beyond state cap must 302 to login error page, got %d body=%s", rec.Code, rec.Body.String())
	}

	// 复审形状:在册条目全部过期后,新 login 不得被 429 短路——过期清理
	// 先于封顶判定执行(否则死条目把 OIDC 登录永久锁死直至重启)。
	oidcStates.Range(func(k, v any) bool {
		if e, ok := v.(oidcStateEntry); ok {
			oidcStates.Store(k, oidcStateEntry{nonce: e.nonce, verifier: e.verifier, returnTo: e.returnTo, created: time.Now().Add(-2 * oidcStateTTL)})
		}
		return true
	})
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("expired entries must be cleaned before cap check (login should pass), got %d body=%s", rec.Code, rec.Body.String())
	}
	// 302 也出现在「state 满员」失败形态（本测试上方已证）——必须再排除
	// 错误页并核对跳转确为 IdP 授权端点，否则死 state 卡死登录仍会假绿。
	location := rec.Header().Get("Location")
	if strings.Contains(location, "oidc_error=") {
		t.Fatalf("cleaned login fell back to error page: %q", location)
	}
	if !strings.HasPrefix(location, idp.issuer+"/authorize?") {
		t.Fatalf("cleaned login must redirect to IdP authorize endpoint, got %q", location)
	}
	if got := oidcStateCount.Load(); got != 1 {
		t.Fatalf("cleaned login state 在册数=%d, want 1（过期条目清理后只登记本次登录）", got)
	}
}

// discovery 失败须短 TTL 负缓存——IdP 故障时不重复回源放大。
func TestOIDCProvider_failure_negative_cache(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	oidcProviderInvalidate(srv.URL)
	t.Cleanup(func() { oidcProviderInvalidate(srv.URL) })

	if _, err := oidcProvider(srv.URL); err == nil {
		t.Fatal("404 discovery must fail")
	}
	if _, err := oidcProvider(srv.URL); err == nil {
		t.Fatal("second call must also fail")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("failure must be negative-cached, upstream hits=%d want 1", got)
	}
}

// preferred_username 纯空白经 TrimSpace 后必须走兜底链,不得产出空用户名行。
func TestOIDCCallback_jit_blank_username_falls_back(t *testing.T) {
	idp := newMockIdP(t)
	idp.usePref = true
	idp.prefUsername = "   "
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	oidcLoginAndGetClaims(t, router)

	var username string
	var cnt int
	db.DB.QueryRow("SELECT username FROM users WHERE auth_provider='oidc'").Scan(&username)
	db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username=''").Scan(&cnt)
	if username == "" || cnt != 0 {
		t.Fatalf("blank preferred_username must fall back (email local-part), got username=%q empty_rows=%d", username, cnt)
	}
}

// OIDC 用户的 username 同为 IdP 源属性——与显示名/密码同一裁定口径,
// 管理员不可改。
func TestUpdateUser_rejects_oidc_username_change(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider) VALUES (7,'sso-alice','','user',1,'oidc')`); err != nil {
		t.Fatal(err)
	}
	rec := serveUserMutation(h, http.MethodPut, "/users/7", `{"username":"renamed"}`, 1, h.UpdateUser)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "OIDC") {
		t.Fatalf("oidc username change must 400 with OIDC hint, got %d %s", rec.Code, rec.Body.String())
	}
}

// 初始管理员 id=1 不可被降级(与不可删除/禁用同语义——break-glass
// 能力不可移除);普通管理员间降级不受影响。
func TestUpdateUser_setup_admin_cannot_be_demoted(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	seedUserAuditTest(t, 2, "admin-2", "admin", true)

	rec := serveUserMutation(h, http.MethodPut, "/users/1", `{"role":"user"}`, 2, h.UpdateUser)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "初始管理员") {
		t.Fatalf("demote setup admin must 400, got %d %s", rec.Code, rec.Body.String())
	}
	// 回归形状:普通管理员(id=2)可被另一管理员降级
	rec = serveUserMutation(h, http.MethodPut, "/users/2", `{"role":"user"}`, 1, h.UpdateUser)
	if rec.Code != http.StatusOK {
		t.Fatalf("demote ordinary admin should pass, got %d %s", rec.Code, rec.Body.String())
	}
}

// 回调失败必须 302 回前端错误页(浏览器导航形态),不得渲染裸 JSON。
func TestOIDCCallback_failure_redirects_to_frontend(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code=x&state=forged", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback failure must 302 to frontend, got %d body=%s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "#/oidc/callback?error=") || strings.Contains(loc, "token=") {
		t.Fatalf("failure redirect must carry error fragment without token: %s", loc)
	}
	var msg string
	if u, err := url.Parse(loc); err == nil {
		q := u.Fragment
		if i := strings.Index(q, "?"); i >= 0 {
			q = q[i+1:]
		}
		vals, _ := url.ParseQuery(q)
		msg = vals.Get("error")
	}
	if msg == "" {
		t.Fatalf("error fragment must carry non-empty message: %s", loc)
	}
}

// 补充:负缓存不钉死——invalidate 后上游恢复即成功。
func TestOIDCProvider_invalidate_clears_failure(t *testing.T) {
	var srvURL string
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() || !strings.Contains(r.URL.Path, "openid-configuration") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srvURL})
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL

	fail.Store(true)
	oidcProviderInvalidate(srvURL)
	if _, err := oidcProvider(srvURL); err == nil {
		t.Fatal("expected failure")
	}
	fail.Store(false)
	oidcProviderInvalidate(srvURL)
	if _, err := oidcProvider(srvURL); err != nil {
		t.Fatalf("after invalidate + upstream recovery, discovery must succeed: %v", err)
	}
}

// login 是浏览器整页导航(登录页按钮/链接触发)——失败形态(未启用/
// state 封顶/discovery 失败/随机源失败)一律 302 回前端登录页错误位
// (oidc_error 经 URL fragment 携带),与回调同型,不渲染裸 JSON。
func TestOIDCLogin_failure_redirects_to_login_page(t *testing.T) {
	assertLoginErrorRedirect := func(rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusFound {
			t.Fatalf("login failure must 302 to login page, got %d body=%s", rec.Code, rec.Body.String())
		}
		loc := rec.Header().Get("Location")
		if !strings.Contains(loc, "#/login?oidc_error=") {
			t.Fatalf("failure redirect must target login page oidc_error param: %s", loc)
		}
		msg := loc[strings.Index(loc, "oidc_error=")+len("oidc_error="):]
		decoded, err := url.QueryUnescape(msg)
		if err != nil || decoded == "" {
			t.Fatalf("oidc_error must carry non-empty message: %s", loc)
		}
	}

	// 形状一:未启用(无配置)
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
	assertLoginErrorRedirect(rec)

	// 形状二:discovery 失败(issuer 指向无发现文档的服务)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(dead.Close)
	putOIDCConfig(t, router, `{"issuer":"`+dead.URL+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
	assertLoginErrorRedirect(rec)

	// 形状三:state 在册封顶
	oidcStates.Range(func(k, _ any) bool { oidcStates.Delete(k); return true })
	oidcStateCount.Store(0)
	old := oidcStateMaxEntries
	oidcStateMaxEntries = 0
	t.Cleanup(func() {
		oidcStateMaxEntries = old
		oidcStates.Range(func(k, _ any) bool { oidcStates.Delete(k); return true })
		oidcStateCount.Store(0)
	})
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	oidcProviderInvalidate(idp.issuer)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
	assertLoginErrorRedirect(rec)
}

// 回调 error 参数仅回显 OAuth2 标准错误码——非白名单/超长值一律
// 吞掉(防外部可控文本经登录页当系统提示渲染的社工注入面)。
func TestOIDCCallback_error_param_sanitized(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	loginState := func() string {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
		u, _ := url.Parse(rec.Header().Get("Location"))
		return u.Query().Get("state")
	}
	callbackError := func(errParam string) string {
		t.Helper()
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?state="+loginState()+"&error="+url.QueryEscape(errParam), nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("callback error shape must still 302, got %d body=%s", rec.Code, rec.Body.String())
		}
		loc := rec.Header().Get("Location")
		frag := loc[strings.Index(loc, "#")+1:]
		q := frag[strings.Index(frag, "?")+1:]
		vals, _ := url.ParseQuery(q)
		return vals.Get("error")
	}

	if got := callbackError("access_denied"); got != "提供商拒绝授权: access_denied" {
		t.Fatalf("standard code must be echoed: %q", got)
	}
	if got := callbackError("custom-injected-text"); got != "提供商拒绝授权" {
		t.Fatalf("non-whitelist value must be swallowed: %q", got)
	}
	if got := callbackError(strings.Repeat("a", 65)); got != "提供商拒绝授权" {
		t.Fatalf("oversized value must be swallowed: %q", got)
	}
	if got := callbackError("ACCESS_DENIED"); got != "提供商拒绝授权: ACCESS_DENIED" {
		t.Fatalf("case-insensitive whitelist match must keep original form: %q", got)
	}
}

// JIT 用户名截断必须 rune 安全——byte 截断会把中文/emoji 切成无效
// UTF-8 落库(前端展示乱码),且冲突去重后缀的长度预算须按 rune 计数。
func TestOIDCCallback_jit_username_rune_safe_truncation(t *testing.T) {
	shape := func(pref string, seedCollision string) string {
		idp := newMockIdP(t)
		idp.usePref = true
		idp.prefUsername = pref
		router, _ := setupOIDCTest(t, idp)
		putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
		if seedCollision != "" {
			if _, err := db.DB.Exec("INSERT INTO users (username, password_hash, role, is_enabled, auth_provider) VALUES (?, '', 'user', 1, 'local')", seedCollision); err != nil {
				t.Fatalf("seed collision user: %v", err)
			}
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
		u, _ := url.Parse(rec.Header().Get("Location"))
		code := simulateIdPIssuesCode(t, u.String())
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code="+code+"&state="+u.Query().Get("state"), nil))
		if rec.Code != http.StatusFound || strings.Contains(rec.Header().Get("Location"), "error=") {
			t.Fatalf("callback should succeed, got %d %s", rec.Code, rec.Header().Get("Location"))
		}
		var name string
		if err := db.DB.QueryRow("SELECT username FROM users WHERE auth_provider='oidc'").Scan(&name); err != nil {
			t.Fatalf("read jit user: %v", err)
		}
		return name
	}

	// 形状一:超长中文(60 rune=180 byte)→ 截到整 50 rune 且合法 UTF-8
	name := shape(strings.Repeat("超", 60), "")
	if !utf8.ValidString(name) {
		t.Fatalf("truncated username must be valid UTF-8, got %q", name)
	}
	if got := len([]rune(name)); got != 50 {
		t.Fatalf("truncated username rune count=%d, want 50 (got %q)", got, name)
	}

	// 形状二:40 rune emoji(160 byte 超 50 但 rune 未超)→ 不截断
	emoji := strings.Repeat("😀", 40)
	name = shape(emoji, "")
	if name != emoji {
		t.Fatalf("40-rune emoji username must pass through uncut, got %q (valid=%v)", name, utf8.ValidString(name))
	}

	// 形状三:49 rune 基名撞本地用户 → 后缀去重按 rune 预算(48 rune+"-2"=50)
	base := strings.Repeat("汉", 49)
	name = shape(base, base)
	if !utf8.ValidString(name) || !strings.HasSuffix(name, "-2") {
		t.Fatalf("collision-suffixed username must be valid UTF-8 ending -2, got %q", name)
	}
	if got := len([]rune(name)); got != 50 {
		t.Fatalf("collision-suffixed username rune count=%d, want 50 (got %q)", got, name)
	}
}

// 未认证访问者可见的错误位不得回显服务端原始错误——
// OIDCLogin 的 discovery 失败此前直接 fail(err.Error())，把 IdP 地址/网络
// 错误文本写进 #/login?oidc_error=；与回调 error 参数白名单清洗口径相悖。
// 失败文案归一为固定短句，原始错误仅落日志。
func TestOIDCLogin_failureMessageDoesNotLeakProviderDetail(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(dead.Close)
	oidcProviderInvalidate(dead.URL)
	putOIDCConfig(t, router, `{"issuer":"`+dead.URL+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
	if recorder.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s, want 302", recorder.Code, recorder.Body.String())
	}
	loc := recorder.Header().Get("Location")
	raw := loc[strings.Index(loc, "oidc_error=")+len("oidc_error="):]
	message, err := url.QueryUnescape(raw)
	if err != nil {
		t.Fatalf("unescape oidc_error: %v", err)
	}
	if message != "OIDC 服务不可达，请检查配置" {
		t.Fatalf("oidc_error=%q, want 固定短句「OIDC 服务不可达，请检查配置」", message)
	}
	for _, leaked := range []string{dead.URL, "OIDC 发现失败", "127.0.0.1"} {
		if strings.Contains(message, leaked) {
			t.Fatalf("oidc_error 泄露服务端细节 %q: %q", leaked, message)
		}
	}
}

// 同族：回调侧 provider 构建/令牌交换/id_token 校验失败同样
// 不得把原始错误回显给未认证浏览器。
func TestOIDCCallback_failureMessageDoesNotLeakProviderDetail(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	// 先取一个合法 state，再切到不可达 issuer——回调在 provider 构建阶段失败。
	login := httptest.NewRecorder()
	router.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
	state, _ := url.Parse(login.Header().Get("Location"))
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(dead.Close)
	oidcProviderInvalidate(dead.URL)
	putOIDCConfig(t, router, `{"issuer":"`+dead.URL+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code=x&state="+state.Query().Get("state"), nil))
	if recorder.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s, want 302", recorder.Code, recorder.Body.String())
	}
	loc := recorder.Header().Get("Location")
	frag := loc[strings.Index(loc, "#")+1:]
	frag = frag[strings.Index(frag, "?")+1:]
	values, _ := url.ParseQuery(frag)
	message := values.Get("error")
	if message != "OIDC 服务不可达，请检查配置" {
		t.Fatalf("callback error=%q, want 固定短句「OIDC 服务不可达，请检查配置」", message)
	}
	if strings.Contains(message, dead.URL) || strings.Contains(message, "127.0.0.1") {
		t.Fatalf("callback error 泄露服务端细节: %q", message)
	}
}

// sanitizeOIDCErrorParam 此前无直接测试——表驱动钉住
// 白名单/超长/伪造值三形状（回调端到端形态另有
// TestOIDCCallback_error_param_sanitized）。
func TestSanitizeOIDCErrorParam_shapes(t *testing.T) {
	cases := []struct{ name, raw, want string }{
		{name: "whitelist code", raw: "access_denied", want: "access_denied"},
		{name: "case-insensitive keeps original", raw: "ACCESS_DENIED", want: "ACCESS_DENIED"},
		{name: "surrounding whitespace trimmed", raw: "  login_required  ", want: "login_required"},
		{name: "forged value swallowed", raw: "custom-injected-text", want: ""},
		{name: "html injection swallowed", raw: `<script>alert(1)</script>`, want: ""},
		{name: "oversized swallowed", raw: strings.Repeat("a", 65), want: ""},
		{name: "empty swallowed", raw: "", want: ""},
	}
	for _, tc := range cases {
		if got := sanitizeOIDCErrorParam(tc.raw); got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
