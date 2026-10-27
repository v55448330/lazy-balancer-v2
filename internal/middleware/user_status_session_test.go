package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/db"
)

type sessionLoginResponse struct {
	Token       string `json:"token"`
	MFAToken    string `json:"mfa_token"`
	MFARequired bool   `json:"mfa_required"`
}

func serveSessionRequest(t *testing.T, router *gin.Engine, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func loginForSessionTest(t *testing.T, router *gin.Engine, username, password string) sessionLoginResponse {
	t.Helper()
	response := serveSessionRequest(t, router, http.MethodPost, "/api/v1/auth/login", `{"username":"`+username+`","password":"`+password+`"}`, "")
	if response.Code != http.StatusOK {
		t.Fatalf("login %s: status=%d body=%s", username, response.Code, response.Body.String())
	}
	var body sessionLoginResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	return body
}

func setUserEnabledForSessionTest(t *testing.T, router *gin.Engine, userID string, enabled bool, adminToken string) {
	t.Helper()
	body := `{"is_enabled":false}`
	if enabled {
		body = `{"is_enabled":true}`
	}
	response := serveSessionRequest(t, router, http.MethodPut, "/api/v1/users/"+userID+"/status", body, adminToken)
	if response.Code != http.StatusOK {
		t.Fatalf("set user %s enabled=%v: status=%d body=%s", userID, enabled, response.Code, response.Body.String())
	}
}

func requireSessionStatus(t *testing.T, router *gin.Engine, token string, want int) {
	t.Helper()
	response := serveSessionRequest(t, router, http.MethodGet, "/api/v1/users/me", "", token)
	if response.Code != want {
		t.Fatalf("GET /users/me: status=%d body=%s, want %d", response.Code, response.Body.String(), want)
	}
}

func seedSessionPassword(t *testing.T) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(hash)
}

func TestUserStatusToggle_revokesOldSessionAcrossDisableEnable(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	hash := seedSessionPassword(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES
		(1,'admin',?,'admin',1),(2,'local-user',?,'user',1),
		(3,'oidc-user','','user',1)`, hash, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE users SET auth_provider='oidc',oidc_issuer='https://issuer.example',oidc_subject='subject-1' WHERE id=3"); err != nil {
		t.Fatal(err)
	}
	adminToken := loginForSessionTest(t, router, "admin", "Secret123!").Token
	oldLocalToken := loginForSessionTest(t, router, "local-user", "Secret123!").Token
	requireSessionStatus(t, router, oldLocalToken, http.StatusOK)

	setUserEnabledForSessionTest(t, router, "2", false, adminToken)
	requireSessionStatus(t, router, oldLocalToken, http.StatusUnauthorized)
	setUserEnabledForSessionTest(t, router, "2", true, adminToken)
	requireSessionStatus(t, router, oldLocalToken, http.StatusUnauthorized)
	var version int
	if err := db.DB.QueryRow("SELECT password_version FROM users WHERE id=2").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("local password_version=%d, want 2 after disable+enable", version)
	}

	newLocalToken := loginForSessionTest(t, router, "local-user", "Secret123!").Token
	if newLocalToken == "" {
		t.Fatal("re-enabled user must receive a new token")
	}
	requireSessionStatus(t, router, newLocalToken, http.StatusOK)
	change := serveSessionRequest(t, router, http.MethodPatch, "/api/v1/users/me", `{"password":"NewSecret123!","current_password":"Secret123!"}`, newLocalToken)
	if change.Code != http.StatusOK {
		t.Fatalf("normal password change: status=%d body=%s", change.Code, change.Body.String())
	}
	requireSessionStatus(t, router, newLocalToken, http.StatusUnauthorized)
	changedPasswordToken := loginForSessionTest(t, router, "local-user", "NewSecret123!").Token
	requireSessionStatus(t, router, changedPasswordToken, http.StatusOK)

	oldOIDCToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": 3, "username": "oidc-user", "role": "user", "auth_method": "oidc",
		"pwd_ver": 0, "jti": "oidc-before-status-toggle", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	requireSessionStatus(t, router, oldOIDCToken, http.StatusOK)
	setUserEnabledForSessionTest(t, router, "3", false, adminToken)
	setUserEnabledForSessionTest(t, router, "3", true, adminToken)
	requireSessionStatus(t, router, oldOIDCToken, http.StatusUnauthorized)
	if err := db.DB.QueryRow("SELECT password_version FROM users WHERE id=3").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("OIDC password_version=%d, want 2 after disable+enable", version)
	}
}

func TestUserStatusToggle_revokesPendingMFAChallenge(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	hash := seedSessionPassword(t)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin',?,'admin',1)`, hash); err != nil {
		t.Fatal(err)
	}
	const recoveryCode = "STATUSRECOVERY01"
	digest := sha256.Sum256([]byte(recoveryCode))
	recoveryHashes := `["` + hex.EncodeToString(digest[:]) + `"]`
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled,mfa_secret,mfa_recovery_codes)
		VALUES (2,'mfa-user',?,'user',1,1,'JBSWY3DPEHPK3PXP',?)`, hash, recoveryHashes); err != nil {
		t.Fatal(err)
	}
	adminToken := loginForSessionTest(t, router, "admin", "Secret123!").Token
	oldChallenge := loginForSessionTest(t, router, "mfa-user", "Secret123!")
	if !oldChallenge.MFARequired || oldChallenge.MFAToken == "" {
		t.Fatalf("password step did not issue MFA challenge: %+v", oldChallenge)
	}

	setUserEnabledForSessionTest(t, router, "2", false, adminToken)
	setUserEnabledForSessionTest(t, router, "2", true, adminToken)
	// 必须在 verify 之前直查：拒绝旧 token 的路径也会惰性删挑战，事后才查
	// 无法区分「启停时主动吊销」与「verify 顺带清理」。
	var challenges int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM mfa_challenges WHERE user_id=2").Scan(&challenges); err != nil {
		t.Fatal(err)
	}
	if challenges != 0 {
		t.Fatalf("old MFA challenges remaining immediately after status toggle=%d, want 0", challenges)
	}
	oldVerification := serveSessionRequest(t, router, http.MethodPost, "/api/v1/auth/mfa/verify", `{"mfa_token":"`+oldChallenge.MFAToken+`","code":"`+recoveryCode+`"}`, "")
	if oldVerification.Code != http.StatusUnauthorized {
		t.Fatalf("old MFA challenge after re-enable: status=%d body=%s, want 401", oldVerification.Code, oldVerification.Body.String())
	}
	var storedHashes string
	if err := db.DB.QueryRow("SELECT mfa_recovery_codes FROM users WHERE id=2").Scan(&storedHashes); err != nil {
		t.Fatal(err)
	}
	if storedHashes != recoveryHashes {
		t.Fatal("rejected old challenge must not consume the recovery code")
	}

	newChallenge := loginForSessionTest(t, router, "mfa-user", "Secret123!")
	newVerification := serveSessionRequest(t, router, http.MethodPost, "/api/v1/auth/mfa/verify", `{"mfa_token":"`+newChallenge.MFAToken+`","code":"`+recoveryCode+`"}`, "")
	if newVerification.Code != http.StatusOK {
		t.Fatalf("new MFA challenge after re-enable: status=%d body=%s", newVerification.Code, newVerification.Body.String())
	}
	var login sessionLoginResponse
	if err := json.Unmarshal(newVerification.Body.Bytes(), &login); err != nil || login.Token == "" {
		t.Fatalf("new MFA login token missing: err=%v body=%s", err, newVerification.Body.String())
	}
	requireSessionStatus(t, router, login.Token, http.StatusOK)
}
