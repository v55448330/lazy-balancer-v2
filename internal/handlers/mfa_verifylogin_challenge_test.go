package handlers

// F49-13（第 49 轮审计）：MFAVerifyLogin 必须先消费挑战、后验码。
// 旧顺序（先 MFAVerifyCode 后 MFAConsumeChallenge）下「挑战已被使用」401
// 发生在验码之后——恢复码「提交即消费」，挑战作废场景（并发登录/过期窗口）
// 白烧一枚恢复码却换不到登录。新契约：
//   - 挑战已消费 → 401「MFA 挑战已被使用」且验码不执行（恢复码不减少）；
//   - 验证码错误 → 挑战不被消费（同 token 重试仍可成功）。

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
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

// seedMFAChallengeLoginFixture 建 MFA 登录二步的最小夹具：启用 MFA 的用户 +
// 一条挑战；返回 (secret, 用户 ID)。与 auth_login_provider_test.go 同 schema 形状。
func seedMFAChallengeLoginFixture(t *testing.T, challengeToken string, consumed int) (string, int64) {
	t.Helper()
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`ALTER TABLE users ADD COLUMN mfa_secret TEXT DEFAULT '';
		ALTER TABLE users ADD COLUMN mfa_recovery_codes TEXT DEFAULT '[]';
		ALTER TABLE users ADD COLUMN mfa_last_timestep INTEGER DEFAULT 0;
		CREATE TABLE mfa_challenges (
			token TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			expires_at DATETIME NOT NULL,
			consumed BOOLEAN DEFAULT 0,
			attempts INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
		t.Fatalf("add mfa schema: %v", err)
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: "LazyBalancer", AccountName: "mfa-user",
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,mfa_enabled,mfa_secret) VALUES ('mfa-root',?,'admin',1,1,?)`, string(hash), key.Secret()); err != nil {
		t.Fatalf("seed mfa user: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO mfa_challenges (token,user_id,expires_at,consumed) VALUES (?, (SELECT id FROM users WHERE username='mfa-root'), datetime('now','+5 minutes'), ?)`, challengeToken, consumed); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}
	var userID int64
	if err := database.QueryRow(`SELECT id FROM users WHERE username='mfa-root'`).Scan(&userID); err != nil {
		t.Fatalf("read user id: %v", err)
	}
	return key.Secret(), userID
}

func postMFAVerify(t *testing.T, router *gin.Engine, token, code string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/auth/mfa/verify",
		strings.NewReader(`{"mfa_token":"`+token+`","code":"`+code+`"}`)))
	return recorder
}

func currentTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestMFAVerifyLogin_consumedChallengeDoesNotBurnRecoveryCode(t *testing.T) {
	// Given：启用 MFA 的用户持两枚恢复码；挑战已被消费（并发登录胜出方/作阈值作废后重放）
	_, userID := seedMFAChallengeLoginFixture(t, "consumed-tok", 1)
	recoveryCode := "RECOVERYCODE1234" // 16 字符，走恢复码分支
	sum := sha256.Sum256([]byte(recoveryCode))
	hashes, _ := json.Marshal([]string{hex.EncodeToString(sum[:]), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"})
	if _, err := db.DB.Exec(`UPDATE users SET mfa_recovery_codes=? WHERE id=?`, string(hashes), userID); err != nil {
		t.Fatalf("seed recovery codes: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	// When：持已消费挑战 + 有效恢复码提交
	recorder := postMFAVerify(t, router, "consumed-tok", recoveryCode)

	// Then 1：401 且为「挑战已被使用」语义（消费判定是挑战状态的唯一权威）
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "MFA 挑战已被使用") {
		t.Fatalf("message=%s, want 「MFA 挑战已被使用」", recorder.Body.String())
	}
	// Then 2：验码不得执行——恢复码一枚不少（修复前旧顺序先验码，恢复码被白烧）
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(mfa_recovery_codes,'[]') FROM users WHERE id=?`, userID).Scan(&raw); err != nil {
		t.Fatalf("read recovery codes: %v", err)
	}
	var remaining []string
	if err := json.Unmarshal([]byte(raw), &remaining); err != nil {
		t.Fatalf("decode recovery codes: %v", err)
	}
	if len(remaining) != 2 {
		t.Fatalf("恢复码被白烧：剩余 %d 枚（应 2 枚），raw=%s", len(remaining), raw)
	}
}

func TestMFAVerifyLogin_wrongCodeKeepsChallengeRetryable(t *testing.T) {
	// Given：有效挑战 + 启用 MFA 的用户
	secret, _ := seedMFAChallengeLoginFixture(t, "retry-tok", 0)
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	// When 1：提交错误验证码
	correct := currentTOTPCode(t, secret)
	wrong := "000000"
	if correct == wrong {
		wrong = "000001"
	}
	first := postMFAVerify(t, router, "retry-tok", wrong)
	if first.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code status=%d body=%s, want 401", first.Code, first.Body.String())
	}

	// Then 1：挑战不被消费（验码失败不烧挑战）
	var consumed int
	if err := db.DB.QueryRow(`SELECT consumed FROM mfa_challenges WHERE token='retry-tok'`).Scan(&consumed); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if consumed != 0 {
		t.Fatalf("验码失败烧掉了挑战：consumed=%d（同 token 应可重试）", consumed)
	}

	// When 2/Then 2：同 token 重试正确验证码 → 登录成功
	second := postMFAVerify(t, router, "retry-tok", correct)
	if second.Code != http.StatusOK {
		t.Fatalf("retry status=%d body=%s, want 200", second.Code, second.Body.String())
	}
}
