package services

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// mfaTestEnv 建临时库并注入时间可控环境。
func mfaTestEnv(t *testing.T) *int {
	t.Helper()
	oldDB := db.DB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("init test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); db.DB = oldDB })
	// Initialize 已种 global_config id=1（caddy_config '{}'）
	return new(int)
}

func mfaSeedUser(t *testing.T, id int) {
	t.Helper()
	if _, err := db.DB.Exec(
		"INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (?,?,?,'admin',1)",
		id, "u"+string(rune('0'+id)), "x"); err != nil {
		t.Fatal(err)
	}
}

func mfaCurrentCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// —— RFC 6238 契约：真实 TOTP 码往返 ——

func TestMFAValidateTOTP_roundtrip(t *testing.T) {
	_ = mfaTestEnv(t)
	secret, _, err := MFAGenerateSecret("tester")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code := mfaCurrentCode(t, secret, now)
	if step, ok := mfaValidateTOTP(secret, code, now); !ok || step <= 0 {
		t.Fatalf("current-window code rejected (step=%d)", step)
	}
	// ±1 窗容差
	if _, ok := mfaValidateTOTP(secret, code, now.Add(25*time.Second)); !ok {
		t.Fatal("−1 window tolerance failed")
	}
	if _, ok := mfaValidateTOTP(secret, code, now.Add(-25*time.Second)); !ok {
		t.Fatal("+1 window tolerance failed")
	}
	// 超容差拒绝
	if _, ok := mfaValidateTOTP(secret, code, now.Add(95*time.Second)); ok {
		t.Fatal("code beyond ±1 window must be rejected")
	}
	// 错码拒绝
	if _, ok := mfaValidateTOTP(secret, "000000", now); ok {
		t.Fatal("wrong code accepted")
	}
}

// —— 重放防护 ——

func TestMFAVerifyCode_replayRejected(t *testing.T) {
	_ = mfaTestEnv(t)
	mfaSeedUser(t, 1)
	secret, _, _ := MFAGenerateSecret("tester")
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret=? WHERE id=1", secret); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code := mfaCurrentCode(t, secret, now)
	if ok, _ := MFAVerifyCode(1, code, now); !ok {
		t.Fatal("first use must succeed")
	}
	if ok, _ := MFAVerifyCode(1, code, now.Add(time.Second)); ok {
		t.Fatal("same-window replay must be rejected")
	}
	if ok, _ := MFAVerifyCode(1, code, now.Add(-time.Second)); ok {
		t.Fatal("earlier-window replay must be rejected")
	}
}

// —— 恢复码：单次消费 ——

func TestMFARecoveryCodes_singleUse(t *testing.T) {
	_ = mfaTestEnv(t)
	mfaSeedUser(t, 2)
	secret, _, _ := MFAGenerateSecret("tester")
	codes, hashes, err := mfaGenerateRecoveryCodes(mfaRecoveryCodeCount)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret=?, mfa_recovery_codes=? WHERE id=2", secret, hashes); err != nil {
		t.Fatal(err)
	}
	if len(codes) != mfaRecoveryCodeCount {
		t.Fatalf("codes=%d want %d", len(codes), mfaRecoveryCodeCount)
	}
	now := time.Now()
	if ok, _ := MFAVerifyCode(2, codes[0], now); !ok {
		t.Fatal("recovery code must verify")
	}
	if ok, _ := MFAVerifyCode(2, codes[0], now); ok {
		t.Fatal("recovery code reuse must be rejected")
	}
	st, _ := MFAGetStatus(2)
	if st.RecoveryCodesRemaining != mfaRecoveryCodeCount-1 {
		t.Fatalf("remaining=%d want %d", st.RecoveryCodesRemaining, mfaRecoveryCodeCount-1)
	}
	// 第二个码仍可用
	if ok, _ := MFAVerifyCode(2, codes[1], now); !ok {
		t.Fatal("second recovery code must still work")
	}
}

// —— 锁定：全局开关门控 ——

func TestMFALockout_globalToggle(t *testing.T) {
	_ = mfaTestEnv(t)
	mfaSeedUser(t, 3)
	secret, _, _ := MFAGenerateSecret("tester")
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret=? WHERE id=3", secret); err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	// 开关关：不锁定
	for i := 0; i < mfaLockoutThreshold+2; i++ {
		if ok, _ := MFAVerifyCode(3, "000000", now); ok {
			t.Fatal("bad code accepted")
		}
	}
	if locked, _ := mfaIsLocked(3, now); locked {
		t.Fatal("lockout must not engage when global toggle off")
	}

	// 开关开：达阈值锁定（计数延续——开关关闭期的失败也计入，防「关开关刷掉
	// 计数再开启」的绕过；本阶段先手工清零模拟新部署起点）
	if _, err := db.DB.Exec("UPDATE global_config SET mfa_lockout_enabled=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_failed_attempts=0 WHERE id=3"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < mfaLockoutThreshold-1; i++ {
		_, _ = MFAVerifyCode(3, "000000", now)
	}
	if locked, _ := mfaIsLocked(3, now); locked {
		t.Fatal("lockout must not engage before threshold")
	}
	// 第 5 次 → 锁定；正确码也被 423 拒
	if ok, _ := MFAVerifyCode(3, "000000", now); ok {
		t.Fatal("bad code accepted")
	}
	if locked, rem := mfaIsLocked(3, now); !locked || rem <= 0 || rem > mfaLockoutDuration {
		t.Fatalf("locked=%v rem=%v", locked, rem)
	}
	goodCode := mfaCurrentCode(t, secret, now)
	if ok, err := MFAVerifyCode(3, goodCode, now); ok || err == nil {
		t.Fatal("locked user must be rejected even with valid code")
	}
	// 到期自动解锁（时间前进）
	future := now.Add(mfaLockoutDuration + time.Minute)
	validCode := mfaCurrentCode(t, secret, future)
	if ok, err := MFAVerifyCode(3, validCode, future); !ok || err != nil {
		t.Fatalf("after lockout expiry valid code must pass: ok=%v err=%v", ok, err)
	}
}

// —— 绑定流程：pending → activate ——

func TestMFASetupActivateFlow(t *testing.T) {
	_ = mfaTestEnv(t)
	mfaSeedUser(t, 4)
	if _, err := db.DB.Exec("UPDATE users SET mfa_pending_secret='junk' WHERE id=4"); err != nil {
		t.Fatal(err)
	}
	// VerifyPending with a TOTP of the REAL secret we'll set next
	secret, _, _ := MFAGenerateSecret("tester")
	if _, err := db.DB.Exec("UPDATE users SET mfa_pending_secret=? WHERE id=4", secret); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code := mfaCurrentCode(t, secret, now)
	if ok, _ := MFAVerifyPending(4, code, now); !ok {
		t.Fatal("pending verify failed for current code")
	}
	codes, err := MFAActivate(4)
	if err != nil || len(codes) != mfaRecoveryCodeCount {
		t.Fatalf("activate: %v codes=%d", err, len(codes))
	}
	st, _ := MFAGetStatus(4)
	if !st.Enabled {
		t.Fatal("activate must set mfa_enabled")
	}
	// activate 幂等保护：pending 已清，再 activate 报错
	if _, err := MFAActivate(4); err == nil {
		t.Fatal("second activate must fail (pending cleared)")
	}
}

// —— 挑战：单次 + 过期 ——

func TestMFAChallengeLifecycle(t *testing.T) {
	_ = mfaTestEnv(t)
	mfaSeedUser(t, 5)
	tok, err := MFAIssueChallenge(5)
	if err != nil || tok == "" {
		t.Fatal(err)
	}
	if !MFAConsumeChallenge(tok, 5) {
		t.Fatal("first consume must succeed")
	}
	if MFAConsumeChallenge(tok, 5) {
		t.Fatal("replay consume must fail")
	}
	if MFAConsumeChallenge(tok, 999) {
		t.Fatal("wrong owner must fail")
	}
	// 过期：手工回拨
	tok2, _ := MFAIssueChallenge(5)
	if _, err := db.DB.Exec("UPDATE mfa_challenges SET expires_at=datetime('now','-1 minute') WHERE token=?", tok2); err != nil {
		t.Fatal(err)
	}
	if MFAConsumeChallenge(tok2, 5) {
		t.Fatal("expired challenge must fail")
	}
}

// —— 管理员重置 ——

func TestMFAResetForUser(t *testing.T) {
	_ = mfaTestEnv(t)
	mfaSeedUser(t, 6)
	secret, _, _ := MFAGenerateSecret("tester")
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret=?, mfa_failed_attempts=3, mfa_locked_until=datetime('now','+5 minutes') WHERE id=6", secret); err != nil {
		t.Fatal(err)
	}
	if err := MFAResetForUser(6); err != nil {
		t.Fatal(err)
	}
	st, _ := MFAGetStatus(6)
	if st.Enabled {
		t.Fatal("reset must disable mfa")
	}
	if locked, _ := mfaIsLocked(6, time.Now()); locked {
		t.Fatal("reset must clear lockout")
	}
	var enabled int
	_ = db.DB.QueryRow("SELECT mfa_enabled FROM users WHERE id=6").Scan(&enabled)
	if enabled != 0 {
		t.Fatal("db state mismatch")
	}
}

// —— 全局开关读取 ——

func TestMFAWriteGuardEnabled(t *testing.T) {
	_ = mfaTestEnv(t)
	if MFAWriteGuardEnabled() {
		t.Fatal("default must be off")
	}
	_, _ = db.DB.Exec("UPDATE global_config SET mfa_write_guard=1 WHERE id=1")
	if !MFAWriteGuardEnabled() {
		t.Fatal("toggle read failed")
	}
}
