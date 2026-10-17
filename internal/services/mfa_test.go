package services

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// mfaTestEnv 建临时库并注入时间可控环境。
func mfaTestEnv(t *testing.T) {
	t.Helper()
	oldDB := db.DB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("init test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); db.DB = oldDB })
	// Initialize 已种 global_config id=1（caddy_config '{}'）
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
	mfaTestEnv(t)
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
	mfaTestEnv(t)
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
	mfaTestEnv(t)
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

// —— 绑定流程：pending → activate ——

func TestMFASetupActivateFlow(t *testing.T) {
	mfaTestEnv(t)
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
	mfaTestEnv(t)
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
	mfaTestEnv(t)
	mfaSeedUser(t, 6)
	secret, _, _ := MFAGenerateSecret("tester")
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret=?, mfa_pending_fails=3 WHERE id=6", secret); err != nil {
		t.Fatal(err)
	}
	if err := MFAResetForUser(6); err != nil {
		t.Fatal(err)
	}
	st, _ := MFAGetStatus(6)
	if st.Enabled {
		t.Fatal("reset must disable mfa")
	}
	// U6a-2：pending 失败计数随重置一并清零（原死断言 if locked := false 的
	// 替换——锁定本就归重置密码路径，此处钉住 reset 对 MFA 自有状态的覆盖）。
	var enabled, pendingFails int
	if err := db.DB.QueryRow("SELECT mfa_enabled, COALESCE(mfa_pending_fails,0) FROM users WHERE id=6").Scan(&enabled, &pendingFails); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatal("db state mismatch")
	}
	if pendingFails != 0 {
		t.Fatalf("mfa_pending_fails=%d, want 0 (reset must clear pending fail counter)", pendingFails)
	}
}

// —— 全局开关读取 ——

func TestMFAWriteGuardEnabled(t *testing.T) {
	mfaTestEnv(t)
	if MFAWriteGuardEnabled() {
		t.Fatal("default must be off")
	}
	_, _ = db.DB.Exec("UPDATE global_config SET mfa_write_guard=1 WHERE id=1")
	if !MFAWriteGuardEnabled() {
		t.Fatal("toggle read failed")
	}
}

// U7a-P5-4（第 66 轮审计）：三个 TOTP 验证器输入容错须一致——MFAVerifyCode/
// MFAVerifyTOTPCode 均先 TrimSpace，MFAVerifyPending 缺失，绑定向导 activate
// 步粘贴带空格验证码恒失败。
func TestMFAVerifyPending_trimsWhitespace(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 9)
	secret, _, err := MFAGenerateSecret("tester")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_pending_secret=? WHERE id=9", secret); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code := mfaCurrentCode(t, secret, now)

	ok, err := MFAVerifyPending(9, "  "+code+" \t", now)
	if err != nil {
		t.Fatalf("verify pending: %v", err)
	}
	if !ok {
		t.Fatal("padded code must verify（pending 验证须与另两个 TOTP 验证器同容错 TrimSpace）")
	}
}

// U08-F10：挑战级失败计数硬闸——第 10 次失败即作废挑战（与全局锁定开关无关），
// 作废后 MFAConsumeChallenge 恒拒绝。
func TestMFARecordChallengeFailure_invalidatesAtThreshold(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 3)
	const token = "tok-challenge-threshold"
	if _, err := db.DB.Exec(`INSERT INTO mfa_challenges (token, user_id, expires_at, consumed, attempts)
		VALUES (?, 3, datetime('now','+10 minutes'), 0, 0)`, token); err != nil {
		t.Fatal(err)
	}

	for attempt := 1; attempt < mfaChallengeFailThreshold; attempt++ {
		if invalidated := MFARecordChallengeFailure(token); invalidated {
			t.Fatalf("第 %d 次失败不应作废（阈值 %d）", attempt, mfaChallengeFailThreshold)
		}
	}
	if invalidated := MFARecordChallengeFailure(token); !invalidated {
		t.Fatalf("第 %d 次失败必须作废并返回 true", mfaChallengeFailThreshold)
	}
	var consumed bool
	var attempts int
	if err := db.DB.QueryRow(`SELECT COALESCE(consumed,0), COALESCE(attempts,0) FROM mfa_challenges WHERE token=?`, token).Scan(&consumed, &attempts); err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatal("达阈值后挑战必须置 consumed=1")
	}
	if attempts != mfaChallengeFailThreshold {
		t.Fatalf("attempts=%d, want %d", attempts, mfaChallengeFailThreshold)
	}
	if MFAConsumeChallenge(token, 3) {
		t.Fatal("作废后的挑战不得再被消费")
	}
}

// U08-F10：pending 验证失败第 5 次即作废 pending secret（重新 setup 才能再试）。
func TestMFARecordPendingFailure_invalidatesAtThreshold(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 4)
	secret, _, err := MFAGenerateSecret("tester")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE users SET mfa_pending_secret=?, mfa_pending_fails=0 WHERE id=4`, secret); err != nil {
		t.Fatal(err)
	}

	for attempt := 1; attempt < mfaPendingFailThreshold; attempt++ {
		if invalidated := MFARecordPendingFailure(4); invalidated {
			t.Fatalf("第 %d 次 pending 失败不应作废（阈值 %d）", attempt, mfaPendingFailThreshold)
		}
	}
	if invalidated := MFARecordPendingFailure(4); !invalidated {
		t.Fatalf("第 %d 次 pending 失败必须作废并返回 true", mfaPendingFailThreshold)
	}
	var pending string
	var fails int
	if err := db.DB.QueryRow(`SELECT COALESCE(mfa_pending_secret,''), COALESCE(mfa_pending_fails,0) FROM users WHERE id=4`).Scan(&pending, &fails); err != nil {
		t.Fatal(err)
	}
	if pending != "" {
		t.Fatalf("pending secret 未清空: %q", pending)
	}
	if fails != 0 {
		t.Fatalf("pending 失败计数未复位: %d", fails)
	}
	if _, err := MFAVerifyPending(4, "123456", time.Now()); err == nil {
		t.Fatal("作废后 MFAVerifyPending 必须报「没有待激活的 MFA 密钥」")
	}
}

// U08-F10：restore 不复活已作废挑战——按 handler 真实顺序（consume→验码失败
// →restore→record failure）驱动 10 轮后，第 11 次登录在 consume 门即被拒绝
// （restore 只在 consume 成功后调用，作废行不经过恢复路径）。
func TestMFARestoreChallenge_invalidatedChallengeStaysDead(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 5)
	const token = "tok-restore-order"
	if _, err := db.DB.Exec(`INSERT INTO mfa_challenges (token, user_id, expires_at, consumed, attempts)
		VALUES (?, 5, datetime('now','+10 minutes'), 0, 0)`, token); err != nil {
		t.Fatal(err)
	}

	for round := 1; round <= mfaChallengeFailThreshold; round++ {
		if !MFAConsumeChallenge(token, 5) {
			t.Fatalf("第 %d 轮 consume 应成功（未达阈值）", round)
		}
		MFARestoreChallenge(token, 5) // 错误码不烧挑战
		MFARecordChallengeFailure(token)
	}
	if MFAConsumeChallenge(token, 5) {
		t.Fatal("达阈值后的挑战不得复活（consume 门必须拒绝，restore 不可达）")
	}
	var consumed bool
	var attempts int
	if err := db.DB.QueryRow(`SELECT COALESCE(consumed,0), COALESCE(attempts,0) FROM mfa_challenges WHERE token=?`, token).Scan(&consumed, &attempts); err != nil {
		t.Fatal(err)
	}
	if !consumed || attempts != mfaChallengeFailThreshold {
		t.Fatalf("终态 consumed=%v attempts=%d, want consumed=true attempts=%d", consumed, attempts, mfaChallengeFailThreshold)
	}
}
