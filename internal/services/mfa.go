package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"lazy-balancer-v2/internal/db"
)

// —— 常量（v2.1.8 MFA）——
const (
	mfaChallengeTTL      = 5 * time.Minute
	mfaRecoveryCodeCount = 10
	mfaLockoutThreshold  = 5
	mfaLockoutDuration   = 10 * time.Minute
	mfaStepUpWindow      = 10 * time.Minute
)

var mfaMu sync.Mutex

// MFAGenerateSecret 生成新 TOTP 密钥（base32，用户绑定向导用；存 pending 直至
// activate）。返回 (secret, otpauth URI)——URI 由库按规范构造，账号位进
// Authenticator 显示。accountName 即用户名。
func MFAGenerateSecret(accountName string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: "LazyBalancer", AccountName: accountName,
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// mfaValidateTOTP 校验 6 位验证码（±1 窗容差），返回命中的时间片（用于重放防护）。
// currentTimesec 由调用方注入以便测试。
func mfaValidateTOTP(secret, code string, now time.Time) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	t := now.Unix()
	for _, drift := range []int64{0, -30, 30} {
		valid, err := totp.ValidateCustom(code, secret, now.Add(time.Duration(drift)*time.Second),
			totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err == nil && valid {
			step := (t + drift) / 30
			return step, true
		}
	}
	return 0, false
}

// —— 恢复代码 ——

// mfaGenerateRecoveryCodes 生成 n 个恢复码，返回 (明文列表, SHA-256 哈希 JSON)。
func mfaGenerateRecoveryCodes(n int) ([]string, string, error) {
	codes := make([]string, 0, n)
	hashes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		raw := make([]byte, 10)
		if _, err := rand.Read(raw); err != nil {
			return nil, "", err
		}
		code := base32.StdEncoding.EncodeToString(raw) // 16 字符
		code = strings.TrimRight(code, "=")
		codes = append(codes, code)
		sum := sha256.Sum256([]byte(code))
		hashes = append(hashes, hex.EncodeToString(sum[:]))
	}
	j, err := json.Marshal(hashes)
	if err != nil {
		return nil, "", err
	}
	return codes, string(j), nil
}

// mfaConsumeRecoveryCode 单次消费：命中即从 JSON 数组删除并写回，返回是否命中。
// R72 S-3：消费语句改条件 UPDATE（... AND mfa_recovery_codes=? 旧值 CAS）——
// read-then-write 在毫秒级并发下可双消费同码；CAS 保证只有一个写入者生效。
func mfaConsumeRecoveryCode(userID int, code string) bool {
	var raw string
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_recovery_codes,'[]') FROM users WHERE id=?", userID).Scan(&raw); err != nil {
		return false
	}
	var hashes []string
	if err := json.Unmarshal([]byte(raw), &hashes); err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(code))
	want := hex.EncodeToString(sum[:])
	for i, h := range hashes {
		if h == want {
			hashes = append(hashes[:i], hashes[i+1:]...)
			j, _ := json.Marshal(hashes)
			res, err := db.DB.Exec("UPDATE users SET mfa_recovery_codes=? WHERE id=? AND mfa_recovery_codes=?", string(j), userID, raw)
			if err != nil {
				return false
			}
			n, _ := res.RowsAffected()
			return n == 1
		}
	}
	return false
}

// —— 失败计数与锁定（全局开关 mfa_lockout_enabled）——

// MFALockoutEnabled 读全局锁定开关。
func MFALockoutEnabled() bool {
	var v int
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_lockout_enabled,0) FROM global_config WHERE id=1").Scan(&v); err != nil {
		return false
	}
	return v == 1
}

// mfaIsLocked 用户锁定中返回剩余时间。
func mfaIsLocked(userID int, now time.Time) (bool, time.Duration) {
	var lockedUntil *time.Time
	if err := db.DB.QueryRow("SELECT mfa_locked_until FROM users WHERE id=?", userID).Scan(&lockedUntil); err != nil || lockedUntil == nil {
		return false, 0
	}
	if now.Before(*lockedUntil) {
		return true, lockedUntil.Sub(now)
	}
	return false, 0
}

// mfaRecordFailure 记一次失败；全局开关开且达阈值 → 锁 10 分钟（计数归零）。
// 返回（是否触发新锁定, 锁定剩余, 是否已处于锁定）。
func mfaRecordFailure(userID int, now time.Time) (locked bool, remaining time.Duration, alreadyLocked bool) {
	if al, _ := mfaIsLocked(userID, now); al {
		return false, 0, true
	}
	if !MFALockoutEnabled() {
		_, _ = db.DB.Exec("UPDATE users SET mfa_failed_attempts=COALESCE(mfa_failed_attempts,0)+1 WHERE id=?", userID)
		return false, 0, false
	}
	var attempts int
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_failed_attempts,0) FROM users WHERE id=?", userID).Scan(&attempts); err != nil {
		return false, 0, false
	}
	attempts++
	if attempts >= mfaLockoutThreshold {
		_, _ = db.DB.Exec("UPDATE users SET mfa_failed_attempts=0, mfa_locked_until=? WHERE id=?",
			now.Add(mfaLockoutDuration).UTC().Format("2006-01-02 15:04:05"), userID)
		return true, mfaLockoutDuration, false
	}
	_, _ = db.DB.Exec("UPDATE users SET mfa_failed_attempts=? WHERE id=?", attempts, userID)
	return false, 0, false
}

// mfaResetFailure 成功验证后清零计数。
func mfaResetFailure(userID int) {
	_, _ = db.DB.Exec("UPDATE users SET mfa_failed_attempts=0 WHERE id=?", userID)
}

// —— 登录二步挑战 ——

// MFAIssueChallenge 密码验证通过后签发 5 分钟单次挑战令牌。
func MFAIssueChallenge(userID int) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	_, err := db.DB.Exec("INSERT INTO mfa_challenges (token,user_id,expires_at) VALUES (?,?,datetime('now','+5 minutes'))",
		token, userID)
	if err != nil {
		return "", err
	}
	// 惰性清理过期行（R72：去掉 consumed=1——未消费的过期挑战同样永久不可用，
	// 保留只会无界累积；同 used_login_tickets 先例的「清全部过期」口径）
	_, _ = db.DB.Exec("DELETE FROM mfa_challenges WHERE expires_at < datetime('now')")
	return token, nil
}

// MFARecordChallengeFailure 挑战级失败计数（R72 B-I-4 硬闸）：单挑战失败 10 次
// 即作废（consumed=1）——与全局锁定开关无关的爆破收敛（分布式 IP 池对单个
// 5 分钟挑战的尝试上限从「10/min/IP × N」收敛为固定 10 次）。
const mfaChallengeFailThreshold = 10

// MFARecordChallengeFailure 记一次失败；达阈值作废并返回 true。
func MFARecordChallengeFailure(token string) bool {
	res, err := db.DB.Exec("UPDATE mfa_challenges SET attempts=COALESCE(attempts,0)+1 WHERE token=? AND consumed=0 AND expires_at > datetime('now')", token)
	if err != nil {
		return false
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false
	}
	var attempts int
	if err := db.DB.QueryRow("SELECT COALESCE(attempts,0) FROM mfa_challenges WHERE token=?", token).Scan(&attempts); err != nil {
		return false
	}
	if attempts >= mfaChallengeFailThreshold {
		_, _ = db.DB.Exec("UPDATE mfa_challenges SET consumed=1 WHERE token=?", token)
		return true
	}
	return false
}

// MFAConsumeChallenge 单次消费挑战：存在、未消费、未过期且属主匹配。
func MFAConsumeChallenge(token string, userID int) bool {
	res, err := db.DB.Exec(
		"UPDATE mfa_challenges SET consumed=1 WHERE token=? AND user_id=? AND consumed=0 AND expires_at > datetime('now')",
		token, userID)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

// —— 主验证入口 ——

// MFAVerifyCode 对启用 MFA 的用户验证 6 位 TOTP 或恢复码（按长度自动分流）。
// 成功：清失败计数、推进 mfa_last_timestep（重放防护）；失败：按全局开关计数/锁定。
// 返回 (ok, err)；锁定期间恒 false。
func MFAVerifyCode(userID int, code string, now time.Time) (bool, error) {
	mfaMu.Lock()
	defer mfaMu.Unlock()

	if al, _ := mfaIsLocked(userID, now); al {
		return false, fmt.Errorf("MFA 验证已锁定，请 10 分钟后重试")
	}

	var secret, recoveryJSON string
	var lastStep int64
	if err := db.DB.QueryRow(
		"SELECT COALESCE(mfa_secret,''), COALESCE(mfa_recovery_codes,'[]'), COALESCE(mfa_last_timestep,0) FROM users WHERE id=?",
		userID).Scan(&secret, &recoveryJSON, &lastStep); err != nil {
		return false, err
	}
	if secret == "" {
		return false, fmt.Errorf("用户未启用 MFA")
	}

	code = strings.TrimSpace(code)
	if len(code) == 6 {
		step, ok := mfaValidateTOTP(secret, code, now)
		if ok {
			// 重放防护：同窗或更早的已用片拒绝（±1 容差窗内）
			if step <= lastStep {
				mfaRecordFailure(userID, now)
				return false, nil
			}
			_, _ = db.DB.Exec("UPDATE users SET mfa_last_timestep=?, mfa_failed_attempts=0 WHERE id=?", step, userID)
			return true, nil
		}
	} else if len(code) >= 10 && len(code) <= 16 {
		if mfaConsumeRecoveryCode(userID, code) {
			mfaResetFailure(userID)
			return true, nil
		}
	}

	_, _, already := mfaRecordFailure(userID, now)
	if already {
		return false, fmt.Errorf("MFA 验证已锁定，请 10 分钟后重试")
	}
	return false, nil
}

// MFAVerifyPending 绑定向导 activate 步：验证 pending secret 的当前码（无重放状态）。
func MFAVerifyPending(userID int, code string, now time.Time) (bool, error) {
	var pending string
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_pending_secret,'') FROM users WHERE id=?", userID).Scan(&pending); err != nil {
		return false, err
	}
	if pending == "" {
		return false, fmt.Errorf("没有待激活的 MFA 密钥，请先调用 setup")
	}
	_, ok := mfaValidateTOTP(pending, code, now)
	return ok, nil
}

// MFAActivate 绑定完成：pending → 正式 secret + 生成恢复码。
// 返回明文恢复码（仅此一次）。
func MFAActivate(userID int) ([]string, error) {
	mfaMu.Lock()
	defer mfaMu.Unlock()

	var pending string
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_pending_secret,'') FROM users WHERE id=?", userID).Scan(&pending); err != nil {
		return nil, err
	}
	if pending == "" {
		return nil, fmt.Errorf("没有待激活的 MFA 密钥")
	}
	codes, hashesJSON, err := mfaGenerateRecoveryCodes(mfaRecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	if _, err := db.DB.Exec(
		"UPDATE users SET mfa_enabled=1, mfa_secret=?, mfa_pending_secret='', mfa_recovery_codes=?, mfa_last_timestep=0, mfa_failed_attempts=0 WHERE id=?",
		pending, hashesJSON, userID); err != nil {
		return nil, err
	}
	return codes, nil
}

// MFARegenerateRecoveryCodes 原地重生成恢复码（旧码全部作废），返回明文。
func MFARegenerateRecoveryCodes(userID int) ([]string, error) {
	// R72 F-5：与 MFAVerifyCode 同持 mfaMu——无锁时与恢复码消费的
	// read-then-write 交错会把刚生成的 10 个新码静默作废。
	mfaMu.Lock()
	defer mfaMu.Unlock()
	codes, hashesJSON, err := mfaGenerateRecoveryCodes(mfaRecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_recovery_codes=? WHERE id=?", hashesJSON, userID); err != nil {
		return nil, err
	}
	return codes, nil
}

// mfaPendingFailThreshold pending 验证失败作废阈值（R72 A-F-2：与全局锁定
// 开关无关的硬闸——10^6 码空间在无限流端点上的暴力面由此收敛为 5 次机会）。
const mfaPendingFailThreshold = 5

// MFARecordPendingFailure 记一次 pending 验证失败；达阈值作废 pending 并返回 true。
func MFARecordPendingFailure(userID int) bool {
	var fails int
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_pending_fails,0) FROM users WHERE id=?", userID).Scan(&fails); err != nil {
		return false
	}
	fails++
	if fails >= mfaPendingFailThreshold {
		_, _ = db.DB.Exec("UPDATE users SET mfa_pending_secret='', mfa_pending_fails=0 WHERE id=?", userID)
		return true
	}
	_, _ = db.DB.Exec("UPDATE users SET mfa_pending_fails=? WHERE id=?", fails, userID)
	return false
}

// MFAClearPendingFailures 成功验证后清零。
func MFAClearPendingFailures(userID int) {
	_, _ = db.DB.Exec("UPDATE users SET mfa_pending_fails=0 WHERE id=?", userID)
}

// MFAResetForUser 管理员重置：清全部 MFA 状态（含锁定/计数/pending）。
func MFAResetForUser(userID int) error {
	// R72 F-5：同上——重置与消费交错时 '[]' 写回可复活已消费项（虽被 secret
	// 为空挡住，仍按串行化口径统一）。
	mfaMu.Lock()
	defer mfaMu.Unlock()
	_, err := db.DB.Exec(
		"UPDATE users SET mfa_enabled=0, mfa_secret='', mfa_pending_secret='', mfa_recovery_codes='[]', mfa_last_timestep=0, mfa_failed_attempts=0, mfa_locked_until=NULL WHERE id=?",
		userID)
	return err
}

// MFAUserEnabled 读用户 MFA 启用态（guard 每请求一次，代价可忽略）。
func MFAUserEnabled(userID int) (bool, error) {
	var v int
	err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=?", userID).Scan(&v)
	if err != nil {
		return false, err
	}
	return v == 1, nil
}

// MFAStatus 用户 MFA 状态摘要。
type MFAStatus struct {
	Enabled                bool `json:"enabled"`
	RecoveryCodesRemaining int  `json:"recovery_codes_remaining"`
}

// MFAGetStatus 读用户状态。
func MFAGetStatus(userID int) (MFAStatus, error) {
	var enabled bool
	var raw string
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0), COALESCE(mfa_recovery_codes,'[]') FROM users WHERE id=?", userID).Scan(&enabled, &raw); err != nil {
		return MFAStatus{}, err
	}
	var hashes []string
	_ = json.Unmarshal([]byte(raw), &hashes)
	return MFAStatus{Enabled: enabled, RecoveryCodesRemaining: len(hashes)}, nil
}

// MFAWriteGuardEnabled 读全局写操作验证开关。
func MFAWriteGuardEnabled() bool {
	var v int
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_write_guard,0) FROM global_config WHERE id=1").Scan(&v); err != nil {
		return false
	}
	return v == 1
}
