package services

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	mfaRecoveryCodeCount = 10
)

// MFA 业务态错误哨兵：调用方按 errors.Is 映射 400（业务文案），其余错误一律按
// 基础设施故障 500 固定文案 + 日志留痕——认证面不透底层 SQL 错误。
var (
	// ErrMFANoPendingSecret 尚无待激活的 pending 密钥（未 setup 或已被并发覆盖）。
	ErrMFANoPendingSecret = errors.New("没有待激活的 MFA 密钥，请先调用 setup")
	// ErrMFASecretChanged 验证与激活之间 pending 密钥被并发改写。
	ErrMFASecretChanged = errors.New("激活期间密钥已变更，请重新绑定")
	// ErrMFANotEnabled 用户尚无正式 MFA 密钥（未启用/被并发禁用）——验证类
	// 入口据此映射 400 业务文案，不再与查询/写库故障同走 500。
	ErrMFANotEnabled = errors.New("MFA 未启用")
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

// mfaConsumeRecoveryCode 单次消费：命中即从 JSON 数组删除并写回。
// 返回 (命中, 错误)——三态：查询/解析/写库失败是存储错误
// （err != nil），与「码未命中/已被并发消费」（false, nil）严格区分；
// 旧实现把存储错误吞成未命中，handler 侧会当作验证码错误累加失败计数并
// 可能触发账户锁定。
// 消费语句改条件 UPDATE（... AND mfa_recovery_codes=? 旧值 CAS）——
// read-then-write 在毫秒级并发下可双消费同码；CAS 保证只有一个写入者生效。
func mfaConsumeRecoveryCode(userID int, code string) (bool, error) {
	var raw string
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_recovery_codes,'[]') FROM users WHERE id=?", userID).Scan(&raw); err != nil {
		return false, err
	}
	var hashes []string
	if err := json.Unmarshal([]byte(raw), &hashes); err != nil {
		return false, fmt.Errorf("恢复码存储损坏: %w", err)
	}
	sum := sha256.Sum256([]byte(code))
	want := hex.EncodeToString(sum[:])
	for i, h := range hashes {
		if h == want {
			hashes = append(hashes[:i], hashes[i+1:]...)
			j, err := json.Marshal(hashes)
			if err != nil {
				return false, err
			}
			res, err := db.DB.Exec("UPDATE users SET mfa_recovery_codes=? WHERE id=? AND mfa_recovery_codes=?", string(j), userID, raw)
			if err != nil {
				return false, err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return false, err
			}
			// 0 行 = 并发消费方已改写旧值（CAS 落败）→ 本码视为未命中。
			return n == 1, nil
		}
	}
	return false, nil
}

// —— 锁定开关读取（2026-09 裁定：仅登录阶段锁定使用，登录后验证失败不计数）——

// MFALockoutEnabled 读全局锁定开关。
// 读取失败必须显式报错——旧实现返回 false 把「读不到」降级为
// 「开关关闭」，锁定门随之被静默绕过。调用方决定口径。
func MFALockoutEnabled() (bool, error) {
	var v int
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_lockout_enabled,0) FROM global_config WHERE id=1").Scan(&v); err != nil {
		return false, err
	}
	return v == 1, nil
}

// —— 登录后验码限流（仅限流不锁定，与「不计数不锁定」裁定相邻的独立层）——

// 登录后 MFA 验码入口（verify-step/禁用/重绑确认/管理员重置前置验码）此前
// 无任何速率门：6 位码 10⁶ 空间在会话有效期内可枚举，且共用全局 mfaMu 的
// 持续灌压会拖慢全体用户登录。此处加 per-user 滑动窗限流：窗口内失败达上限
// 后调用方回 429，验码成功清零。刻意不落库、不置锁（2026-09「登录后验码
// 只提示不计数不锁定」裁定保持——本层只是速率收敛，重启即失的内存态）。
const (
	mfaVerifyAttemptLimit  = 5
	mfaVerifyAttemptWindow = time.Minute
)

var mfaVerifyAttempts = struct {
	sync.Mutex
	failures  map[int][]time.Time
	lastSweep time.Time
}{failures: make(map[int][]time.Time)}

// mfaPruneVerifyAttemptsLocked 清理窗口外条目（调用方须持锁）。
func mfaPruneVerifyAttemptsLocked(userID int, now time.Time) []time.Time {
	kept := mfaVerifyAttempts.failures[userID][:0]
	for _, at := range mfaVerifyAttempts.failures[userID] {
		if now.Sub(at) < mfaVerifyAttemptWindow {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(mfaVerifyAttempts.failures, userID)
		return nil
	}
	mfaVerifyAttempts.failures[userID] = kept
	return kept
}

// MFAVerifyAttemptLimited 报告该用户登录后验码是否已触发限流（滑动窗内
// 失败次数达上限）。now 由调用方注入以便测试。
func MFAVerifyAttemptLimited(userID int, now time.Time) bool {
	mfaVerifyAttempts.Lock()
	defer mfaVerifyAttempts.Unlock()
	return len(mfaPruneVerifyAttemptsLocked(userID, now)) >= mfaVerifyAttemptLimit
}

// mfaVerifyAttemptsSweepInterval 节制全表清扫频率；窗口内只裁剪当前用户，
// 避免大量活跃失败用户让每笔失败都持锁遍历全表。
const mfaVerifyAttemptsSweepInterval = mfaVerifyAttemptWindow

// mfaVerifyAttemptsSweepThreshold 触发全表清扫的条目数阈值。条目有界于
// 「窗口内失败过的用户数」，删除/一次性用户由周期清扫回收。
const mfaVerifyAttemptsSweepThreshold = 64

// mfaSweepVerifyAttemptsLocked 整表裁剪窗口外条目（调用方须持锁）。
func mfaSweepVerifyAttemptsLocked(now time.Time) {
	for userID := range mfaVerifyAttempts.failures {
		mfaPruneVerifyAttemptsLocked(userID, now)
	}
}

// MFARecordVerifyAttemptFailure 记一次登录后验码失败（仅真验证码错误时调用；
// 基础设施故障与业务态哨兵不计入）。
func MFARecordVerifyAttemptFailure(userID int, now time.Time) {
	mfaVerifyAttempts.Lock()
	defer mfaVerifyAttempts.Unlock()
	kept := mfaPruneVerifyAttemptsLocked(userID, now)
	mfaVerifyAttempts.failures[userID] = append(kept, now)
	if len(mfaVerifyAttempts.failures) > mfaVerifyAttemptsSweepThreshold &&
		(mfaVerifyAttempts.lastSweep.IsZero() || now.Sub(mfaVerifyAttempts.lastSweep) >= mfaVerifyAttemptsSweepInterval) {
		mfaSweepVerifyAttemptsLocked(now)
		mfaVerifyAttempts.lastSweep = now
	}
}

// MFAClearVerifyAttempts 验码成功后清零该用户的限流计数（正常用户不被
// 历史失败拖入 429）。
func MFAClearVerifyAttempts(userID int) {
	mfaVerifyAttempts.Lock()
	delete(mfaVerifyAttempts.failures, userID)
	mfaVerifyAttempts.Unlock()
}

// MFAResetVerifyAttemptsForTest 清空全部限流状态（仅测试：内存态跨用例残留
// 会让同 user id 的后序用例误中 429）。
func MFAResetVerifyAttemptsForTest() {
	mfaVerifyAttempts.Lock()
	mfaVerifyAttempts.failures = make(map[int][]time.Time)
	mfaVerifyAttempts.lastSweep = time.Time{}
	mfaVerifyAttempts.Unlock()
}

// —— 登录二步挑战 ——

// MFAIssueChallenge 密码验证通过后签发 5 分钟单次挑战令牌。
// 挑战落签发时的 users.password_version——验证端要求与当前版本
// 相等，改密/重置后旧挑战立即失效（INSERT..SELECT 单语句取版本，避免
// 「先读版本后写挑战」的竞态窗口）。
func MFAIssueChallenge(userID int) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	res, err := db.DB.Exec(`INSERT INTO mfa_challenges (token,user_id,expires_at,password_version)
		SELECT ?, id, datetime('now','+5 minutes'), COALESCE(password_version,0) FROM users WHERE id=?`,
		token, userID)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return "", fmt.Errorf("用户不存在")
	}
	// 惰性清理过期行（去掉 consumed=1——未消费的过期挑战同样永久不可用，
	// 保留只会无界累积；同 used_login_tickets 先例的「清全部过期」口径）
	_, _ = db.DB.Exec("DELETE FROM mfa_challenges WHERE expires_at < datetime('now')")
	return token, nil
}

// mfaChallengeFailThreshold 是单挑战失败次数的硬闸：全部锁定开关关闭时仍生效。
const mfaChallengeFailThreshold = 10

// MFARecordChallengeFailure 记一次失败；达阈值作废并返回 true。挑战级失败
// 计数独立于全局锁定开关：单挑战失败 10 次即作废（consumed=1）——分布式 IP
// 池对单个 5 分钟挑战的尝试上限从「10/min/IP × N」收敛为固定 10 次。
// 单语句原子形状（UPDATE…RETURNING，与 MFARecordPendingFailure 同族）：
// 计数自增与作废判定同语句——三语句形状（自增→读计数→置作废）在
// 「读计数→置作废」窗口内，并发爆破可越过阈值继续自增且多个调用方同报
// 作废。RETURNING 取回自增后计数，达阈值即本语句已置 consumed=1。
// 返回值语义：true=本次自增使挑战作废（消费方 MFAVerifyLogin 仅作留痕
// 语义忽略返回值——作废状态由 consumed 列承载，消费门自行判定）。
func MFARecordChallengeFailure(token string) bool {
	var attempts int
	if err := db.DB.QueryRow(`UPDATE mfa_challenges
		SET attempts=COALESCE(attempts,0)+1,
		    consumed=CASE WHEN COALESCE(attempts,0)+1>=? THEN 1 ELSE consumed END
		WHERE token=? AND consumed=0 AND expires_at > datetime('now')
		RETURNING COALESCE(attempts,0)`, mfaChallengeFailThreshold, token).Scan(&attempts); err != nil {
		// 挑战不存在/已消费/已过期是正常判定分支；其余写失败说明失败计数
		// 没落库（挑战级作废阈值会静默失效），必须留痕。
		if !errors.Is(err, sql.ErrNoRows) {
			Logf("error", "MFA 挑战失败计数写入失败: %v", err)
		}
		return false
	}
	return attempts >= mfaChallengeFailThreshold
}

// MFAConsumeChallenge 单次消费挑战：存在、未消费、未过期且属主匹配。
// 返回 (false,nil) 仅表示挑战不可消费；SQL/驱动错误必须显式传给调用方。
func MFAConsumeChallenge(token string, userID int) (bool, error) {
	res, err := db.DB.Exec(
		"UPDATE mfa_challenges SET consumed=1 WHERE token=? AND user_id=? AND consumed=0 AND expires_at > datetime('now')",
		token, userID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// MFARestoreChallenge 归还已消费挑战：MFAVerifyLogin
// 先消费后验码，验码失败时挑战必须恢复未消费——错误验证码不烧挑战，用户可持
// 同一 token 重试；失败计数仍由 MFARecordChallengeFailure 负责（达阈值作废）。
// 仅归还属主匹配的挑战；过期行恢复亦无妨（消费判定恒带 expires_at 门）。
//
// 前置条件 attempts < 阈值：两个失败尝试交错时，A 记倒数第 10 次失败已把挑战
// 作废（consumed=1），B 的归还若在此后到达会把作废状态抹回未消费——单挑战
// 10 次硬闸被并发抹平。阈值判定与写入同一条件 UPDATE，归还永不复活已作废挑战。
func MFARestoreChallenge(token string, userID int) {
	// 归还是「错误验证码不烧挑战」的实现基础：写失败会让用户持同一 token
	// 也无法重试（挑战停在已消费态），因此必须留痕而非静默丢弃。
	if _, err := db.DB.Exec("UPDATE mfa_challenges SET consumed=0 WHERE token=? AND user_id=? AND consumed=1 AND COALESCE(attempts,0) < ?",
		token, userID, mfaChallengeFailThreshold); err != nil {
		Logf("warn", "MFA 挑战归还失败: %v", err)
	}
}

// —— 主验证入口 ——

// mfaVerifyTOTPLocked 是 MFAVerifyCode/MFAVerifyTOTPCode 的共享内核
// （历史收敛；调用方须持 mfaMu）：读取 secret 与重放状态——secret 为空报
// 「用户未启用 MFA」（两入口同口径）；code 为 6 位时校验 TOTP，成功推进
// mfa_last_timestep（重放防护：同窗或更早的已用片拒绝，±1 容差窗内；
// 状态写失败必须传播——吞错时同片码可在容差窗内重放换取新
// step-up 窗）。返回 (true,nil)=通过；(false,nil)=码错误/重放/非 6 位；
// (false,err)=查询/写库故障。
func mfaVerifyTOTPLocked(userID int, code string, now time.Time) (bool, error) {
	var secret string
	var lastStep int64
	if err := db.DB.QueryRow(
		"SELECT COALESCE(mfa_secret,''), COALESCE(mfa_last_timestep,0) FROM users WHERE id=?",
		userID).Scan(&secret, &lastStep); err != nil {
		return false, err
	}
	if secret == "" {
		return false, ErrMFANotEnabled
	}
	if len(code) == 6 {
		step, ok := mfaValidateTOTP(secret, code, now)
		if ok {
			if step <= lastStep {
				return false, nil
			}
			if _, err := db.DB.Exec("UPDATE users SET mfa_last_timestep=? WHERE id=?", step, userID); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	// 2026-09 用户裁定：登录后的 MFA 验证失败只提示不计数不锁定（全系统唯一
	// 锁定在登录阶段 5 次/10 分钟、受「登录失败锁定」开关控制；登录两步的
	// 失败计数由 handler 侧 recordLoginFailure 负责）。
	return false, nil
}

// MFAVerifyCode 对启用 MFA 的用户验证 6 位 TOTP 或恢复码（按长度自动分流）。
// 成功：推进 mfa_last_timestep（重放防护）；失败：只提示不计数不锁定（2026-09
// 裁定：全系统唯一锁定=登录阶段密码+验证码同计 5 次/10 分钟、受「登录失败
// 锁定」开关控制，登录两步的失败计数由 handler 侧 recordLoginFailure 负责）。
// 返回 (ok, err)。
func MFAVerifyCode(userID int, code string, now time.Time) (bool, error) {
	mfaMu.Lock()
	defer mfaMu.Unlock()

	code = strings.TrimSpace(code)
	if len(code) >= 10 && len(code) <= 16 {
		// 恢复码通道（一次性应急登录凭证）：secret 门与 TOTP 内核同口径——
		// 恢复码存储由 mfaConsumeRecoveryCode 自读自消费（原入口综合查询里的
		// mfa_recovery_codes 列从未被使用，随本次收敛移除该死读）。
		var secret string
		if err := db.DB.QueryRow("SELECT COALESCE(mfa_secret,'') FROM users WHERE id=?", userID).Scan(&secret); err != nil {
			return false, err
		}
		if secret == "" {
			return false, ErrMFANotEnabled
		}
		consumed, err := mfaConsumeRecoveryCode(userID, code)
		if err != nil {
			return false, err
		}
		return consumed, nil
	}
	return mfaVerifyTOTPLocked(userID, code, now)
}

// MFAVerifyTOTPCode 仅校验 6 位动态验证码（用户裁决 N+10：除登录与重置 MFA
// 外的全部 MFA 入口——verify-step 写守卫链（含配置导入）、重新绑定确认段、
// 禁用确认——不接受恢复码。恢复码是一次性应急登录凭证，其「提交即消费」
// 语义与高敏操作的二次校验/审计链不兼容，且不应作为操作授权凭证）。
// 非 6 位输入与错误 TOTP 同按失败计（硬门冷却同样生效）；不触碰恢复码存储。
func MFAVerifyTOTPCode(userID int, code string, now time.Time) (bool, error) {
	mfaMu.Lock()
	defer mfaMu.Unlock()
	return mfaVerifyTOTPLocked(userID, strings.TrimSpace(code), now)
}

// MFAVerifyPending 绑定向导 activate 步：验证 pending secret 的当前码（无重放状态）。
// 与 MFAVerifyCode/MFAVerifyTOTPCode 同容错——入口
// TrimSpace（粘贴带空格验证码此前恒败）。
func MFAVerifyPending(userID int, code string, now time.Time) (bool, error) {
	var pending string
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_pending_secret,'') FROM users WHERE id=?", userID).Scan(&pending); err != nil {
		return false, err
	}
	if pending == "" {
		return false, ErrMFANoPendingSecret
	}
	code = strings.TrimSpace(code)
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
		return nil, ErrMFANoPendingSecret
	}
	codes, hashesJSON, err := mfaGenerateRecoveryCodes(mfaRecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	// CAS 绑定已验 pending——验证(MFAVerifyPending)与激活两请求间
	// 并发 MFASetup 会覆盖 pending,无条件提升会把未经验码的新 secret 转正
	// (用户 authenticator 持旧值 → MFA 永久不可用,自伤 DoS)。
	result, err := db.DB.Exec(
		"UPDATE users SET mfa_enabled=1, mfa_secret=?, mfa_pending_secret='', mfa_recovery_codes=?, mfa_last_timestep=0 WHERE id=? AND mfa_pending_secret=?",
		pending, hashesJSON, userID, pending)
	if err != nil {
		return nil, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return nil, ErrMFASecretChanged
	}
	return codes, nil
}

// MFARegenerateRecoveryCodes 原地重生成恢复码（旧码全部作废），返回明文。
func MFARegenerateRecoveryCodes(userID int) ([]string, error) {
	// 与 MFAVerifyCode 同持 mfaMu——无锁时与恢复码消费的
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

// mfaPendingFailThreshold pending 验证失败作废阈值（与全局锁定
// 开关无关的硬闸——10^6 码空间在无限流端点上的暴力面由此收敛为 5 次机会）。
const mfaPendingFailThreshold = 5

// MFARecordPendingFailure 记一次 pending 验证失败；达阈值作废 pending 并返回 true。
// 单条原子条件 UPDATE(读-改-写双语句在并发爆破下丢更新,硬闸
// 退化约 2 倍预算)——达阈值同语句清空 pending 并回写 0,以影响行数判定。
// 写失败必须上抛：activate 无登录限流，pending 码空间 10^6 的收敛完全依赖
// 本硬闸；吞错返回 false 会让调用方按「未达阈值」继续放行（DB 写故障期
// 爆破面无限），且应用日志零痕迹。
func MFARecordPendingFailure(userID int) (bool, error) {
	var reset int64
	if err := db.DB.QueryRow(`UPDATE users
		SET mfa_pending_fails=CASE WHEN COALESCE(mfa_pending_fails,0)+1>=? THEN 0 ELSE COALESCE(mfa_pending_fails,0)+1 END,
		    mfa_pending_secret=CASE WHEN COALESCE(mfa_pending_fails,0)+1>=? THEN '' ELSE mfa_pending_secret END
		WHERE id=?
		RETURNING CASE WHEN COALESCE(mfa_pending_fails,0)=0 THEN 1 ELSE 0 END`, mfaPendingFailThreshold, mfaPendingFailThreshold, userID).Scan(&reset); err != nil {
		// 与挑战计数同族留痕（ErrNoRows=用户已不存在，同样不可能记账）。
		Logf("error", "MFA pending 失败计数写入失败: %v", err)
		return false, err
	}
	return reset == 1, nil
}

// MFAClearPendingFailures 成功验证后清零。
func MFAClearPendingFailures(userID int) {
	_, _ = db.DB.Exec("UPDATE users SET mfa_pending_fails=0 WHERE id=?", userID)
}

// MFAResetForUser 管理员重置：清全部 MFA 状态（secret/pending/恢复码/重放片，
// pending 含失败计数）；登录锁定归重置密码路径。
func MFAResetForUser(userID int) error {
	// 同上——重置与消费交错时 '[]' 写回可复活已消费项（虽被 secret
	// 为空挡住，仍按串行化口径统一）。
	mfaMu.Lock()
	defer mfaMu.Unlock()
	_, err := db.DB.Exec(
		"UPDATE users SET mfa_enabled=0, mfa_secret='', mfa_pending_secret='', mfa_pending_fails=0, mfa_recovery_codes='[]', mfa_last_timestep=0 WHERE id=?",
		userID)
	return err
}

// MFAUserEnabledWith 读用户 MFA 启用态（带库句柄版本，与 RoleOf 同族）：
// 守卫链上的读取必须与同请求的其他读取同源——生产两处句柄同一指针，但
// 嵌入/测试装配注入独立句柄时，读包级 db.DB 会让「角色按 A 库、MFA 按 B 库」
// 拼出自相矛盾的判定。
func MFAUserEnabledWith(database *sql.DB, userID int) (bool, error) {
	if database == nil {
		return false, errors.New("读取 MFA 启用态: 数据库未初始化")
	}
	var v int
	err := database.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=?", userID).Scan(&v)
	if err != nil {
		return false, err
	}
	return v == 1, nil
}

// MFAUserEnabled 读用户 MFA 启用态（guard 每请求一次，代价可忽略）。
// 进程库句柄的便捷包装；仅供 handler 直调，守卫链必须用 With 变体。
func MFAUserEnabled(userID int) (bool, error) {
	return MFAUserEnabledWith(db.DB, userID)
}

// MFAStatus 用户 MFA 状态摘要。
type MFAStatus struct {
	Enabled                bool `json:"enabled"`
	RecoveryCodesRemaining int  `json:"recovery_codes_remaining"`
}

// MFAGetStatus 读用户状态。
// 恢复码列解析失败是存储损坏，必须显性报错——
// 此前吞掉 JSON 错误会展示「剩余 0 个」，掩盖损坏且与
// mfaConsumeRecoveryCode 的三态口径分裂。
func MFAGetStatus(userID int) (MFAStatus, error) {
	var enabled bool
	var raw string
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0), COALESCE(mfa_recovery_codes,'[]') FROM users WHERE id=?", userID).Scan(&enabled, &raw); err != nil {
		return MFAStatus{}, err
	}
	var hashes []string
	if err := json.Unmarshal([]byte(raw), &hashes); err != nil {
		return MFAStatus{}, fmt.Errorf("恢复码存储损坏: %w", err)
	}
	return MFAStatus{Enabled: enabled, RecoveryCodesRemaining: len(hashes)}, nil
}

// MFAWriteGuardEnabledWith 读全局写操作验证开关（带库句柄版本，与
// MFAUserEnabledWith 同族——守卫链上两处读取必须与角色读取同源）。
func MFAWriteGuardEnabledWith(database *sql.DB) (bool, error) {
	if database == nil {
		return false, errors.New("读取 MFA 写操作验证开关: 数据库未初始化")
	}
	var v int
	if err := database.QueryRow("SELECT COALESCE(mfa_write_guard,0) FROM global_config WHERE id=1").Scan(&v); err != nil {
		return false, err
	}
	return v == 1, nil
}

// MFAWriteGuardEnabled 读全局写操作验证开关。
// 读取失败必须显式报错——旧实现返回 false 把「读不到」
// 降级为「开关关闭」且无任何留痕，与 MFALockoutEnabled 的裁定（读失败
// 显式报错、调用方决定口径）分裂。调用方各自决定 /路由级
// step-up 守卫按裁定维持 fail-open（第二因子便利层，jwtAuth 已在前序
// fail-closed 把关）但必须留痕；API Key 创建路径与相邻的 MFA 状态读取同口径
// fail-closed。进程库句柄的便捷包装；守卫链必须用 With 变体。
func MFAWriteGuardEnabled() (bool, error) {
	return MFAWriteGuardEnabledWith(db.DB)
}
