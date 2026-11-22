package notify

// 认证失败通知去抖（登录失败 / MFA 验证失败）：按「用户|IP」10 分钟窗口，
// 首次发布、窗口内静默。暴力破解尝试会按请求产生失败事件——不去抖会灌满
// 发布队列（与 cc_triggered 逐 IP 去抖同因）。
//
// 终态原因（账户已锁定/已禁用）绕过去抖立即发布：这类结果不是重复尝试的
// 噪音，而是账户状态的安全事实，任何一次都不得被窗口吞掉。

import (
	"strings"
	"sync"
	"time"
)

const authFailureDedupWindow = 10 * time.Minute

var (
	authFailureMu   sync.Mutex
	authFailureSeen = map[string]time.Time{} // 用户|IP → 上次发布时刻
	// authFailureNow 测试缝（生产恒 time.Now）。
	authFailureNow = time.Now
)

// PublishLoginFailed 发布登录失败（用户|IP 去抖；终态原因绕过）。
// Fields 键序=目录模板参数序「用户（原因），来源 IP」。
func PublishLoginFailed(username, reason, ip string) {
	if authFailureDebounced(username, ip, reason) {
		// 通知静默但日报认证计数仍按每次失败累加（去抖只作用于通知噪音，
		// 不得让失败统计少记）。
		noteAuthEvent(EvtLoginFailed)
		return
	}
	Publish(Event{Type: EvtLoginFailed,
		Fields: map[string]string{"1": username, "2": reason, "3": ip}})
}

// PublishMFAVerifyFailed 发布 MFA 验证码校验失败（用户|IP 去抖；终态原因绕过）。
// Fields 键序=目录模板参数序「用户（失败详情）」。
func PublishMFAVerifyFailed(username, detail, ip string) {
	if authFailureDebounced(username, ip, detail) {
		// 同登录失败：通知去抖不减少日报 MFA 失败计数。
		noteAuthEvent(EvtMFAVerifyFailed)
		return
	}
	Publish(Event{Type: EvtMFAVerifyFailed,
		Fields: map[string]string{"1": username, "2": detail}})
}

// authFailureDebounced 报告本次失败是否应静默（窗口内重复）。终态原因恒不
// 静默，且不占用/刷新窗口（锁定/禁用事实重复出现时仍每次可见）。
func authFailureDebounced(username, ip, reason string) bool {
	if authFailureTerminalReason(reason) {
		return false
	}
	now := authFailureNow()
	key := username + "|" + ip
	authFailureMu.Lock()
	defer authFailureMu.Unlock()
	if at, ok := authFailureSeen[key]; ok && now.Sub(at) < authFailureDedupWindow {
		return true
	}
	authFailureSeen[key] = now
	pruneAuthFailureLocked(now)
	return false
}

// authFailureTerminalReason 终态原因判定（锁定/禁用）。用「已锁定/已禁用」
// 完整语义词而非裸「锁定/禁用」——MFA 失败详情「禁用 MFA 前验证失败」不含
// 账户终态语义，不得绕过认证失败去抖。
func authFailureTerminalReason(reason string) bool {
	return strings.Contains(reason, "已锁定") || strings.Contains(reason, "已禁用")
}

// pruneAuthFailureLocked 清理超窗条目（随写入懒清理，map 有界）。
func pruneAuthFailureLocked(now time.Time) {
	for key, at := range authFailureSeen {
		if now.Sub(at) >= authFailureDedupWindow {
			delete(authFailureSeen, key)
		}
	}
}
