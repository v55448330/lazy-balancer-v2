package services

// 证书任务重试冷却的服务端单源策略（列表下发 / 服务端门禁 / 任务监控动态行
// 三处共用）：
//   - disabled：不可重试（永久条件，不是限流），下发侧为 null（不可判定）；
//   - issued：无通用冷却；
//   - failed：通用冷却 5 分钟自 updated_at 起算，但行带 CA 退避窗口
//     （ca_available_after，B2 失败语义统一后所有失败都写：429=Retry-After
//     封顶 3h，其余 1h/2h/3h 阶梯）时并入窗口——窗口远晚于通用冷却；
//   - waiting_ca（仅旧备份/导入存量）：无通用冷却，并入 CA 退避窗口；
//   - queued 15 分钟、其余执行态 2 分钟（均自 updated_at 起算，
//     与重试门同一基准）。
//
// 两个列表接口（/certificates/jobs 与 /system/tasks 的证书行动态行）统一下发
// 「此刻剩余秒」：0 = 现在即可重试，>0 = 还需等待的秒数，null = 该状态永久不可
// 重试。剩余值已按 updated_at 扣减已流逝部分（waiting_ca 取 CA 退避到期时刻），
// 前端判据只需比较「>0」，不得再按 updated_at 二次扣减——曾出现下发剩余秒、
// 前端又从 updated_at 起算时长，冷却过半即引导用户点击一次必然 429 的重试。

import (
	"database/sql"
	"time"
)

// CertJobRetryCooldown 是重试冷却的通用策略源（按状态），返回「完整窗口」。
// 下发口径还要按 updated_at 扣减已流逝部分（见 CertJobRetryRemaining），服务端
// 门禁则先过本窗口、再单独过 CertJobCAcooldownActive（force 可越过）。
func CertJobRetryCooldown(status string) (time.Duration, bool) {
	switch status {
	case "disabled":
		return 0, false
	case "issued", "waiting_ca":
		return 0, true
	case "queued":
		return 15 * time.Minute, true
	case "failed":
		return 5 * time.Minute, true
	default:
		return 2 * time.Minute, true
	}
}

// CertJobCAcooldownActive 报告任务是否仍处于 CA 退避窗口（ca_available_after
// 未到期）。B2 失败语义统一后 waiting_ca 停车状态退役：失败统一落 failed 并
// 携带退避窗口（429=Retry-After 封顶 3h，其余 1h/2h/3h 阶梯）——窗口判据按
// failed 判定；waiting_ca 仅保留给旧备份/导入带来的存量行（迁移前历史形态），
// 窗口语义不变。「任务重试」与「手动触发签发」两个入口必须共用本判据：同状态
// 同语义却一个要求 force、另一个直接重排，会让规则列表的「重新签发」静默越过
// 冷却、清空 ca_available_after 并继续消耗 CA 配额。
func CertJobCAcooldownActive(status string, caAvailableAfter sql.NullTime, now time.Time) bool {
	if !caAvailableAfter.Valid || !now.Before(caAvailableAfter.Time) {
		return false
	}
	return status == "failed" || status == "waiting_ca"
}

// CertJobRetryRemaining 返回「此刻还剩多少冷却」：通用窗口按 updated_at（缺失
// 回退 created_at，两列都缺失按刚更新计满窗口，与重试门的 fail-closed 同口径）
// 扣减已流逝时间；行带 CA 退避窗口（failed/waiting_ca + ca_available_after）
// 时在窗口内直接取 ca_available_after 的剩余。
// ok=false 表示永久不可重试（下发侧应表达为 null，而不是「0=现在可重试」）。
func CertJobRetryRemaining(status string, updatedAt, createdAt, caAvailableAfter sql.NullTime, now time.Time) (time.Duration, bool) {
	window, retryable := CertJobRetryCooldown(status)
	if !retryable {
		return 0, false
	}
	if CertJobCAcooldownActive(status, caAvailableAfter, now) {
		return caAvailableAfter.Time.Sub(now), true
	}
	if window <= 0 {
		return 0, true
	}
	reference := updatedAt
	if !reference.Valid {
		reference = createdAt
	}
	if !reference.Valid {
		return window, true
	}
	if remaining := reference.Time.Add(window).Sub(now); remaining > 0 {
		return remaining, true
	}
	return 0, true
}

// CertJobRetryCooldownSeconds 把剩余时长规范化为下发口径（秒，向上取整）：
// 剩余不足 1 秒时下发 1 而非 0——0 在下发侧语义是「现在即可重试」，会把仍在
// 冷却中的任务引导成一次必然 429 的重试。
func CertJobRetryCooldownSeconds(remaining time.Duration) int64 {
	if remaining <= 0 {
		return 0
	}
	return int64((remaining + time.Second - 1) / time.Second)
}

// CertJobRetryRemainingSeconds 是「此刻剩余冷却（秒）」的下发单源：不可重试
// （disabled）→ ok=false，消费方下发 null；其余按剩余时长取整（0=现在可重试）。
func CertJobRetryRemainingSeconds(status string, updatedAt, createdAt, caAvailableAfter sql.NullTime, now time.Time) (int64, bool) {
	remaining, retryable := CertJobRetryRemaining(status, updatedAt, createdAt, caAvailableAfter, now)
	if !retryable {
		return 0, false
	}
	return CertJobRetryCooldownSeconds(remaining), true
}
