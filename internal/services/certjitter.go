package services

import (
	"hash/fnv"
	"time"
)

// 自动重签时间抖动（2026-10-30 用户裁定）：全部证书规则不再在同一时刻（到期前
// 恰好 renewalDays 窗口）扎堆涌入续签扫描——按规则 ID 确定性抖动，把每条规则
// 的入队时刻摊开在「到期前窗口 − 6h」区间：
//
//	jitter = FNV-1a32(rule_id) % 21600   （0–6h，确定性）
//
// 确定性 = 前后端同算法同值：前端镜像实现 web/src/utils/certJobExpiry.ts
// certRenewalJitterSeconds（手写 FNV-1a32），「自动重签时间」列显示
// expires_at − 窗口 − jitter，与扫描入队判据同一时刻。两侧各持同一份固定向量表
// （certjitter_test.go / certJobExpiry.spec.ts），任一侧算法或模数漂移即同时红。

// certRenewalJitterWindowSeconds 抖动窗口上界（6h，模数）。
const certRenewalJitterWindowSeconds = 6 * 60 * 60

// CertRenewalJitterSeconds 返回规则 ID 的确定性续签抖动秒数（[0, 6h)）。
func CertRenewalJitterSeconds(ruleID string) int64 {
	h := fnv.New32a()
	// hash.Hash 的 Write 按 stdlib 契约永不返回错误
	_, _ = h.Write([]byte(ruleID))
	return int64(h.Sum32() % certRenewalJitterWindowSeconds)
}

// certRenewalJitter 扫描比较用的 Duration 形态。
func certRenewalJitter(ruleID string) time.Duration {
	return time.Duration(CertRenewalJitterSeconds(ruleID)) * time.Second
}
