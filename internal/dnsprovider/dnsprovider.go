package dnsprovider

import "context"

// Provider abstracts DNS record manipulation for ACME DNS-01 challenges.
type Provider interface {
	// Present creates (or reuses an existing same-value) _acme-challenge TXT record and retains its provider record ID.
	Present(ctx context.Context, zone, tokenFQDN, value string, ttl int) error
	// CleanUp removes only record IDs created by this provider instance for the challenge name.
	CleanUp(ctx context.Context, zone, tokenFQDN string) error
}

// ValueCleaner is the optional capability of removing only the TXT records
// that were created for one specific challenge value. Concurrent issuances
// for the same domain present different values; value-aware cleanup deletes
// only the caller's own record (plus legacy/stale leftovers) instead of
// every record under the challenge name.
type ValueCleaner interface {
	CleanUpValue(ctx context.Context, zone, tokenFQDN, value string) error
}

// CleanUpChallenge removes the DNS-01 records owned by one challenge value.
// Providers without value awareness fall back to name-based cleanup.
func CleanUpChallenge(ctx context.Context, provider Provider, zone, tokenFQDN, value string) error {
	if valueCleaner, ok := provider.(ValueCleaner); ok {
		return valueCleaner.CleanUpValue(ctx, zone, tokenFQDN, value)
	}
	return provider.CleanUp(ctx, zone, tokenFQDN)
}

// CleanupCounter 是可选能力：报告一次按值清理将选中的记录条数。计数必须
// 纯本地（ownership 账本/内存表），不得引入网络往返——调用方在 deferred
// 清理开始前排定预算。读取失败按至少 1 条计（预算宁大勿小）。
type CleanupCounter interface {
	CountCleanupRecords(zone, tokenFQDN, value string) int
}

// CountChallengeCleanupRecords 返回一个挑战的按值清理将尝试删除的记录条数
// （本挑战自建记录 + 同名 legacy/stale 回收条目）。provider 无计数能力时按
// 1 条计（本挑战自建记录恒在）。
func CountChallengeCleanupRecords(provider Provider, zone, tokenFQDN, value string) int {
	if counter, ok := provider.(CleanupCounter); ok {
		if n := counter.CountCleanupRecords(zone, tokenFQDN, value); n > 0 {
			return n
		}
	}
	return 1
}
