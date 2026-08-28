package dnsprovider

import "context"

// Provider abstracts DNS record manipulation for ACME DNS-01 challenges.
type Provider interface {
	// Present creates a distinct _acme-challenge TXT record and retains its provider record ID.
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
