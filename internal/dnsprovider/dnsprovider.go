package dnsprovider

import "context"

// Provider abstracts DNS record manipulation for ACME DNS-01 challenges.
type Provider interface {
	// Present creates a distinct _acme-challenge TXT record and retains its provider record ID.
	Present(ctx context.Context, zone, tokenFQDN, value string, ttl int) error
	// CleanUp removes only record IDs created by this provider instance for the challenge name.
	CleanUp(ctx context.Context, zone, tokenFQDN string) error
}
