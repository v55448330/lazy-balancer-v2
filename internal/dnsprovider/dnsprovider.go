package dnsprovider

import "context"

// Provider abstracts DNS record manipulation for ACME DNS-01 challenges.
type Provider interface {
	// Present creates or updates the _acme-challenge TXT record.
	Present(ctx context.Context, zone, tokenFQDN, value string, ttl int) error
	// CleanUp removes the _acme-challenge TXT record.
	CleanUp(ctx context.Context, zone, tokenFQDN string) error
}
