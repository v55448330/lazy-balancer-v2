package dnsprovider

import (
	"encoding/json"
	"fmt"
	"strings"

	"lazy-balancer-v2/internal/dnsprovider/dnspod"
	"lazy-balancer-v2/internal/dnsprovider/tencent"
)

// DNSCredentials is the unified credential envelope stored in global_config.dns_credentials.
type DNSCredentials struct {
	Mode      string `json:"mode"` // "dnspod" or "tencent"
	APIToken  string `json:"api_token,omitempty"`
	SecretID  string `json:"secret_id,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
}

// NewProviderFromCredentials parses the stored JSON credentials and returns the appropriate Provider.
func NewProviderFromCredentials(rawJSON string) (Provider, error) {
	var creds DNSCredentials
	if err := json.Unmarshal([]byte(rawJSON), &creds); err != nil {
		return nil, fmt.Errorf("invalid dns credentials: %w", err)
	}

	switch strings.ToLower(creds.Mode) {
	case "dnspod":
		if creds.APIToken == "" {
			return nil, fmt.Errorf("DNSPod credentials require api_token")
		}
		return dnspod.New(creds.APIToken), nil
	case "tencent":
		if creds.SecretID == "" || creds.SecretKey == "" {
			return nil, fmt.Errorf("Tencent Cloud credentials require secret_id and secret_key")
		}
		return tencent.New(creds.SecretID, creds.SecretKey)
	default:
		return nil, fmt.Errorf("unsupported dns provider mode: %s", creds.Mode)
	}
}
