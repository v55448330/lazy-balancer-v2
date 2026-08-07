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
	return newProviderFromCredentials(rawJSON, "")
}

func NewPersistentProviderFromCredentials(rawJSON, dataDir string) (Provider, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("DNS ownership data directory is required")
	}
	return newProviderFromCredentials(rawJSON, dataDir)
}

func newProviderFromCredentials(rawJSON, dataDir string) (Provider, error) {
	var creds DNSCredentials
	if err := json.Unmarshal([]byte(rawJSON), &creds); err != nil {
		return nil, fmt.Errorf("invalid dns credentials: %w", err)
	}

	// Support credentials saved by the UI certificate-configs form, which use
	// auth_mode, app_id, app_token (DNSPod) or auth_mode, secret_id, secret_key (Tencent).
	if creds.Mode == "" {
		var legacy struct {
			AuthMode  string `json:"auth_mode"`
			AppID     string `json:"app_id"`
			AppToken  string `json:"app_token"`
			SecretID  string `json:"secret_id"`
			SecretKey string `json:"secret_key"`
		}
		if err := json.Unmarshal([]byte(rawJSON), &legacy); err == nil {
			creds.Mode = legacy.AuthMode
			if creds.APIToken == "" && legacy.AppID != "" && legacy.AppToken != "" {
				creds.APIToken = legacy.AppID + "," + legacy.AppToken
			}
			if creds.SecretID == "" {
				creds.SecretID = legacy.SecretID
			}
			if creds.SecretKey == "" {
				creds.SecretKey = legacy.SecretKey
			}
		}
	}

	switch strings.ToLower(creds.Mode) {
	case "dnspod":
		if creds.APIToken == "" {
			return nil, fmt.Errorf("DNSPod credentials require api_token")
		}
		if dataDir != "" {
			return dnspod.NewPersistent(creds.APIToken, dataDir)
		}
		return dnspod.New(creds.APIToken), nil
	case "tencent", "tencent_cloud":
		if creds.SecretID == "" || creds.SecretKey == "" {
			return nil, fmt.Errorf("Tencent Cloud credentials require secret_id and secret_key")
		}
		if dataDir != "" {
			return tencent.NewPersistent(creds.SecretID, creds.SecretKey, dataDir)
		}
		return tencent.New(creds.SecretID, creds.SecretKey)
	default:
		return nil, fmt.Errorf("unsupported dns provider mode: %s", creds.Mode)
	}
}
