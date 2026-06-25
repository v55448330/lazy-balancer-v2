package dnsproviders

import "fmt"

func init() { Register(&DNSPod{}) }

type DNSPod struct{}

func (d *DNSPod) Code() string       { return "dnspod" }
func (d *DNSPod) Name() string       { return "DNSPod (腾讯云)" }
func (d *DNSPod) ModuleName() string { return "dns.providers.dnspod" }

func (d *DNSPod) CredentialFields() []CredentialField {
	return []CredentialField{
		{Name: "app_id", Label: "App ID", Type: "text", Required: true, Placeholder: "12345"},
		{Name: "app_token", Label: "App Token", Type: "password", Required: true, Placeholder: "Your DNSPod API token"},
	}
}

func (d *DNSPod) BuildCredentialsJSON(creds map[string]string) (map[string]interface{}, error) {
	appID := creds["app_id"]
	appToken := creds["app_token"]
	if appID != "" && appToken != "" {
		return map[string]interface{}{
			"api_token": appID + "," + appToken,
		}, nil
	}
	// Backward compatibility with legacy auth_token field
	if authToken := creds["auth_token"]; authToken != "" {
		return map[string]interface{}{
			"api_token": authToken,
		}, nil
	}
	return nil, fmt.Errorf("app_id and app_token are required")
}
