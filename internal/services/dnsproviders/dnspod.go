package dnsproviders

import "fmt"

func init() { Register(&DNSPod{}) }

type DNSPod struct{}

func (d *DNSPod) Code() string       { return "dnspod" }
func (d *DNSPod) Name() string       { return "DNSPod (腾讯云)" }
func (d *DNSPod) ModuleName() string { return "dns.providers.dnspod" }
func (d *DNSPod) EnvVarPrefix() string { return "DNSPOD_AUTH_TOKEN" }

func (d *DNSPod) CredentialFields() []CredentialField {
	return []CredentialField{
		{Name: "auth_token", Label: "Auth Token", Type: "password", Required: true, Placeholder: "APP_ID,APP_TOKEN"},
	}
}

func (d *DNSPod) BuildCredentialsJSON(creds map[string]string) (map[string]interface{}, error) {
	if creds["auth_token"] == "" {
		return nil, fmt.Errorf("auth_token is required")
	}
	return map[string]interface{}{
		"auth_token": creds["auth_token"],
	}, nil
}
