package dnsproviders

import "fmt"

func init() { Register(&Cloudflare{}) }

type Cloudflare struct{}

func (c *Cloudflare) Code() string       { return "cloudflare" }
func (c *Cloudflare) Name() string       { return "Cloudflare" }
func (c *Cloudflare) ModuleName() string { return "dns.providers.cloudflare" }
func (c *Cloudflare) EnvVarPrefix() string { return "CF_API_TOKEN" }

func (c *Cloudflare) CredentialFields() []CredentialField {
	return []CredentialField{
		{Name: "api_token", Label: "API Token", Type: "password", Required: true},
	}
}

func (c *Cloudflare) BuildCredentialsJSON(creds map[string]string) (map[string]interface{}, error) {
	if creds["api_token"] == "" {
		return nil, fmt.Errorf("api_token is required")
	}
	return map[string]interface{}{
		"api_token": creds["api_token"],
	}, nil
}
