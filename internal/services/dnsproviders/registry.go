package dnsproviders

type CredentialField struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Placeholder string `json:"placeholder,omitempty"`
}

type Provider interface {
	Code() string
	Name() string
	ModuleName() string
	CredentialFields() []CredentialField
	CredentialFieldOptions(field string) []string
	BuildCredentialsJSON(creds map[string]string) (map[string]interface{}, error)
	Validate(creds map[string]string, testDomain string) error
}

type BaseProvider struct{}

func (b *BaseProvider) CredentialFieldOptions(field string) []string { return nil }

func (b *BaseProvider) Validate(creds map[string]string, testDomain string) error {
	return nil
}

var registry = map[string]Provider{}

func Register(p Provider) {
	registry[p.Code()] = p
}

func Get(code string) (Provider, bool) {
	p, ok := registry[code]
	return p, ok
}

func List() []Provider {
	list := make([]Provider, 0, len(registry))
	for _, p := range registry {
		list = append(list, p)
	}
	return list
}
