package dnsproviders

import "testing"

func TestDNSPodCredentials(t *testing.T) {
	p, ok := Get("dnspod")
	if !ok {
		t.Fatal("dnspod not registered")
	}
	_, err := p.BuildCredentialsJSON(map[string]string{})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestCloudflareCredentials(t *testing.T) {
	p, ok := Get("cloudflare")
	if !ok {
		t.Fatal("cloudflare not registered")
	}
	_, err := p.BuildCredentialsJSON(map[string]string{})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestListProviders(t *testing.T) {
	list := List()
	if len(list) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(list))
	}
}

func TestEnvVarName(t *testing.T) {
	p, _ := Get("dnspod")
	name := EnvVarName(42, p)
	if name != "DNSPOD_AUTH_TOKEN_42" {
		t.Fatalf("unexpected env var name: %s", name)
	}
}
