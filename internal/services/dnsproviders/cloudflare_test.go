package dnsproviders

import (
	"context"
	"errors"
	"testing"

	"lazy-balancer-v2/internal/dnsprovider"
)

// fakeVerifyProvider 是 VerifyToken 能力的探针替身：记录调用形态与 ctx 透传。
type fakeVerifyProvider struct {
	verifyCalls int
	verifyErr   error
	lastCtx     context.Context
}

func (f *fakeVerifyProvider) Present(context.Context, string, string, string, int) error {
	return nil
}

func (f *fakeVerifyProvider) CleanUp(context.Context, string, string) error { return nil }

func (f *fakeVerifyProvider) VerifyToken(ctx context.Context) error {
	f.verifyCalls++
	f.lastCtx = ctx
	return f.verifyErr
}

func TestCloudflare_metadata(t *testing.T) {
	provider := &Cloudflare{}
	if provider.Code() != "cloudflare" {
		t.Fatalf("code=%q, want cloudflare", provider.Code())
	}
	if provider.Name() != "Cloudflare" {
		t.Fatalf("name=%q, want Cloudflare", provider.Name())
	}
	if provider.ModuleName() != "dns.providers.cloudflare" {
		t.Fatalf("moduleName=%q, want dns.providers.cloudflare", provider.ModuleName())
	}

	fields := provider.CredentialFields()
	if len(fields) != 2 {
		t.Fatalf("fields=%d, want 2（auth_mode + api_token）", len(fields))
	}
	authMode := fields[0]
	if authMode.Name != "auth_mode" || authMode.Type != "select" || !authMode.Required {
		t.Fatalf("auth_mode 字段=%+v, want select 且必填", authMode)
	}
	if got, want := authMode.OptionLabels["cloudflare"], "API Token"; got != want {
		t.Fatalf("auth_mode option_labels[cloudflare]=%q, want %q", got, want)
	}
	tokenField := fields[1]
	if tokenField.Name != "api_token" || tokenField.Type != "password" || !tokenField.Required {
		t.Fatalf("api_token 字段=%+v, want password 且必填", tokenField)
	}
	if got, ok := tokenField.VisibleWhen["auth_mode"]; !ok || len(got) != 1 || got[0] != "cloudflare" {
		t.Fatalf("api_token visible_when=%v, want auth_mode=[cloudflare]", tokenField.VisibleWhen)
	}
	if options := provider.CredentialFieldOptions("auth_mode"); len(options) != 1 || options[0] != "cloudflare" {
		t.Fatalf("auth_mode options=%v, want [cloudflare]（api_token 单形态）", options)
	}
}

func TestCloudflare_registered(t *testing.T) {
	if _, ok := Get("cloudflare"); !ok {
		t.Fatal("cloudflare 未注册（init Register 缺失）")
	}
	codes := make(map[string]bool, 0)
	for _, p := range List() {
		codes[p.Code()] = true
	}
	if !codes["cloudflare"] {
		t.Fatal("List() 缺 cloudflare")
	}
}

// buildCredentials 同时接受 UI 形态与 canonical 形态，产出可回喂；他族凭据
// 显性拒绝（fail-visible，provider 元数据与凭据真相不得分裂）。
func TestCloudflare_BuildCredentialsJSON_canonicalizes(t *testing.T) {
	provider := &Cloudflare{}
	for name, input := range map[string]map[string]string{
		"ui form":         {"auth_mode": "cloudflare", "api_token": "cf-tok"},
		"canonical form":  {"mode": "cloudflare", "api_token": "cf-tok"},
		"with auth alias": {"auth_mode": "cloudflare", "mode": "dnspod", "api_token": "cf-tok"},
	} {
		canonical, err := provider.BuildCredentialsJSON(input)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if canonical["mode"] != "cloudflare" || canonical["api_token"] != "cf-tok" {
			t.Fatalf("%s canonical=%v, want cloudflare/api_token", name, canonical)
		}
	}
	for name, input := range map[string]map[string]string{
		"dnspod token":  {"mode": "dnspod", "api_token": "123,abc"},
		"tencent pair":  {"mode": "tencent", "secret_id": "sid", "secret_key": "skey"},
		"aliyun pair":   {"mode": "aliyun", "access_key_id": "ak", "access_key_secret": "sk"},
		"missing token": {"auth_mode": "cloudflare"},
	} {
		if _, err := provider.BuildCredentialsJSON(input); err == nil {
			t.Fatalf("%s 必须拒绝（fail-visible）", name)
		}
	}
}

// Validate 走 GET /user/tokens/verify 真实验证（provider 构造经可替换接缝）：
// Token 验证失败原样上抛、凭据缺失在 provider 构造前失败。
func TestCloudflare_Validate_invokesTokenVerify(t *testing.T) {
	restore := newDNSProviderFromCredentials
	t.Cleanup(func() { newDNSProviderFromCredentials = restore })

	provider := &Cloudflare{}
	creds := map[string]string{"auth_mode": "cloudflare", "api_token": "cf-tok"}

	t.Run("success", func(t *testing.T) {
		fake := &fakeVerifyProvider{}
		newDNSProviderFromCredentials = func(string) (dnsprovider.Provider, error) { return fake, nil }
		ctx := context.WithValue(context.Background(), struct{}{}, "probe")
		if err := provider.Validate(ctx, creds, "example.com"); err != nil {
			t.Fatalf("validate: %v", err)
		}
		if fake.verifyCalls != 1 {
			t.Fatalf("verifyCalls=%d, want 1", fake.verifyCalls)
		}
		if fake.lastCtx != ctx {
			t.Fatal("调用方 ctx 未透传（请求断开/超时必须立即可见）")
		}
	})

	t.Run("verify failure propagates", func(t *testing.T) {
		fake := &fakeVerifyProvider{verifyErr: errors.New("Token 无效或已被撤销: code=9109: Invalid API Token")}
		newDNSProviderFromCredentials = func(string) (dnsprovider.Provider, error) { return fake, nil }
		err := provider.Validate(context.Background(), creds, "example.com")
		if err == nil || !errors.Is(err, fake.verifyErr) {
			t.Fatalf("error=%v, want 原样上抛 VerifyToken 错误", err)
		}
	})

	t.Run("invalid credentials rejected before construction", func(t *testing.T) {
		called := false
		newDNSProviderFromCredentials = func(string) (dnsprovider.Provider, error) {
			called = true
			return &fakeVerifyProvider{}, nil
		}
		if err := provider.Validate(context.Background(), map[string]string{"auth_mode": "cloudflare"}, "example.com"); err == nil {
			t.Fatal("缺 token 必须失败")
		}
		if called {
			t.Fatal("凭据缺失不得进入 provider 构造")
		}
	})
}
