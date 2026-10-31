package dnsproviders

import (
	"context"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/dnsprovider"
)

// Given：注册表中的阿里云 provider。
// When：读取元数据。
// Then：Code/Name/ModuleName 与凭据字段形态钉死——字段名是凭据 JSON 的
// 持久化契约（access_key_id/access_key_secret），类型决定前端渲染。
func TestAliyunProviderMetadata(t *testing.T) {
	provider := &Aliyun{}
	if provider.Code() != "aliyun" {
		t.Fatalf("code=%q, want aliyun", provider.Code())
	}
	if provider.Name() != "阿里云 DNS" {
		t.Fatalf("name=%q", provider.Name())
	}
	if provider.ModuleName() != "dns.providers.aliyun" {
		t.Fatalf("module=%q", provider.ModuleName())
	}
	fields := provider.CredentialFields()
	if len(fields) != 2 {
		t.Fatalf("fields=%+v, want 2（access_key_id + access_key_secret）", fields)
	}
	if fields[0].Name != "access_key_id" || fields[0].Type != "text" || !fields[0].Required || fields[0].Label != "AccessKey ID" {
		t.Fatalf("field0=%+v, want access_key_id text required", fields[0])
	}
	if fields[1].Name != "access_key_secret" || fields[1].Type != "password" || !fields[1].Required || fields[1].Label != "AccessKey Secret" {
		t.Fatalf("field1=%+v, want access_key_secret password required（Label=官方名 AccessKey Secret）", fields[1])
	}
	for _, field := range fields {
		if field.VisibleWhen != nil {
			t.Fatalf("field %s VisibleWhen=%v, want nil（单族 provider 无认证模式分支）", field.Name, field.VisibleWhen)
		}
	}
	if got := provider.CredentialFieldOptions("auth_mode"); got != nil {
		t.Fatalf("options=%v, want nil", got)
	}
}

// Given：UI 形态（裸 access 对）与 canonical 形态（带 mode）。
// When：BuildCredentialsJSON。
// Then：产出 canonical aliyun 凭据且可回喂（canonical 入库不落
// 「凭证缺失/歧义」，与 dnspod 侧 round-trip 契约同构）。
func TestAliyun_BuildCredentialsJSON_acceptsCanonicalOutput(t *testing.T) {
	provider := &Aliyun{}
	for _, input := range []map[string]string{
		{"access_key_id": "ak-id", "access_key_secret": "ak-secret"},
		{"mode": "aliyun", "access_key_id": "ak-id", "access_key_secret": "ak-secret"},
		{"auth_mode": "aliyun", "access_key_id": "ak-id", "access_key_secret": "ak-secret"},
	} {
		canonical, err := provider.BuildCredentialsJSON(input)
		if err != nil {
			t.Fatalf("build canonical from %v: %v", input, err)
		}
		if canonical["mode"] != "aliyun" || canonical["access_key_id"] != "ak-id" || canonical["access_key_secret"] != "ak-secret" {
			t.Fatalf("canonical=%v, want aliyun access 对", canonical)
		}
		canonicalStrings := map[string]string{}
		for key, value := range canonical {
			text, ok := value.(string)
			if !ok {
				t.Fatalf("canonical[%s]=%T, want string", key, value)
			}
			canonicalStrings[key] = text
		}
		if _, err := provider.BuildCredentialsJSON(canonicalStrings); err != nil {
			t.Fatalf("canonical %v must be accepted as input: %v", canonicalStrings, err)
		}
	}
}

// 非阿里云族凭据在 Aliyun provider 下必须显性拒绝（fail-visible）：
// 静默存储他族凭据会让「provider 元数据」与「凭据真相」分裂。
func TestAliyun_BuildCredentialsJSON_rejectsForeignFamily(t *testing.T) {
	provider := &Aliyun{}
	for name, creds := range map[string]map[string]string{
		"tencent pair": {"mode": "tencent", "secret_id": "sid", "secret_key": "skey"},
		"dnspod token": {"mode": "dnspod", "api_token": "123,abc"},
		"missing":      {},
	} {
		if _, err := provider.BuildCredentialsJSON(creds); err == nil {
			t.Fatalf("%s 必须拒绝", name)
		} else if !strings.Contains(strings.ToLower(err.Error()), "access_key_id") {
			t.Fatalf("%s error=%q, want 点名 access_key_id", name, err.Error())
		}
	}
}

// Given：Present 烧尽验证预算、清理应拿到独立预算（共享探针的接线验证）。
// When：Aliyun.Validate。
// Then：探针走共享 helper——独立清理预算 + 随机探针值 + 标准 challenge FQDN。
func TestAliyun_Validate_usesSharedProbe(t *testing.T) {
	originalTimeout := dnsProviderValidateTimeout
	dnsProviderValidateTimeout = 150 * time.Millisecond
	t.Cleanup(func() { dnsProviderValidateTimeout = originalTimeout })
	fake := &budgetConsumingProvider{}
	originalFactory := newDNSProviderFromCredentials
	newDNSProviderFromCredentials = func(string) (dnsprovider.Provider, error) { return fake, nil }
	t.Cleanup(func() { newDNSProviderFromCredentials = originalFactory })

	provider := &Aliyun{}
	credentials := map[string]string{"access_key_id": "ak-id", "access_key_secret": "ak-secret"}
	if err := provider.Validate(context.Background(), credentials, "example.com"); err != nil {
		t.Fatalf("validate: %v（清理失败不得报假失败）", err)
	}
	if fake.probeFVQDN != "_acme-challenge.lb-test.example.com." {
		t.Fatalf("probe FQDN=%q", fake.probeFVQDN)
	}
	if !strings.HasPrefix(fake.probeValue, "lazy-balancer-test-") {
		t.Fatalf("probe value=%q, want lazy-balancer-test-<随机后缀>", fake.probeValue)
	}
	if !fake.hasCleanupDead {
		t.Fatal("CleanUp was not called with a budgeted context")
	}
	if fake.cleanupCtxErr != nil {
		t.Fatalf("cleanup ctx err=%v, want 独立预算下 ctx 未过期", fake.cleanupCtxErr)
	}
	if fake.cleanupBudget <= dnsProviderValidateTimeout || fake.cleanupBudget > dnsProviderValidateTimeout*retryEnvelopeFactor {
		t.Fatalf("cleanup budget=%v, want (%v, %v]", fake.cleanupBudget, dnsProviderValidateTimeout, dnsProviderValidateTimeout*retryEnvelopeFactor)
	}
}
