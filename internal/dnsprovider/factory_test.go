package dnsprovider

import (
	"context"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/dnsprovider/aliyun"
	"lazy-balancer-v2/internal/dnsprovider/dnspod"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
	"lazy-balancer-v2/internal/dnsprovider/tencent"
)

func TestNewProviderFromCredentials_infers_mode_from_credential_fields(t *testing.T) {
	// Given/When/Then: legacy rows migrated before the mode field existed
	// carry only the credential fields — infer instead of rejecting
	provider, err := NewProviderFromCredentials(`{"api_token":"123,abc"}`)
	if err != nil {
		t.Fatalf("infer dnspod from api_token: %v", err)
	}
	if _, ok := provider.(*dnspod.Provider); !ok {
		t.Fatalf("provider=%T, want *dnspod.Provider", provider)
	}

	provider, err = NewProviderFromCredentials(`{"secret_id":"id","secret_key":"key"}`)
	if err != nil {
		t.Fatalf("infer tencent from secret pair: %v", err)
	}
	if _, ok := provider.(*tencent.Provider); !ok {
		t.Fatalf("provider=%T, want *tencent.Provider", provider)
	}

	// Legacy UI form without auth_mode also infers dnspod from app_id/app_token
	provider, err = NewProviderFromCredentials(`{"app_id":"123","app_token":"abc"}`)
	if err != nil {
		t.Fatalf("infer dnspod from legacy app_id/app_token: %v", err)
	}
	if _, ok := provider.(*dnspod.Provider); !ok {
		t.Fatalf("provider=%T, want *dnspod.Provider", provider)
	}
}

func TestNewProviderFromCredentials_rejects_ambiguous_or_missing_credentials(t *testing.T) {
	// Given/When/Then: both credential families present is ambiguous
	if _, err := NewProviderFromCredentials(`{"api_token":"123,abc","secret_id":"id","secret_key":"key"}`); err == nil {
		t.Fatal("ambiguous credentials must be rejected")
	}
	// No credentials at all
	if _, err := NewProviderFromCredentials(`{}`); err == nil {
		t.Fatal("missing credentials must be rejected")
	}
	// Incomplete secret pair cannot select tencent and has no token either
	if _, err := NewProviderFromCredentials(`{"secret_id":"id"}`); err == nil {
		t.Fatal("incomplete secret pair must be rejected")
	}
}

func TestNewProviderFromCredentials_explicit_mode_still_wins(t *testing.T) {
	// Given/When: explicit mode with matching credentials
	provider, err := NewProviderFromCredentials(`{"mode":"tencent","secret_id":"id","secret_key":"key"}`)
	if err != nil {
		t.Fatalf("explicit mode: %v", err)
	}

	// Then
	if _, ok := provider.(*tencent.Provider); !ok {
		t.Fatalf("provider=%T, want *tencent.Provider", provider)
	}
}

// 空 mode 无法推断时的错误文案必须可诊断分流——两类凭证
// 并存=歧义（需显式 mode 消歧），全缺/不完整=缺失（需补齐凭证）。原实现两者
// 同落 default 的「unsupported dns provider mode: 」（mode 为空），排障无法区分。
func TestNewProviderFromCredentials_emptyModeErrorDistinguishesAmbiguityFromMissing(t *testing.T) {
	_, ambiguousErr := NewProviderFromCredentials(`{"api_token":"123,abc","secret_id":"id","secret_key":"key"}`)
	if ambiguousErr == nil {
		t.Fatal("ambiguous credentials must be rejected")
	}
	_, missingErr := NewProviderFromCredentials(`{}`)
	if missingErr == nil {
		t.Fatal("missing credentials must be rejected")
	}
	if ambiguousErr.Error() == missingErr.Error() {
		t.Fatalf("歧义与缺失必须给出不同文案, both=%q", ambiguousErr.Error())
	}
	if !strings.Contains(ambiguousErr.Error(), "歧义") {
		t.Fatalf("歧义文案须含「歧义」, got %q", ambiguousErr.Error())
	}
	if !strings.Contains(missingErr.Error(), "缺失") {
		t.Fatalf("缺失文案须含「缺失」, got %q", missingErr.Error())
	}
	// 显式未知 mode 仍走原 unsupported 文案（非空 mode 不进歧义/缺失分流）。
	if _, err := NewProviderFromCredentials(`{"mode":"route53","api_token":"1,2"}`); err == nil ||
		!strings.Contains(err.Error(), "unsupported dns provider mode") {
		t.Fatalf("显式未知 mode 须保留原 unsupported 文案, got %v", err)
	}
}

// UI 形态（auth_mode + app_id/app_token 等）是唯一真相——
// 游离的消费层 mode 字段不得压过它。否则「保存前凭证测试」（UI 形态）与
// 真实签发（mode 优先）会使用两套不同凭据，验证结论不覆盖实际链路。
func TestNewProviderFromCredentials_authModeOverridesStrayMode(t *testing.T) {
	provider, err := NewProviderFromCredentials(`{"auth_mode":"dnspod","app_id":"123","app_token":"abc","mode":"tencent","secret_id":"sid","secret_key":"skey"}`)
	if err != nil {
		t.Fatalf("credentials with stray mode: %v", err)
	}
	dnspodProvider, ok := provider.(*dnspod.Provider)
	if !ok {
		t.Fatalf("provider=%T, want *dnspod.Provider（auth_mode 优先）", provider)
	}
	// 凭据相等以账户摘要（String()，由完整凭据派生）判定：包外不再暴露凭据
	// 访问器，避免把凭据读取面扩到任何同包/跨包代码。
	if dnspodProvider.String() != dnspod.New("123,abc").String() {
		t.Fatalf("provider=%s, want 凭据 123,abc（UI 字段为凭据真相）", dnspodProvider.String())
	}
}

// UI 形态的 app_id/app_token 必须覆盖陈旧 api_token（掩码合并后
// 两形态并存的短暂状态），保证校验与签发使用同一组凭据。
func TestNewProviderFromCredentials_uiFieldsOverrideStaleAPIToken(t *testing.T) {
	provider, err := NewProviderFromCredentials(`{"auth_mode":"dnspod","api_token":"old,old","app_id":"123","app_token":"abc"}`)
	if err != nil {
		t.Fatalf("credentials with stale api_token: %v", err)
	}
	dnspodProvider, ok := provider.(*dnspod.Provider)
	if !ok {
		t.Fatalf("provider=%T, want *dnspod.Provider", provider)
	}
	if dnspodProvider.String() != dnspod.New("123,abc").String() {
		t.Fatalf("provider=%s, want 凭据 123,abc（app_id/app_token 优先）", dnspodProvider.String())
	}
}

// stubProvider 只记录调用形态，用于验证能力分派（不含 DNS 网络行为）。
type stubProvider struct {
	presentCalls int
	cleanupCalls int
	valueCalls   int
}

func (p *stubProvider) Present(context.Context, string, string, string, int) error {
	p.presentCalls++
	return nil
}

func (p *stubProvider) CleanUp(context.Context, string, string) error {
	p.cleanupCalls++
	return nil
}

// valueStubProvider 在 stubProvider 上叠加 ValueCleaner/CleanupCounter 能力。
type valueStubProvider struct {
	stubProvider
	count int
}

func (p *valueStubProvider) CleanUpValue(context.Context, string, string, string) error {
	p.valueCalls++
	return nil
}

func (p *valueStubProvider) CountCleanupRecords(string, string, string) int { return p.count }

// 按值清理的能力分派：具备 ValueCleaner 走按值清理，否则回落按名清理
// （两条分支都无测试时，类型断言写反/漏判不会有任何红灯）。
func TestCleanUpChallenge_dispatchesToValueCleanerWhenAvailable(t *testing.T) {
	plain := &stubProvider{}
	if err := CleanUpChallenge(context.Background(), plain, "example.com", "_acme-challenge.example.com.", "v"); err != nil {
		t.Fatalf("clean up plain provider: %v", err)
	}
	if plain.cleanupCalls != 1 || plain.valueCalls != 0 {
		t.Fatalf("plain calls cleanup=%d value=%d, want 1/0", plain.cleanupCalls, plain.valueCalls)
	}

	aware := &valueStubProvider{}
	if err := CleanUpChallenge(context.Background(), aware, "example.com", "_acme-challenge.example.com.", "v"); err != nil {
		t.Fatalf("clean up value-aware provider: %v", err)
	}
	if aware.valueCalls != 1 || aware.cleanupCalls != 0 {
		t.Fatalf("value-aware calls cleanup=%d value=%d, want 0/1", aware.cleanupCalls, aware.valueCalls)
	}
}

// 清理预算是「宁大勿小」：无计数能力的 provider 与计数为 0 的 provider 都必须
// 按 1 条计（读失败 = 0 不得把预算算成 0 而直接跳过清理）。
func TestCountChallengeCleanupRecords_fallsBackToAtLeastOne(t *testing.T) {
	if got := CountChallengeCleanupRecords(&stubProvider{}, "example.com", "_acme-challenge.example.com.", "v"); got != 1 {
		t.Fatalf("count without capability=%d, want 1", got)
	}
	if got := CountChallengeCleanupRecords(&valueStubProvider{count: 0}, "example.com", "_acme-challenge.example.com.", "v"); got != 1 {
		t.Fatalf("count with zero report=%d, want 1（读失败/零条目按至少 1 条）", got)
	}
	if got := CountChallengeCleanupRecords(&valueStubProvider{count: 3}, "example.com", "_acme-challenge.example.com.", "v"); got != 3 {
		t.Fatalf("count with report=%d, want 3", got)
	}
}

// aliyun 族：显式 mode 与裸 access 对的字段形态推断（access_key_id/
// access_key_secret 与 tencent 的 secret_id/secret_key 形态互斥，同名判族无歧义）。
func TestNewProviderFromCredentials_aliyunFamily(t *testing.T) {
	// 显式 mode。
	provider, err := NewProviderFromCredentials(`{"mode":"aliyun","access_key_id":"ak","access_key_secret":"sk"}`)
	if err != nil {
		t.Fatalf("explicit aliyun mode: %v", err)
	}
	aliyunProvider, ok := provider.(*aliyun.Provider)
	if !ok {
		t.Fatalf("provider=%T, want *aliyun.Provider", provider)
	}
	// 裸 access 对（无 mode）按字段形态推断为 aliyun。
	provider, err = NewProviderFromCredentials(`{"access_key_id":"ak","access_key_secret":"sk"}`)
	if err != nil {
		t.Fatalf("infer aliyun from access pair: %v", err)
	}
	if _, ok := provider.(*aliyun.Provider); !ok {
		t.Fatalf("provider=%T, want *aliyun.Provider", provider)
	}
	// 账户摘要由凭据对派生（与 tencent 同口径）：String() 只暴露账户摘要。
	wantAccount := ownership.AccountDigest("ak\x00sk")
	if aliyunProvider.String() != "aliyun.Provider{account:"+wantAccount+"}" {
		t.Fatalf("account digest mismatch: %s, want %s", aliyunProvider.String(), wantAccount)
	}
	// 凭据不完整（只有 ID）→ 缺失拒绝。
	if _, err := NewProviderFromCredentials(`{"access_key_id":"ak"}`); err == nil {
		t.Fatal("incomplete aliyun pair must be rejected")
	}
}

// 三族凭据并存（token + tencent secret + aliyun access 对）必须歧义拒绝；
// aliyun access 对与任一既有族并存同样歧义。
func TestNewProviderFromCredentials_aliyunAmbiguity(t *testing.T) {
	for name, raw := range map[string]string{
		"aliyun+tencent": `{"access_key_id":"ak","access_key_secret":"sk","secret_id":"sid","secret_key":"skey"}`,
		"aliyun+dnspod":  `{"access_key_id":"ak","access_key_secret":"sk","api_token":"123,abc"}`,
		"all three":      `{"access_key_id":"ak","access_key_secret":"sk","secret_id":"sid","secret_key":"skey","api_token":"123,abc"}`,
	} {
		_, err := NewProviderFromCredentials(raw)
		if err == nil {
			t.Fatalf("%s 并存必须歧义拒绝", name)
		}
		if !strings.Contains(err.Error(), "歧义") {
			t.Fatalf("%s error=%q, want 歧义文案", name, err.Error())
		}
	}
	// 显式 mode 可消歧：三族并存 + mode=aliyun → aliyun。
	provider, err := NewProviderFromCredentials(`{"mode":"aliyun","access_key_id":"ak","access_key_secret":"sk","secret_id":"sid","secret_key":"skey","api_token":"123,abc"}`)
	if err != nil {
		t.Fatalf("explicit mode disambiguates: %v", err)
	}
	if _, ok := provider.(*aliyun.Provider); !ok {
		t.Fatalf("provider=%T, want *aliyun.Provider（显式 mode 消歧）", provider)
	}
}
