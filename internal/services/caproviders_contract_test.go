package services

// CA 提供商校验/归一化契约：边界值、0=默认语义与审计共用的语义比较。
// 这些 helper 是所有入口（写侧/队列刷新/审计比对）的唯一事实源，任一处把
// `<` 写成 `<=` 或默认值漂移都必须被直接测试拦下。

import (
	"errors"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func TestNormalizeCAProviderBounds(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{-5, 1}, {0, 1}, {1, 1}, {100, 100}, {101, 101},
	} {
		if got := NormalizeCAProviderMaxConcurrent(tc.in); got != tc.want {
			t.Errorf("NormalizeCAProviderMaxConcurrent(%d)=%d, want %d", tc.in, got, tc.want)
		}
	}
	for _, tc := range []struct{ in, want int }{
		{-1, 2000}, {0, 2000}, {1000, 1000}, {2000, 2000}, {60000, 60000}, {60001, 60001},
	} {
		if got := NormalizeCAProviderMinIntervalMS(tc.in); got != tc.want {
			t.Errorf("NormalizeCAProviderMinIntervalMS(%d)=%d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestCredentialsSemanticallyEqual(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"reordered top-level keys", `{"a":1,"b":2}`, `{"b":2,"a":1}`, true},
		{"whitespace only", " { \"a\" : 1 } ", `{"a":1}`, true},
		{"nested reorder", `{"outer":{"b":"2","a":"1"}}`, `{"outer":{"a":"1","b":"2"}}`, true},
		{"value change", `{"a":1}`, `{"a":2}`, false},
		{"invalid vs valid", `not-json`, `{"a":1}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CredentialsSemanticallyEqual(tc.a, tc.b); got != tc.want {
				t.Fatalf("CredentialsSemanticallyEqual(%q,%q)=%v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// seedCAProviderForContract 在独立测试库里播种一个启用中的 CA 提供商并返回 id。
func seedCAProviderForContract(t *testing.T, provider, credentials string) int {
	t.Helper()
	_, database := newClusterTestService(t)
	directory := ZeroSSLDirectoryURL
	if provider == ProviderLetsEncrypt {
		directory = LetsEncryptDirectoryURL
	}
	res, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES ('contract',?,?,?,1,1000,1)`, provider, directory, credentials)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return int(id)
}

func TestUpdateCAProvider_validationBoundaries(t *testing.T) {
	tooLongName := strings.Repeat("a", 101)
	cases := []struct {
		name    string
		seed    string
		req     models.UpdateCAProviderRequest
		wantErr error
	}{
		{
			name:    "invalid provider enum",
			seed:    ProviderZeroSSL,
			req:     models.UpdateCAProviderRequest{Provider: new("acme")},
			wantErr: ErrCAProviderInvalidProvider,
		},
		{
			name:    "whitespace name",
			seed:    ProviderZeroSSL,
			req:     models.UpdateCAProviderRequest{Name: new("   ")},
			wantErr: ErrCAProviderInvalidName,
		},
		{
			name:    "name over 100 runes",
			seed:    ProviderZeroSSL,
			req:     models.UpdateCAProviderRequest{Name: &tooLongName},
			wantErr: ErrCAProviderNameTooLong,
		},
		{
			name:    "max concurrency over 100",
			seed:    ProviderZeroSSL,
			req:     models.UpdateCAProviderRequest{MaxConcurrent: new(101)},
			wantErr: ErrCAProviderMaxConcurrentTooHigh,
		},
		{
			name:    "negative max concurrency",
			seed:    ProviderZeroSSL,
			req:     models.UpdateCAProviderRequest{MaxConcurrent: new(-1)},
			wantErr: ErrCAProviderMaxConcurrentTooLow,
		},
		{
			name:    "min interval over 60000",
			seed:    ProviderZeroSSL,
			req:     models.UpdateCAProviderRequest{MinIntervalMS: new(60001)},
			wantErr: ErrCAProviderMinIntervalTooHigh,
		},
		{
			name:    "negative min interval",
			seed:    ProviderZeroSSL,
			req:     models.UpdateCAProviderRequest{MinIntervalMS: new(-1)},
			wantErr: ErrCAProviderMinIntervalTooLow,
		},
		{
			name:    "zerossl credentials must be JSON",
			seed:    ProviderZeroSSL,
			req:     models.UpdateCAProviderRequest{Credentials: new("not-json")},
			wantErr: ErrCAProviderInvalidCredentials,
		},
		{
			name:    "letsencrypt credentials must be empty",
			seed:    ProviderLetsEncrypt,
			req:     models.UpdateCAProviderRequest{Credentials: new(`{"eab_kid":"kid"}`)},
			wantErr: ErrCAProviderLetsEncryptCredentialsNotEmpty,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			credentials := `{"eab_kid":"kid","eab_hmac_key":"secret"}`
			if tc.seed == ProviderLetsEncrypt {
				credentials = ""
			}
			id := seedCAProviderForContract(t, tc.seed, credentials)
			if _, err := NewCAProviderService().UpdateCAProvider(id, tc.req); !errors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestUpdateCAProvider_nameAtLimitAndZeroNormalizationPersist(t *testing.T) {
	id := seedCAProviderForContract(t, ProviderZeroSSL, `{"eab_kid":"kid","eab_hmac_key":"secret"}`)
	okName := strings.Repeat("a", 100)
	updated, err := NewCAProviderService().UpdateCAProvider(id, models.UpdateCAProviderRequest{
		Name:          &okName,
		MaxConcurrent: new(0),
		MinIntervalMS: new(0),
	})
	if err != nil {
		t.Fatalf("update at-boundary name + zero normalization: %v", err)
	}
	// UpdateCAProvider 返回的是事务内旧行（handler 审计基线），落库结果必须回读。
	var storedName string
	var storedMax, storedMin int
	if err := db.DB.QueryRow(`SELECT name, max_concurrent, min_interval_ms FROM ca_providers WHERE id=?`, id).Scan(&storedName, &storedMax, &storedMin); err != nil {
		t.Fatalf("read updated provider: %v", err)
	}
	if storedName != okName {
		t.Fatalf("name=%q, want 100-rune name", storedName)
	}
	if storedMax != 1 || storedMin != 2000 {
		t.Fatalf("max=%d min=%d, want 归一 1/2000", storedMax, storedMin)
	}
	if updated.Name == "" {
		t.Fatal("旧行快照缺失（审计基线契约）")
	}
}
