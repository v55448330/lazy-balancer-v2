package handlers

// 跨族掩码继承守卫的「族 → 提供商代码」口径：凭证族 tencent（腾讯云 API）由
// dnspod 提供商消费（auth_mode=tencent_cloud 是其合法认证方式），守卫比较前
// 必须归一到提供商注册表口径；其余族与提供商代码同名。旧族 token 经掩码继承
// 进入异族提供商的形态仍必须 400 点名拒绝（fail-visible 语义不放宽）。

import (
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func seedCertificateConfigWithProvider(t *testing.T, name, provider, credentials string) int64 {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled)
		VALUES (?,?,?,1)`, name, provider, credentials)
	if err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate config id: %v", err)
	}
	return id
}

// Given 库内配置为阿里云提供商（access 对凭证）。
// When 管理员把提供商切到 DNSPod 并提交腾讯云 API 凭证（auth_mode=tencent_cloud）。
// Then 200 落库——tencent 族由 dnspod 提供商消费，守卫不得按「族名 != 提供商
// 代码」误拒；旧族 access 对不得随合并继承。canonical mode 形态同口径。
func TestUpdateCertificateConfig_tencentCloudFamilyAllowedOnDnspodProviderSwitch(t *testing.T) {
	for _, shape := range []struct {
		name        string
		credentials string
	}{
		{"ui_auth_mode", `{"auth_mode":"tencent_cloud","secret_id":"sid","secret_key":"skey"}`},
		{"canonical_mode", `{"mode":"tencent","secret_id":"sid","secret_key":"skey"}`},
	} {
		t.Run(shape.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			id := seedCertificateConfigWithProvider(t, "aliyun-to-dnspod-"+shape.name, "aliyun",
				`{"auth_mode":"aliyun","access_key_id":"old-ak","access_key_secret":"old-sk"}`)

			response := putCertificateConfig(t, h, id,
				`{"dns_provider":"dnspod","dns_credentials":`+shape.credentials+`}`)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200（tencent 族由 dnspod 提供商消费，不得误拒）", response.Code, response.Body.String())
			}

			var provider string
			if err := db.DB.QueryRow("SELECT dns_provider FROM certificate_configs WHERE id=?", id).Scan(&provider); err != nil {
				t.Fatalf("read provider: %v", err)
			}
			if provider != "dnspod" {
				t.Fatalf("provider=%q, want dnspod", provider)
			}
			_, _, stored := storedCertificateCredentials(t, id)
			if stored["secret_id"] != "sid" || stored["secret_key"] != "skey" {
				t.Fatalf("stored credentials=%v, want 提交的腾讯云 secret 对", stored)
			}
			if _, ok := stored["access_key_id"]; ok {
				t.Fatalf("stored credentials=%v, 旧族 access 对不得继承", stored)
			}
		})
	}
}

// 回归形状（基线钉测）：旧族 token 经掩码继承进入异族提供商仍必须 400 点名
// （MessageKey 稳定语义键）——族归一只放宽 tencent→dnspod 的合法消费关系，
// 不得把真正的跨族掩码继承一并放行。
func TestUpdateCertificateConfig_crossFamilyMaskedInheritanceStillRejected(t *testing.T) {
	for _, shape := range []struct {
		name        string
		oldProvider string
		oldCreds    string
		newProvider string
		submitted   string
	}{
		{
			name:        "dnspod_bare_token_into_cloudflare",
			oldProvider: "dnspod",
			oldCreds:    `{"api_token":"old-id,old-tok"}`,
			newProvider: "cloudflare",
			submitted:   `{"api_token":"***"}`,
		},
		{
			name:        "aliyun_access_pair_into_cloudflare",
			oldProvider: "aliyun",
			oldCreds:    `{"auth_mode":"aliyun","access_key_id":"old-ak","access_key_secret":"old-sk"}`,
			newProvider: "cloudflare",
			submitted:   `{"access_key_id":"***","access_key_secret":"***"}`,
		},
	} {
		t.Run(shape.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			id := seedCertificateConfigWithProvider(t, "cross-family-"+shape.name, shape.oldProvider, shape.oldCreds)

			response := putCertificateConfig(t, h, id,
				`{"dns_provider":"`+shape.newProvider+`","dns_credentials":`+shape.submitted+`}`)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400（跨族掩码继承必须点名拒绝）", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), `"message_key":"cert.dnsCredentialFamilyProviderMismatch"`) {
				t.Fatalf("body=%s, want 跨族守卫稳定语义键 cert.dnsCredentialFamilyProviderMismatch", response.Body.String())
			}
			var provider string
			if err := db.DB.QueryRow("SELECT dns_provider FROM certificate_configs WHERE id=?", id).Scan(&provider); err != nil {
				t.Fatalf("read provider: %v", err)
			}
			if provider != shape.oldProvider {
				t.Fatalf("provider=%q, want 保持 %q（拒绝不得落库）", provider, shape.oldProvider)
			}
		})
	}
}
