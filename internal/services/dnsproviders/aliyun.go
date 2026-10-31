package dnsproviders

import (
	"context"
	"encoding/json"
	"fmt"

	"lazy-balancer-v2/internal/dnsprovider"
)

func init() { Register(&Aliyun{}) }

type Aliyun struct {
	BaseProvider
}

func (a *Aliyun) Code() string       { return "aliyun" }
func (a *Aliyun) Name() string       { return "阿里云 DNS" }
func (a *Aliyun) ModuleName() string { return "dns.providers.aliyun" }

// CredentialFields 只声明 access 对两字段：阿里云凭据单一认证族，无需
// dnspod 的 auth_mode select（可见性分支）——凭据字段名即持久化契约，与
// factory 的 CredentialEnvelope JSON tag 一致。
func (a *Aliyun) CredentialFields() []CredentialField {
	return []CredentialField{
		{
			Name: "access_key_id", Label: "AccessKey ID", Type: "text", Required: true,
			Placeholder: "阿里云 RAM AccessKey ID（授权 AliyunDNSFullAccess）",
		},
		{
			Name: "access_key_secret", Label: "AccessKey Secret", Type: "password", Required: true,
			Placeholder: "阿里云 RAM AccessKey Secret",
		},
	}
}

// buildCredentials 校验并产出规范凭据 map（与 DNSPod.buildCredentials 同构）：
// 推断/归一逻辑不在本函数——`dnsprovider.CanonicalCredentials` 是「原始凭证 →
// 规范凭据」的唯一实现，保存前验证（本函数）与签发链 provider 构造共用它。
// 同时接受 UI 形态（access 对裸字段）与 canonical 形态（mode + access 对，
// 本函数产物）——产出可回喂。非 aliyun 族凭据显性拒绝：静默存储他族凭据会让
// 「provider 元数据」与「凭据真相」分裂（fail-visible）。
func (a *Aliyun) buildCredentials(creds map[string]string) (map[string]string, error) {
	canonical, err := (dnsprovider.CredentialEnvelope{
		Mode:            creds["mode"],
		AuthMode:        creds["auth_mode"],
		APIToken:        creds["api_token"],
		AppID:           creds["app_id"],
		AppToken:        creds["app_token"],
		SecretID:        creds["secret_id"],
		SecretKey:       creds["secret_key"],
		AccessKeyID:     creds["access_key_id"],
		AccessKeySecret: creds["access_key_secret"],
	}).Canonical()
	if err != nil {
		return nil, err
	}
	if canonical.Mode != "aliyun" {
		return nil, fmt.Errorf("阿里云 DNS 凭证需要 access_key_id 和 access_key_secret（dnspod/腾讯云凭据请配置在对应提供商下）")
	}
	return map[string]string{
		"mode":              "aliyun",
		"access_key_id":     canonical.AccessKeyID,
		"access_key_secret": canonical.AccessKeySecret,
	}, nil
}

func (a *Aliyun) BuildCredentialsJSON(creds map[string]string) (map[string]interface{}, error) {
	m, err := a.buildCredentials(creds)
	if err != nil {
		return nil, err
	}
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result, nil
}

// Validate 走共享探针（validate_probe.go，与 DNSPod 同一 Present→按值清理
// 骨架与预算口径）；本侧只负责凭据归一与 provider 构造。
func (a *Aliyun) Validate(ctx context.Context, creds map[string]string, testDomain string) error {
	m, err := a.buildCredentials(creds)
	if err != nil {
		return err
	}
	// Validate 路径消费 JSON 串形态（factory 契约）——本侧自行 Marshal。
	data, _ := json.Marshal(m)
	provider, err := newDNSProviderFromCredentials(string(data))
	if err != nil {
		return err
	}
	return runValidateProbe(ctx, provider, testDomain, "aliyun")
}
