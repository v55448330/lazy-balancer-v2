package dnsproviders

import (
	"context"
	"encoding/json"
	"fmt"

	"lazy-balancer-v2/internal/dnsprovider"
)

func init() { Register(&Cloudflare{}) }

type Cloudflare struct {
	BaseProvider
}

func (c *Cloudflare) Code() string       { return "cloudflare" }
func (c *Cloudflare) Name() string       { return "Cloudflare" }
func (c *Cloudflare) ModuleName() string { return "dns.providers.cloudflare" }

// CredentialFields 声明 auth_mode 单选（api_token 单形态，选项文案面向用户）
// 与 api_token 密码字段：auth_mode 用 select 而非裸字段，与 dnspod 的字段形态
// 同构（前端按 visible_when 渲染），并为未来认证形态留位。凭据字段名即持久
// 化契约，与 factory 的 CredentialEnvelope JSON tag 一致。Global API Key 有意
// 不暴露——全账户权限、无 scope 收敛，安全面不可接受。
func (c *Cloudflare) CredentialFields() []CredentialField {
	visibleOnly := func(mode string) map[string][]string {
		return map[string][]string{"auth_mode": {mode}}
	}
	return []CredentialField{
		{
			Name: "auth_mode", Label: "认证方式", Type: "select", Required: true, Placeholder: "cloudflare",
			OptionLabels: map[string]string{"cloudflare": "API Token（推荐）"},
		},
		{
			Name: "api_token", Label: "API Token", Type: "password", Required: true,
			Placeholder: "Cloudflare API Token（My Profile → API Tokens 创建；权限 Zone → DNS → Edit + Zone → Zone → Read，可限定 zone）",
			VisibleWhen: visibleOnly("cloudflare"),
		},
	}
}

func (c *Cloudflare) CredentialFieldOptions(field string) []string {
	if field == "auth_mode" {
		return []string{"cloudflare"}
	}
	return nil
}

// buildCredentials 校验并产出规范凭据 map（与 DNSPod/Aliyun 的 buildCredentials
// 同构）：推断/归一逻辑不在本函数——`dnsprovider.CanonicalCredentials` 是
// 「原始凭证 → 规范凭据」的唯一实现，保存前验证（本函数）与签发链 provider
// 构造共用它。同时接受 UI 形态（auth_mode + api_token）与 canonical 形态
// （mode + api_token，本函数产物）——产出可回喂。非 cloudflare 族凭据显性
// 拒绝：静默存储他族凭据会让「provider 元数据」与「凭据真相」分裂
// （fail-visible）。
func (c *Cloudflare) buildCredentials(creds map[string]string) (map[string]string, error) {
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
	if canonical.Mode != "cloudflare" {
		return nil, fmt.Errorf("Cloudflare DNS 凭证需要 api_token（dnspod/腾讯云/阿里云凭据请配置在对应提供商下）")
	}
	return map[string]string{
		"mode":      "cloudflare",
		"api_token": canonical.APIToken,
	}, nil
}

func (c *Cloudflare) BuildCredentialsJSON(creds map[string]string) (map[string]interface{}, error) {
	m, err := c.buildCredentials(creds)
	if err != nil {
		return nil, err
	}
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result, nil
}

// VerifyTokener 是 Cloudflare 保存前验证的 provider 侧能力：GET
// /user/tokens/verify 真实验证 Token 有效性（active 才算通过）——不触 DNS
// 写入、无需 zone，与 dnspod/aliyun 的「随机 TXT 写入→按值清理」探针形态不同
// 但同属真实验证（保存前探测契约不变：失败不得落库）。
type VerifyTokener interface {
	VerifyToken(ctx context.Context) error
}

// Validate 走 Token verify 探测（ctx 为调用方请求 ctx 上界）：凭据归一 →
// provider 构造 → VerifyToken。testDomain 形参保留接口契约（Token 验证无需
// 测试域）。
func (c *Cloudflare) Validate(ctx context.Context, creds map[string]string, testDomain string) error {
	m, err := c.buildCredentials(creds)
	if err != nil {
		return err
	}
	// Validate 路径消费 JSON 串形态（factory 契约）——本侧自行 Marshal。
	data, _ := json.Marshal(m)
	provider, err := newDNSProviderFromCredentials(string(data))
	if err != nil {
		return err
	}
	verifier, ok := provider.(VerifyTokener)
	if !ok {
		return fmt.Errorf("cloudflare provider 未实现 Token 验证能力")
	}
	return verifier.VerifyToken(ctx)
}
