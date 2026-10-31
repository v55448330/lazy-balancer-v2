package dnsprovider

import (
	"encoding/json"
	"fmt"
	"strings"

	"lazy-balancer-v2/internal/dnsprovider/aliyun"
	"lazy-balancer-v2/internal/dnsprovider/dnspod"
	"lazy-balancer-v2/internal/dnsprovider/tencent"
)

// DNSCredentials is the unified credential envelope. 真实存储位置是
// certificate_configs.dns_credentials（global_config.dns_credentials 为已停用的
// 遗留字段，2026-09-05 证书域审计核实签发链无消费方）。
type DNSCredentials struct {
	Mode      string `json:"mode"` // "dnspod", "tencent" or "aliyun"
	APIToken  string `json:"api_token,omitempty"`
	SecretID  string `json:"secret_id,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	// AccessKey 对是 aliyun 族的 canonical 形态（阿里云 RAM AccessKey）。
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
}

// CredentialEnvelope 是「原始凭证 JSON → 规范凭据」归一所需的全部输入字段：
// UI 存储形态（auth_mode + app_id/app_token 或 secret_id/secret_key 或
// access_key_id/access_key_secret）与 canonical 形态（mode + 各族凭据）共用
// 同一结构。多出的字段被忽略，因此同一实现可同时服务多条路径。
type CredentialEnvelope struct {
	Mode            string `json:"mode"`
	AuthMode        string `json:"auth_mode"`
	APIToken        string `json:"api_token"`
	AppID           string `json:"app_id"`
	AppToken        string `json:"app_token"`
	SecretID        string `json:"secret_id"`
	SecretKey       string `json:"secret_key"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
}

// CanonicalCredentials 把任意形态的原始凭证 JSON 归一为规范凭据。
//
// 这是「原始凭证 → 规范凭据」的唯一实现：保存前验证（services/dnsproviders
// 的表单 map）与签发链 provider 构造（newProviderFromCredentials）都必须调用
// 它。两侧各写一份推断会让同一份库内 JSON 得到相反结论——历史形态：一侧在
// 两类凭证并存时静默选腾讯云，另一侧报「凭证歧义」，表现为「保存前测试通过
// 但签发持续失败」。
//
// 优先级（契约）：
//   - auth_mode（UI 形态）> mode（canonical 形态）——UI 形态是凭据真相；
//   - app_id+app_token 折叠为 api_token，且优先于游离的 api_token
//     （掩码合并的短暂状态会同时带两形态）；
//   - 无显式 mode/auth_mode 时按字段形态推断：仅一类凭据→该类；
//     多类并存→歧义拒绝（不再静默择一）；全缺/不完整→缺失。
func CanonicalCredentials(rawJSON string) (DNSCredentials, error) {
	var env CredentialEnvelope
	if err := json.Unmarshal([]byte(rawJSON), &env); err != nil {
		return DNSCredentials{}, fmt.Errorf("invalid dns credentials: %w", err)
	}
	return env.Canonical()
}

// Canonical 是 CanonicalCredentials 的字段形态入口，供已解析成表单 map 的
// 调用方（证书配置的保存前验证）复用同一归一实现。
func (env CredentialEnvelope) Canonical() (DNSCredentials, error) {
	mode := env.AuthMode
	if mode == "" {
		mode = env.Mode
	}
	apiToken := env.APIToken
	if env.AppID != "" && env.AppToken != "" {
		apiToken = env.AppID + "," + env.AppToken
	}
	hasToken := apiToken != ""
	hasSecret := env.SecretID != "" && env.SecretKey != ""
	hasAccess := env.AccessKeyID != "" && env.AccessKeySecret != ""

	if mode == "" {
		// 迁移早于 mode 字段落库的存量行只带凭证字段本身：按字段形态推断
		// provider（APIToken→DNSPod token；SecretID+SecretKey→腾讯云 secret；
		// AccessKeyID+AccessKeySecret→阿里云 access 对）。多类并存=歧义（需
		// 显式 mode 消歧）；全缺/不完整=缺失（需补齐凭证）。文案同时保留
		// UI 面（"请选择认证方式"）与协议面（"缺失"）语义。
		families := 0
		for _, present := range []bool{hasToken, hasSecret, hasAccess} {
			if present {
				families++
			}
		}
		switch {
		case families > 1:
			return DNSCredentials{}, fmt.Errorf("DNS 凭证歧义：多类凭证同时存在，无法判定提供商（请显式指定 mode=dnspod、mode=tencent 或 mode=aliyun）")
		case hasToken:
			mode = "dnspod"
		case hasSecret:
			mode = "tencent"
		case hasAccess:
			mode = "aliyun"
		default:
			return DNSCredentials{}, fmt.Errorf("请选择认证方式：DNS 凭证缺失或不足以判定提供商（需 api_token，或 secret_id+secret_key，或 access_key_id+access_key_secret；也可显式指定 mode）")
		}
	}

	switch strings.ToLower(mode) {
	case "dnspod":
		if !hasToken {
			return DNSCredentials{}, fmt.Errorf("DNSPod 认证方式需要提供 App ID 和 App Token")
		}
		return DNSCredentials{Mode: "dnspod", APIToken: apiToken}, nil
	case "tencent", "tencent_cloud":
		if !hasSecret {
			return DNSCredentials{}, fmt.Errorf("腾讯云认证方式需要提供 SecretId 和 SecretKey")
		}
		return DNSCredentials{Mode: "tencent", SecretID: env.SecretID, SecretKey: env.SecretKey}, nil
	case "aliyun":
		if !hasAccess {
			return DNSCredentials{}, fmt.Errorf("阿里云认证方式需要提供 AccessKey ID 和 AccessKey Secret")
		}
		return DNSCredentials{Mode: "aliyun", AccessKeyID: env.AccessKeyID, AccessKeySecret: env.AccessKeySecret}, nil
	}
	return DNSCredentials{}, fmt.Errorf("unsupported dns provider mode: %s", mode)
}

// NewProviderFromCredentials parses the stored JSON credentials and returns the appropriate Provider.
func NewProviderFromCredentials(rawJSON string) (Provider, error) {
	return newProviderFromCredentials(rawJSON, "")
}

func NewPersistentProviderFromCredentials(rawJSON, dataDir string) (Provider, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("DNS ownership data directory is required")
	}
	return newProviderFromCredentials(rawJSON, dataDir)
}

func newProviderFromCredentials(rawJSON, dataDir string) (Provider, error) {
	creds, err := CanonicalCredentials(rawJSON)
	if err != nil {
		return nil, err
	}
	switch creds.Mode {
	case "dnspod":
		if dataDir != "" {
			return dnspod.NewPersistent(creds.APIToken, dataDir)
		}
		return dnspod.New(creds.APIToken), nil
	case "tencent":
		if dataDir != "" {
			return tencent.NewPersistent(creds.SecretID, creds.SecretKey, dataDir)
		}
		return tencent.New(creds.SecretID, creds.SecretKey)
	case "aliyun":
		if dataDir != "" {
			return aliyun.NewPersistent(creds.AccessKeyID, creds.AccessKeySecret, dataDir)
		}
		return aliyun.New(creds.AccessKeyID, creds.AccessKeySecret)
	default:
		return nil, fmt.Errorf("unsupported dns provider mode: %s", creds.Mode)
	}
}
