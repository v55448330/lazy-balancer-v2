package dnsproviders

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"lazy-balancer-v2/internal/dnsprovider"
)

var newDNSProviderFromCredentials = dnsprovider.NewProviderFromCredentials

func init() { Register(&DNSPod{}) }

type DNSPod struct {
	BaseProvider
}

func (d *DNSPod) Code() string       { return "dnspod" }
func (d *DNSPod) Name() string       { return "DNSPod (腾讯云)" }
func (d *DNSPod) ModuleName() string { return "dns.providers.dnspod" }

func (d *DNSPod) CredentialFields() []CredentialField {
	return []CredentialField{
		{Name: "auth_mode", Label: "认证方式", Type: "select", Required: true, Placeholder: "dnspod"},
		{Name: "app_id", Label: "App ID", Type: "text", Required: false, Placeholder: "DNSPod 账号的 App ID（旧版）"},
		{Name: "app_token", Label: "App Token", Type: "password", Required: false, Placeholder: "DNSPod 账号的 API Token（旧版）"},
		{Name: "secret_id", Label: "SecretId", Type: "text", Required: false, Placeholder: "腾讯云 API SecretId（新版）"},
		{Name: "secret_key", Label: "SecretKey", Type: "password", Required: false, Placeholder: "腾讯云 API SecretKey（新版）"},
	}
}

func (d *DNSPod) CredentialFieldOptions(field string) []string {
	if field == "auth_mode" {
		return []string{"dnspod", "tencent_cloud"}
	}
	return nil
}

// buildCredentials 校验并产出规范凭据 map（LBS-B-R3，第 69 轮：内核直返
// map——曾先 Marshal 成 JSON 串、BuildCredentialsJSON 再 Unmarshal 回 map
// 的序列化往返，仅为类型转换且 Unmarshal 不可能失败）。
func (d *DNSPod) buildCredentials(creds map[string]string) (map[string]string, error) {
	mode := creds["auth_mode"]
	if mode == "" {
		if creds["secret_id"] != "" && creds["secret_key"] != "" {
			mode = "tencent_cloud"
		} else if creds["app_id"] != "" && creds["app_token"] != "" {
			mode = "dnspod"
		}
	}

	switch mode {
	case "tencent_cloud":
		if creds["secret_id"] == "" || creds["secret_key"] == "" {
			return nil, fmt.Errorf("腾讯云认证方式需要提供 SecretId 和 SecretKey")
		}
		// CERT40-3:canonical 不再携带 api_token 拼接值——tencent 模式消费端
		// (factory.go)只读 secret_id/secret_key,拼接串是零消费死字段。
		return map[string]string{
			"mode":       "tencent",
			"secret_id":  creds["secret_id"],
			"secret_key": creds["secret_key"],
		}, nil
	case "dnspod":
		if creds["app_id"] == "" || creds["app_token"] == "" {
			return nil, fmt.Errorf("DNSPod 认证方式需要提供 App ID 和 App Token")
		}
		return map[string]string{
			"mode":      "dnspod",
			"api_token": creds["app_id"] + "," + creds["app_token"],
		}, nil
	}
	return nil, fmt.Errorf("请选择认证方式")
}

func (d *DNSPod) BuildCredentialsJSON(creds map[string]string) (map[string]interface{}, error) {
	m, err := d.buildCredentials(creds)
	if err != nil {
		return nil, err
	}
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result, nil
}

func (d *DNSPod) Validate(creds map[string]string, testDomain string) error {
	m, err := d.buildCredentials(creds)
	if err != nil {
		return err
	}
	// Validate 路径消费 JSON 串形态（factory 契约）——本侧自行 Marshal。
	data, _ := json.Marshal(m)
	provider, err := newDNSProviderFromCredentials(string(data))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	domain := strings.TrimSpace(testDomain)
	if domain == "" {
		return fmt.Errorf("测试域名不能为空")
	}
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	challengeName := "_acme-challenge.lb-test." + domain
	if err := provider.Present(ctx, domain, challengeName, "lazy-balancer-test", 600); err != nil {
		return fmt.Errorf("DNS 写入测试失败: %w", err)
	}
	if err := provider.CleanUp(ctx, domain, challengeName); err != nil {
		// CERT42-6（第 42 轮审计）：清理失败时测试 TXT 记录可能已残留——记告警
		// 并在错误文案点名手动清理路径；返回错误语义不变（验证仍判失败）。
		log.Printf("warn: dnspod 验证清理失败，测试记录 %s 可能残留，请手动清理: %v", challengeName, err)
		return fmt.Errorf("DNS 清理测试失败: %w（测试记录可能已残留，请登录 DNS 控制台手动清理 %s TXT 记录）", err, strings.TrimSuffix(challengeName, "."))
	}
	return nil
}
