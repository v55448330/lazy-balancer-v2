package dnsproviders

import (
	"context"
	"encoding/json"
	"fmt"
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

func (d *DNSPod) buildCredentialsJSON(creds map[string]string) (string, error) {
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
			return "", fmt.Errorf("腾讯云认证方式需要提供 SecretId 和 SecretKey")
		}
		data, _ := json.Marshal(map[string]string{
			"mode":       "tencent",
			"secret_id":  creds["secret_id"],
			"secret_key": creds["secret_key"],
			"api_token":  creds["secret_id"] + "," + creds["secret_key"],
		})
		return string(data), nil
	case "dnspod":
		if creds["app_id"] == "" || creds["app_token"] == "" {
			return "", fmt.Errorf("DNSPod 认证方式需要提供 App ID 和 App Token")
		}
		data, _ := json.Marshal(map[string]string{
			"mode":      "dnspod",
			"api_token": creds["app_id"] + "," + creds["app_token"],
		})
		return string(data), nil
	}
	return "", fmt.Errorf("请选择认证方式")
}

func (d *DNSPod) BuildCredentialsJSON(creds map[string]string) (map[string]interface{}, error) {
	raw, err := d.buildCredentialsJSON(creds)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (d *DNSPod) Validate(creds map[string]string, testDomain string) error {
	rawJSON, err := d.buildCredentialsJSON(creds)
	if err != nil {
		return err
	}
	provider, err := newDNSProviderFromCredentials(rawJSON)
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
		return fmt.Errorf("DNS 清理测试失败: %w", err)
	}
	return nil
}
