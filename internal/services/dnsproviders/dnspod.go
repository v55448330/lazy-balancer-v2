package dnsproviders

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"lazy-balancer-v2/internal/dnsprovider"
)

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
	provider, err := dnsprovider.NewProviderFromCredentials(rawJSON)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if testDomain == "" {
		return fmt.Errorf("测试域名不能为空")
	}
	domain := strings.TrimSpace(testDomain)
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	challengeName := "_acme-challenge.lb-test." + domain
	if err := provider.Present(ctx, domain, challengeName, "lazy-balancer-test", 600); err != nil {
		return fmt.Errorf("DNS 写入测试失败: %v", err)
	}
	_ = provider.CleanUp(ctx, domain, challengeName)
	return nil
}

func (d *DNSPod) validateDNSPod(appID, appToken string) error {
	form := url.Values{}
	form.Set("login_token", appID+","+appToken)
	form.Set("format", "json")

	resp, err := http.PostForm("https://dnsapi.cn/Info.Version", form)
	if err != nil {
		return fmt.Errorf("无法连接到 DNSPod API: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("DNSPod API 返回状态码 %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Status struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("解析 DNSPod 响应失败: %v", err)
	}
	if result.Status.Code != "1" {
		return fmt.Errorf("DNSPod 凭证无效: %s", result.Status.Message)
	}
	return nil
}

func (d *DNSPod) validateTencentCloud(secretID, secretKey string) error {
	const (
		service   = "cns"
		host      = "cns.tencentcloudapi.com"
		action    = "DescribeDomainList"
		version   = "2021-09-22"
		region    = "ap-guangzhou"
		signatureMethod = "HmacSHA256"
	)

	timestamp := time.Now().Unix()
	nonce := fmt.Sprintf("%d", time.Now().UnixNano())

	params := map[string]string{
		"Action":          action,
		"Version":         version,
		"Region":          region,
		"Timestamp":       fmt.Sprintf("%d", timestamp),
		"Nonce":           nonce,
		"SecretId":        secretID,
		"SignatureMethod": signatureMethod,
		"Offset":          "0",
		"Limit":           "1",
	}

	params["Signature"] = d.tencentCloudSignature(params, secretKey, "GET", host, "/")

	u := url.URL{Scheme: "https", Host: host, Path: "/"}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return fmt.Errorf("构建请求失败: %v", err)
	}
	req.Header.Set("Host", host)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("无法连接到腾讯云 API: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("腾讯云 API 返回状态码 %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Response struct {
			Error struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("解析腾讯云响应失败: %v", err)
	}
	if result.Response.Error.Code != "" {
		return fmt.Errorf("腾讯云凭证无效: %s", result.Response.Error.Message)
	}
	return nil
}

func (d *DNSPod) tencentCloudSignature(params map[string]string, secretKey, method, host, uri string) string {
	var keys []string
	for k := range params {
		if k == "Signature" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var queryParts []string
	for _, k := range keys {
		queryParts = append(queryParts, k+"="+params[k])
	}
	queryString := strings.Join(queryParts, "&")

	signString := method + host + uri + "?" + queryString

	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(signString))
	return hex.EncodeToString(h.Sum(nil))
}
