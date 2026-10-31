package dnsproviders

import (
	"context"
	"encoding/json"
	"log"

	"lazy-balancer-v2/internal/dnsprovider"
)

var newDNSProviderFromCredentials = dnsprovider.NewProviderFromCredentials

// warnLog 是本包的告警输出接缝：包边界不允许导入 services 的分级
// Logf，默认写标准库 log 并保留原有 "warn: " 前缀形态；services 侧在 init
// 注入 Logf("warn", ...)，使告警与全局日志级别过滤/JSON 输出同形态（此前
// 直接 log.Printf 的残留在 warn 以上级别过滤或 JSON 输出场景会丢失/形态分叉）。
var warnLog = func(format string, args ...any) { log.Printf("warn: "+format, args...) }

// SetWarnLogger 注入分级告警输出（生产由 services 包 init 调用；nil 忽略）。
func SetWarnLogger(fn func(format string, args ...any)) {
	if fn != nil {
		warnLog = fn
	}
}

func init() { Register(&DNSPod{}) }

type DNSPod struct {
	BaseProvider
}

func (d *DNSPod) Code() string       { return "dnspod" }
func (d *DNSPod) Name() string       { return "DNSPod (腾讯云)" }
func (d *DNSPod) ModuleName() string { return "dns.providers.dnspod" }

func (d *DNSPod) CredentialFields() []CredentialField {
	// visible_when/option_labels：字段可见性与选项文案
	// 由后端元数据下发，前端不再硬编码两种认证模式的字段名。
	visibleOnly := func(mode string) map[string][]string {
		return map[string][]string{"auth_mode": {mode}}
	}
	return []CredentialField{
		{
			Name: "auth_mode", Label: "认证方式", Type: "select", Required: true, Placeholder: "dnspod",
			OptionLabels: map[string]string{"dnspod": "DNSPod API", "tencent_cloud": "腾讯云 API"},
		},
		{Name: "app_id", Label: "App ID", Type: "text", Required: false, Placeholder: "DNSPod 账号的 App ID（旧版）", VisibleWhen: visibleOnly("dnspod")},
		{Name: "app_token", Label: "App Token", Type: "password", Required: false, Placeholder: "DNSPod 账号的 API Token（旧版）", VisibleWhen: visibleOnly("dnspod")},
		{Name: "secret_id", Label: "SecretId", Type: "text", Required: false, Placeholder: "腾讯云 API SecretId（新版）", VisibleWhen: visibleOnly("tencent_cloud")},
		{Name: "secret_key", Label: "SecretKey", Type: "password", Required: false, Placeholder: "腾讯云 API SecretKey（新版）", VisibleWhen: visibleOnly("tencent_cloud")},
	}
}

func (d *DNSPod) CredentialFieldOptions(field string) []string {
	if field == "auth_mode" {
		return []string{"dnspod", "tencent_cloud"}
	}
	return nil
}

// buildCredentials 校验并产出规范凭据 map（内核直返
// map——曾先 Marshal 成 JSON 串、BuildCredentialsJSON 再 Unmarshal 回 map
// 的序列化往返，仅为类型转换）。
//
// 推断/归一逻辑不在本函数：`dnsprovider.CanonicalCredentials` 是「原始凭证 →
// 规范凭据」的唯一实现，保存前验证（本函数）与签发链 provider 构造共用它。
// 两侧曾各写一份推断，导致同一份库内 JSON 在「测试」与「签发」上结论相反。
// 同时接受 UI 形态（auth_mode + 表单字段，存储形态）与 canonical 形态
// （mode + api_token / mode + secret 对，本函数产物）——产出可回喂。
func (d *DNSPod) buildCredentials(creds map[string]string) (map[string]string, error) {
	canonical, err := (dnsprovider.CredentialEnvelope{
		Mode:      creds["mode"],
		AuthMode:  creds["auth_mode"],
		APIToken:  creds["api_token"],
		AppID:     creds["app_id"],
		AppToken:  creds["app_token"],
		SecretID:  creds["secret_id"],
		SecretKey: creds["secret_key"],
	}).Canonical()
	if err != nil {
		return nil, err
	}
	if canonical.Mode == "dnspod" {
		return map[string]string{"mode": "dnspod", "api_token": canonical.APIToken}, nil
	}
	// canonical 的 tencent 形态不再携带 api_token 拼接值——tencent 模式消费端
	// 只读 secret_id/secret_key，拼接串是零消费死字段。
	return map[string]string{
		"mode":       canonical.Mode,
		"secret_id":  canonical.SecretID,
		"secret_key": canonical.SecretKey,
	}, nil
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

// dnsProviderValidateTimeout / retryEnvelopeFactor 与共享探针（validate_probe.go）
// 同源——本文件仅保留 Validate 的 provider 构造，探针预算常量定义在探针侧。

func (d *DNSPod) Validate(ctx context.Context, creds map[string]string, testDomain string) error {
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
	return runValidateProbe(ctx, provider, testDomain, "dnspod")
}
