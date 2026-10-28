package dnsproviders

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	mathrand "math/rand/v2"
	"strings"
	"time"

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

// dnsProviderValidateTimeout 保存前验证的命令预算（测试缝：var 而非 const，
// 测试按比例缩放保持墙钟快速；生产代码不得改写）。
var dnsProviderValidateTimeout = 30 * time.Second

// retryEnvelopeFactor 是单次 DNS API 调用相对基础预算的倍数：Present 与
// CleanUp 都走 retry.Transport（429/5xx 3 次尝试 + 1s/2s 退避），单次调用
// 的总耗时可能长于基础预算，共用基础预算会把「限流/慢响应」误报成超时失败。
// 两侧必须用同一倍数——只把 Present 提到 3 倍而清理仍用基础预算时，
// 「清理假失败」只是从写入侧挪到了清理侧。
const retryEnvelopeFactor = 3

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

	domain := strings.TrimSpace(testDomain)
	if domain == "" {
		return fmt.Errorf("测试域名不能为空")
	}
	// 输入域用于 challenge FQDN，provider 调用必须用可注册根域——
	// 否则账户只管理 example.com 时输入 www.example.com 会在 getDomainID 精确
	// 查找处误报「domain not found」，与真实签发链（PSL 解析）口径分裂。
	// 已知限制：委派子区（账户实际 zone=sub.example.com）PSL 不可见，需以根域
	// 验证（见 dnsprovider.ResolveZone 注释）。
	zone, err := dnsprovider.ResolveZone(domain)
	if err != nil {
		return fmt.Errorf("测试域名无效: %w", err)
	}
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	challengeName := "_acme-challenge.lb-test." + domain
	// 探针值带随机后缀——清理失败残留的常量值记录不会
	// 让下一次验证产生同 (名,值) 歧义（腾讯云对完全重复 TXT 的处理不在本仓
	// 契约内，去掉可避免的碰撞面）。
	probeValue := fmt.Sprintf("lazy-balancer-test-%08x", mathrand.Uint32())
	// 写入探测同时受调用方请求 ctx（客户端断开/请求超时立即中止）与内部
	// 预算约束——取二者更早者。清理预算必须独立（见下方注释）：请求 ctx 已
	// 取消时仍要尽力删掉测试记录。
	if ctx == nil {
		ctx = context.Background()
	}
	presentCtx, presentCancel := context.WithTimeout(ctx, dnsProviderValidateTimeout*retryEnvelopeFactor)
	defer presentCancel()
	if err := provider.Present(presentCtx, zone, challengeName, probeValue, 600); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("DNS 写入测试超时（DNS API 响应过慢或重试退避耗尽写入预算 %s）: %w", dnsProviderValidateTimeout*retryEnvelopeFactor, err)
		}
		return fmt.Errorf("DNS 写入测试失败: %w", err)
	}
	// 清理必须用独立预算——共用 Present 的 ctx 时，传输层重试包络
	// （429/5xx 3 次 × 30s 退避）耗尽预算后 CleanUp 立即因 ctx.Err() 失败，
	// 用户看到「DNS 清理测试失败」的假失败（记录其实写入成功）。独立预算同样
	// 要覆盖重试包络（retryEnvelopeFactor）：清理链含两次网络往返
	// （getDomainID 未命中缓存时 Domain.List 分页 + Record.Remove），只用基础
	// 30s 时慢/限流 provider 会在删除已成功或即将成功的路径上被 ctx 截断，
	// 把「可能已删除」误报成「清理失败」。
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), dnsProviderValidateTimeout*retryEnvelopeFactor)
	defer cleanupCancel()
	// 按值清理（能力分派）：探针值每次随机，并发验证同一域名时按名清理会
	// 删掉另一个请求仍在传播检查中的记录。无 ValueCleaner 的 provider 回退按名。
	if err := dnsprovider.CleanUpChallenge(cleanupCtx, provider, zone, challengeName, probeValue); err != nil {
		// 清理失败时测试 TXT 记录可能已残留——记告警
		// 并在错误文案点名手动清理路径；返回错误语义不变（验证仍判失败）。
		warnLog("dnspod 验证清理失败，测试记录 %s 可能残留，请手动清理: %v", challengeName, err)
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("DNS 清理测试超时（DNS API 响应过慢或重试退避耗尽清理预算 %s，删除可能已完成或仍在服务端排队）: %w（若残留请登录 DNS 控制台手动清理 %s TXT 记录）", dnsProviderValidateTimeout*retryEnvelopeFactor, err, strings.TrimSuffix(challengeName, "."))
		}
		return fmt.Errorf("DNS 清理测试失败: %w（测试记录可能已残留，请登录 DNS 控制台手动清理 %s TXT 记录）", err, strings.TrimSuffix(challengeName, "."))
	}
	return nil
}
