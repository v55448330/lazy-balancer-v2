package dnsproviders

// 保存前验证的共享探针：随机值 TXT Present → 按值清理 → 失败残留告警文案。
// 从 dnspod.go 的 Validate 骨架抽出（原样搬迁，行为零变化，由既有 dnspod
// 探针测试钉住），供 DNSPod 与 Aliyun 等「单 zone TXT 探针」型 provider 共用；
// 各 provider 只负责 buildCredentials → provider 构造，探针流程单源。

import (
	"context"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"strings"
	"time"

	"lazy-balancer-v2/internal/dnsprovider"
)

// dnsProviderValidateTimeout 保存前验证的命令预算（测试缝：var 而非 const，
// 测试按比例缩放保持墙钟快速；生产代码不得改写）。
var dnsProviderValidateTimeout = 30 * time.Second

// retryEnvelopeFactor 是单次 DNS API 调用相对基础预算的倍数：Present 与
// CleanUp 都走 retry.Transport（429/5xx 3 次尝试 + 1s/2s 退避），单次调用
// 的总耗时可能长于基础预算，共用基础预算会把「限流/慢响应」误报成超时失败。
// 两侧必须用同一倍数——只把 Present 提到 3 倍而清理仍用基础预算时，
// 「清理假失败」只是从写入侧挪到了清理侧。
const retryEnvelopeFactor = 3

// runValidateProbe 执行一次保存前验证探针（ctx 为调用方请求 ctx 上界）：
// 输入域解析可注册根域 → 随机探针值写入（预算=基础×重试包络）→ 独立预算
// 按值清理；清理失败告警留痕并在错误文案点名手动清理路径。probeLabel 是
// 告警前缀（provider 代码形态，如 "dnspod"/"aliyun"）。
func runValidateProbe(ctx context.Context, provider dnsprovider.Provider, testDomain, probeLabel string) error {
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
	// 要覆盖重试包络（retryEnvelopeFactor）：清理链含多次网络往返，只用基础
	// 30s 时慢/限流 provider 会在删除已成功或即将成功的路径上被 ctx 截断，
	// 把「可能已删除」误报成「清理失败」。
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), dnsProviderValidateTimeout*retryEnvelopeFactor)
	defer cleanupCancel()
	// 按值清理（能力分派）：探针值每次随机，并发验证同一域名时按名清理会
	// 删掉另一个请求仍在传播检查中的记录。无 ValueCleaner 的 provider 回退按名。
	if err := dnsprovider.CleanUpChallenge(cleanupCtx, provider, zone, challengeName, probeValue); err != nil {
		// 清理失败时测试 TXT 记录可能已残留——记告警
		// 并在错误文案点名手动清理路径；返回错误语义不变（验证仍判失败）。
		warnLog("%s 验证清理失败，测试记录 %s 可能残留，请手动清理: %v", probeLabel, challengeName, err)
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("DNS 清理测试超时（DNS API 响应过慢或重试退避耗尽清理预算 %s，删除可能已完成或仍在服务端排队）: %w（若残留请登录 DNS 控制台手动清理 %s TXT 记录）", dnsProviderValidateTimeout*retryEnvelopeFactor, err, strings.TrimSuffix(challengeName, "."))
		}
		return fmt.Errorf("DNS 清理测试失败: %w（测试记录可能已残留，请登录 DNS 控制台手动清理 %s TXT 记录）", err, strings.TrimSuffix(challengeName, "."))
	}
	return nil
}
