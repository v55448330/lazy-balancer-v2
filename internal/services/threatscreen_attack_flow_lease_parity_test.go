package services

// 采样租约模型的跨模块一致性守门。
//
// 攻击光流采样租约在两处独立实现：管理端 services（本包）与 Caddy 侧
// caddygeoip/traffic_lease.go。两处必须同语义——TTL 缺省与钳制区间、lease_id
// 长度上限、并发租约上限、抽样因子上限。历史上两处靠「注释说同族」维持，
// 任一侧单边调整都会让前端心跳（按管理端口径续租）与执行面（按 Caddy 口径
// 判定存活/抽样）撕开：TTL 不一致=租约在另一侧提前过期导致采样抖动；上限
// 不一致=一侧接受另一侧拒绝；抽样上限不一致=大屏档位与实际事件密度分叉。
//
// 本测试直接从对端源码抽取常量逐项比对（对端为独立 Go module，无法 import
// 常量），任一侧改动即整包变红。

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// caddyTrafficLeaseSource 对端租约实现源码路径（相对本包目录）。
var caddyTrafficLeaseSource = filepath.Join("..", "..", "caddygeoip", "traffic_lease.go")

// parseCaddyTrafficLeaseConstant 从对端源码抽出一个常量字面量（秒级 TTL 或
// 整数），未命中即失败——改名/挪文件必须让本守门显式报错，不得静默跳过。
func parseCaddyTrafficLeaseConstant(t *testing.T, src, name string) int {
	t.Helper()
	pattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `(\s+uint32)?\s*=\s*(\d+)`)
	match := pattern.FindStringSubmatch(src)
	if match == nil {
		t.Fatalf("对端常量 %s 未在 %s 中找到（改名/挪位后必须同步本守门）", name, caddyTrafficLeaseSource)
	}
	value, err := strconv.Atoi(match[2])
	if err != nil {
		t.Fatalf("对端常量 %s 解析失败: %v", name, err)
	}
	return value
}

func TestThreatScreenLease_parityWithCaddySide(t *testing.T) {
	raw, err := os.ReadFile(caddyTrafficLeaseSource)
	if err != nil {
		t.Fatalf("读取对端租约实现失败: %v", err)
	}
	src := string(raw)

	// TTL 三档（秒）：缺省/下限/上限。
	for _, probe := range []struct {
		caddy    string
		services time.Duration
	}{
		{"trafficLeaseTTLDefault", threatScreenAttackFlowLeaseTTLDefault},
		{"trafficLeaseTTLMin", threatScreenAttackFlowLeaseTTLMin},
		{"trafficLeaseTTLMax", threatScreenAttackFlowLeaseTTLMax},
	} {
		want := parseCaddyTrafficLeaseConstant(t, src, probe.caddy)
		if got := int(probe.services / time.Second); got != want {
			t.Fatalf("TTL 不一致：services %s=%ds, caddygeoip %s=%ds", probe.services, got, probe.caddy, want)
		}
	}

	// lease_id 长度上限与并发租约上限。
	if want := parseCaddyTrafficLeaseConstant(t, src, "trafficLeaseIDMaxLen"); threatScreenAttackFlowLeaseIDMaxLen != want {
		t.Fatalf("lease_id 长度上限不一致：services=%d, caddygeoip=%d", threatScreenAttackFlowLeaseIDMaxLen, want)
	}
	if want := parseCaddyTrafficLeaseConstant(t, src, "trafficLeasesMax"); threatScreenAttackFlowLeaseMax != want {
		t.Fatalf("并发租约上限不一致：services=%d, caddygeoip=%d", threatScreenAttackFlowLeaseMax, want)
	}

	// 抽样因子上限：对端是常量，本侧由归一函数表达（钳 [0,max]）——用行为
	// 断言而不是再抄一份常量。
	sampleMax := parseCaddyTrafficLeaseConstant(t, src, "trafficLeaseSampleNMax")
	if got := clampThreatScreenAttackFlowSampleN(sampleMax); got != sampleMax {
		t.Fatalf("抽样上限不一致：clamp(%d)=%d, caddygeoip max=%d", sampleMax, got, sampleMax)
	}
	if got := clampThreatScreenAttackFlowSampleN(sampleMax + 1); got != sampleMax {
		t.Fatalf("抽样档位未钳到与 caddygeoip 相同的上限：clamp(%d)=%d, want %d", sampleMax+1, got, sampleMax)
	}
	// 档位归一形状（0=关闭语义两侧一致，负数按全量=1）。
	if got := clampThreatScreenAttackFlowSampleN(0); got != 0 {
		t.Fatalf("clamp(0)=%d, want 0（0=关闭逐请求事件）", got)
	}
	if got := clampThreatScreenAttackFlowSampleN(-3); got != 1 {
		t.Fatalf("clamp(-3)=%d, want 1（负数=全量）", got)
	}
}
