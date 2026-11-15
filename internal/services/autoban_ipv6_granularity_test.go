package services

// 自动封禁 IPv6 /64 计数粒度与保留地址硬排除钉测：
//   - 隐私扩展地址在 /64 内轮换必须聚合计数（逐地址建键永不达阈值）；
//   - 封禁条目落 /64 CIDR（名单/匹配器按前缀封禁整段）；
//   - 归一语义与 lbhuman.normalizeIP（CC 检测/cookie 绑定）逐形等价；
//   - 保留/私网/回环地址与攻击光流环同一判据排除，不得计入。

import (
	"net"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// lbhumanNormalizeIPReference 是 lbhuman/cookie.go normalizeIP 的语义参照
// （逐行同算法）：lbhuman 是依赖 Caddy 的独立插件模块，面板主模块不引入其
// 依赖树，等价性由本对拍钉测锁定——修改任一侧必须同步另一侧。
func lbhumanNormalizeIPReference(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if parsed.To4() != nil {
		return ip
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String()
}

// Given 同 /64 的多个隐私扩展地址，各自计数 threshold-1 次（逐地址键形态
// 下任何单地址都不达标）。
// When 经生产喂入门累计。
// Then /64 聚合达标产生封禁候选，且名单条目为 /64 CIDR 而非裸地址。
func TestAutobanObserve_ipv6PrivacyRotationAggregatesPer64(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	setAutobanConfigRaw(t, true, 3, 5, "1h", "blocked", false)

	addrs := []string{
		"2606:4700:abcd:1234:1111:2222:3333:4444",
		"2606:4700:abcd:1234:aaaa:bbbb:cccc:dddd",
		"2606:4700:abcd:1234::9",
	}
	for _, ip := range addrs {
		for range 2 { // 每地址 2 次 < 阈值 3：逐地址键永不达标
			autobanObserveEventScopedAt(AutobanConfig{Enabled: true, Threshold: 3, WindowMinutes: 5, Duration: "1h", Scope: "blocked"},
				ip, "blocked", "942100", autobanNow())
		}
	}

	autobanMu.Lock()
	keys := make([]string, 0, len(autobanWindows))
	for k := range autobanWindows {
		keys = append(keys, k)
	}
	w := autobanWindows["2606:4700:abcd:1234::"]
	autobanMu.Unlock()
	if len(keys) != 1 || keys[0] != "2606:4700:abcd:1234::" {
		t.Fatalf("同 /64 轮换必须聚合为单键 2606:4700:abcd:1234::，实际键=%v", keys)
	}
	if w == nil || w.Count != 6 || !w.Reached {
		t.Fatalf("/64 聚合计数=%+v, want count=6 reached", w)
	}

	candidates := autobanCandidates(3, 5*time.Minute)
	if len(candidates) != 1 || candidates[0].IP != "2606:4700:abcd:1234::" || candidates[0].Count != 6 {
		t.Fatalf("候选=%+v, want 单条 /64 键 count=6", candidates)
	}
	out, err := autobanMergeEntries(AutobanConfig{Duration: "1h"}, candidates)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(out.Banned) != 1 || out.Banned[0] != "2606:4700:abcd:1234::/64" {
		t.Fatalf("封禁条目=%v, want /64 CIDR（整段封禁）", out.Banned)
	}
	entries := entryValues(presetEntries(t))
	e, ok := entries["2606:4700:abcd:1234::/64"]
	if !ok || !autobanEntryIsAutomatic(e) || e.ExpiresAt == "" {
		t.Fatalf("名单终态=%+v, want /64 CIDR 自动条目带到期", entries)
	}
}

// 不同 /64 不得互相聚合（归一只取前 64 位，第 5 段起差异保留）。
func TestAutobanObserve_ipv6Different64StaySeparate(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h", Scope: "blocked"}
	autobanObserveEventScopedAt(cfg, "2606:4700:abcd:1234::1", "blocked", "942100", autobanNow())
	autobanObserveEventScopedAt(cfg, "2606:4700:abcd:1235::1", "blocked", "942100", autobanNow())
	autobanMu.Lock()
	defer autobanMu.Unlock()
	if len(autobanWindows) != 2 {
		t.Fatalf("不同 /64 必须独立计数，键数=%d", len(autobanWindows))
	}
	if autobanWindows["2606:4700:abcd:1234::"] == nil || autobanWindows["2606:4700:abcd:1235::"] == nil {
		t.Fatalf("键形态=%v, want 两个 /64 网络地址", autobanWindows)
	}
}

// IPv4 粒度零变化：裸地址键、裸地址条目（回归形状）。
func TestAutobanObserve_ipv4GranularityUnchanged(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "blocked", false)
	for range 2 {
		autobanObserveEventScopedAt(AutobanConfig{Enabled: true, Threshold: 2, WindowMinutes: 5, Duration: "1h", Scope: "blocked"},
			"45.33.32.9", "blocked", "942100", autobanNow())
	}
	autobanMu.Lock()
	w := autobanWindows["45.33.32.9"]
	autobanMu.Unlock()
	if w == nil || w.Count != 2 {
		t.Fatalf("IPv4 键必须保持裸地址, got %+v", w)
	}
	out, err := autobanMergeEntries(AutobanConfig{Duration: "1h"}, autobanCandidates(2, 5*time.Minute))
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(out.Banned) != 1 || out.Banned[0] != "45.33.32.9" {
		t.Fatalf("IPv4 封禁条目=%v, want 裸地址（不得补 /32 改变既有形态）", out.Banned)
	}
}

// 归一语义与 lbhuman.normalizeIP 逐形等价（跨模块对拍：IPv6 压缩/展开/大小写、
// 4in6 映射、IPv4、不可解析串）。改任一侧必须同步另一侧。
func TestAutobanNormalizeIP_equivalentToLbhumanSemantics(t *testing.T) {
	for _, ip := range []string{
		"2001:db8:1234:5678::1",
		"2001:0DB8:1234:5678:FFFF:EEEE:DDDD:CCCC",
		"2001:db8:1234:5678::9999",
		"2001:db8:9999::1",
		"::1",
		"fe80::1",
		"::ffff:203.0.113.7",
		"203.0.113.7",
		"not-an-ip",
		"",
	} {
		if got, want := autobanNormalizeIP(ip), lbhumanNormalizeIPReference(ip); got != want {
			t.Fatalf("autobanNormalizeIP(%q)=%q, lbhuman 语义=%q（两侧必须同步）", ip, got, want)
		}
	}
}

// 封禁条目值形态：/64 网络地址落 CIDR；非网络地址的 IPv6（带外直填桶形态）
// 与 IPv4 保持裸值。
func TestAutobanBanValue_cidrOnlyFor64Network(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2606:4700:abcd:1234::", "2606:4700:abcd:1234::/64"},
		{"2606:4700:abcd:1234::1", "2606:4700:abcd:1234::1"},
		{"45.33.32.9", "45.33.32.9"},
		{"not-an-ip", "not-an-ip"},
	}
	for _, tc := range cases {
		if got := autobanBanValue(tc.in); got != tc.want {
			t.Fatalf("autobanBanValue(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

// /64 条目已在名单时不得重复追加；刚到期 /64 同轮不得重封（身份键对齐）。
func TestAutobanMergeEntries_ipv6CIDRIdentityDedupAndExpiry(t *testing.T) {
	f := installAutobanFixture(t, "2026-11-15 10:00:00")
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "2606:4700:abcd:1234::/64", Remark: autobanEntryRemark, CreatedAt: "2026-11-15 09:00:00", ExpiresAt: "2026-11-15 11:00:00"},
	})
	candidates := []AutobanSuggestion{{IP: "2606:4700:abcd:1234::", Count: 9}}
	out, err := autobanMergeEntries(AutobanConfig{Duration: "1h"}, candidates)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(out.Banned) != 0 || out.Total != 1 {
		t.Fatalf("已在名单的 /64 不得重复追加: %+v", out)
	}

	// 到期形态：条目到期后同轮候选不得立即重封。
	f.Advance(2 * time.Hour)
	out, err = autobanMergeEntries(AutobanConfig{Duration: "1h"}, candidates)
	if err != nil {
		t.Fatalf("merge after expiry: %v", err)
	}
	if len(out.Expired) != 1 || len(out.Banned) != 0 {
		t.Fatalf("刚到期 /64 同轮不得重封: expired=%v banned=%v", out.Expired, out.Banned)
	}
}

// 解封清桶：删除 /64 CIDR 条目必须清掉归一计数键（删除即解封不被撤销）。
func TestAutobanForgetIPs_cidrValueClearsNormalizedCounter(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h", Scope: "blocked"}
	autobanObserveEventScopedAt(cfg, "2606:4700:abcd:1234::7", "blocked", "942100", autobanNow())
	AutobanSetSuggestionsForTest([]AutobanSuggestion{{IP: "2606:4700:abcd:1234::", Count: 1}})

	AutobanForgetIPs([]string{"2606:4700:abcd:1234::/64"})

	autobanMu.Lock()
	n := len(autobanWindows)
	suggestions := len(autobanSuggestions)
	autobanMu.Unlock()
	if n != 0 || suggestions != 0 {
		t.Fatalf("删除 /64 条目必须清计数键与建议: windows=%d suggestions=%d", n, suggestions)
	}
}

// 保留地址硬排除（与光流环同判据）：内网/回环/链路本地/文档示例命中 CRS
// 不得计入——内网扫描器不是外网攻击证据，计入会自动封禁内网服务。
func TestAutobanObserve_reservedClientIPsExcluded(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h",
		Scope: "blocked,logged,challenge_issued,challenge_failed"}
	reserved := []string{
		"127.0.0.1", "10.1.2.3", "192.168.1.10", "172.16.0.9",
		"100.64.0.1", "169.254.1.1", "192.0.2.5", "198.51.100.7", "203.0.113.9",
		"::1", "fe80::1", "fc00::1", "2001:db8::1",
	}
	for _, ip := range reserved {
		autobanObserveEventScopedAt(cfg, ip, "blocked", "942100", autobanNow())
		autobanObserveEventScopedAt(cfg, ip, "challenged", "human_failed", autobanNow())
	}
	autobanMu.Lock()
	n := len(autobanWindows)
	autobanMu.Unlock()
	if n != 0 {
		t.Fatalf("保留地址不得计入自动封禁（WAF/人机两路），键数=%d", n)
	}

	// 对照：公网地址照常计数（排除门不得误伤）。
	autobanObserveEventScopedAt(cfg, "45.33.32.9", "blocked", "942100", autobanNow())
	autobanMu.Lock()
	w := autobanWindows["45.33.32.9"]
	autobanMu.Unlock()
	if w == nil || w.Count != 1 {
		t.Fatalf("公网地址必须照常计数, got %+v", w)
	}
}

// 人机批喂入同门：保留地址的挑战发放/失败不得计入（ObserveHumanEvents 路径）。
func TestObserveHumanEvents_reservedIPsExcluded(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "challenge_issued,challenge_failed", false)
	ObserveHumanEvents([]HumanObserveItem{
		{IP: "192.168.1.10", Kind: "fail", At: autobanNow()},
		{IP: "::1", Kind: "challenge", At: autobanNow()},
		{IP: "45.33.32.9", Kind: "fail", At: autobanNow()},
	})
	autobanMu.Lock()
	defer autobanMu.Unlock()
	if len(autobanWindows) != 1 || autobanWindows["45.33.32.9"] == nil {
		t.Fatalf("仅公网地址应计数，键=%v", autobanWindows)
	}
}
