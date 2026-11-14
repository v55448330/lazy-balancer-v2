package handlers

// 连接详情远端剥端口契约：IPv4/IPv6（带括号与无括号）都必须剥掉端口再查
// 归属地——此前只认「≤1 个冒号」的 IPv4 形态，IPv6 远端带端口整体进查库，
// 归属地恒空（与 IPv4 展示不一致）。归属地查询经 enrichIPLocationLookup 缝
// 注入，断言「查库收到的 IP 形态」与「Remote 展示值」。

import (
	"net"
	"testing"
)

func TestJoinConnectionsMetadata_stripsPortForIPv4AndIPv6(t *testing.T) {
	var lookedUp []string
	old := enrichIPLocationLookup
	enrichIPLocationLookup = func(ip string) string {
		lookedUp = append(lookedUp, ip)
		if net.ParseIP(ip) == nil {
			return "" // 非 IP（带端口/通配残值）查库无结果——与真实 xdb 同语义
		}
		return "中国|广东省|深圳市|电信|CN"
	}
	t.Cleanup(func() { enrichIPLocationLookup = old })
	// 进程内归属地缓存吸收重复 IP（enrichIPLocationCached 按 IP 键）——重置
	// 保隔离，使查库次数断言确定（否则他测已缓存同 IP 会少查）。
	enrichLocationCache.Lock()
	enrichLocationCache.entries = make(map[string]enrichLocationCacheEntry)
	enrichLocationCache.Unlock()

	entries := []connectionEntry{
		{Remote: "1.2.3.4:53981"},
		{Remote: "[240e:56:1:2::9]:443"},
		{Remote: "240e:56:1:2::9:443"}, // netstat 无括号形态
		{Remote: "*:80"},
	}
	joinConnectionsMetadata(entries)

	wantRemotes := []string{"1.2.3.4", "240e:56:1:2::9", "240e:56:1:2::9", "80"}
	for i, want := range wantRemotes {
		if entries[i].Remote != want {
			t.Fatalf("entries[%d].Remote=%q, want %q（端口必须剥掉）", i, entries[i].Remote, want)
		}
	}
	// 查库收到的必须是剥端口后的纯 IP（带端口整体查库 → xdb 解析失败恒空）。
	// 重复 IPv6（entries[1]/[2] 同 IP）由进程内缓存吸收，只查一次；通配
	// *:80 剥前缀后为 "80"（非 IP，查库返回空串，归属地留空）。故 4 行 → 3 次查库。
	wantLookups := []string{"1.2.3.4", "240e:56:1:2::9", "80"}
	if len(lookedUp) != len(wantLookups) {
		t.Fatalf("查库次数=%d (%v), want %d（重复 IP 缓存吸收）", len(lookedUp), lookedUp, len(wantLookups))
	}
	for i, want := range wantLookups {
		if lookedUp[i] != want {
			t.Fatalf("查库 IP[%d]=%q, want %q（IPv6 带端口查库归属地恒空）", i, lookedUp[i], want)
		}
	}
	for i := range 3 {
		if entries[i].Country == "" {
			t.Fatalf("entries[%d] 归属地为空（剥端口后应能查到）", i)
		}
	}
}
