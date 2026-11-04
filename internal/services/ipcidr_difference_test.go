package services

import (
	"net/netip"
	"reflect"
	"testing"

	"lazy-balancer-v2/wafiplist"
)

// differenceIPEntries 是渲染层差集原语（left 匹配集 − right 匹配集）：直通∩
// 保留检测重叠 IP 的信任路由归属由它裁决——直通优先，与 TCP 路由序
// （直通路由 → 保留检测路由）同语义。解析口径与 aggregateIPEntries 一致
// （wafiplist.ParseIPEntry：裸 IP 补前缀、主机位掩码归零、4in6 归一）。

func TestDifferenceIPEntries_exactEntryRemoved(t *testing.T) {
	got := differenceIPEntries([]string{"10.0.0.9"}, []string{"10.0.0.9"})
	if len(got) != 0 {
		t.Fatalf("got=%v, want 空差集（同一条目两侧覆盖）", got)
	}
}

func TestDifferenceIPEntries_nestedRangeSplits(t *testing.T) {
	// 宿主 /24 减去其中 /25 → 仅剩前一半：真实 CIDR 差集，字符串相等剔除不够。
	got := differenceIPEntries([]string{"10.0.0.0/24"}, []string{"10.0.0.128/25"})
	if !reflect.DeepEqual(got, []string{"10.0.0.0/25"}) {
		t.Fatalf("got=%v, want [10.0.0.0/25]", got)
	}
	// 宿主落在扣除宽段内部 → 整体消失。
	got = differenceIPEntries([]string{"10.0.0.9"}, []string{"10.0.0.0/24"})
	if len(got) != 0 {
		t.Fatalf("got=%v, want 空差集（left 被 right 宽段覆盖）", got)
	}
}

func TestDifferenceIPEntries_disjointKeepsAll(t *testing.T) {
	got := differenceIPEntries(
		[]string{"10.0.0.0/24", "2001:db8::/48"},
		[]string{"192.0.2.0/24", "2001:db8:1::/48"},
	)
	want := []string{"10.0.0.0/24", "2001:db8::/48"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v, want %v（不相交条目原样保留）", got, want)
	}
}

func TestDifferenceIPEntries_unparseablePassthrough(t *testing.T) {
	// left 不可解析条目原样透传（与 aggregateIPEntries 同口径：不静默削弱
	// 名单）；right 的坏条目匹配不到任何地址，不参与扣除。
	got := differenceIPEntries([]string{"10.0.0.9", "garbage"}, []string{"10.0.0.9", "junk"})
	if !reflect.DeepEqual(got, []string{"garbage"}) {
		t.Fatalf("got=%v, want [garbage]（坏条目透传，合法条目被扣除）", got)
	}
	got = differenceIPEntries([]string{"10.0.0.9"}, []string{"junk"})
	if !reflect.DeepEqual(got, []string{"10.0.0.9/32"}) {
		t.Fatalf("got=%v, want [10.0.0.9/32]（right 坏条目不扣除任何地址）", got)
	}
}

func TestDifferenceIPEntries_4in6EntryUnmaps(t *testing.T) {
	// ParseIPEntry 归一 4in6 → v4；两侧同一地址必须互相覆盖。
	got := differenceIPEntries([]string{"::ffff:10.0.0.9"}, []string{"10.0.0.9"})
	if len(got) != 0 {
		t.Fatalf("got=%v, want 空差集（4in6 与 v4 同地址归一一侧）", got)
	}
}

// 性质测试：差集匹配集 ≡ left 命中且 right 不命中（逐点等价）——探针取各段
// 边界 ±1 与段内随机点，判定一律经 netip.Contains（同一解析口径）。
func TestDifferenceIPEntries_equivalenceProperty(t *testing.T) {
	left := []string{"10.0.0.0/24", "10.0.1.0/24", "198.51.100.0/25", "2001:db8::/48"}
	right := []string{"10.0.0.128/25", "10.0.1.0/24", "198.51.100.64/26", "2001:db8:0:1::/64"}
	got := differenceIPEntries(left, right)

	in := func(entries []string, addr netip.Addr) bool {
		for _, entry := range entries {
			prefix, err := wafiplist.ParseIPEntry(entry)
			if err != nil {
				continue
			}
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	}

	probes := []string{
		"10.0.0.1", "10.0.0.127", "10.0.0.128", "10.0.0.255",
		"10.0.1.1", "10.0.2.1",
		"198.51.100.1", "198.51.100.63", "198.51.100.64", "198.51.100.127", "198.51.100.128",
		"2001:db8::1", "2001:db8:0:1::1", "2001:db8:0:2::1",
		"203.0.113.9",
	}
	for _, probe := range probes {
		addr := netip.MustParseAddr(probe)
		want := in(left, addr) && !in(right, addr)
		if gotHit := in(got, addr); gotHit != want {
			t.Fatalf("probe %s: 差集命中=%v, want %v（left ∩ ¬right）\ngot=%v", probe, gotHit, want, got)
		}
	}

	// 输出为聚合规范形态：升序且两两不相交（下游 client_ip ranges 依赖）。
	parsed := make([]netip.Prefix, 0, len(got))
	for _, entry := range got {
		prefix, err := wafiplist.ParseIPEntry(entry)
		if err != nil {
			t.Fatalf("差集输出含不可解析条目 %q: %v", entry, err)
		}
		parsed = append(parsed, prefix)
	}
	for i := 1; i < len(parsed); i++ {
		if parsed[i-1].Overlaps(parsed[i]) {
			t.Fatalf("差集输出存在重叠段：%v", parsed)
		}
	}
}
