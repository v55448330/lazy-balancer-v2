package services

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"testing"
)

// CIDR 聚合（v2.3.x）：兄弟前缀归并 + 去重 + 覆盖剔除 + 排序。
// 不变量：合并前后匹配集合逐点相等（性质测试钉住）。
func TestAggregateIPEntries_siblingMerge(t *testing.T) {
	got := aggregateIPEntries([]string{"10.0.0.0/25", "10.0.0.128/25"})
	if !reflect.DeepEqual(got, []string{"10.0.0.0/24"}) {
		t.Fatalf("got=%v, want [10.0.0.0/24]", got)
	}
}

func TestAggregateIPEntries_dedupAndCover(t *testing.T) {
	got := aggregateIPEntries([]string{"10.0.0.0/24", "10.0.1.0/24", "10.0.0.0/16", "10.0.0.0/24"})
	if !reflect.DeepEqual(got, []string{"10.0.0.0/16"}) {
		t.Fatalf("got=%v, want [10.0.0.0/16]", got)
	}
}

func TestAggregateIPEntries_bareIPAndV6(t *testing.T) {
	got := aggregateIPEntries([]string{"203.0.113.7", "2001:db8::1", "2001:db8::/64", "2001:db8::/64"})
	want := []string{"203.0.113.7/32", "2001:db8::/64"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v, want %v", got, want)
	}
}

// 迭代收敛：四个 /26 连续相邻 → 两级归并为一个 /24。
func TestAggregateIPEntries_iterativeConvergence(t *testing.T) {
	got := aggregateIPEntries([]string{"192.0.2.0/26", "192.0.2.64/26", "192.0.2.128/26", "192.0.2.192/26"})
	if !reflect.DeepEqual(got, []string{"192.0.2.0/24"}) {
		t.Fatalf("got=%v, want [192.0.2.0/24]", got)
	}
}

// 不可解析条目透传（不静默削弱安全名单——引擎层对坏条目 fail-closed）。
func TestAggregateIPEntries_unparseablePassthrough(t *testing.T) {
	got := aggregateIPEntries([]string{"10.0.0.0/8", "garbage-entry"})
	if !reflect.DeepEqual(got, []string{"10.0.0.0/8", "garbage-entry"}) {
		t.Fatalf("got=%v, want 含透传坏条目", got)
	}
}

// 性质测试：随机 200 条混合名单（嵌套 /16-/24、相邻 /24、v6、重复项），
// 对合并前后两集合各随机探 200 个 IP，Contains 判定逐点一致。
func TestAggregateIPEntries_equivalenceProperty(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 0))
	var entries []string
	for range 200 {
		switch rng.IntN(5) {
		case 0: // /16 嵌套源
			entries = append(entries, fmt.Sprintf("10.%d.0.0/16", rng.IntN(4)))
		case 1: // 相邻 /24（落在 /16 内，制造覆盖+兄弟归并）
			entries = append(entries, fmt.Sprintf("10.%d.%d.0/24", rng.IntN(4), rng.IntN(8)))
		case 2: // 裸 IP
			entries = append(entries, fmt.Sprintf("203.0.113.%d", rng.IntN(256)))
		case 3: // v6
			entries = append(entries, fmt.Sprintf("2001:db8:%x::/48", rng.IntN(4)))
		case 4: // 重复项（从已有里挑）
			if len(entries) > 0 {
				entries = append(entries, entries[rng.IntN(len(entries))])
			}
		}
	}

	contains := func(set []string, addr netip.Addr) bool {
		for _, entry := range set {
			p, err := netip.ParsePrefix(entry)
			if err != nil {
				if a, aerr := netip.ParseAddr(entry); aerr == nil {
					bits := 32
					if a.Is6() {
						bits = 128
					}
					p = netip.PrefixFrom(a, bits)
				} else {
					continue
				}
			}
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}

	merged := aggregateIPEntries(entries)
	for range 200 {
		var addr netip.Addr
		if rng.IntN(2) == 0 {
			addr = netip.AddrFrom4([4]byte{byte(10 + rng.IntN(200)), byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256))})
		} else {
			addr = netip.MustParseAddr(fmt.Sprintf("2001:db8:%x::%x", rng.IntN(8), rng.IntN(65536)))
		}
		if contains(entries, addr) != contains(merged, addr) {
			t.Fatalf("probe %s: pre=%v post=%v — 合并前后集合不等价", addr, contains(entries, addr), contains(merged, addr))
		}
	}
}
