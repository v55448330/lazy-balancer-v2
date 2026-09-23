package wafiplist

import (
	"encoding/binary"
	"math"
	"net/netip"
	"sort"
	"strings"
)

// AggregatePrefixes 聚合 IP/CIDR 名单：解析（裸 IP 补 /32 //128、主机位掩码
// 归零）→ 去重 → 兄弟前缀归并（同 bits、同父段的相邻对合并为 bits-1 父段，
// 迭代收敛）→ 剔除被更宽段覆盖的段 → 按地址排序。产出为「升序、去重、
// 不相交」前缀集——既是 @ipListFast 二分检索的加载形态，也是渲染层名单的
// 规范发射形态。不可解析条目被丢弃（调用方需先自行校验/透传）。
// 不变量：聚合前后匹配集合逐点相等。
func AggregatePrefixes(entries []string) []netip.Prefix {
	set := make(map[netip.Prefix]struct{}, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		prefix, err := ParseIPEntry(entry)
		if err != nil {
			continue
		}
		set[prefix] = struct{}{}
	}
	prefixes := make([]netip.Prefix, 0, len(set))
	for p := range set {
		prefixes = append(prefixes, p)
	}
	// 地址升序，同地址宽段（bits 小）在前——保证任意与后续段重叠的已留存段
	// 必为更宽段（CIDR 前缀重叠即含嵌套），栈顶 Contains 判定即充分。
	sort.Slice(prefixes, func(i, j int) bool {
		if c := prefixes[i].Addr().Compare(prefixes[j].Addr()); c != 0 {
			return c < 0
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})

	merged := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		push := true
		for len(merged) > 0 {
			top := merged[len(merged)-1]
			// 兄弟段（同 bits、同父段、地址相邻）→ 归并为父段，继续向上尝试。
			// 必须先于「不重叠即停」判定：兄弟段的末地址恰比 p 起始小 1。
			if top.Bits() == p.Bits() && top.Addr().Is4() == p.Addr().Is4() &&
				netip.PrefixFrom(top.Addr(), top.Bits()-1).Masked() == netip.PrefixFrom(p.Addr(), p.Bits()-1).Masked() {
				p = netip.PrefixFrom(top.Addr(), top.Bits()-1).Masked()
				merged = merged[:len(merged)-1]
				continue
			}
			// 被更宽段覆盖 → 丢弃
			if top.Bits() <= p.Bits() && top.Contains(p.Addr()) {
				push = false
				break
			}
			// 栈顶段在 p 之前结束（不重叠不相邻）→ 不会再与 p 及之后交互
			if prefixLastAddr(top).Compare(p.Addr()) < 0 {
				break
			}
			break
		}
		if push {
			merged = append(merged, p)
		}
	}
	return merged
}

// AggregateIPEntries 同 AggregatePrefixes，字符串进出（渲染层形态）；
// 不可解析条目原样透传在末尾（不静默削弱安全名单——引擎层对坏条目
// fail-closed）。
func AggregateIPEntries(entries []string) []string {
	var parseable, passthrough []string
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, err := ParseIPEntry(entry); err != nil {
			passthrough = append(passthrough, entry)
			continue
		}
		parseable = append(parseable, entry)
	}
	merged := AggregatePrefixes(parseable)
	out := make([]string, 0, len(merged)+len(passthrough))
	for _, p := range merged {
		out = append(out, p.String())
	}
	return append(out, passthrough...)
}

// prefixLastAddr 计算前缀的末地址（广播地址），用于区间相交/相邻判定。
func prefixLastAddr(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		a := p.Addr().As4()
		last := binary.BigEndian.Uint32(a[:]) | (math.MaxUint32 >> p.Bits())
		return netip.AddrFrom4([4]byte{byte(last >> 24), byte(last >> 16), byte(last >> 8), byte(last)})
	}
	a := p.Addr().As16()
	hi := binary.BigEndian.Uint64(a[:8])
	lo := binary.BigEndian.Uint64(a[8:])
	if p.Bits() <= 64 {
		hi |= math.MaxUint64 >> p.Bits()
		lo = math.MaxUint64
	} else {
		lo |= math.MaxUint64 >> (p.Bits() - 64)
	}
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], hi)
	binary.BigEndian.PutUint64(b[8:], lo)
	return netip.AddrFrom16(b)
}
