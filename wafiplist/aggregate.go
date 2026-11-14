package wafiplist

import (
	"net/netip"
	"sort"
	"strings"
)

// AggregatePrefixes 聚合 IP/CIDR 名单（字符串入口）：逐条目解析一次
// （ParseIPEntry——裸 IP 补 /32 //128、主机位掩码归零、4in6 归一）后交给
// AggregateParsedPrefixes 聚合。不可解析条目被丢弃（调用方需先自行校验/
// 透传）。
func AggregatePrefixes(entries []string) []netip.Prefix {
	parsed := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		prefix, err := ParseIPEntry(entry)
		if err != nil {
			continue
		}
		parsed = append(parsed, prefix)
	}
	return AggregateParsedPrefixes(parsed)
}

// AggregateParsedPrefixes 聚合**已解析**前缀（ParseIPEntry 产物或等价形态）：
// 去重 → 兄弟前缀归并（同 bits、同父段的相邻对合并为 bits-1 父段，迭代收敛）
// → 剔除被更宽段覆盖的段 → 按地址排序。产出为「升序、去重、不相交」前缀集
// ——既是 @ipListFast 二分检索的加载形态，也是渲染层名单的规范发射形态。
// 不变量：聚合前后匹配集合逐点相等。
//
// 单源原语：字符串入口（AggregatePrefixes/AggregateIPEntries）与
// 「解析已完成」的调用方（名单加载、.fast 编译、选项树）共用同一聚合实现——
// 同一条目只解析一次，不再「校验一次 + 聚合再解析一次」。
func AggregateParsedPrefixes(parsed []netip.Prefix) []netip.Prefix {
	set := make(map[netip.Prefix]struct{}, len(parsed))
	for _, p := range parsed {
		if !p.IsValid() {
			continue
		}
		// ParseIPEntry 已掩码；此处幂等再掩码，防外部构造的未掩码前缀破坏
		// 二分不变量（主机位非零条目能通过读侧校验却查询假阴性）。
		set[p.Masked()] = struct{}{}
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
			// 其余形态（不重叠、相邻但非兄弟）出栈推入：CIDR 前缀区间非嵌套
			// 即不相交；排序保证 top 起点 ≤ p 起点，不相交则 top 整段在 p
			// 之前，也不会与后续条目（起点更靠后）相交。
			break
		}
		if push {
			merged = append(merged, p)
		}
	}
	return merged
}

// AggregateIPEntries 同 AggregatePrefixes，字符串进出（渲染层形态）；不可解析
// 条目原样透传在末尾（不静默削弱安全名单）。透传的方向语义不对称：引擎对坏行
// 严格解析失败 → 匹配器 fail-stale，无缓存时按未命中——deny 名单=不拦、
// allow 名单（否定算子）=全拒。因此渲染侧的威胁库文本在读取阶段已按下载口径
// 剔除坏行（services.scanThreatTextEntries 单遍扫描的 kept 集）；其他调用方
// 传入坏行须自行承担该方向差异。逐条目只解析一次。
func AggregateIPEntries(entries []string) []string {
	var passthrough []string
	parsed := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		prefix, err := ParseIPEntry(entry)
		if err != nil {
			passthrough = append(passthrough, entry)
			continue
		}
		parsed = append(parsed, prefix)
	}
	merged := AggregateParsedPrefixes(parsed)
	out := make([]string, 0, len(merged)+len(passthrough))
	for _, p := range merged {
		out = append(out, p.String())
	}
	return append(out, passthrough...)
}
