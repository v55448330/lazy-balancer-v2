package services

import (
	"fmt"
	"net/netip"
	"strings"

	"lazy-balancer-v2/wafiplist"
)

// NormalizeCIDRs 逐条规范化（trim + 统一前缀形态）并去重——重复条目在匹配
// 语义上等价，去重后库内条数与审计 delta 的「N 条」同源（此前重复 CIDR 会
// 以多条落库，审计口径与用户直觉不符）。顺序保持（配置列表语义）。
func NormalizeCIDRs(values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		prefix, err := wafiplist.ParseIPEntry(value)
		if err != nil {
			return nil, fmt.Errorf("%q 不是有效 CIDR: %w", value, err)
		}
		canonical := prefix.String()
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	return normalized, nil
}

// NormalizeMCPIPWhitelistStrings 归一 API Key 来源 IP 白名单（带外数据面专用：
// 主节点快照下发等不经 REST 写侧校验的通道）。逐条规范化并去重，无法解析的
// 条目被丢弃并作为第二个返回值回传供调用方留痕——白名单语义下丢弃条目等于
// 收紧允许来源（fail-closed），不会放宽访问面。写侧（REST 创建/更新）仍走
// NormalizeCIDRs 整体拒绝的口径：用户可改正，集群快照不可。
func NormalizeMCPIPWhitelistStrings(values []string) (normalized []string, dropped []string) {
	normalized = make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		prefix, err := wafiplist.ParseIPEntry(strings.TrimSpace(value))
		if err != nil {
			dropped = append(dropped, value)
			continue
		}
		canonical := prefix.String()
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	return normalized, dropped
}

// aggregateIPEntries 委托 wafiplist.AggregateIPEntries（v2.3.x 单一实现——
// 渲染层与 @ipListFast 算子共享同一聚合/检索形态）：去重、兄弟归并、覆盖
// 剔除、排序；不可解析条目透传在末尾。不变量：合并前后匹配集合逐点相等。
func aggregateIPEntries(entries []string) []string {
	return wafiplist.AggregateIPEntries(entries)
}

// differenceIPEntries 返回 left 匹配集减去 right 匹配集（渲染层字符串形态）：
// 直通∩保留检测重叠 IP 的信任路由归属由它裁决——直通优先，与 TCP 路由序
// 「直通 → 保留检测」同语义（否则同一 IP 在 HTTP 产 id:12、TCP 零事件，
// 跨协议分叉）。逐条目按 wafiplist.ParseIPEntry 解析（与 aggregateIPEntries/
// 名单算子同一口径：裸 IP 补 /32·/128、主机位掩码归零、4in6 归一），按前缀
// 集合做真实差集（宿主宽段减去嵌套子段会拆分出剩余段），产出聚合规范形态
// （升序、去重、不相交）。不可解析的 left 条目原样透传在末尾（与
// aggregateIPEntries 同口径——不静默削弱名单）；right 的不可解析条目匹配
// 不到任何地址，不参与扣除。
func differenceIPEntries(left, right []string) []string {
	leftPrefixes, leftUnparseable := parseIPEntriesForSetOp(left)
	remaining := wafiplist.AggregateParsedPrefixes(leftPrefixes)
	if len(remaining) > 0 && len(right) > 0 {
		rightPrefixes, _ := parseIPEntriesForSetOp(right)
		for _, sub := range wafiplist.AggregateParsedPrefixes(rightPrefixes) {
			next := make([]netip.Prefix, 0, len(remaining))
			for _, host := range remaining {
				next = append(next, subtractPrefix(host, sub)...)
			}
			remaining = next
			if len(remaining) == 0 {
				break
			}
		}
	}
	merged := wafiplist.AggregateParsedPrefixes(remaining)
	out := make([]string, 0, len(merged)+len(leftUnparseable))
	for _, prefix := range merged {
		out = append(out, prefix.String())
	}
	return append(out, leftUnparseable...)
}

// parseIPEntriesForSetOp 按渲染层统一解析口径拆分条目：可解析前缀 + 不可解析
// 透传条目（空串跳过，与 wafiplist.AggregateIPEntries 同形状）。
func parseIPEntriesForSetOp(entries []string) ([]netip.Prefix, []string) {
	prefixes := make([]netip.Prefix, 0, len(entries))
	var unparseable []string
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		prefix, err := wafiplist.ParseIPEntry(entry)
		if err != nil {
			unparseable = append(unparseable, entry)
			continue
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, unparseable
}

// subtractPrefix 返回 host 前缀减去 sub 前缀后的剩余前缀集（0/1/2 段）：
// 不相交（含跨族）原样返回；sub 覆盖 host（重叠且不窄于 host）时整体消失；
// host 宽于 sub 时沿 sub 所在分支逐层二分，兄弟半段留存、收敛到 sub 位宽
// 后该分支整段扣除（CIDR 重叠必为嵌套，二分判定充分）。
func subtractPrefix(host, sub netip.Prefix) []netip.Prefix {
	if !host.Overlaps(sub) {
		return []netip.Prefix{host}
	}
	if sub.Bits() <= host.Bits() {
		return nil
	}
	var out []netip.Prefix
	cur := host
	for cur.Bits() < sub.Bits() {
		lower, upper := splitPrefixHalf(cur)
		if lower.Contains(sub.Addr()) {
			out = append(out, upper)
			cur = lower
		} else {
			out = append(out, lower)
			cur = upper
		}
	}
	return out
}

// splitPrefixHalf 把一个前缀二分（位宽 +1）：返回低半段与高半段。高半段起点 =
// 低半段起点置位第 (位宽 - bits - 1) 位（自低位起算），对掩码归一的输入地址
// 只做位或即得规范前缀。
func splitPrefixHalf(prefix netip.Prefix) (lower, upper netip.Prefix) {
	bits := prefix.Bits()
	lower = netip.PrefixFrom(prefix.Addr(), bits+1)
	if prefix.Addr().Is4() {
		octets := prefix.Addr().As4()
		flip := 31 - bits
		octets[3-flip/8] |= 1 << (flip % 8)
		return lower, netip.PrefixFrom(netip.AddrFrom4(octets), bits+1)
	}
	octets := prefix.Addr().As16()
	flip := 127 - bits
	octets[15-flip/8] |= 1 << (flip % 8)
	return lower, netip.PrefixFrom(netip.AddrFrom16(octets), bits+1)
}
