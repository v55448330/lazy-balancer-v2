package services

import (
	"fmt"
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
