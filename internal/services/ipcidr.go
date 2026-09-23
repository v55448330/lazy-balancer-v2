package services

import (
	"fmt"
	"net"
	"strings"

	"lazy-balancer-v2/wafiplist"
)

func NormalizeCIDRs(values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if ip := net.ParseIP(value); ip != nil {
			if ip.To4() != nil {
				value += "/32"
			} else {
				value += "/128"
			}
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("%q 不是有效 CIDR", value)
		}
		normalized = append(normalized, network.String())
	}
	return normalized, nil
}

// aggregateIPEntries 委托 wafiplist.AggregateIPEntries（v2.3.x 单一实现——
// 渲染层与 @ipListFast 算子共享同一聚合/检索形态）：去重、兄弟归并、覆盖
// 剔除、排序；不可解析条目透传在末尾。不变量：合并前后匹配集合逐点相等。
func aggregateIPEntries(entries []string) []string {
	return wafiplist.AggregateIPEntries(entries)
}
