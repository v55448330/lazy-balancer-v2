package caddygeoip

import (
	"fmt"
	"testing"
)

// 锁分片路由白盒钉（F1 RED：基线无分片路由函数，本文件在基线编译失败；
// 实现后 GREEN）：①同 id 恒路由到同片（幂等——注册/关闭/等待/清扫对同一
// 计时 ID 必须落在同一片，否则条目查不到）②不同 id 横跨多片（路由未退化
// ——全部落单片等价于没分片）。
func TestAuditTimingShard_routingStableAndSpread(t *testing.T) {
	const id = "0123456789abcdef"
	first := auditTimingShardFor(id)
	if first == nil {
		t.Fatal("shard routing returned nil")
	}
	for range 200 {
		if auditTimingShardFor(id) != first {
			t.Fatal("same id must always route to the same shard")
		}
	}
	seen := map[*auditTimingShard]bool{}
	for i := range 256 {
		seen[auditTimingShardFor(fmt.Sprintf("%016x", i))] = true
	}
	if len(seen) < 8 {
		t.Fatalf("256 ids routed to %d/%d shards; routing is degenerate", len(seen), auditTimingShardCount)
	}
}
