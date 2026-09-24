package middleware

// 第 49 轮 F49-P5-19①：PurgeAPIKeyWhitelistCache 必须按 keyID 前缀精确清扫——
// "|" 分隔保证 keyID=3 不误伤 "30|…" 前缀；其他 Key 的条目不受影响。

import (
	"net"
	"testing"
)

func TestPurgeAPIKeyWhitelistCache_sweepsByKeyIDPrefix(t *testing.T) {
	// Given：keyID 3 的两个历史白名单版本条目 + keyID 30 的一个条目（前缀陷阱形状）
	_, network, _ := net.ParseCIDR("10.0.0.0/8")
	apiKeyWhitelistCache.Store(`3|["10.0.0.0/8"]`, []*net.IPNet{network})
	apiKeyWhitelistCache.Store(`3|["192.168.0.0/16"]`, []*net.IPNet{network})
	apiKeyWhitelistCache.Store(`30|["10.0.0.0/8"]`, []*net.IPNet{network})
	t.Cleanup(func() {
		apiKeyWhitelistCache.Delete(`3|["10.0.0.0/8"]`)
		apiKeyWhitelistCache.Delete(`3|["192.168.0.0/16"]`)
		apiKeyWhitelistCache.Delete(`30|["10.0.0.0/8"]`)
	})

	// When
	PurgeAPIKeyWhitelistCache(3)

	// Then：3 的两个版本条目全清扫；30 的条目保留
	if _, ok := apiKeyWhitelistCache.Load(`3|["10.0.0.0/8"]`); ok {
		t.Fatal("keyID=3 的旧白名单条目未被清扫")
	}
	if _, ok := apiKeyWhitelistCache.Load(`3|["192.168.0.0/16"]`); ok {
		t.Fatal("keyID=3 的另一历史版本条目未被清扫")
	}
	if _, ok := apiKeyWhitelistCache.Load(`30|["10.0.0.0/8"]`); !ok {
		t.Fatal("keyID=30 的条目被误伤（前缀必须含 | 分隔）")
	}
}

// P5-21（第 50 轮审计）：配置导入/集群快照的 api_keys 整体替换后，白名单
// CIDR 解析缓存必须整体清空——键含 keyID 前缀无法枚举存活 Key，逐 Key
// 清扫不可行；批量替换后缓存必须为空（解析缓存重建廉价）。
func TestPurgeAllAPIKeyWhitelistCache_emptiesCache(t *testing.T) {
	// Given：两个 Key 的白名单条目
	_, network, _ := net.ParseCIDR("10.0.0.0/8")
	apiKeyWhitelistCache.Store(`3|["10.0.0.0/8"]`, []*net.IPNet{network})
	apiKeyWhitelistCache.Store(`30|["10.0.0.0/8"]`, []*net.IPNet{network})

	// When
	PurgeAllAPIKeyWhitelistCache()

	// Then：缓存全空
	remaining := 0
	apiKeyWhitelistCache.Range(func(_, _ any) bool { remaining++; return true })
	if remaining != 0 {
		t.Fatalf("缓存剩余 %d 条, want 0（api_keys 整体替换后必须清空）", remaining)
	}
}
