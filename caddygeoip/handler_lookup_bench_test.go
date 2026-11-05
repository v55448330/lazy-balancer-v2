package caddygeoip

import (
	"testing"

	"github.com/lionsoul2014/ip2region/binding/golang/service"
)

// BenchmarkIp2RegionLookup 量化旧策略（VIndexCache：vector index 常驻 +
// 每查询 1-2 次 pread）的查询成本。before/after 各跑 5s，与
// BenchmarkIp2RegionLookupContentCache 对比 ns/op 与 allocs/op。
// 本文件在基线（优化前）即可编译——before 数字从此文件测出。
func BenchmarkIp2RegionLookup(b *testing.B) {
	xdbPath := findTestXdb()
	if xdbPath == "" {
		b.Skip("no ip2region xdb available; place one under caddygeoip/testdata/ to run this benchmark")
	}
	searcher, err := service.NewIp2RegionWithPath(xdbPath, "")
	if err != nil {
		b.Fatalf("open vindex-cache searcher: %v", err)
	}
	b.Cleanup(func() { searcher.Close() })

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// xorshift64 每worker独立状态：随机 IPv4（单播空间 1.0.0.0-223.255.255.255），
		// 4 字节形态直查（跳过字符串解析，隔离出纯查询成本）。
		state := benchWorkerSeq.Add(1)*0x9E3779B97F4A7C15 | 1
		next := func() uint64 {
			state ^= state << 13
			state ^= state >> 7
			state ^= state << 17
			return state
		}
		ip := make([]byte, 4)
		for pb.Next() {
			ip[0] = byte(1 + next()%223)
			ip[1] = byte(next())
			ip[2] = byte(next())
			ip[3] = byte(next())
			if _, err := searcher.Search(ip); err != nil {
				b.Errorf("search %v: %v", ip, err)
				return
			}
		}
	})
}
