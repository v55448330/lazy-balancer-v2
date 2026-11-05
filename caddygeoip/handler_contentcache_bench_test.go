package caddygeoip

import (
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkIp2RegionLookupContentCache 量化新策略（xdb 全量内容缓存 +
// 池化 buffer searcher，查询零 syscall）的查询成本。仅在优化后的代码上
// 编译运行，与 BenchmarkIp2RegionLookup（VIndexCache 旧策略）对比。
func BenchmarkIp2RegionLookupContentCache(b *testing.B) {
	src := findTestXdb()
	if src == "" {
		b.Skip("no ip2region xdb available; place one under caddygeoip/testdata/ to run this benchmark")
	}
	path := filepath.Join(b.TempDir(), "ip2region.xdb")
	data, err := os.ReadFile(src)
	if err != nil {
		b.Fatalf("read source xdb: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		b.Fatalf("seed xdb copy: %v", err)
	}
	searcher, err := sharedGeoIPSearcher(path, "")
	if err != nil {
		b.Fatalf("acquire content-cache searcher: %v", err)
	}
	b.Cleanup(func() {
		geoipSharedMu.Lock()
		delete(geoipSharedSearchers, path+"\x00")
		geoipSharedMu.Unlock()
		geoipContentMu.Lock()
		delete(geoipContentCache, path)
		geoipContentMu.Unlock()
		searcher.Close()
	})

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
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
