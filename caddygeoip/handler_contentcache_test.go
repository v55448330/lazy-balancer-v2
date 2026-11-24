package caddygeoip

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/lionsoul2014/ip2region/binding/golang/service"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

// removeSharedSearcher 移除一个共享 searcher 条目与指定的内容缓存条目（测试
// 清理单源）。共享表的一切读写都在 geoipSharedMu 内（与生产侧 Provision 同
// 锁口径）：裸 delete 会与并发装载/换库重建构成数据竞争。
func removeSharedSearcher(key string, contentPaths ...string) {
	geoipSharedMu.Lock()
	delete(geoipSharedSearchers, key)
	geoipSharedMu.Unlock()
	geoipContentMu.Lock()
	for _, path := range contentPaths {
		delete(geoipContentCache, path)
	}
	geoipContentMu.Unlock()
}

// cleanupSharedSearcher 移除测试注入的共享 searcher 条目与内容缓存条目
// （测试间串扰防线：路径键唯一但内容缓存按路径键共享，必须一并清理）。
func cleanupSharedSearcher(t *testing.T, path string) {
	t.Helper()
	t.Cleanup(func() { removeSharedSearcher(path+"\x00", path) })
}

// TestRemoveSharedSearcher_takesSharedLock：共享表的删除必须持有 geoipSharedMu
// ——生产侧 Provision 在锁内读写该表，测试清理若裸 delete，与并发装载/换库
// 重建构成数据竞争。判据是「另一 goroutine 持锁期间删除不得生效」：持锁方
// 未释放前条目必须仍在表内，释放后删除必须完成（不依赖调度时序）。
func TestRemoveSharedSearcher_takesSharedLock(t *testing.T) {
	const key = "remove-shared-searcher-probe\x00"
	geoipSharedMu.Lock()
	geoipSharedSearchers[key] = &geoipSharedSearcher{}
	geoipSharedMu.Unlock()
	t.Cleanup(func() {
		geoipSharedMu.Lock()
		delete(geoipSharedSearchers, key)
		geoipSharedMu.Unlock()
	})

	started := make(chan struct{})
	done := make(chan struct{})
	geoipSharedMu.Lock()
	go func() {
		close(started)
		removeSharedSearcher(key)
		close(done)
	}()
	<-started
	select {
	case <-done:
		geoipSharedMu.Unlock()
		t.Fatal("removeSharedSearcher 在 geoipSharedMu 被他人持有时完成了删除：删除路径必须先取锁")
	case <-time.After(100 * time.Millisecond):
	}
	if _, ok := geoipSharedSearchers[key]; !ok {
		geoipSharedMu.Unlock()
		t.Fatal("持锁期间条目被删除：删除路径未走 geoipSharedMu")
	}
	geoipSharedMu.Unlock()
	<-done
	geoipSharedMu.Lock()
	_, still := geoipSharedSearchers[key]
	geoipSharedMu.Unlock()
	if still {
		t.Fatal("释放锁后条目仍在表内：removeSharedSearcher 未删除目标键")
	}
}

func seedXdbCopy(t *testing.T) string {
	t.Helper()
	src := findTestXdb()
	if src == "" {
		t.Skip("no ip2region xdb available; place one under caddygeoip/testdata/ to run this test")
	}
	path := filepath.Join(t.TempDir(), "ip2region.xdb")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source xdb: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("seed xdb copy: %v", err)
	}
	return path
}

// F3 核心钉：同一 v4 xdb 被多个共享实例（不同 v6 键）引用时必须共享同一份
// 内容字节——内容缓存按路径持有唯一条目，两个实例的池都引用它，内存代价
// = xdb 大小 × 1（而非 × 实例数）。同时量化构造后的堆增量（RSS 代理口径）。
func TestGeoipContentCache_sharedAcrossInstanceKeys(t *testing.T) {
	path := seedXdbCopy(t)
	cleanupSharedSearcher(t, path)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	v6 := filepath.Join(t.TempDir(), "ip2region_v6.xdb")
	writeV6FixtureXDB(t, v6, defaultV6Fixtures(t))
	t.Cleanup(func() {
		geoipSharedMu.Lock()
		delete(geoipSharedSearchers, path+"\x00"+v6)
		geoipSharedMu.Unlock()
	})

	s1, err := sharedGeoIPSearcher(path, "")
	if err != nil {
		t.Fatalf("acquire v4-only instance: %v", err)
	}
	geoipContentMu.Lock()
	buf1, entry1 := geoipContentCache[path].buf, geoipContentCache[path]
	geoipContentMu.Unlock()
	if buf1 == nil {
		t.Fatal("content cache must hold the loaded xdb bytes")
	}

	// 第二个实例：同一 v4 路径、不同 v6 键 → 独立实例、共享同一份内容字节。
	s2, err := sharedGeoIPSearcher(path, v6)
	if err != nil {
		t.Fatalf("acquire v4+v6 instance: %v", err)
	}
	geoipContentMu.Lock()
	buf2 := geoipContentCache[path].buf
	entries := 0
	for key := range geoipContentCache {
		if key == path {
			entries++
		}
	}
	geoipContentMu.Unlock()

	if s1 == s2 {
		t.Fatal("distinct v6 keys must build distinct instances (v6 pools differ)")
	}
	if len(buf1) != len(buf2) || unsafe.SliceData(buf1) != unsafe.SliceData(buf2) {
		t.Fatal("same-form xdb path must resolve to one shared content buffer")
	}
	if entries != 1 {
		t.Fatalf("content cache must hold exactly one entry per path, got %d", entries)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	t.Logf("xdb=%d bytes (%.1f MiB); heap delta after 2 instances constructed: +%.1f MiB (target ≈1×xdb)",
		len(buf1), float64(len(buf1))/(1<<20), float64(after.HeapAlloc-before.HeapAlloc)/(1<<20))
	_ = entry1
}

// 对拍钉（F3 验收①）：新策略（全量内容缓存池）与旧策略（VIndexCache 池）
// 对同一 xdb 随机抽样 1000 IP 逐条结果一致；且新策略查询零 syscall
// （GetIOCount==0），旧策略同 IP 至少 1 次 IO——「零 pread」的机器实证。
func TestGeoipContentCache_lookupParityWithVIndexPolicy(t *testing.T) {
	path := seedXdbCopy(t)
	cleanupSharedSearcher(t, path)

	oldSearcher, err := service.NewIp2RegionWithPath(path, "")
	if err != nil {
		t.Fatalf("open old-policy searcher: %v", err)
	}
	t.Cleanup(func() { oldSearcher.Close() })
	newSearcher, err := sharedGeoIPSearcher(path, "")
	if err != nil {
		t.Fatalf("acquire new-policy searcher: %v", err)
	}

	// 新策略零 IO 实证：借一只池内 searcher，查询后 ioCount 必为 0。
	s := <-newSearcher.v4.searchers
	if _, err := s.Search("114.114.114.114"); err != nil {
		t.Fatalf("content-cache probe search: %v", err)
	}
	if got := s.GetIOCount(); got != 0 {
		newSearcher.v4.searchers <- s
		t.Fatalf("content-cache search ioCount=%d, want 0 (zero syscall)", got)
	}
	newSearcher.v4.searchers <- s

	// 旧策略 IO 形态对照（独立构造的 VIndexCache searcher）：同文件同 IP
	// 至少 1 次 IO——证明两策略的读取路径确实不同。
	vIndex, err := xdb.LoadVectorIndexFromFile(path)
	if err != nil {
		t.Fatalf("load vector index: %v", err)
	}
	vSearcher, err := xdb.NewWithVectorIndex(xdb.IPv4, path, vIndex)
	if err != nil {
		t.Fatalf("open vindex searcher: %v", err)
	}
	t.Cleanup(func() { vSearcher.Close() })
	if _, err := vSearcher.Search("114.114.114.114"); err != nil {
		t.Fatalf("vindex probe search: %v", err)
	}
	if got := vSearcher.GetIOCount(); got < 1 {
		t.Fatalf("vindex search ioCount=%d, want >=1 (pread per lookup)", got)
	}

	// 1000 随机 IP 对拍：两策略结果逐条一致（含错误形态）。PCG 固定种子
	// 保证抽样流可复现（对拍样本集跨运行稳定）。
	rng := rand.New(rand.NewPCG(20261106, 42))
	for range 1000 {
		ip := fmt.Sprintf("%d.%d.%d.%d", 1+rng.IntN(223), rng.IntN(256), rng.IntN(256), rng.IntN(256))
		regionOld, errOld := oldSearcher.Search(ip)
		regionNew, errNew := newSearcher.Search(ip)
		if (errOld == nil) != (errNew == nil) {
			t.Fatalf("ip %s: error mismatch old=%v new=%v", ip, errOld, errNew)
		}
		if regionOld != regionNew {
			t.Fatalf("ip %s: region mismatch old=%q new=%q", ip, regionOld, regionNew)
		}
	}
}

// 换库重建必须装载新字节：文件形态变化后重建的实例引用新的内容缓冲
// （缓存条目同步替换），不得继续复用旧 inode 的字节。
func TestGeoipContentCache_rebuildOnFormChangeLoadsFreshBytes(t *testing.T) {
	path := seedXdbCopy(t)
	cleanupSharedSearcher(t, path)

	s1, err := sharedGeoIPSearcher(path, "")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	geoipContentMu.Lock()
	buf1, mod1 := geoipContentCache[path].buf, geoipContentCache[path].modTime
	geoipContentMu.Unlock()

	newMtime := time.Now().Add(2 * time.Minute)
	if err := os.Chtimes(path, newMtime, newMtime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	s2, err := sharedGeoIPSearcher(path, "")
	if err != nil {
		t.Fatalf("rebuild acquire: %v", err)
	}
	geoipContentMu.Lock()
	buf2, mod2 := geoipContentCache[path].buf, geoipContentCache[path].modTime
	geoipContentMu.Unlock()

	if s1 == s2 {
		t.Fatal("form change must rebuild the instance")
	}
	if unsafe.SliceData(buf1) == unsafe.SliceData(buf2) || !mod2.After(mod1) {
		t.Fatalf("rebuild must load fresh content bytes (buf ptr unchanged or stale modTime %v)", mod2)
	}
	if region, err := s2.Search("114.114.114.114"); err != nil || region == "" {
		t.Fatalf("rebuilt instance must serve lookups: region=%q err=%v", region, err)
	}
}

// 外层共享实例缓存键必须含 inode（与内容缓存 geoipContentBuffer 同口径）：
// 带外 rsync -a 换库（新 inode、保留 mtime+size）时，仅 mtime+size 的外层键
// 会短路命中旧实例——内容缓存虽能凭 inode 检出新字节，但外层根本不走重建，
// 旧 inode 的库被无限期当有效数据服务。本钉以「同 mtime+size、新 inode」的
// rename 替换强制外层重建。
func TestGeoipSharedSearcher_rebuildOnInodeChangeWithSameForm(t *testing.T) {
	path := seedXdbCopy(t)
	cleanupSharedSearcher(t, path)

	s1, err := sharedGeoIPSearcher(path, "")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// 构造「同内容、同 mtime+size、新 inode」的替换文件（rsync -a 形态）：
	// 复制原字节到临时文件 → 回拨 mtime 到原值 → rename 覆盖（新 inode）。
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tmp := path + ".rsync-new"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}

	s2, err := sharedGeoIPSearcher(path, "")
	if err != nil {
		t.Fatalf("rebuild acquire: %v", err)
	}
	if s1 == s2 {
		t.Fatal("inode 变化（同 mtime+size）必须重建外层共享实例，不得短路命中旧实例")
	}
	if region, err := s2.Search("114.114.114.114"); err != nil || region == "" {
		t.Fatalf("rebuilt instance must serve lookups: region=%q err=%v", region, err)
	}
}
