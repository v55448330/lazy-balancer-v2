package services

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// testSegments mirror a production xdb whose fifth region field carries the
// alpha-2 country code; the last segment exercises the malformed path.
var testSegments = []xdbSegment{
	{startIP: 0x01020300, endIP: 0x010203FF, region: "美国|0|0|0|US"},
	{startIP: 0x01020400, endIP: 0x010204FF, region: "中国|0|0|0|CN"},
	{startIP: 0x01020500, endIP: 0x010205FF, region: "0|0|0|0"},
}

type xdbSegment struct {
	startIP uint32
	endIP   uint32
	region  string
}

// writeTestXDB builds a minimal but structurally valid IPv4 xdb (structure
// 2.0: header, vector index, region strings, segment index) so the real
// BufferCache search path runs without any network dependency.
func writeTestXDB(t *testing.T, path string, segments []xdbSegment) {
	t.Helper()
	const (
		headerSize      = 256
		vectorIndexSize = 256 * 256 * 8
		segmentSize     = 14 // startIP 4 + endIP 4 + dataLen 2 + dataPtr 4
	)
	buf := make([]byte, headerSize+vectorIndexSize)

	// Region strings follow the vector index; each distinct region once.
	regionPtr := map[string]uint32{}
	next := uint32(headerSize + vectorIndexSize)
	appendRegion := func(region string) uint32 {
		if ptr, ok := regionPtr[region]; ok {
			return ptr
		}
		ptr := next
		buf = append(buf, region...)
		next = uint32(len(buf))
		regionPtr[region] = ptr
		return ptr
	}

	// Pass 1: all region strings, deduplicated.
	for _, seg := range segments {
		appendRegion(seg.region)
	}
	// Pass 2: contiguous segment index blocks (the searcher binary-searches
	// fixed 14-byte blocks between the vector entry's start/end pointers).
	blockPtrs := make([]uint32, len(segments))
	for i, seg := range segments {
		blockPtrs[i] = next
		block := make([]byte, segmentSize)
		binary.LittleEndian.PutUint32(block[0:], seg.startIP)
		binary.LittleEndian.PutUint32(block[4:], seg.endIP)
		binary.LittleEndian.PutUint16(block[8:], uint16(len(seg.region)))
		binary.LittleEndian.PutUint32(block[10:], regionPtr[seg.region])
		buf = append(buf, block...)
		next = uint32(len(buf))
	}

	// Vector index entry for the shared first-two-byte prefix.
	b0, b1 := byte(segments[0].startIP>>24), byte(segments[0].startIP>>16)
	idx := headerSize + (int(b0)*256+int(b1))*8
	binary.LittleEndian.PutUint32(buf[idx:], blockPtrs[0])
	binary.LittleEndian.PutUint32(buf[idx+4:], blockPtrs[len(blockPtrs)-1]+segmentSize)

	// Header: structure 2.0, vector index policy, IPv4 pointers.
	binary.LittleEndian.PutUint16(buf[0:], 2)
	binary.LittleEndian.PutUint16(buf[2:], 1)
	binary.LittleEndian.PutUint32(buf[8:], blockPtrs[0])
	binary.LittleEndian.PutUint32(buf[12:], blockPtrs[len(blockPtrs)-1])
	binary.LittleEndian.PutUint16(buf[16:], 4)
	binary.LittleEndian.PutUint16(buf[18:], 4)

	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
}

// withIP2RegionPaths points the singleton at the given files and resets the
// loaded searcher afterwards so tests stay isolated under -shuffle. R57 B-#1
// 起 ValidateGeoIPCountries 以 live searcher 为判据——进入时也必须清空遗留
// searcher，否则前序测试加载的真实 xdb 会让本测试的 live 判定意外为 loaded。
func withIP2RegionPaths(t *testing.T, live, dist string) {
	t.Helper()
	oldLive, oldDist := ip2regionLivePath, ip2regionDistPath
	ip2regionMu.Lock()
	if ip2regionSearcher != nil {
		ip2regionSearcher.Close()
		ip2regionSearcher = nil
	}
	ip2regionMu.Unlock()
	ip2regionLivePath, ip2regionDistPath = live, dist
	t.Cleanup(func() {
		ip2regionMu.Lock()
		if ip2regionSearcher != nil {
			ip2regionSearcher.Close()
			ip2regionSearcher = nil
		}
		ip2regionMu.Unlock()
		ip2regionLivePath, ip2regionDistPath = oldLive, oldDist
	})
}

func Test_parseCountryCode_returns_alpha2_from_fifth_field(t *testing.T) {
	tests := []struct {
		name   string
		region string
		want   string
	}{
		{"full region", "美国|0|0|0|US", "US"},
		{"unknown country", "0|0|0|0|CN", "CN"},
		{"too few fields", "中国|0|0", ""},
		{"empty region", "", ""},
		{"extra fields keep fifth", "0|0|0|0|JP|extra", "JP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When
			got := parseCountryCode(tt.region)

			// Then
			if got != tt.want {
				t.Fatalf("parseCountryCode(%q)=%q, want %q", tt.region, got, tt.want)
			}
		})
	}
}

func Test_Lookup_returns_empty_without_loaded_database(t *testing.T) {
	// Given the singleton never loaded (paths point at nonexistent files)

	// When / Then
	if got := Lookup("1.2.3.4"); got != "" {
		t.Fatalf("Lookup without loaded database=%q, want empty", got)
	}
}

func Test_InitIP2Region_loads_live_xdb_then_Lookup_and_Reload(t *testing.T) {
	// Given a valid xdb at the live path
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, live, testSegments)
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))

	// When initialized and queried
	InitIP2Region()
	if got := Lookup("1.2.3.100"); got != "US" {
		t.Fatalf("Lookup(1.2.3.100)=%q, want US", got)
	}
	if got := Lookup("1.2.4.50"); got != "CN" {
		t.Fatalf("Lookup(1.2.4.50)=%q, want CN", got)
	}
	if got := Lookup("1.2.5.9"); got != "" {
		t.Fatalf("Lookup(1.2.5.9)=%q, want empty for malformed region", got)
	}
	if got := Lookup("8.8.8.8"); got != "" {
		t.Fatalf("Lookup(8.8.8.8)=%q, want empty for unknown IP", got)
	}

	// When reloaded, the searcher stays hot-swappable
	Reload()
	if got := Lookup("1.2.3.100"); got != "US" {
		t.Fatalf("Lookup after Reload=%q, want US", got)
	}
}

func Test_InitIP2Region_copies_distribution_xdb_when_live_missing(t *testing.T) {
	// Given only the distribution copy exists
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	dist := filepath.Join(dir, "waf.dist", "ip2region.xdb")
	if err := os.MkdirAll(filepath.Dir(dist), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestXDB(t, dist, testSegments)
	withIP2RegionPaths(t, live, dist)

	// When initialized
	InitIP2Region()

	// Then the live copy exists and lookups work
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("live xdb not copied from distribution: %v", err)
	}
	if got := Lookup("1.2.3.1"); got != "US" {
		t.Fatalf("Lookup after dist copy=%q, want US", got)
	}
}

func Test_Lookup_concurrent_with_Reload(t *testing.T) {
	// Given a loaded database
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, live, testSegments)
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))
	InitIP2Region()

	// When 100 goroutines look up while the searcher is reloaded repeatedly
	var wg sync.WaitGroup
	wg.Add(100)
	for i := 0; i < 100; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if got := Lookup("1.2.3.10"); got != "US" {
					t.Errorf("Lookup during Reload=%q, want US", got)
					return
				}
			}
		}()
	}
	for i := 0; i < 3; i++ {
		Reload()
	}
	wg.Wait()
}

func Test_GetSetIP2RegionVersion_roundtrip(t *testing.T) {
	// Given a fresh database whose version row is seeded
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if got := GetIP2RegionVersion(); got != "unknown" {
		t.Fatalf("initial version=%q, want unknown", got)
	}

	// When the version is stored
	SetIP2RegionVersion("2026-08-12")

	// Then it reads back
	if got := GetIP2RegionVersion(); got != "2026-08-12" {
		t.Fatalf("stored version=%q, want 2026-08-12", got)
	}
}

// N+13 H2-F2：GetIP2RegionRegionTree 按 xdb stat 键记忆化——稳态调用返回
// 同一树（免 ~220ms 全量扫描），stat 键变化（带外替换/触摸）触发重扫。
func Test_GetIP2RegionRegionTree_memoizes_until_xdb_stat_changes(t *testing.T) {
	// Given：双段 fixture xdb（单段会使 header Start/End 指针相等、树扫描
	// 判空返回 nil），记忆化状态清零（隔离前序测试）
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, live, []xdbSegment{
		{startIP: 0x01020300, endIP: 0x010203FF, region: "中国|广东省|深圳市|0|CN"},
		{startIP: 0x01020400, endIP: 0x010204FF, region: "中国|福建省|厦门市|0|CN"},
	})
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))
	resetRegionTreeMemoForTest(t)

	first := GetIP2RegionRegionTree()
	if first == nil {
		t.Fatal("scan returned nil for valid fixture xdb")
	}

	// When / Then：稳态第二次调用命中记忆化（同一树指针，零重扫）
	if second := GetIP2RegionRegionTree(); second != first {
		t.Fatal("steady-state call must return memoized tree (same pointer)")
	}

	// When：带外替换可见性——stat 键变化（mtime 前拨 2s）后再次调用
	fi, err := os.Stat(live)
	if err != nil {
		t.Fatalf("stat fixture xdb: %v", err)
	}
	touched := fi.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(live, touched, touched); err != nil {
		t.Fatalf("touch fixture xdb: %v", err)
	}
	third := GetIP2RegionRegionTree()

	// Then：重扫产出新树，且重扫后稳态再次命中记忆化
	if third == first {
		t.Fatal("xdb stat change (mtime) must trigger rescan, got stale memoized tree")
	}
	if third == nil || len(third.Provinces) == 0 {
		t.Fatal("rescan after stat change returned no tree")
	}
	if fourth := GetIP2RegionRegionTree(); fourth != third {
		t.Fatal("post-rescan steady state must hit memo again")
	}
}

func resetRegionTreeMemoForTest(t *testing.T) {
	t.Helper()
	regionTreeMemoMu.Lock()
	regionTreeMemo, regionTreeMemoKey = nil, ""
	regionTreeMemoMu.Unlock()
	t.Cleanup(func() {
		regionTreeMemoMu.Lock()
		regionTreeMemo, regionTreeMemoKey = nil, ""
		regionTreeMemoMu.Unlock()
	})
}
