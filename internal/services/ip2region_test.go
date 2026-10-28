package services

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
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
// loaded searcher afterwards so tests stay isolated under -shuffle.
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
	ip2regionSearcherSource = ""
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
	// Given the singleton is explicitly reset and the paths point at nonexistent
	// files（不依赖前序用例的清理——单跑/-shuffle 下断言对象同样成立）
	dir := t.TempDir()
	withIP2RegionPaths(t, filepath.Join(dir, "missing.xdb"), filepath.Join(dir, "missing-dist.xdb"))

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

func Test_LookupRegion_returns_raw_region_or_empty(t *testing.T) {
	// Given an xdb whose segments carry full region strings
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, live, []xdbSegment{
		{startIP: 0x01020600, endIP: 0x010206FF, region: "中国|广东省|深圳市|电信|CN"},
		{startIP: 0x01020700, endIP: 0x010207FF, region: "美国|0|0|0|US"},
	})
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))
	InitIP2Region()

	// When / Then: the raw pipe-separated region comes back verbatim
	if got := LookupRegion("1.2.6.9"); got != "中国|广东省|深圳市|电信|CN" {
		t.Fatalf("LookupRegion(1.2.6.9)=%q, want raw China region string", got)
	}
	if got := LookupRegion("1.2.7.9"); got != "美国|0|0|0|US" {
		t.Fatalf("LookupRegion(1.2.7.9)=%q, want raw US region string", got)
	}
	if got := LookupRegion("8.8.8.8"); got != "" {
		t.Fatalf("LookupRegion(unknown)=%q, want empty", got)
	}
}

func Test_LookupRegion_empty_without_loaded_database(t *testing.T) {
	// Given the singleton never loaded
	withIP2RegionPaths(t, filepath.Join(t.TempDir(), "missing.xdb"), filepath.Join(t.TempDir(), "missing-dist.xdb"))

	// When / Then
	if got := LookupRegion("1.2.3.4"); got != "" {
		t.Fatalf("LookupRegion without database=%q, want empty", got)
	}
}

func Test_InitIP2Region_copies_distribution_xdb_when_live_missing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		master   bool
		wantLive bool
	}{
		{name: "master copies dist into live", master: true, wantLive: true},
		{name: "slave loads dist read-only without touching live", master: false, wantLive: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSecurityEnumTestDB(t)
			if !tc.master {
				if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
					t.Fatalf("set slave role: %v", err)
				}
			}
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

			if tc.wantLive {
				// Then the live copy exists and lookups work
				if _, err := os.Stat(live); err != nil {
					t.Fatalf("live xdb not copied from distribution: %v", err)
				}
			} else {
				// 从节点：live 由集群同步治理，本地补齐会与主端声明打架——
				// 文件、派生缓存、版本行一律不落盘，但查询必须可用。
				if _, err := os.Stat(live); !os.IsNotExist(err) {
					t.Fatalf("从节点不得写 live 文件（stat err=%v）", err)
				}
				if _, err := os.Stat(live + ".provinces.json"); !os.IsNotExist(err) {
					t.Fatalf("从节点不得写派生缓存（stat err=%v）", err)
				}
				gotVersion, err := GetIP2RegionVersion()
				if err != nil {
					t.Fatalf("读取从节点 IP 库版本: %v", err)
				}
				if gotVersion == "bundled" {
					t.Fatal("从节点不得写版本行标识（bundled 属主节点本地修复产物）")
				}
			}
			if got := Lookup("1.2.3.1"); got != "US" {
				t.Fatalf("Lookup after dist load=%q, want US", got)
			}
		})
	}
}

// 从节点（is_master=0）+ live 可装载：派生缓存（省份列表/地域树）同样不得
// 落盘——「文件/版本行/派生缓存一律不落盘」是从节点只读不变量的显式契约，
// 不能只在 readOnlyDist（live 缺失/损坏）分支成立。查询仍必须可用
// （内存重建）。
func Test_InitIP2Region_slaveWithValidLiveWritesNoDerivedCaches(t *testing.T) {
	setupSecurityEnumTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("set slave role: %v", err)
	}
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, live, testSegments)
	withIP2RegionPaths(t, live, filepath.Join(dir, "waf.dist", "ip2region.xdb"))

	InitIP2Region()

	if got := Lookup("1.2.3.1"); got != "US" {
		t.Fatalf("Lookup after slave init=%q, want US", got)
	}
	if _, err := os.Stat(live + ".provinces.json"); !os.IsNotExist(err) {
		t.Fatalf("从节点不得写省份派生缓存（stat err=%v）", err)
	}
	if _, err := os.Stat(live + ".regions.json"); !os.IsNotExist(err) {
		t.Fatalf("从节点不得写地域树派生缓存（stat err=%v）", err)
	}
}

// 从节点（is_master=0）遇到损坏 live 库：不得以 dist 覆盖（文件/版本行/
// sidecar 由集群同步治理），但必须只读装载镜像库供本地查询——否则面板归属地
// 全空且地域拦截静默失效。
func Test_InitIP2Region_slaveKeepsCorruptLiveAndLoadsDistReadOnly(t *testing.T) {
	setupSecurityEnumTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("set slave role: %v", err)
	}
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	dist := filepath.Join(dir, "waf.dist", "ip2region.xdb")
	if err := os.MkdirAll(filepath.Dir(dist), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestXDB(t, dist, testSegments)
	const corrupt = "corrupt-half-written-xdb"
	if err := os.WriteFile(live, []byte(corrupt), 0o644); err != nil {
		t.Fatal(err)
	}
	withIP2RegionPaths(t, live, dist)

	InitIP2Region()

	if got := Lookup("1.2.3.100"); got != "US" {
		t.Fatalf("从节点损坏 live 未只读装载 dist: Lookup=%q, want US", got)
	}
	raw, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != corrupt {
		t.Fatal("从节点不得覆盖损坏的 live 库（等待集群同步自愈）")
	}
	if _, err := os.Stat(live + ".version"); !os.IsNotExist(err) {
		t.Fatalf("从节点不得写 .version sidecar（stat err=%v）", err)
	}
	gotVersion, err := GetIP2RegionVersion()
	if err != nil {
		t.Fatalf("读取损坏 live 场景的 IP 库版本: %v", err)
	}
	if gotVersion == "bundled" {
		t.Fatal("从节点不得写版本行标识（bundled 属主节点本地修复产物）")
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
	setupIsolatedDB(t)
	if got, err := GetIP2RegionVersion(); err != nil || got != "unknown" {
		t.Fatalf("initial version=%q, want unknown", got)
	}

	// When the version is stored
	SetIP2RegionVersion("2026-08-12")

	// Then it reads back
	if got, err := GetIP2RegionVersion(); err != nil || got != "2026-08-12" {
		t.Fatalf("stored version=%q, want 2026-08-12", got)
	}
}

// GetIP2RegionRegionTree 按 xdb stat 键记忆化——稳态调用返回
// 同一树（免 ~220ms 全量扫描），stat 键变化（带外替换/触摸）触发重扫。
func Test_GetIP2RegionRegionTree_memoizes_until_xdb_stat_changes(t *testing.T) {
	// Given：双段 fixture xdb（树扫描判空只认 maxPtr < minPtr，单段
	// Start==End 会正常迭代一次并产出有效树——这里用双段只为额外覆盖多段
	// 拼接），记忆化状态清零（隔离前序测试）
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

// resetProvincesMemoForTest 省份列表记忆化清零（与 resetRegionTreeMemoForTest
// 同构——切换 live 路径/searcher 的用例必须复位，隔离前序测试残留）。
func resetProvincesMemoForTest(t *testing.T) {
	t.Helper()
	provincesMemoMu.Lock()
	provincesMemo, provincesMemoKey = nil, ""
	provincesMemoMu.Unlock()
	t.Cleanup(func() {
		provincesMemoMu.Lock()
		provincesMemo, provincesMemoKey = nil, ""
		provincesMemoMu.Unlock()
	})
}

// 条目数从 header StartIndexPtr/EndIndexPtr 直读（xdb v2 官方边界，2 次
// ReadAt），不再扫 65536 格 vector 推导（每次调用 65536 次 8B ReadAt，
// BufferCache 已全内存纯浪费；且 vector 端点语义含末条结尾，推导 off-by-one）。
func TestEntryCountFromXDBHeader_readsHeaderBounds(t *testing.T) {
	// Given: 构造最小 xdb——header(start=1000,end=1000+14*)+vector 全零
	const n = 100
	dir := t.TempDir()
	path := filepath.Join(dir, "ip2region.xdb")
	header := make([]byte, 256)
	binary.LittleEndian.PutUint32(header[8:], 1000)
	binary.LittleEndian.PutUint32(header[12:], 1000+14*(n-1))
	vector := make([]byte, 256*256*8)
	// 干扰格:旧实现在 vector 区(文件偏移 264=8+32*8)植入超界端点——
	// 旧推导被拉偏(306),header 直读不受影响(100)。
	binary.LittleEndian.PutUint32(vector[32*8:], 5000)
	binary.LittleEndian.PutUint32(vector[32*8+4:], 5000+14*20)
	data := append(header, vector...)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// When/Then: 真值 N(header 边界直读)
	if got := entryCountFromXDBHeader(path); got != n {
		t.Fatalf("entryCountFromXDBHeader()=%d, want %d (header bounds)", got, n)
	}
	// 坏库/空库边界：end < start → 0（不得算出负值）
	broken := filepath.Join(dir, "broken.xdb")
	brokenHeader := make([]byte, 16)
	binary.LittleEndian.PutUint32(brokenHeader[8:], 1000)
	binary.LittleEndian.PutUint32(brokenHeader[12:], 900)
	if err := os.WriteFile(broken, brokenHeader, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := entryCountFromXDBHeader(broken); got != 0 {
		t.Fatalf("end<start 应返回 0, got %d", got)
	}
}

// 条目数必须与在役 searcher 同源：只读降级（live 缺失、searcher 来自镜像内置
// 库）与热换失败保留旧库这两种既有形态下，读 live 路径会显示 0 或按损坏
// 文件 header 算出越界值，而归属地查询其实正常。
func TestGetIP2RegionEntryCount_tracksInServiceSearcherSource(t *testing.T) {
	dir := t.TempDir()
	segments := []xdbSegment{
		{startIP: 0x65000100, endIP: 0x650001FF, region: "中国|浙江省|杭州市|0|CN"},
		{startIP: 0x65000200, endIP: 0x650002FF, region: "中国|江苏省|南京市|0|CN"},
		{startIP: 0x65000300, endIP: 0x650003FF, region: "美国|加利福尼亚|洛杉矶|0|US"},
	}
	dist := filepath.Join(dir, "dist.xdb")
	writeTestXDB(t, dist, segments)
	// live 缺失（从节点/只读降级形态）——旧实现从这里读，恒得 0。
	live := filepath.Join(dir, "absent-live.xdb")
	withIP2RegionPaths(t, live, dist)
	resetProvincesMemoForTest(t)

	searcher, err := openIP2RegionSearcher(dist)
	if err != nil {
		t.Fatalf("open dist searcher: %v", err)
	}
	ip2regionMu.Lock()
	swapIP2RegionSearcher(searcher, dist)
	ip2regionMu.Unlock()

	if got := GetIP2RegionEntryCount(); got != len(segments) {
		t.Fatalf("GetIP2RegionEntryCount()=%d, want %d（必须取在役 searcher 的来源，不是 live 路径）", got, len(segments))
	}
	// 正向控制：在役查询确实可用（同一来源）。
	if region := LookupRegion("101.0.1.5"); !strings.Contains(region, "浙江") {
		t.Fatalf("在役 searcher 查询失败: %q", region)
	}

	// 卸载后无在役库 → 0（不得回落到 live 路径或残留计数）。
	ResetIP2RegionSearcherForTest()
	if got := GetIP2RegionEntryCount(); got != 0 {
		t.Fatalf("卸载后 GetIP2RegionEntryCount()=%d, want 0", got)
	}
}

// writeRegionTreeCache 落盘失败此前静默吞错且仍写
// INFO「已重建」成功行（日志谎报）。修复后失败写 WARN「重建落盘失败」且
// 无 INFO 成功行；writeProvincesCache 错误沿返回值上抛给调用点留痕。
func TestWriteRegionTreeCache_writeFailureLogsWarn(t *testing.T) {
	// Given：live 路径的父级是一个普通文件——原子落盘的 CreateTemp 返回
	// ENOTDIR，失败与运行用户/文件系统权限无关（容器内 root 下 chmod 0555
	// 仍可写，权限注入不可移植）。
	dir := t.TempDir()
	notADir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(notADir, "ip2region.xdb")
	old := ip2regionLivePath
	ip2regionLivePath = live
	t.Cleanup(func() { ip2regionLivePath = old })
	logDir := t.TempDir()
	taskengine.SetLogDir(logDir)
	t.Cleanup(func() { taskengine.SetLogDir("") })

	var appLog strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&appLog)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	// When：落盘失败路径
	writeRegionTreeCache(&IP2RegionRegionTree{Provinces: []string{"海外"}, Cities: map[string][]string{}})

	// Then：失败只写应用日志，不越权写 ip2region 任务日志。
	data, _ := os.ReadFile(taskengine.TaskLogPath("ip2region"))
	if len(data) > 0 {
		t.Fatalf("公共缓存重建不得写 ip2region 任务日志: %s", data)
	}
	if !strings.Contains(appLog.String(), "重建落盘失败") {
		t.Fatalf("应用日志缺少失败留痕: %s", appLog.String())
	}
	if strings.Contains(appLog.String(), "地域树缓存已重建") {
		t.Fatalf("落盘失败不得写成功行（谎报）: %s", appLog.String())
	}
	// And：省份缓存写失败沿返回值上抛给调用点（writeProvincesCache 不再吞错）。
	if err := writeProvincesCache(ip2regionLivePath+".provinces.json", []byte("[]")); err == nil {
		t.Fatal("writeProvincesCache 必须返回落盘错误（调用点据此留痕）")
	}
}

// 省份列表记忆化（与 regionTreeMemo 同构）：336 次采样搜索持
// ip2regionSearchMu 全局锁——校验端/缓存重建在同一份 xdb 上的重复调用
// 必须命中 stat 键记忆化（path|size|mtime），xdb 替换（stat 变化）后重扫。
func TestGetIP2RegionProvinces_memoizesByStatKey(t *testing.T) {
	// Given：fixture xdb（采样点 101.1.1.1 命中中国段）装入 live searcher
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, live, []xdbSegment{
		{startIP: 0x65000100, endIP: 0x650001FF, region: "中国|浙江省|杭州市|0|CN"},
	})
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))
	resetProvincesMemoForTest(t)
	searcher, err := openIP2RegionSearcher(live)
	if err != nil {
		t.Fatalf("open fixture searcher: %v", err)
	}
	ip2regionMu.Lock()
	ip2regionSearcher = searcher
	ip2regionSearcherSource = live
	ip2regionMu.Unlock()

	// When：同一份 xdb 上连续两次调用
	base := ip2regionProvinceScans.Load()
	first := GetIP2RegionProvinces()
	second := GetIP2RegionProvinces()

	// Then：第二次命中记忆化（零重扫），内容同值
	if scans := ip2regionProvinceScans.Load() - base; scans != 1 {
		t.Fatalf("两次调用全量采样 %d 次, want 1（稳态必须命中 stat 键记忆化）", scans)
	}
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatalf("记忆化结果漂移: %v vs %v", first, second)
	}
	found := false
	for _, p := range first {
		if strings.HasPrefix(p, "浙江") {
			found = true
		}
	}
	if !found {
		t.Fatalf("fixture 采样点未产出浙江（规范化形态）: %v", first)
	}

	// When：带外替换可见性——stat 键变化（mtime 前拨 2s）后再次调用
	fi, err := os.Stat(live)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(live, fi.ModTime().Add(-2*time.Second), fi.ModTime().Add(-2*time.Second)); err != nil {
		t.Fatal(err)
	}
	third := GetIP2RegionProvinces()

	// Then：stat 键变化触发重扫（记忆化不失效=陈旧省份列表永续）
	if scans := ip2regionProvinceScans.Load() - base; scans != 2 {
		t.Fatalf("stat 变化后采样累计 %d 次, want 2（键变化必须重扫）", scans)
	}
	if strings.Join(first, ",") != strings.Join(third, ",") {
		t.Fatalf("同内容重扫结果应一致: %v vs %v", first, third)
	}
}

// live 库存在但不可装载（掉电半写/带外损坏）时必须回退镜像内置库并留痕
// （版本行 bundled），而不是放弃装载让归属地长期为空。
func Test_InitIP2Region_fallsBackToDistWhenLiveUnreadable(t *testing.T) {
	setupIsolatedDB(t)
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	dist := filepath.Join(dir, "waf.dist", "ip2region.xdb")
	if err := os.MkdirAll(filepath.Dir(dist), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestXDB(t, dist, testSegments)
	if err := os.WriteFile(live, []byte("corrupt-half-written-xdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	withIP2RegionPaths(t, live, dist)

	InitIP2Region()

	if got := Lookup("1.2.3.100"); got != "US" {
		t.Fatalf("损坏 live 未回退 dist: Lookup=%q, want US", got)
	}
	want, err := os.ReadFile(dist)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("live 必须被替换为 dist 内容")
	}
	if v, verr := GetIP2RegionVersion(); verr != nil || v != "bundled" {
		t.Fatalf("version=%q,%v, want bundled 保守标识", v, verr)
	}
}

// 结构自检门：合法 xdb 通过；截断/指针越界拒绝（装载路径的前置门，
// 坏文件不得进入绑定库的无边界切片）。
func TestCheckIP2RegionXDBStructure(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.xdb")
	writeTestXDB(t, valid, testSegments)
	if err := checkIP2RegionXDBStructure(valid); err != nil {
		t.Fatalf("合法 xdb 须通过结构门: %v", err)
	}

	data, err := os.ReadFile(valid)
	if err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(dir, "truncated.xdb")
	if err := os.WriteFile(truncated, data[:100000], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkIP2RegionXDBStructure(truncated); err == nil {
		t.Fatal("截断文件须被结构门拒绝")
	}

	// 头内段索引指针越出文件（尺寸足够，指针损坏）
	badPtr := filepath.Join(dir, "badptr.xdb")
	corrupt := append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(corrupt[12:], uint32(len(corrupt)))
	if err := os.WriteFile(badPtr, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkIP2RegionXDBStructure(badPtr); err == nil {
		t.Fatal("段索引指针越界须被结构门拒绝")
	}
}

// writeCorruptProbeSegmentXDB 造「结构自检通过、探针搜索越界」的 xdb：只改写
// 114.114 向量条目（非零起点 + 巨大终点），头内段索引指针保持原值。
func writeCorruptProbeSegmentXDB(t *testing.T, path string) {
	t.Helper()
	writeTestXDB(t, path, testSegments)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const vectorEntryOff = 256 + (114*256+114)*8
	binary.LittleEndian.PutUint32(data[vectorEntryOff:], 524544)
	binary.LittleEndian.PutUint32(data[vectorEntryOff+4:], 0x7FFFFF00)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// 导入校验入口必须与更新路径同强度：结构门通过但段指针越界的文件会在真实
// 搜索时 panic，落盘后请求期 Search 直接 500/启动期采样崩溃。
func TestValidateIP2RegionFile_rejectsProbePanicOnCorruptSegment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.xdb")
	writeCorruptProbeSegmentXDB(t, path)
	if err := ValidateIP2RegionFile(path); err == nil {
		t.Fatal("段指针损坏的 xdb 必须被导入校验拒绝（探针搜索 + recover）")
	}
}

// Reload 是文件进入 live 热路径的第二入口：坏文件不得装载为在役 searcher。
func TestReload_rejectsProbePanicOnCorruptSegment(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	writeCorruptProbeSegmentXDB(t, live)
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))

	if err := Reload(); err == nil {
		t.Fatal("Reload 必须拒绝段指针损坏的 xdb（不得装载为在役 searcher）")
	}
	ip2regionMu.RLock()
	installed := ip2regionSearcher != nil
	ip2regionMu.RUnlock()
	if installed {
		t.Fatal("被拒绝的 xdb 不得装载为在役 searcher")
	}
}

// 启动入口同强度：损坏 live 库 + 无镜像回退时不得装载，也不得在省份采样期
// panic（main 无 recover，启动期 panic=进程退出）。
func TestInitIP2Region_rejectsProbePanicOnCorruptSegment(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	writeCorruptProbeSegmentXDB(t, live)
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))

	InitIP2Region()
	ip2regionMu.RLock()
	installed := ip2regionSearcher != nil
	ip2regionMu.RUnlock()
	if installed {
		t.Fatal("启动装载必须与导入/Reload 同强度拒绝损坏 xdb")
	}
}

// 主节点判定可写却写 live 失败（/app/data 只读、磁盘满、路径被同名文件占位）
// 时，必须与从节点分支同一只读降级：以镜像内置库装载，面板归属地/库状态保持
// 可用。旧实现直接放弃 → searcher 为空、归属地全空，且无任何可见的降级路径。
func Test_InitIP2Region_masterDistCopyFailureLoadsDistReadOnly(t *testing.T) {
	setupSecurityEnumTestDB(t)
	dir := t.TempDir()
	dist := filepath.Join(dir, "waf.dist", "ip2region.xdb")
	if err := os.MkdirAll(filepath.Dir(dist), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestXDB(t, dist, testSegments)
	// live 的父路径是普通文件 → os.Stat(live) 报错（按「缺失」处理），
	// copyFile 的 MkdirAll 必然失败（可写判定为真但写不成）。
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(blocker, "ip2region.xdb")
	withIP2RegionPaths(t, live, dist)

	InitIP2Region()

	if got := Lookup("1.2.3.1"); got != "US" {
		t.Fatalf("主节点 live 写入失败后未只读装载 dist: Lookup=%q, want US", got)
	}
	if _, err := os.Stat(live); err == nil {
		t.Fatal("live 不得被静默创建（降级是只读的）")
	}
}

// 同族：live 存在但不可装载（此处以目录占位模拟半写/带外损坏）且主节点
// dist 回退拷贝失败（rename 到目录必然失败）时，同样只读装载 dist。
func Test_InitIP2Region_masterCorruptLiveCopyFailureLoadsDistReadOnly(t *testing.T) {
	setupSecurityEnumTestDB(t)
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	if err := os.MkdirAll(live, 0o755); err != nil {
		t.Fatal(err)
	}
	dist := filepath.Join(dir, "waf.dist", "ip2region.xdb")
	if err := os.MkdirAll(filepath.Dir(dist), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestXDB(t, dist, testSegments)
	withIP2RegionPaths(t, live, dist)

	InitIP2Region()

	if got := Lookup("1.2.3.100"); got != "US" {
		t.Fatalf("主节点回退拷贝失败后未只读装载 dist: Lookup=%q, want US", got)
	}
	if info, err := os.Stat(live); err != nil || !info.IsDir() {
		t.Fatalf("live 现场必须保持原样（不得被半写文件覆盖）: err=%v", err)
	}
}
