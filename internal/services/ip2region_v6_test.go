package services

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// —— IPv6 xdb 测试夹具与解析面测试 ——
//
// writeTestXDBV6 builds a minimal but structurally valid IPv6 xdb (structure
// 3.0, ip_version=6, 38-byte segment index: startIP 16 + endIP 16 + dataLen 2
// + dataPtr 4, big-endian IP compare) so the real BufferCache search path runs
// without any network dependency. 布局锚定绑定库 xdb/version.go（IPv6
// SegmentIndexSize=38、IPCompare=bytes.Compare）与 xdb/header.go（256B 头，
// [0:2] 结构版本=3、[16:18] IP 版本=6）。

type xdbSegmentV6 struct {
	startIP [16]byte
	endIP   [16]byte
	region  string
}

// v6SegIPHardcoded 把完整冒号十六进制 IPv6 地址解析为 16 字节大端形态（测试
// 夹具专用：net.ParseIP 承载解析，畸形地址直接 panic 让夹具错误显性）。
func v6SegIPHardcoded(s string) [16]byte {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("v6 fixture ip invalid: " + s)
	}
	var out [16]byte
	copy(out[:], ip.To16())
	return out
}

func writeTestXDBV6(t *testing.T, path string, segments []xdbSegmentV6) {
	t.Helper()
	const (
		headerSize      = 256
		vectorIndexSize = 256 * 256 * 8
		segmentSize     = 38
	)
	buf := make([]byte, headerSize+vectorIndexSize)

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
	for _, seg := range segments {
		appendRegion(seg.region)
	}
	blockPtrs := make([]uint32, len(segments))
	for i, seg := range segments {
		blockPtrs[i] = next
		block := make([]byte, segmentSize)
		copy(block[0:16], seg.startIP[:])
		copy(block[16:32], seg.endIP[:])
		binary.LittleEndian.PutUint16(block[32:], uint16(len(seg.region)))
		binary.LittleEndian.PutUint32(block[34:], regionPtr[seg.region])
		buf = append(buf, block...)
		next = uint32(len(buf))
	}
	// 向量索引按 IP 前两字节键入（与 v4 同形）；夹具段共享前缀时收敛到
	// 同一 8B 条目，不同前缀各写一格。
	for i, seg := range segments {
		idx := headerSize + (int(seg.startIP[0])*256+int(seg.startIP[1]))*8
		curStart := binary.LittleEndian.Uint32(buf[idx:])
		curEnd := binary.LittleEndian.Uint32(buf[idx+4:])
		if curStart == 0 && curEnd == 0 {
			binary.LittleEndian.PutUint32(buf[idx:], blockPtrs[i])
			binary.LittleEndian.PutUint32(buf[idx+4:], blockPtrs[i]+segmentSize)
			continue
		}
		if blockPtrs[i] < curStart {
			binary.LittleEndian.PutUint32(buf[idx:], blockPtrs[i])
		}
		if blockPtrs[i]+segmentSize > curEnd {
			binary.LittleEndian.PutUint32(buf[idx+4:], blockPtrs[i]+segmentSize)
		}
	}
	// Header: structure 3.0, ip_version=6, runtime ptr bytes=4。
	binary.LittleEndian.PutUint16(buf[0:], 3)
	binary.LittleEndian.PutUint16(buf[2:], 1)
	binary.LittleEndian.PutUint32(buf[8:], blockPtrs[0])
	binary.LittleEndian.PutUint32(buf[12:], blockPtrs[len(blockPtrs)-1])
	binary.LittleEndian.PutUint16(buf[16:], 6)
	binary.LittleEndian.PutUint16(buf[18:], 4)
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}
}

// defaultV6TestSegments 是 v6 夹具的语义段：中国电信 240e::/20 段样本（与
// 生产 v6 探针 ip2RegionV6ProbeIP 同族）、中国省段、海外段、残行段。
func defaultV6TestSegments() []xdbSegmentV6 {
	seg := func(start, end, region string) xdbSegmentV6 {
		return xdbSegmentV6{startIP: v6SegIPHardcoded(start), endIP: v6SegIPHardcoded(end), region: region}
	}
	return []xdbSegmentV6{
		seg("240e:0000:0000:0000:0000:0000:0000:0000", "240e:0000:0000:ffff:ffff:ffff:ffff:ffff", "中国|北京|北京市|电信|CN"),
		seg("240e:0056:0000:0000:0000:0000:0000:0000", "240e:0056:ffff:ffff:ffff:ffff:ffff:ffff", "中国|浙江省|杭州市|电信|CN"),
		seg("2606:4700:0000:0000:0000:0000:0000:0000", "2606:4700:ffff:ffff:ffff:ffff:ffff:ffff", "United States|California|San Francisco|Cloudflare, Inc.|US"),
		seg("2a00:1450:0000:0000:0000:0000:0000:0000", "2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff", "Germany|Hesse|Frankfurt am Main|Google LLC|DE"),
		seg("2001:0db8:0000:0000:0000:0000:0000:0000", "2001:0db8:0000:ffff:ffff:ffff:ffff:ffff", "0|0|0|0"),
	}
}

// withIP2RegionV6Paths 与 withIP2RegionPaths 同形：把 v6 双路径指到测试目录
// 并在用例结束后恢复（含 searcher 清场，防 -shuffle 串号）。
func withIP2RegionV6Paths(t *testing.T, liveV6, distV6 string) {
	t.Helper()
	oldLive, oldDist := ip2regionV6LivePath, ip2regionV6DistPath
	ip2regionV6LivePath, ip2regionV6DistPath = liveV6, distV6
	t.Cleanup(func() {
		ip2regionV6LivePath, ip2regionV6DistPath = oldLive, oldDist
	})
}

// setIP2RegionV6EnabledForTest 注入 v6 开关测试缝（save/restore；不依赖 DB
// ——纯函数级用例无隔离库也可用）。
func setIP2RegionV6EnabledForTest(t *testing.T, enabled bool) {
	t.Helper()
	old := ip2RegionV6EnabledOverride
	v := enabled
	ip2RegionV6EnabledOverride = &v
	t.Cleanup(func() { ip2RegionV6EnabledOverride = old })
}

// TestIP2RegionXDBLayout_structureVersionDispatch 钉住布局判定矩阵：
// 结构 2.0 → v4（旧库 [16:20] 为 0）、3.0+ip4 → v4、3.0+ip6 → v6（38B）、
// 交叉/非法形态显性报错（v4 文件换名到 v6 路径必须被拒）。
func TestIP2RegionXDBLayout_structureVersionDispatch(t *testing.T) {
	mk := func(structure, ipVersion uint16) []byte {
		header := make([]byte, 20)
		binary.LittleEndian.PutUint16(header[0:], structure)
		binary.LittleEndian.PutUint16(header[16:], ipVersion)
		return header
	}
	if size, ver, err := ip2RegionXDBLayout(mk(2, 0)); err != nil || size != 14 || ver != 4 {
		t.Fatalf("structure 2.0: size=%d ver=%d err=%v, want 14/4/nil", size, ver, err)
	}
	if size, ver, err := ip2RegionXDBLayout(mk(2, 4)); err != nil || size != 14 || ver != 4 {
		t.Fatalf("structure 2.0 ip4: size=%d ver=%d err=%v, want 14/4/nil", size, ver, err)
	}
	if _, _, err := ip2RegionXDBLayout(mk(2, 6)); err == nil {
		t.Fatal("structure 2.0 with ip6 must be rejected")
	}
	if size, ver, err := ip2RegionXDBLayout(mk(3, 4)); err != nil || size != 14 || ver != 4 {
		t.Fatalf("structure 3.0 ip4: size=%d ver=%d err=%v, want 14/4/nil", size, ver, err)
	}
	if size, ver, err := ip2RegionXDBLayout(mk(3, 6)); err != nil || size != 38 || ver != 6 {
		t.Fatalf("structure 3.0 ip6: size=%d ver=%d err=%v, want 38/6/nil", size, ver, err)
	}
	if _, _, err := ip2RegionXDBLayout(mk(3, 5)); err == nil {
		t.Fatal("structure 3.0 with unknown ip version must be rejected")
	}
	if _, _, err := ip2RegionXDBLayout(mk(9, 4)); err == nil {
		t.Fatal("unknown structure must be rejected")
	}
}

// TestCheckIP2RegionXDBStructure_v6LayoutGate：v6 夹具通过自检；v4 夹具换名
// 到 v6 语义路径被拒（布局判定防「v4 文件按 38B 解段」的乱码树）；截断 v6
// 显性报错。
func TestCheckIP2RegionXDBStructure_v6LayoutGate(t *testing.T) {
	dir := t.TempDir()
	v6Path := filepath.Join(dir, "v6.xdb")
	writeTestXDBV6(t, v6Path, defaultV6TestSegments())
	if err := checkIP2RegionXDBStructure(v6Path); err != nil {
		t.Fatalf("valid v6 xdb must pass structure gate: %v", err)
	}

	v4Path := filepath.Join(dir, "v4.xdb")
	writeTestXDB(t, v4Path, testSegments)
	if err := checkIP2RegionXDBStructure(v4Path); err != nil {
		t.Fatalf("valid v4 xdb must pass structure gate: %v", err)
	}

	trunc, err := os.Create(filepath.Join(dir, "trunc.xdb"))
	if err != nil {
		t.Fatal(err)
	}
	if err := trunc.Truncate(600 * 1024); err != nil {
		t.Fatal(err)
	}
	trunc.Close()
	if err := checkIP2RegionXDBStructure(filepath.Join(dir, "trunc.xdb")); err == nil {
		t.Fatal("truncated v6 xdb must be rejected")
	}
}

// TestOpenValidatedIP2RegionSearcherDual_v6Attach 哨兵等价性钉测（面板侧）：
// v6 附加后 240e 段命中「中国|浙江省|杭州市」真实行；未附加（空路径）时同
// IP 返回空串（禁用族语义，调用方回落哨兵）；损坏 v6 附加被降级为禁用且
// v4 查询不受影响。
func TestOpenValidatedIP2RegionSearcherDual_v6Attach(t *testing.T) {
	dir := t.TempDir()
	v4Path := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, v4Path, []xdbSegment{
		{startIP: 0x01020300, endIP: 0x010203FF, region: "中国|广东省|深圳市|电信|CN"},
	})
	v6Path := filepath.Join(dir, "ip2region_v6.xdb")
	writeTestXDBV6(t, v6Path, defaultV6TestSegments())

	searcher, err := openValidatedIP2RegionSearcherDual(v4Path, v6Path)
	if err != nil {
		t.Fatalf("dual searcher: %v", err)
	}
	defer searcher.Close()
	region, err := searcher.Search("240e:56:1:2::9")
	if err != nil || !strings.Contains(region, "杭州市") {
		t.Fatalf("v6 search=%q err=%v, want 中国|浙江省|杭州市 形态", region, err)
	}
	region, err = searcher.Search("2606:4700::1111")
	if err != nil || !strings.Contains(region, "United States") {
		t.Fatalf("v6 overseas search=%q err=%v, want United States 形态", region, err)
	}
	// v4 族不受 v6 附加影响。
	region, err = searcher.Search("1.2.3.66")
	if err != nil || !strings.Contains(region, "深圳市") {
		t.Fatalf("v4 search=%q err=%v, want 深圳 形态", region, err)
	}

	disabled, err := openValidatedIP2RegionSearcherDual(v4Path, "")
	if err != nil {
		t.Fatalf("v6-disabled searcher: %v", err)
	}
	defer disabled.Close()
	region, err = disabled.Search("240e:56:1:2::9")
	if err != nil || region != "" {
		t.Fatalf("disabled v6 search=%q err=%v, want empty/nil (sentinel semantics)", region, err)
	}

	corruptV6 := filepath.Join(dir, "corrupt_v6.xdb")
	if err := os.WriteFile(corruptV6, []byte("not an xdb at all"), 0644); err != nil {
		t.Fatal(err)
	}
	degraded, err := openValidatedIP2RegionSearcherDual(v4Path, corruptV6)
	if err != nil {
		t.Fatalf("corrupt v6 must degrade, not fail: %v", err)
	}
	defer degraded.Close()
	if region, err := degraded.Search("1.2.3.66"); err != nil || !strings.Contains(region, "深圳市") {
		t.Fatalf("v4 must stay healthy with corrupt v6: %q %v", region, err)
	}
	if region, err := degraded.Search("240e:56:1:2::9"); err != nil || region != "" {
		t.Fatalf("corrupt v6 must degrade to disabled: %q %v", region, err)
	}
}

// TestOpenValidatedIP2RegionSearcherDual_probeRejectsCorruptV4：更新安装校验
// 入口（dual 变体）必须与启动/重载/导入同强度——结构自检通过、探针段越界的
// 损坏 v4 在真实 Search 时 panic，校验须把 panic 转成错误（recover 真实可达），
// 不得让坏工件经弱门进入 live。此前 dual 变体只构造不探针，recover 恒不可达。
func TestOpenValidatedIP2RegionSearcherDual_probeRejectsCorruptV4(t *testing.T) {
	dir := t.TempDir()
	v4Path := filepath.Join(dir, "corrupt.xdb")
	writeCorruptProbeSegmentXDB(t, v4Path)

	searcher, err := openValidatedIP2RegionSearcherDual(v4Path, "")
	if err == nil {
		searcher.Close()
		t.Fatal("段指针损坏的 v4 必须被 dual 校验拒绝（探针 Search + recover）")
	}
	if searcher != nil {
		t.Fatal("拒绝时不得返回半构造 searcher")
	}
	if !strings.Contains(err.Error(), "内部异常") && !strings.Contains(err.Error(), "搜索失败") {
		t.Fatalf("错误须指明探针校验失败: %v", err)
	}
}

// TestValidateIP2RegionV6XDB_probeRejectsBroken：结构自检通过、探针段越界的
// 损坏 v6（段指针改写指向向量区）必须被显性拒绝——与 v4 同强度。
func TestValidateIP2RegionV6XDB_probeRejectsBroken(t *testing.T) {
	dir := t.TempDir()
	v6Path := filepath.Join(dir, "v6.xdb")
	writeTestXDBV6(t, v6Path, defaultV6TestSegments())
	if err := validateIP2RegionV6XDB(v6Path); err != nil {
		t.Fatalf("healthy v6 fixture must validate: %v", err)
	}
	// 改写探针 IP 所在向量条目为越界指针（≥ 文件大小）。
	raw, err := os.ReadFile(v6Path)
	if err != nil {
		t.Fatal(err)
	}
	idx := 256 + (0x24*256+0x0e)*8 // 240e 前缀的向量槽（[0]=0x24,[1]=0x0e）
	binary.LittleEndian.PutUint32(raw[idx:], uint32(len(raw))+1024)
	if err := os.WriteFile(v6Path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err := validateIP2RegionV6XDB(v6Path); err == nil {
		t.Fatal("v6 with out-of-range vector pointer must be rejected")
	}
}

// TestEntryCountFromXDBHeader_v6SegmentSize：条目数推导按布局取段宽
// （v6=38B），v4 保持 14B。
func TestEntryCountFromXDBHeader_v6SegmentSize(t *testing.T) {
	dir := t.TempDir()
	v6Path := filepath.Join(dir, "v6.xdb")
	writeTestXDBV6(t, v6Path, defaultV6TestSegments())
	// 夹具 5 段 → 条目数 5。
	if got := entryCountFromXDBHeader(v6Path); got != 5 {
		t.Fatalf("v6 entry count=%d, want 5", got)
	}
	v4Path := filepath.Join(dir, "v4.xdb")
	writeTestXDB(t, v4Path, testSegments)
	if got := entryCountFromXDBHeader(v4Path); got != len(testSegments) {
		t.Fatalf("v4 entry count=%d, want %d", got, len(testSegments))
	}
}

// TestRegionTreeFromXDB_v6Scan：v6 独立扫描产出省/市/国家集（38B 段解索引）；
// regionTreeForSettings 在 v6 启用时产出并集树（海外哨兵恒末位、无重复）。
func TestRegionTreeFromXDB_v6Scan(t *testing.T) {
	dir := t.TempDir()
	v4Path := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, v4Path, []xdbSegment{
		{startIP: 0x01020300, endIP: 0x010203FF, region: "中国|广东省|深圳市|电信|CN"},
	})
	v6Path := filepath.Join(dir, "ip2region_v6.xdb")
	writeTestXDBV6(t, v6Path, defaultV6TestSegments())
	withIP2RegionPaths(t, v4Path, filepath.Join(dir, "missing-dist.xdb"))

	tree := regionTreeFromXDB(v6Path)
	if tree == nil {
		t.Fatal("v6 scan returned nil")
	}
	assertTreeContains(t, tree, "北京市", "杭州市", "United States", "Germany")

	// 并集树（v6 关闭=纯 v4 树）。
	setIP2RegionV6EnabledForTest(t, false)
	withIP2RegionV6Paths(t, v6Path, filepath.Join(dir, "dist_v6.xdb"))
	merged := regionTreeForSettings()
	if merged == nil {
		t.Fatal("merged tree (v6 off) returned nil")
	}
	if containsString(merged.Provinces, "北京市") {
		t.Fatal("v6 disabled must not union v6 provinces")
	}
	setIP2RegionV6EnabledForTest(t, true)
	merged = regionTreeForSettings()
	if merged == nil {
		t.Fatal("merged tree (v6 on) returned nil")
	}
	assertTreeContains(t, merged, "北京市", "杭州市", "United States", "Germany", "广东省")
	if !containsString(merged.Cities["浙江省"], "杭州市") {
		t.Fatalf("merged tree must contain 浙江省→杭州市: %v", merged.Cities["浙江省"])
	}
	if last := merged.Provinces[len(merged.Provinces)-1]; last != "海外" {
		t.Fatalf("海外 sentinel must stay last, got tail=%v", merged.Provinces)
	}
	if listCountString(merged.Provinces, "海外") != 1 {
		t.Fatalf("海外 sentinel must appear exactly once: %v", merged.Provinces)
	}
}

func assertTreeContains(t *testing.T, tree *IP2RegionRegionTree, want ...string) {
	t.Helper()
	for _, w := range want {
		inProvinces := listContainsString(tree.Provinces, w)
		inCountries := listContainsString(tree.Countries, w)
		inCities := false
		for _, cities := range tree.Cities {
			if listContainsString(cities, w) {
				inCities = true
				break
			}
		}
		if !inProvinces && !inCountries && !inCities {
			t.Fatalf("tree missing %q: provinces=%v countries=%v", w, tree.Provinces, tree.Countries)
		}
	}
}

func listContainsString(list []string, want string) bool {
	return listCountString(list, want) > 0
}

func listCountString(list []string, want string) int {
	n := 0
	for _, item := range list {
		if item == want {
			n++
		}
	}
	return n
}
