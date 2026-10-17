package wafiplist

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// Step 1 TDD: .fast 二进制格式读写往返
func TestFastFile_WriteReadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.fast")

	// 乱序输入：本函数原地排序（U14-12 契约声明）。期望值用**独立**的已序
	// 切片——旧测试复用被原地排序的同一入参比较，删除排序仍绿（假绿）。
	v4 := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("1.2.3.4/32"),
	}
	v6 := []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("::1/128"),
	}
	wantV4 := []netip.Prefix{
		netip.MustParsePrefix("1.2.3.4/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.0/24"),
	}
	wantV6 := []netip.Prefix{
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("2001:db8::/32"),
	}

	if err := WriteFastFile(path, v4, v6); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}

	state, err := ReadFastFile(path)
	if err != nil {
		t.Fatalf("ReadFastFile: %v", err)
	}

	if len(state.V4) != len(v4) {
		t.Fatalf("V4 count=%d, want %d", len(state.V4), len(v4))
	}
	if len(state.V6) != len(v6) {
		t.Fatalf("V6 count=%d, want %d", len(state.V6), len(v6))
	}
	for i, p := range wantV4 {
		if state.V4[i] != p {
			t.Errorf("V4[%d]=%v, want %v", i, state.V4[i], p)
		}
	}
	for i, p := range wantV6 {
		if state.V6[i] != p {
			t.Errorf("V6[%d]=%v, want %v", i, state.V6[i], p)
		}
	}
}

// 空集往返
func TestFastFile_EmptySets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.fast")
	if err := WriteFastFile(path, nil, nil); err != nil {
		t.Fatalf("WriteFastFile empty: %v", err)
	}
	state, err := ReadFastFile(path)
	if err != nil {
		t.Fatalf("ReadFastFile empty: %v", err)
	}
	if len(state.V4) != 0 || len(state.V6) != 0 {
		t.Fatalf("expected empty, got V4=%d V6=%d", len(state.V4), len(state.V6))
	}
}

// 损坏 magic
func TestFastFile_BadMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.fast")
	os.WriteFile(path, []byte("XXXX\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), 0644)
	if _, err := ReadFastFile(path); err == nil {
		t.Fatal("expected error for bad magic")
	}
}

// 截断文件
func TestFastFile_Truncated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trunc.fast")
	// header 声称 100 条 v4 但数据只有 10 字节
	header := make([]byte, 16)
	copy(header[0:4], fastFileMagic)
	header[4] = 0
	header[5] = 0
	header[6] = 0
	header[7] = 100 // v4_count=100
	os.WriteFile(path, append(header, make([]byte, 10)...), 0644)
	if _, err := ReadFastFile(path); err == nil {
		t.Fatal("expected error for truncated file")
	}
}

// PLUG-L1（第 69 轮 P2）：腐化 bits/乱序条目静默破坏二分判定——ReadFastFile
// 必须校验 bits 范围（v4≤32/v6≤128）与地址非降序不变量，响亮拒绝腐化文件。
func TestFastFile_CorruptedBitsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.fast")
	// 一条 v4 条目：addr=10.0.0.0, bits=33（越界）
	data := make([]byte, 0, 16+5)
	data = append(data, []byte(fastFileMagic)...)
	data = append(data, 0, 0, 0, 1) // v4_count=1
	data = append(data, 0, 0, 0, 0) // v6_count=0
	data = append(data, 0, 0, 0, 0) // 保留 4 字节（header 共 16B）
	data = append(data, 10, 0, 0, 0, 33)
	os.WriteFile(path, data, 0644)
	if _, err := ReadFastFile(path); err == nil {
		t.Fatal("bits>32 must be rejected（invalid prefix 静默破坏二分）")
	}
}

// 同族：乱序条目（地址降序）拒绝。
func TestFastFile_UnorderedRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unordered.fast")
	data := make([]byte, 0, 16+10)
	data = append(data, []byte(fastFileMagic)...)
	data = append(data, 0, 0, 0, 2)      // v4_count=2
	data = append(data, 0, 0, 0, 0)      // v6_count=0
	data = append(data, 0, 0, 0, 0)      // 保留 4 字节（header 共 16B）
	data = append(data, 10, 0, 0, 2, 24) // 10.0.0.2/24
	data = append(data, 10, 0, 0, 1, 24) // 10.0.0.1/24（降序违例）
	os.WriteFile(path, data, 0644)
	if _, err := ReadFastFile(path); err == nil {
		t.Fatal("descending address order must be rejected")
	}
}

// PL-1（第 70 轮 P4）：升序校验不验「嵌套/同址不同 bits」形态——
// 10.0.0.0/16 与其子段 10.0.1.0/24 地址升序却互相包含，二分可被窄段遮蔽
// 返回假阴性（「可加载但查询错误」正是 WriteFastFile 注释定义的最坏静默
// 腐化形态）。须响亮拒绝。
func TestFastFile_NestedPrefixesRejected(t *testing.T) {
	dir := t.TempDir()
	// 宽段 10.0.0.0/16 + 其中段 10.0.1.0/24（升序合法、嵌套违例）
	v4 := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("10.0.1.0/24"),
	}
	nestedPath := filepath.Join(dir, "nested-v4.fast")
	if err := WriteFastFile(nestedPath, v4, nil); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if _, err := ReadFastFile(nestedPath); err == nil {
		t.Fatal("nested v4 prefixes (wide + contained sub) must be rejected（二分假阴性）")
	}

	// 同址不同 bits：10.0.0.0/16 + 10.0.0.0/24（Compare==0 非降序、包含）
	sameAddr := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/24"),
	}
	sameAddrPath := filepath.Join(dir, "same-addr-v4.fast")
	if err := WriteFastFile(sameAddrPath, sameAddr, nil); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if _, err := ReadFastFile(sameAddrPath); err == nil {
		t.Fatal("same-address different-bits v4 prefixes must be rejected（二分假阴性）")
	}

	// v6 同口径：2001:db8::/32 + 2001:db8:1::/48
	v6 := []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001:db8:1::/48"),
	}
	v6Path := filepath.Join(dir, "nested-v6.fast")
	if err := WriteFastFile(v6Path, nil, v6); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if _, err := ReadFastFile(v6Path); err == nil {
		t.Fatal("nested v6 prefixes must be rejected（二分假阴性）")
	}

	// 反例：相邻（不嵌套）合法文件不受影响——10.0.0.0/24 + 10.0.1.0/24
	adjacent := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.1.0/24"),
	}
	adjacentPath := filepath.Join(dir, "adjacent.fast")
	if err := WriteFastFile(adjacentPath, adjacent, nil); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if _, err := ReadFastFile(adjacentPath); err != nil {
		t.Fatalf("adjacent disjoint prefixes must load, got: %v", err)
	}
}
