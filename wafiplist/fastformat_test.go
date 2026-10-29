package wafiplist

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildFastFileRaw 构造早期形态（flags=0，无尾部校验和）.fast 原始字节：
// 测读侧不变量校验时绕开写侧同一断言——用 WriteFastFile 造嵌套夹具会被
// 写侧拒绝，两侧互相掩蔽。
func buildFastFileRaw(t *testing.T, v4, v6 []netip.Prefix) []byte {
	t.Helper()
	data := make([]byte, 0, fastFileHeaderSize+len(v4)*5+len(v6)*17)
	data = append(data, []byte(fastFileMagic)...)
	data = binary.BigEndian.AppendUint32(data, uint32(len(v4)))
	data = binary.BigEndian.AppendUint32(data, uint32(len(v6)))
	data = binary.BigEndian.AppendUint32(data, 0) // flags=0：早期无校验形态
	for _, p := range v4 {
		addr := p.Addr().As4()
		data = append(data, addr[:]...)
		data = append(data, byte(p.Bits()))
	}
	for _, p := range v6 {
		addr := p.Addr().As16()
		data = append(data, addr[:]...)
		data = append(data, byte(p.Bits()))
	}
	return data
}

// Step 1 TDD: .fast 二进制格式读写往返
func TestFastFile_WriteReadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.fast")

	// 乱序输入：本函数原地排序。期望值用**独立**的已序
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

// 腐化 bits/乱序条目静默破坏二分判定——ReadFastFile
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

// 升序校验不验「嵌套/同址不同 bits」形态——
// 10.0.0.0/16 与其子段 10.0.1.0/24 地址升序却互相包含，二分可被窄段遮蔽
// 返回假阴性（「可加载但查询错误」正是 WriteFastFile 注释定义的最坏静默
// 腐化形态）。须响亮拒绝。
func TestFastFile_NestedPrefixesRejected(t *testing.T) {
	dir := t.TempDir()
	// 宽段 10.0.0.0/16 + 其中段 10.0.1.0/24（升序合法、嵌套违例）。
	// 用原始字节构造：写侧现在自带同一断言，用 WriteFastFile 造夹具会先被拒。
	nestedPath := filepath.Join(dir, "nested-v4.fast")
	if err := os.WriteFile(nestedPath, buildFastFileRaw(t, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("10.0.1.0/24"),
	}, nil), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(nestedPath); err == nil {
		t.Fatal("nested v4 prefixes (wide + contained sub) must be rejected（二分假阴性）")
	}

	// 同址不同 bits：10.0.0.0/16 + 10.0.0.0/24（Compare==0 非降序、包含）
	sameAddrPath := filepath.Join(dir, "same-addr-v4.fast")
	if err := os.WriteFile(sameAddrPath, buildFastFileRaw(t, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/24"),
	}, nil), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(sameAddrPath); err == nil {
		t.Fatal("same-address different-bits v4 prefixes must be rejected（二分假阴性）")
	}

	// v6 同口径：2001:db8::/32 + 2001:db8:1::/48
	v6Path := filepath.Join(dir, "nested-v6.fast")
	if err := os.WriteFile(v6Path, buildFastFileRaw(t, nil, []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001:db8:1::/48"),
	}), 0644); err != nil {
		t.Fatal(err)
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

// 崩溃残留回收：.fast 原子写在 CreateTemp 与 rename 之间掉电/崩溃会留下
// <base>.<rand>.tmp，waf 目录没有 IP 名单目录的 tmp GC 分支——写入前顺带
// 回收本文件超龄残留（在役临时文件年轻，不受影响；其他名单的残留不归
// 本次清理，避免并发写入方互相误删）。
func TestWriteFastFile_sweepsStaleTempFiles(t *testing.T) {
	dir := t.TempDir()
	base := "threat-x.iplist.fast"
	stale := filepath.Join(dir, base+".123456.tmp")
	young := filepath.Join(dir, base+".654321.tmp")
	other := filepath.Join(dir, "other.iplist.fast.999.tmp")
	for _, p := range []string{stale, young, other} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * fastFileTempMaxAge)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(other, old, old); err != nil {
		t.Fatal(err)
	}
	if err := WriteFastFile(filepath.Join(dir, base), []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, nil); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("本文件的超龄临时残留必须回收")
	}
	if _, err := os.Stat(young); err != nil {
		t.Fatalf("未超龄（可能在役）的临时文件不得删除: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("其他名单的残留不归本次清理: %v", err)
	}
}

// 写侧自证读侧不变量：未聚合输入（嵌套/同址不同 bits/重复条目）必须返回
// error 并且不落盘——否则产物「写成功、读必失败」，节点回退侧拿到不可用
// 名单（策略被跳过或回退文本）。
func TestWriteFastFile_rejectsUnaggregatedInput(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		v4   []netip.Prefix
		v6   []netip.Prefix
	}{
		{"嵌套v4", []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/16"),
			netip.MustParsePrefix("10.0.1.0/24"),
		}, nil},
		{"同址不同bits", []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/16"),
			netip.MustParsePrefix("10.0.0.0/24"),
		}, nil},
		{"重复同前缀", []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
			netip.MustParsePrefix("10.0.0.0/24"),
		}, nil},
		{"嵌套v6", nil, []netip.Prefix{
			netip.MustParsePrefix("2001:db8::/32"),
			netip.MustParsePrefix("2001:db8:1::/48"),
		}},
	}
	for _, tc := range cases {
		path := filepath.Join(dir, tc.name+".fast")
		if err := WriteFastFile(path, tc.v4, tc.v6); err == nil {
			t.Fatalf("%s: 未聚合输入必须被写侧拒绝（读侧会拒绝该产物）", tc.name)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s: 拒绝时不得落盘", tc.name)
		}
	}
}

// 内容完整性：写侧产物带 crc32c 尾部；位翻转若仍满足 magic/count/bits/
// 掩码/升序/不相交不变量（如某段地址高位跳变但不越邻）必须被校验和拒绝，
// 否则从节点回退路径会静默改变实际拦截集合。flags==0 的早期无校验产物
// 仍可加载（跨版本回滚兼容）；除校验和位外的未知 flags 位仍拒绝。
func TestFastFile_ChecksumDetectsSilentCorruption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crc.fast")
	if err := WriteFastFile(path, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}, nil); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if flags := binary.BigEndian.Uint32(data[12:16]); flags&fastFileChecksumFlag == 0 {
		t.Fatal("写侧必须置 crc32c 校验和位")
	}

	// 篡改第二条地址首字节 203→201：仍掩码（/24）、仍升序、仍不相交——
	// 三条结构不变量全部通过，只有校验和能发现。
	tampered := append([]byte(nil), data...)
	tampered[fastFileHeaderSize+5] = 201
	if err := os.WriteFile(path, tampered, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(path); err == nil {
		t.Fatal("仍满足结构不变量的位翻转必须被校验和拒绝（静默漏拦/误拦）")
	}

	// 兼容：flags 清零 + 去掉尾部 4 字节 = 早期无校验形态，照常加载。
	legacy := append([]byte(nil), data[:len(data)-4]...)
	binary.BigEndian.PutUint32(legacy[12:16], 0)
	legacyPath := filepath.Join(dir, "legacy.fast")
	if err := os.WriteFile(legacyPath, legacy, 0644); err != nil {
		t.Fatal(err)
	}
	state, err := ReadFastFile(legacyPath)
	if err != nil {
		t.Fatalf("早期无校验产物必须仍可加载（回滚兼容）: %v", err)
	}
	if len(state.V4) != 2 {
		t.Fatalf("legacy V4 entries=%d, want 2", len(state.V4))
	}

	// 除校验和位外的未知位仍拒绝（格式演进必须显式）。
	bad := append([]byte(nil), legacy...)
	binary.BigEndian.PutUint32(bad[12:16], 2)
	badPath := filepath.Join(dir, "badflags.fast")
	if err := os.WriteFile(badPath, bad, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(badPath); err == nil {
		t.Fatal("未知 flags 位必须拒绝")
	}
}

// 读侧必须校验主机位已掩码——.fast 是跨进程输入（节点回传），
// 单条未掩码条目可通过 bits/升序/嵌套全部校验，却让二分查询用未掩码地址
// 比较而假阴性（威胁名单静默漏拦）。
func TestFastFile_UnmaskedEntriesRejected(t *testing.T) {
	dir := t.TempDir()

	// 单条未掩码 v4：1.2.3.200/24（无前驱可比较嵌套；修复前可加载）。
	v4Path := filepath.Join(dir, "unmasked-v4.fast")
	data := make([]byte, 0, 16+5)
	data = append(data, []byte(fastFileMagic)...)
	data = append(data, 0, 0, 0, 1) // v4_count=1
	data = append(data, 0, 0, 0, 0) // v6_count=0
	data = append(data, 0, 0, 0, 0) // 保留 4 字节
	data = append(data, 1, 2, 3, 200, 24)
	if err := os.WriteFile(v4Path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(v4Path); err == nil {
		t.Fatal("unmasked v4 host bits must be rejected（二分假阴性）")
	}

	// 单条未掩码 v6：2001:db8::1/32。
	v6Addr := netip.MustParseAddr("2001:db8::1").As16()
	v6Path := filepath.Join(dir, "unmasked-v6.fast")
	data = make([]byte, 0, 16+17)
	data = append(data, []byte(fastFileMagic)...)
	data = append(data, 0, 0, 0, 0) // v4_count=0
	data = append(data, 0, 0, 0, 1) // v6_count=1
	data = append(data, 0, 0, 0, 0) // 保留 4 字节
	data = append(data, v6Addr[:]...)
	data = append(data, 32)
	if err := os.WriteFile(v6Path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(v6Path); err == nil {
		t.Fatal("unmasked v6 host bits must be rejected（二分假阴性）")
	}

	// 反例：写侧产物（掩码后）照常加载。
	okPath := filepath.Join(dir, "masked.fast")
	if err := WriteFastFile(okPath, []netip.Prefix{
		netip.MustParsePrefix("1.2.3.200/24"),
	}, []netip.Prefix{netip.MustParsePrefix("2001:db8::1/32")}); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if _, err := ReadFastFile(okPath); err != nil {
		t.Fatalf("masked entries from WriteFastFile must load, got: %v", err)
	}
}

// ReadFastFile 对跨进程.fast 输入必须先过 Stat
// 体积门再读字节——异常/恶意超大文件不得在读取阶段就拖垮内存（文本名单
// 路径已有 maxFileBytes 同型硬上限，iplistfast.go:249-250）。
func TestFastFile_ReadSizeCap(t *testing.T) {
	dir := t.TempDir()
	old := maxFastFileBytes
	maxFastFileBytes = 4096
	t.Cleanup(func() { maxFastFileBytes = old })

	// 超限文件：内容本身合法（写侧产物拼接填充无所谓——体积门先于内容解析）。
	bigPath := filepath.Join(dir, "big.fast")
	if err := os.WriteFile(bigPath, make([]byte, 4097), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(bigPath); err == nil {
		t.Fatal("oversize .fast must be rejected before reading body")
	}

	// 回归形状：上限内的合法文件照常加载。
	okPath := filepath.Join(dir, "ok.fast")
	if err := WriteFastFile(okPath, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if _, err := ReadFastFile(okPath); err != nil {
		t.Fatalf("in-cap .fast must load: %v", err)
	}

	// 边界形状：恰好等于上限的文件不被体积门误杀（由后续内容校验裁决）。
	exactPath := filepath.Join(dir, "exact.fast")
	if err := os.WriteFile(exactPath, make([]byte, 4096), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(exactPath); err == nil || !strings.Contains(err.Error(), "magic") {
		t.Fatalf("exact-cap file must pass the size gate and fail on content (magic), got: %v", err)
	}
}

// 读侧族校验必须与写侧同口径：v6 段出现 4-in-6 映射地址（::ffff:1.2.3.4）
// 是跨进程输入的族错配形态——16 字节地址、bits 合法、掩码/升序/不相交全部
// 通过，但该前缀永远匹配不到纯 IPv6 查询（也不会被 v4 段命中），即静默漏拦。
func TestFastFile_4in6InV6SectionRejected(t *testing.T) {
	dir := t.TempDir()

	mapped := netip.MustParseAddr("::ffff:1.2.3.4").As16()
	path := filepath.Join(dir, "mapped-v6.fast")
	data := make([]byte, 0, 16+17)
	data = append(data, []byte(fastFileMagic)...)
	data = append(data, 0, 0, 0, 0) // v4_count=0
	data = append(data, 0, 0, 0, 1) // v6_count=1
	data = append(data, 0, 0, 0, 0) // 保留 4 字节
	data = append(data, mapped[:]...)
	data = append(data, 128)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(path); err == nil || !strings.Contains(err.Error(), "4-in-6") {
		t.Fatalf("4-in-6 v6 entry must be rejected with a family error, got: %v", err)
	}

	// 反例：纯 v6 段照常加载（族校验不得误伤正常产物）。
	okPath := filepath.Join(dir, "pure-v6.fast")
	if err := WriteFastFile(okPath, nil, []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if _, err := ReadFastFile(okPath); err != nil {
		t.Fatalf("pure v6 entries must load, got: %v", err)
	}
}

// 条目数上限是读侧第二道门（体积门挡不住「小文件 × 巨大 header 计数」）：
// header 计数直接决定 make([]netip.Prefix, …) 的规模，若只信任计数，
// 64MiB 文件可声明 1300 万条并展开成数百 MiB 前缀集。
func TestFastFile_ReadEntryCap(t *testing.T) {
	dir := t.TempDir()
	old := maxFastEntries
	maxFastEntries = 3
	t.Cleanup(func() { maxFastEntries = old })

	// 小型 + 巨量计数：体积远低于上限，必须在分配前被条目门拒绝。
	hugePath := filepath.Join(dir, "huge-count.fast")
	data := make([]byte, 0, fastFileHeaderSize)
	data = append(data, []byte(fastFileMagic)...)
	data = append(data, 0xff, 0xff, 0xff, 0xf0) // v4_count ≈ 43 亿
	data = append(data, 0, 0, 0, 0)             // v6_count=0
	data = append(data, 0, 0, 0, 0)             // flags=0
	if err := os.WriteFile(hugePath, data, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(hugePath); err == nil || !strings.Contains(err.Error(), "entry count") {
		t.Fatalf("huge header count must be rejected by the entry cap, got: %v", err)
	}

	// v4+v6 合计口径：单族各半仍超限同样拒绝（上限不是逐族各一份）。
	mixedPath := filepath.Join(dir, "mixed-count.fast")
	data = data[:0]
	data = append(data, []byte(fastFileMagic)...)
	data = append(data, 0, 0, 0, 2) // v4_count=2
	data = append(data, 0, 0, 0, 2) // v6_count=2
	data = append(data, 0, 0, 0, 0) // flags=0
	if err := os.WriteFile(mixedPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(mixedPath); err == nil || !strings.Contains(err.Error(), "entry count") {
		t.Fatalf("v4+v6 combined count above cap must be rejected, got: %v", err)
	}

	// 反例：恰好等于上限的产物照常加载（条目门不得误伤正常产物）。
	okPath := filepath.Join(dir, "within-cap.fast")
	if err := WriteFastFile(okPath, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("11.0.0.0/8"),
		netip.MustParsePrefix("12.0.0.0/8"),
	}, nil); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	state, err := ReadFastFile(okPath)
	if err != nil {
		t.Fatalf("entry count at cap must load, got: %v", err)
	}
	if len(state.V4) != 3 {
		t.Fatalf("loaded v4 entries=%d, want 3", len(state.V4))
	}
}

// 写侧自证读侧上限：越过 maxFastEntries / maxFastFileBytes 的产物读侧必然
// 拒收——写出来只会得到「写成功、读失败」的名单。写侧必须显式报错且不落盘，
// 上限恢复后同一输入可写出并被 ReadFastFile 接受（读侧实证）。
func TestWriteFastFile_selfEnforcesReadCaps(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("10.0.2.0/24"),
		netip.MustParsePrefix("10.0.3.0/24"),
		netip.MustParsePrefix("10.0.4.0/24"),
	}
	path := filepath.Join(t.TempDir(), "caps.fast")

	oldEntries := maxFastEntries
	t.Cleanup(func() { maxFastEntries = oldEntries })
	maxFastEntries = 4
	if err := WriteFastFile(path, prefixes, nil); err == nil {
		t.Fatal("超出 maxFastEntries 的写入必须被拒绝（读侧必然拒收）")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("被拒绝的写入不得落盘: stat err=%v", statErr)
	}

	maxFastEntries = oldEntries
	oldBytes := maxFastFileBytes
	t.Cleanup(func() { maxFastFileBytes = oldBytes })
	maxFastFileBytes = 32
	if err := WriteFastFile(path, prefixes, nil); err == nil {
		t.Fatal("超出 maxFastFileBytes 的写入必须被拒绝（读侧必然拒收）")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("被拒绝的写入不得落盘: stat err=%v", statErr)
	}

	// 上限恢复：同一输入可写出，且读侧接受（证明拒绝理由确实是上限而非输入）。
	maxFastFileBytes = oldBytes
	if err := WriteFastFile(path, prefixes, nil); err != nil {
		t.Fatalf("上限恢复后写入失败: %v", err)
	}
	state, err := ReadFastFile(path)
	if err != nil {
		t.Fatalf("上限恢复后产物必须被读侧接受: %v", err)
	}
	if len(state.V4) != len(prefixes) {
		t.Fatalf("loaded v4=%d, want %d", len(state.V4), len(prefixes))
	}
}

func TestWriteFastFile_directoryDurabilityFailureWarnsAndKeepsReadableArtifact(t *testing.T) {
	for _, failure := range []string{"open", "sync"} {
		t.Run(failure, func(t *testing.T) {
			originalOpen, originalSync := fastFileDirOpen, fastFileDirSync
			t.Cleanup(func() {
				fastFileDirOpen, fastFileDirSync = originalOpen, originalSync
			})
			boom := errors.New("forced directory durability failure")
			if failure == "open" {
				fastFileDirOpen = func(string) (*os.File, error) { return nil, boom }
			} else {
				fastFileDirSync = func(*os.File) error { return boom }
			}
			var logs bytes.Buffer
			originalOutput, originalFlags := log.Writer(), log.Flags()
			log.SetOutput(&logs)
			log.SetFlags(0)
			t.Cleanup(func() {
				log.SetOutput(originalOutput)
				log.SetFlags(originalFlags)
			})

			path := filepath.Join(t.TempDir(), "list.fast")
			if err := WriteFastFile(path, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil); err != nil {
				t.Fatalf("post-rename durability failure must preserve the established success semantics: %v", err)
			}
			if _, err := ReadFastFile(path); err != nil {
				t.Fatalf("replacement artifact must remain readable: %v", err)
			}
			if !strings.Contains(logs.String(), "durability unconfirmed") {
				t.Fatalf("durability failure must be visible in logs: %q", logs.String())
			}
		})
	}
}
