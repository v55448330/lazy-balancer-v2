package wafiplist

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// fastFileMagic 是 .fast 二进制格式的魔数（Lazy Balancer Fast v1）。
const fastFileMagic = "LBF1"

// fastFileHeaderSize 是 .fast 文件头固定长度。
const fastFileHeaderSize = 16

// fastFileChecksumFlag 是 header flags 的「尾部带 crc32c 校验和」位。
// 格式演进规则：该位置 1 表示文件末尾追加 4 字节 big-endian crc32c
// （Castagnoli，覆盖 header+条目区）；flags==0 是早期无校验形态，读侧兼容
// 接受（跨版本回滚期旧产物仍可加载）；其余未知位一律拒绝。写侧总是置位。
const fastFileChecksumFlag = 1 << 0

// fastFileCRCTable 是 crc32c（Castagnoli）查表（包级共享，只读）。
var fastFileCRCTable = crc32.MakeTable(crc32.Castagnoli)

// 目录同步缝仅用于故障注入；生产语义仍是 rename 后尽力同步并显性告警。
var (
	fastFileDirOpen = os.Open
	fastFileDirSync = func(dir *os.File) error { return dir.Sync() }
)

// maxFastFileBytes 是 ReadFastFile 读取前的体积硬上限（历史
// 审计）：.fast 是跨进程输入（节点回传/从节点回退），不能只依赖写侧自律——
// 异常/恶意超大文件必须先过 Stat 体积门，再进入读取与内容校验。与文本名单
// 路径的 maxFileBytes（iplistfast.go）同型；二进制条目 5B/v4、17B/v6，
// 64MiB 约容纳千万级条目，远超威胁库下载侧 200000 条上限，正常产物远不可及。
// 包内可调（仅同包测试收窄），不构成跨模块契约。
var maxFastFileBytes int64 = 64 << 20

// maxFastEntries 是读侧条目数（v4Count+v6Count）硬上限。体积门挡不住
// 「条目数 × 内存放大」：最小 v4 条目 5 字节，64MiB 文件可承载约 1342 万条，
// 展开为 netip.Prefix（每条约 32 字节）即约 410MiB，叠加 data 与消费方
// []string 展开可达 GiB 量级。百万条已远超威胁库下载侧 200000 条上限，与
// 文本名单 maxEntries 同值口径（纵深防御的第二道，第一道是体积）。包内可调
// （仅同包测试收窄），不构成跨模块契约。
var maxFastEntries = 1_000_000

// FastFileState 是从 .fast 二进制文件加载的内存态（排序不相交前缀集）。
// 生产消费方=services 侧从节点回退（securityiplists.go ReadFastFile）。
type FastFileState struct {
	V4 []netip.Prefix // 排序不相交 IPv4 前缀
	V6 []netip.Prefix // 排序不相交 IPv6 前缀
}

// WriteFastFile 将前缀集序列化为 .fast 二进制格式并原子写入。
// 输入应已聚合为不相交集合；为守住二分查询契约，本函数在**内部副本**上
// 防御性掩码主机位并排序，并在写入前断言「升序 + 互不相交」——嵌套/同址
// 输入返回 error 而非写出「写成功、读必失败」的产物（ReadFastFile 对同形态
// 一律拒绝；跨进程回退侧会拿到不可用名单）。本函数不聚合/不去重。
// 调用方切片的内容与顺序都不被改写。
//
// 族校验：v4 切片只接受纯 IPv4 前缀，v6 切片只接受纯 IPv6 前缀
// （4in6 映射形态须先 Unmap 归 v4）。族错配返回 error 而不是 panic/静默腐化
// ——As4 对 v6 入参 panic；As16 对 v4 会写出「4-in-6 地址 + v4 bits」的
// 可加载但永不命中形态。主机位未掩码的条目（如 1.2.3.200/24）会让二分查询
// 用未掩码地址比较而假阴性——写侧必须先掩码；读侧亦对每项校验 p==p.Masked()
// （.fast 是跨进程输入，不单靠写侧自律）。
//
// 原子写用独占临时名（CreateTemp）：固定 path+".tmp" 在并发/多调用
// 方下互相覆盖（rename ENOENT 或旧代际覆盖新代际）。本函数自身不持锁，
// 生产调用方仍须持 wafFileMu 串行化代际。写入前顺带回收本文件超龄的
// 崩溃残留临时文件（sweepStaleFastTemps）。
func WriteFastFile(path string, v4, v6 []netip.Prefix) error {
	for _, p := range v4 {
		if !p.IsValid() || !p.Addr().Is4() {
			return fmt.Errorf("fastfile: v4 条目 %v 不是纯 IPv4 前缀（族错配）", p)
		}
	}
	for _, p := range v6 {
		if !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() {
			return fmt.Errorf("fastfile: v6 条目 %v 不是纯 IPv6 前缀（族错配/无效）", p)
		}
	}
	// 掩码 + 排序都在副本上做：掩码会改变地址（进而改变正确排序次序），
	// 直接原地改调用方切片会静默改写其数据。
	mv4 := make([]netip.Prefix, len(v4))
	for i, p := range v4 {
		mv4[i] = p.Masked()
	}
	mv6 := make([]netip.Prefix, len(v6))
	for i, p := range v6 {
		mv6[i] = p.Masked()
	}
	sort.Slice(mv4, func(i, j int) bool { return mv4[i].Addr().Compare(mv4[j].Addr()) < 0 })
	sort.Slice(mv6, func(i, j int) bool { return mv6[i].Addr().Compare(mv6[j].Addr()) < 0 })
	// 读侧不变量在写侧自证：排序后若某前缀包含更晚前缀，必包含其直接后继
	// （地址介于两者之间的条目只能是这个后继）——相邻 O(n) 断言即可覆盖
	// 全部嵌套/同址形态。
	if err := assertDisjointPrefixes("v4", mv4); err != nil {
		return err
	}
	if err := assertDisjointPrefixes("v6", mv6); err != nil {
		return err
	}

	// 读侧上限在写侧自证：产物越过条目数或体积上限时 ReadFastFile 必然
	// 拒收，写出去只会得到「写成功、读失败」的名单——跨进程回退侧拿不到
	// 可用数据，且失败点远离真实原因。宁可写侧显式报错且不落盘。
	if total := len(mv4) + len(mv6); total > maxFastEntries {
		return fmt.Errorf("fastfile: 条目数 %d 超过读侧上限 %d（产物必被 ReadFastFile 拒收，未写出）", total, maxFastEntries)
	}
	// 计算总大小（header + 条目 + 4 字节 crc32c 尾部）
	size := fastFileHeaderSize + len(mv4)*5 + len(mv6)*17 + 4
	if int64(size) > maxFastFileBytes {
		return fmt.Errorf("fastfile: 产物体积 %d 字节超过读侧上限 %d（产物必被 ReadFastFile 拒收，未写出）", size, maxFastFileBytes)
	}
	buf := make([]byte, size)

	// Header
	copy(buf[0:4], fastFileMagic)
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(mv4)))
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(mv6)))
	binary.BigEndian.PutUint32(buf[12:16], fastFileChecksumFlag)

	// v4 entries: [4B addr][1B bits]
	offset := fastFileHeaderSize
	for _, p := range mv4 {
		addr := p.Addr().As4()
		copy(buf[offset:offset+4], addr[:])
		buf[offset+4] = byte(p.Bits())
		offset += 5
	}

	// v6 entries: [16B addr][1B bits]
	for _, p := range mv6 {
		addr := p.Addr().As16()
		copy(buf[offset:offset+16], addr[:])
		buf[offset+16] = byte(p.Bits())
		offset += 17
	}

	// 尾部 crc32c（覆盖 header+条目区）：格式内校验使「位翻转但仍满足
	// 掩码/升序/不相交」的静默漏拦/误拦可验证——.fast 是跨进程输入。
	binary.BigEndian.PutUint32(buf[offset:offset+4], crc32.Checksum(buf[:offset], fastFileCRCTable))

	// 原子写（与 @ipListFast 投影同模式）：独占临时名 + rename。
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("fastfile mkdir: %w", err)
	}
	sweepStaleFastTemps(filepath.Dir(path), filepath.Base(path))
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("fastfile tmp create: %w", err)
	}
	tmpName := tmp.Name()
	discard := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(buf); err != nil {
		discard()
		return fmt.Errorf("fastfile tmp write: %w", err)
	}
	// CreateTemp 建 0600，正式文件沿用既有 0644（跨进程可读）。
	if err := tmp.Chmod(0o644); err != nil {
		discard()
		return fmt.Errorf("fastfile tmp chmod: %w", err)
	}
	// Sync 语义：写侧是「独占临时名写满 + fsync + rename」，正常路径不会
	// 产生空/半截 .fast 产物（rename 前失败只留可回收的 .tmp）。即便产物在
	// 极端掉电窗口内损坏，唯一生产读点 ReadFastFile 会以 magic/flags/尺寸/
	// CRC 拒绝；消费方（services 侧名单加载）在文本名单在场时回退文本、
	// 否则显式报错——不存在 fail-open 的空集装载。
	if err := tmp.Sync(); err != nil {
		discard()
		return fmt.Errorf("fastfile tmp sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("fastfile tmp close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("fastfile rename: %w", err)
	}
	if dir, derr := fastFileDirOpen(filepath.Dir(path)); derr == nil {
		if serr := fastFileDirSync(dir); serr != nil {
			// Ruling（与 internal/atomicfile 互相对照）：rename 已生效，新 .fast
			// 可见且内容完整（写侧 fsync 已完成），目录 fsync 失败只影响「掉电后
			// rename 本身是否持久」。atomicfile 的簿记文件选择上抛 error 让调用方
			// 补偿；本路径若返回 error 会让 ipcompile 记「编译失败」并按失败回退，
			// 与磁盘已替换的状态不一致，故选择告警并返回 nil。
			log.Printf("WARNING: fastfile dir sync after rename %q failed (artifact replaced, durability unconfirmed): %v", path, serr)
		}
		_ = dir.Close()
	} else {
		// 与上分支口径一致：目录打不开同样意味着 durability 未确认，不得
		// 静默（旧实现只对 Sync 失败返回 error、对 Open 失败完全静默）。
		log.Printf("WARNING: fastfile dir open for sync %q failed (durability unconfirmed): %v", path, derr)
	}
	return nil
}

// ReadFastFile 读取 .fast 二进制文件并展开为内存前缀集。
// 加载成本 O(n) 纯内存拷贝——无文本解析、无排序（20 万条 ~0.2ms）。
//
// 读侧与文本名单（iplistfast.go parseIPListFile）同口径的三道门：
//  1. 前置体积门（fd.Stat）：超限文件不进入内存；
//  2. 定长读：容量=stat 尺寸，不按内容放大——stat 与读取之间的窗口内
//     路径可被 tmp+rename 换成任意大小文件，只按 stat 判限不构成硬上限；
//  3. 读后复核同一 inode（size,mtime）：原位追加/截断/同尺寸改写会读到
//     半代内容，本次放弃而非把混合字节当合法名单。
func ReadFastFile(path string) (*FastFileState, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("fastfile open: %w", err)
	}
	defer fd.Close()
	info, err := fd.Stat()
	if err != nil {
		return nil, fmt.Errorf("fastfile stat: %w", err)
	}
	if info.Size() > maxFastFileBytes {
		return nil, fmt.Errorf("fastfile: size %d exceeds cap %d", info.Size(), maxFastFileBytes)
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(fd, data); err != nil {
		return nil, fmt.Errorf("fastfile read: %w", err)
	}
	if after, statErr := fd.Stat(); ipListGenerationChanged(info, after, statErr) {
		return nil, fmt.Errorf("fastfile: %q rewritten during read", path)
	}
	if len(data) < fastFileHeaderSize {
		return nil, fmt.Errorf("fastfile: too short (%d bytes)", len(data))
	}
	if string(data[0:4]) != fastFileMagic {
		return nil, fmt.Errorf("fastfile: bad magic %q", string(data[0:4]))
	}
	v4Count := binary.BigEndian.Uint32(data[4:8])
	v6Count := binary.BigEndian.Uint32(data[8:12])
	// 条目上限先于任何按计数分配的 make：header 计数是跨进程输入，
	// 体积门内的小文件同样可以声明巨大计数。
	if total := int64(v4Count) + int64(v6Count); total > int64(maxFastEntries) {
		return nil, fmt.Errorf("fastfile: entry count %d exceeds cap %d", total, maxFastEntries)
	}
	// 未知 flags 位不得静默忽略（格式演进必须显式：未来的特性位
	// 若被当 0 解析，会按错误的条目布局读数据）。已知位：bit0=尾部 crc32c。
	flags := binary.BigEndian.Uint32(data[12:16])
	if flags & ^uint32(fastFileChecksumFlag) != 0 {
		return nil, fmt.Errorf("fastfile: unknown flags %#x", flags)
	}
	hasChecksum := flags&fastFileChecksumFlag != 0

	expectedSize := fastFileHeaderSize + int(v4Count)*5 + int(v6Count)*17
	if hasChecksum {
		expectedSize += 4
	}
	if len(data) != expectedSize {
		return nil, fmt.Errorf("fastfile: size mismatch (have %d, want %d)", len(data), expectedSize)
	}
	// 内容完整性：位翻转若仍满足 magic/count/bits/掩码/升序/不相交不变量
	// （如某段地址高位跳变但不越邻），旧读侧会静默接受并改变实际拦截集合。
	// flags==0 的早期产物无校验和，按旧行为接受（跨版本回滚兼容）。
	if hasChecksum {
		want := binary.BigEndian.Uint32(data[len(data)-4:])
		if got := crc32.Checksum(data[:len(data)-4], fastFileCRCTable); got != want {
			return nil, fmt.Errorf("fastfile: checksum mismatch (have %08x, want %08x)", got, want)
		}
	}

	state := &FastFileState{
		V4: make([]netip.Prefix, v4Count),
		V6: make([]netip.Prefix, v6Count),
	}

	// 腐化防御——bits 越界（netip.PrefixFrom 产 invalid
	// 前缀）与地址降序都会静默破坏二分判定的排序不变量，响亮拒绝。
	// 展开 v4
	offset := fastFileHeaderSize
	for i := 0; i < int(v4Count); i++ {
		var addr [4]byte
		copy(addr[:], data[offset:offset+4])
		bits := int(data[offset+4])
		if bits > 32 {
			return nil, fmt.Errorf("fastfile: v4 entry %d bits out of range: %d", i, bits)
		}
		state.V4[i] = netip.PrefixFrom(netip.AddrFrom4(addr), bits)
		// 主机位必须已掩码——与写侧同一不变量。未掩码条目
		// （1.2.3.200/24）地址升序/不相交校验都可能通过，但二分查询用
		// 未掩码地址比较会假阴性（威胁名单静默漏拦）。读侧是跨进程输入
		// （节点回传的 .fast），不能只依赖写侧自律。
		if state.V4[i] != state.V4[i].Masked() {
			return nil, fmt.Errorf("fastfile: v4 entry %d host bits not masked: %s", i, state.V4[i])
		}
		if i > 0 && state.V4[i-1].Addr().Compare(state.V4[i].Addr()) > 0 {
			return nil, fmt.Errorf("fastfile: v4 entries not in ascending order at %d", i)
		}
		// 嵌套/同址不同 bits（升序合法却互相包含）会被
		// 窄段遮蔽产生二分假阴性——「可加载但查询错误」的最坏静默腐化形态，
		// 响亮拒绝。
		if i > 0 && state.V4[i-1].Contains(state.V4[i].Addr()) {
			return nil, fmt.Errorf("fastfile: v4 entries not disjoint at %d (%s contains %s)", i, state.V4[i-1], state.V4[i])
		}
		offset += 5
	}

	// 展开 v6（同口径校验）
	for i := 0; i < int(v6Count); i++ {
		var addr [16]byte
		copy(addr[:], data[offset:offset+16])
		bits := int(data[offset+16])
		if bits > 128 {
			return nil, fmt.Errorf("fastfile: v6 entry %d bits out of range: %d", i, bits)
		}
		entryAddr := netip.AddrFrom16(addr)
		// 族校验与写侧同口径：v6 段只接受纯 IPv6。4-in-6 映射地址
		// （::ffff:1.2.3.4）在 16 字节布局里完全合法，bits/掩码/升序/不相交
		// 也都能通过，却是「可加载但永不命中」的静默漏拦形态（v4 段不含它，
		// 纯 v6 查询也不匹配它）。读侧是跨进程输入，不能只依赖写侧自律。
		if entryAddr.Is4In6() {
			return nil, fmt.Errorf("fastfile: v6 entry %d is a 4-in-6 mapped address: %s", i, entryAddr)
		}
		state.V6[i] = netip.PrefixFrom(entryAddr, bits)
		// v6 同口径——主机位未掩码即拒。
		if state.V6[i] != state.V6[i].Masked() {
			return nil, fmt.Errorf("fastfile: v6 entry %d host bits not masked: %s", i, state.V6[i])
		}
		if i > 0 && state.V6[i-1].Addr().Compare(state.V6[i].Addr()) > 0 {
			return nil, fmt.Errorf("fastfile: v6 entries not in ascending order at %d", i)
		}
		// v6 同口径——互相包含即拒。
		if i > 0 && state.V6[i-1].Contains(state.V6[i].Addr()) {
			return nil, fmt.Errorf("fastfile: v6 entries not disjoint at %d (%s contains %s)", i, state.V6[i-1], state.V6[i])
		}
		offset += 17
	}

	return state, nil
}

// FastPath 返回 .iplist 源文件对应的 .fast 编译文件路径。
func FastPath(iplistPath string) string {
	return iplistPath + ".fast"
}

// assertDisjointPrefixes 断言已排序前缀集「地址不降序且互不包含」——与
// ReadFastFile 的加载不变量同口径（二分查询正确性依赖不相交）。
func assertDisjointPrefixes(family string, sorted []netip.Prefix) error {
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1].Contains(sorted[i].Addr()) {
			return fmt.Errorf("fastfile: %s entries not disjoint at %d (%s contains %s)", family, i, sorted[i-1], sorted[i])
		}
	}
	return nil
}

// fastFileTempMaxAge 是 .fast 临时残留的回收门槛：CreateTemp 与 rename 之间
// 崩溃/掉电会留下 <base>.<rand>.tmp；waf 目录没有 IP 名单目录的 tmp GC 分支，
// 长期运行实例会随历史名单积累。门槛远大于任何一次写入耗时，在役临时文件
// 不会被误删。
const fastFileTempMaxAge = time.Hour

// sweepStaleFastTemps 回收本文件名前缀的超龄临时残留（仅本 base，避免误删
// 并发写入其他名单的临时文件；os.ReadDir 失败静默——回收是尽力而为，
// 不得影响写入主流程）。
func sweepStaleFastTemps(dir, base string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	deadline := time.Now().Add(-fastFileTempMaxAge)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, base+".") || !strings.HasSuffix(name, ".tmp") {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil || info.ModTime().After(deadline) {
			continue
		}
		_ = os.Remove(filepath.Join(dir, name))
	}
}
