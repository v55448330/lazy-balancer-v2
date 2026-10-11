package wafiplist

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
)

// fastFileMagic 是 .fast 二进制格式的魔数（Lazy Balancer Fast v1）。
const fastFileMagic = "LBF1"

// fastFileHeaderSize 是 .fast 文件头固定长度。
const fastFileHeaderSize = 16

// FastFileState 是从 .fast 二进制文件加载的内存态（排序不相交前缀集）。
// 生产消费方=services 侧从节点回退（securityiplists.go ReadFastFile）。
type FastFileState struct {
	V4 []netip.Prefix // 排序不相交 IPv4 前缀
	V6 []netip.Prefix // 排序不相交 IPv6 前缀
}

// WriteFastFile 将排序前缀集序列化为 .fast 二进制格式并原子写入。
// 输入必须已排序且不相交（CIDR 聚合后）——本函数不做排序/聚合。
func WriteFastFile(path string, v4, v6 []netip.Prefix) error {
	// 防御性排序：.fast 的二分查询契约要求升序不相交。调用方（生产路径
	// AggregatePrefixes）已排序，此处兜底防静默损坏——乱序输入会产出
	// 「可加载但查询错误」的文件，是最坏形态的静默腐化。已序输入的排序
	// 开销近似线性。
	sort.Slice(v4, func(i, j int) bool { return v4[i].Addr().Compare(v4[j].Addr()) < 0 })
	sort.Slice(v6, func(i, j int) bool { return v6[i].Addr().Compare(v6[j].Addr()) < 0 })
	// 计算总大小
	size := fastFileHeaderSize + len(v4)*5 + len(v6)*17
	buf := make([]byte, size)

	// Header
	copy(buf[0:4], fastFileMagic)
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(v4)))
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(v6)))
	binary.BigEndian.PutUint32(buf[12:16], 0) // flags reserved

	// v4 entries: [4B addr][1B bits]
	offset := fastFileHeaderSize
	for _, p := range v4 {
		addr := p.Addr().As4()
		copy(buf[offset:offset+4], addr[:])
		buf[offset+4] = byte(p.Bits())
		offset += 5
	}

	// v6 entries: [16B addr][1B bits]
	for _, p := range v6 {
		addr := p.Addr().As16()
		copy(buf[offset:offset+16], addr[:])
		buf[offset+16] = byte(p.Bits())
		offset += 17
	}

	// 原子写（与 @ipListFast 投影同模式）
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("fastfile mkdir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0644); err != nil {
		return fmt.Errorf("fastfile tmp write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("fastfile rename: %w", err)
	}
	return nil
}

// ReadFastFile 读取 .fast 二进制文件并展开为内存前缀集。
// 加载成本 O(n) 纯内存拷贝——无文本解析、无排序（20 万条 ~0.2ms）。
func ReadFastFile(path string) (*FastFileState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fastfile read: %w", err)
	}
	if len(data) < fastFileHeaderSize {
		return nil, fmt.Errorf("fastfile: too short (%d bytes)", len(data))
	}
	if string(data[0:4]) != fastFileMagic {
		return nil, fmt.Errorf("fastfile: bad magic %q", string(data[0:4]))
	}
	v4Count := binary.BigEndian.Uint32(data[4:8])
	v6Count := binary.BigEndian.Uint32(data[8:12])

	expectedSize := fastFileHeaderSize + int(v4Count)*5 + int(v6Count)*17
	if len(data) < expectedSize {
		return nil, fmt.Errorf("fastfile: truncated (have %d, want %d)", len(data), expectedSize)
	}

	state := &FastFileState{
		V4: make([]netip.Prefix, v4Count),
		V6: make([]netip.Prefix, v6Count),
	}

	// PLUG-L1（第 69 轮 P2）：腐化防御——bits 越界（netip.PrefixFrom 产 invalid
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
		if i > 0 && state.V4[i-1].Addr().Compare(state.V4[i].Addr()) > 0 {
			return nil, fmt.Errorf("fastfile: v4 entries not in ascending order at %d", i)
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
		state.V6[i] = netip.PrefixFrom(netip.AddrFrom16(addr), bits)
		if i > 0 && state.V6[i-1].Addr().Compare(state.V6[i].Addr()) > 0 {
			return nil, fmt.Errorf("fastfile: v6 entries not in ascending order at %d", i)
		}
		offset += 17
	}

	return state, nil
}

// FastPath 返回 .iplist 源文件对应的 .fast 编译文件路径。
func FastPath(iplistPath string) string {
	return iplistPath + ".fast"
}
