package services

import (
	"bytes"
	"fmt"
	"net/netip"

	"lazy-balancer-v2/wafiplist"
)

// 统一编译器（唯一入口 CompileFromIplistFile）：
// 源条目（.iplist 文本行）→ CIDR 聚合 → 排序 → 序列化 .fast 二进制。
// 产出。@ipListFast 算子恒读渲染期 per-policy.txt 投影
// （iplistfile.go），不读 .fast；.fast 的真实消费方=本包从节点回退
// （securityiplists.go ReadFastFile——waf_files 通道只同步二进制的形态）。
//
// 编译发生在:
//   - 威胁库定时更新后（源=.iplist 文件）
//   - 集群同步收到 .iplist 后（从节点本地编译）
//   - 容器重启时（ApplyConfigOnStartup → 渲染 → 编译）

// iterIPListTextLines 遍历 .iplist 文本的有效条目行（空行与 #/; 注释行
// 跳过）——转发 wafiplist.ForEachIPListLine：行过滤口径跨模块单源（此前
// services 与 wafiplist 各持一份等价循环，前缀/空白归一规则演化时会静默
// 分叉）。本侧只保留「坏行由回调决定」的处置策略（严格报错的消费方在回调内
// 自行决定）；切分按 bytes.IndexByte 原地扫描，不复制整份文本、不生成
// []string 头数组，注释/空行零分配。fn 返回 false 提前终止。
func iterIPListTextLines(raw []byte, fn func(line string) bool) {
	wafiplist.ForEachIPListLine(raw, func(_ int, line string) bool { return fn(line) })
}

// CompileFromIplistFile 从 .iplist 纯文本源文件编译 .fast 二进制。
// 源文件格式：每行一个 IP/CIDR，# 或 ; 开头为注释，空行跳过。
// 非法行跳过并计数（WARN 语义——合法行正常编译，不因单行损坏全量失败）。
//
// 生产编译触发点（全仓 CompileFromIplistFile 调用面）：
//  1. 威胁库更新器——下载落盘/heal（threatupdate.go WriteThreatIplistCompiled 与 healThreatFastFromText）；
//  2. lbbak 导入（config_backup_lbbak.go，持 WafFileLock 调用）。
//
// 从节点不同步 .iplist 源文件（只同步 .fast，零编译裁定）；启动路径只渲染 .txt 投影，不触发编译。
func CompileFromIplistFile(iplistPath string) error {
	raw, err := readIplistTextBounded(iplistPath)
	if err != nil {
		return fmt.Errorf("读取 .iplist %s: %w", iplistPath, err)
	}
	// 逐条目只解析一次：解析产物直接进聚合，不再
	// 「校验解析一次 + AggregatePrefixes 再解析一次」。
	// 容量估算用换行计数（bytes.Count 零分配）并封顶（compilePrefixCapHint，
	// 对齐 wafiplist.prefixCapHint 口径）——注释/空行密集的文件不得把预分配
	// 放大到数十 MiB；超出部分由 append 几何增长补齐，不改变拒绝语义。
	prefixes := make([]netip.Prefix, 0, compilePrefixCapHint(bytes.Count(raw, []byte("\n"))))
	skipped := 0
	over := false
	iterIPListTextLines(raw, func(line string) bool {
		if len(prefixes)+skipped >= iplistTextMaxEntries {
			over = true
			return false
		}
		prefix, err := wafiplist.ParseIPEntry(line)
		if err != nil {
			skipped++
			return true
		}
		prefixes = append(prefixes, prefix)
		return true
	})
	if over {
		return fmt.Errorf("读取 .iplist %s: 条目数超过上限 %d", iplistPath, iplistTextMaxEntries)
	}
	if skipped > 0 {
		Logf("warn", "编译 %s: 跳过 %d 条非法行", iplistPath, skipped)
	}
	v4, v6 := splitV4V6(wafiplist.AggregateParsedPrefixes(prefixes))
	return wafiplist.WriteFastFile(wafiplist.FastPath(iplistPath), v4, v6)
}

// compilePrefixInitialCapacity 是编译侧预分配的条目上限（2^16 × 32B ≈ 2MiB，
// 与 wafiplist.initialPrefixCapacity 同量级）。
const compilePrefixInitialCapacity = 1 << 16

// compilePrefixCapHint 返回编译侧一次性预分配的条目容量：换行计数 +1（末行
// 无换行），再封顶 compilePrefixInitialCapacity。预分配只服务热路径常量因子，
// 注释/空行密集文件（带外写入/损坏残留）的超大预估由 append 几何增长补齐，
// 体积门与条目门仍先/后独立生效（不改变任何拒绝语义）。
func compilePrefixCapHint(newlines int) int {
	capHint := newlines + 1
	if capHint > compilePrefixInitialCapacity {
		capHint = compilePrefixInitialCapacity
	}
	return capHint
}

// CompileFromEntries/CompileFromPrefixes 已删除（新发现，用户
// 裁定删除）：两函数生产零消费方——注释声称的「自定义列表保存即时编译/
// 渲染层 per-policy 投影」场景不存在（保存路径从不即时编译，per-policy
// 投影是 .txt 文本形态不写 .fast）。

// splitV4V6 前缀按地址族分拣（曾双份同型循环的收敛产物；
// 自此由.fast 编译单点消费，等价于旧的 aggregateAndSplit 末段）。
func splitV4V6(prefixes []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range prefixes {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}
