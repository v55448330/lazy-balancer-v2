package services

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"lazy-balancer-v2/wafiplist"
)

// 统一编译器（唯一入口 CompileFromIplistFile）：
// 源条目（.iplist 文本行）→ CIDR 聚合 → 排序 → 序列化 .fast 二进制。
// 产出。PLUG-D1（第 69 轮）：@ipListFast 算子恒读渲染期 per-policy .txt 投影
// （iplistfile.go），不读 .fast；.fast 的真实消费方=本包从节点回退
// （securityiplists.go ReadFastFile——waf_files 通道只同步二进制的形态）。
//
// 编译发生在:
//   - 威胁库定时更新后（源=.iplist 文件）
//   - 集群同步收到 .iplist 后（从节点本地编译）
//   - 容器重启时（ApplyConfigOnStartup → 渲染 → 编译）

// CompileFromIplistFile 从 .iplist 纯文本源文件编译 .fast 二进制。
// 源文件格式：每行一个 IP/CIDR，# 或 ; 开头为注释，空行跳过。
// 非法行跳过并计数（WARN 语义——合法行正常编译，不因单行损坏全量失败）。
func CompileFromIplistFile(iplistPath string) error {
	raw, err := os.ReadFile(iplistPath)
	if err != nil {
		return fmt.Errorf("读取 .iplist %s: %w", iplistPath, err)
	}
	lines := strings.Split(string(raw), "\n")
	entries := make([]string, 0, len(lines))
	skipped := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if _, err := wafiplist.ParseIPEntry(line); err != nil {
			skipped++
			continue
		}
		entries = append(entries, line)
	}
	if skipped > 0 {
		Logf("warn", "编译 %s: 跳过 %d 条非法行", iplistPath, skipped)
	}
	v4, v6 := aggregateAndSplit(entries)
	return wafiplist.WriteFastFile(wafiplist.FastPath(iplistPath), v4, v6)
}

// CompileFromEntries/CompileFromPrefixes 已删除（第 69 轮修复期新发现，用户
// 裁定删除）：两函数生产零消费方——注释声称的「自定义列表保存即时编译/
// 渲染层 per-policy 投影」场景不存在（保存路径从不即时编译，per-policy
// 投影是 .txt 文本形态不写 .fast）。

// splitV4V6 前缀按地址族分拣（LBS-B-R2，第 69 轮：曾双份同型循环的收敛产物，
// CompileFromPrefixes 删除后由 aggregateAndSplit 单点消费）。
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

// aggregateAndSplit: 条目字符串列表 → CIDR 聚合+排序 → v4/v6 分离
func aggregateAndSplit(entries []string) ([]netip.Prefix, []netip.Prefix) {
	return splitV4V6(wafiplist.AggregatePrefixes(entries))
}
