package wafiplist

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// 基准：@ipListFast 二分判定（5000 条名单，命中/未命中各一）——回归锚点
// （对照组：等价集合的暴力线性扫描）。
func benchmarkSetup(b *testing.B, n int) (plugintypes.Operator, []string) {
	b.Helper()
	dir := b.TempDir()
	old := AllowedPathPrefix
	AllowedPathPrefix = dir + string(filepath.Separator)
	oldInterval := StatCheckInterval
	StatCheckInterval = 0
	b.Cleanup(func() { AllowedPathPrefix = old; StatCheckInterval = oldInterval })
	entries := make([]string, 0, n)
	for i := range n {
		entries = append(entries, fmt.Sprintf("%d.%d.%d.%d", 1+(i%220), (i*53)%256, (i*97)%256, (i*13)%250+1))
	}
	path := filepath.Join(dir, "bench.txt")
	if err := os.WriteFile(path, []byte(strings.Join(entries, "\n")+"\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	op, err := newIPListFast(plugintypes.OperatorOptions{Arguments: path})
	if err != nil {
		b.Fatal(err)
	}
	return op, entries
}

func BenchmarkIPListFast_5000_miss(b *testing.B) {
	op, _ := benchmarkSetup(b, 5000)
	b.ReportAllocs()
	for b.Loop() {
		op.Evaluate(nil, "240.1.2.3")
	}
}

func BenchmarkIPListFast_5000_hit(b *testing.B) {
	op, entries := benchmarkSetup(b, 5000)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		op.Evaluate(nil, entries[i%len(entries)])
		i++
	}
}

// BenchmarkIPListFast_5000_throttled 生产形态：StatCheckInterval=1s 节流后
// 的纯判定热路径（无 stat syscall）。
func BenchmarkIPListFast_5000_throttled(b *testing.B) {
	op, _ := benchmarkSetup(b, 5000)
	StatCheckInterval = 0 // benchmarkSetup 已置 0；此处显式语义注释
	// 预热一次后拨回节流——后续 Evaluate 走缓存直读
	op.Evaluate(nil, "240.1.2.3")
	StatCheckInterval = time.Hour
	b.Cleanup(func() { StatCheckInterval = 0 })
	b.ReportAllocs()
	for b.Loop() {
		op.Evaluate(nil, "240.1.2.3")
	}
}

// BenchmarkLinearScan_5000_miss 对照组：旧形态（[]net.IPNet 线性扫描）。
func BenchmarkLinearScan_5000_miss(b *testing.B) {
	_, entries := benchmarkSetup(b, 5000)
	prefixes := AggregatePrefixes(entries)
	b.ReportAllocs()
	for b.Loop() {
		needle := netip.MustParseAddr("240.1.2.3")
		for _, p := range prefixes {
			if p.Contains(needle) {
				break
			}
		}
	}
}

// —— 威胁库满量标尺（MaxEntries 的 1/5，真实上限形态）——
// benchmarkSetupLarge 构造 n 条混合名单（v4 CIDR + 裸 IP + v6），磁盘形态与
// 威胁库投影文件一致（聚合前原始条目）。
func benchmarkSetupLarge(b *testing.B, n int) (plugintypes.Operator, []string) {
	b.Helper()
	dir := b.TempDir()
	old := AllowedPathPrefix
	AllowedPathPrefix = dir + string(filepath.Separator)
	oldInterval := StatCheckInterval
	StatCheckInterval = 0
	b.Cleanup(func() { AllowedPathPrefix = old; StatCheckInterval = oldInterval })
	entries := make([]string, 0, n)
	for i := range n {
		switch i % 3 {
		case 0: // CIDR /24
			entries = append(entries, fmt.Sprintf("%d.%d.%d.0/24", 1+(i%220), (i*53)%256, (i*97)%256))
		case 1: // 裸 IP
			entries = append(entries, fmt.Sprintf("%d.%d.%d.%d", 1+(i%220), (i*53)%256, (i*97)%256, (i*13)%250+1))
		default: // v6
			entries = append(entries, fmt.Sprintf("2001:db8:%x::/48", i%0xffff))
		}
	}
	path := filepath.Join(dir, "bench-large.txt")
	if err := os.WriteFile(path, []byte(strings.Join(entries, "\n")+"\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	op, err := newIPListFast(plugintypes.OperatorOptions{Arguments: path})
	if err != nil {
		b.Fatal(err)
	}
	return op, entries
}

// BenchmarkIPListFast_200000_throttled 20 万条（威胁库下载上限形态）热路径：
// 节流后纯二分判定——生产每请求成本的上限锚点。
func BenchmarkIPListFast_200000_throttled(b *testing.B) {
	op, _ := benchmarkSetupLarge(b, 200000)
	op.Evaluate(nil, "240.1.2.3")
	StatCheckInterval = time.Hour
	b.Cleanup(func() { StatCheckInterval = 0 })
	b.ReportAllocs()
	for b.Loop() {
		op.Evaluate(nil, "240.1.2.3")
	}
}

// BenchmarkParseIPListFile_200000 20 万条全量解析+聚合（重载一次性成本）——
// 名单重建阻塞面的上限锚点（fail-stale 窗口内旧集合在役，不影响判定）。
func BenchmarkParseIPListFile_200000(b *testing.B) {
	dir := b.TempDir()
	entries := make([]string, 0, 200000)
	for i := range 200000 {
		entries = append(entries, fmt.Sprintf("%d.%d.%d.%d", 1+(i%220), (i*53)%256, (i*97)%256, (i*13)%250+1))
	}
	path := filepath.Join(dir, "bench-parse.txt")
	if err := os.WriteFile(path, []byte(strings.Join(entries, "\n")+"\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseIPListFile(path, info); err != nil {
			b.Fatal(err)
		}
	}
}
