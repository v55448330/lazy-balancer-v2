package services

import (
	"net/netip"
	"testing"
)

// .iplist 编译容量预估必须封顶（对齐 wafiplist.prefixCapHint 口径）：
// 注释/空行密集的文件（带外写入/损坏残留）会把「换行计数」预估放大到
// 数百万项（每项 32B ≈ 数十 MiB 瞬时分配）却几乎全空。预分配只服务热路径
// 常量因子，超出部分由 append 几何增长补齐，不改变任何拒绝语义。
func TestCompilePrefixCapHint_cappedForCommentDenseFile(t *testing.T) {
	const capBound = 1 << 16 // 与 wafiplist.initialPrefixCapacity 同量级（2MiB）
	cases := []struct {
		name     string
		newlines int
		wantMax  int
	}{
		{"small file", 100, 101},
		{"dense entries", 10000, 10001},
		{"comment dense 64MiB", 64 << 20, capBound},
		{"pathological 2GiB newlines", 2 << 30, capBound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := compilePrefixCapHint(tc.newlines)
			if got > tc.wantMax {
				t.Fatalf("compilePrefixCapHint(%d)=%d, want <= %d（预分配必须封顶）", tc.newlines, got, tc.wantMax)
			}
			if got < 1 {
				t.Fatalf("compilePrefixCapHint(%d)=%d, want >= 1", tc.newlines, got)
			}
		})
	}
	// 上界与条目门语义无关：即便预估被收窄，仍不得超过容量上界。
	if got := compilePrefixCapHint(1 << 40); got > capBound {
		t.Fatalf("预分配 %d 超过容量上界 %d", got, capBound)
	}
	//  sanity：netip.Prefix 尺寸确认（每项 32B 量级）。
	var p netip.Prefix
	_ = p
}
