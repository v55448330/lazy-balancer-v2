package caddyl4sec

import (
	"os"
	"path/filepath"
	"testing"
)

// 4in6（IPv4-mapped IPv6）字面量条目：装载时地址被 Unmap 成 4 字节，前缀位数必须
// 同步减 96。否则得到「v4 地址 + >32 位数」的非法前缀——它排在全部 v4 条目之后、
// 比较恒小，二分查找落空后让「起始地址最高的那条 v4 条目」永远不命中（单条 v4
// 名单时整份 v4 面失效）。投影文件的正常写者会把 4in6 归一成 v4 文本，这类条目
// 只能由手改 / 旧文件 / 带外写入产生；装载器必须自证不受其影响。
func ipFileCases(t *testing.T, lines string, cases []struct {
	ip   string
	want bool
}) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(file, []byte(lines), 0o640); err != nil {
		t.Fatal(err)
	}
	m := newIPFileMatcherForTest(t, file)
	for _, tc := range cases {
		got, err := ipFileMatch(t, m, tc.ip)
		if err != nil {
			t.Fatalf("Match(%q) unexpected error: %v", tc.ip, err)
		}
		if got != tc.want {
			t.Fatalf("Match(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestIPFileV4MappedPrefixDoesNotBreakV4Set(t *testing.T) {
	ipFileCases(t, "10.1.0.0/16\n10.2.0.0/16\n::ffff:10.9.0.0/120\n", []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},  // 回归形状：首条 v4 仍命中
		{"10.2.2.2", true},  // 目标形状：起始地址最高的 v4 条目不得被 4in6 行挤失效
		{"10.9.0.5", true},  // 4in6 前缀按本意归一成 10.9.0.0/24
		{"10.9.1.5", false}, // 归一后不越界
		{"2001:db8::1", false},
	})
}

func TestIPFileV4MappedBareAddressDoesNotBreakV4Set(t *testing.T) {
	ipFileCases(t, "10.1.0.0/16\n::ffff:10.9.0.5\n", []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true}, // 单条 v4 名单不得被一条 4in6 行挤成整份失效
		{"10.1.255.254", true},
		{"10.9.0.5", true}, // 裸 4in6 地址 = /128 → 归一成 /32
		{"10.9.0.6", false},
	})
}

func TestIPFileV4MappedEntryLeavesIPv6Unaffected(t *testing.T) {
	ipFileCases(t, "2001:db8::/48\n::ffff:10.9.0.5\n", []struct {
		ip   string
		want bool
	}{
		{"2001:db8::1", true},
		{"2001:db9::1", false},
		{"10.9.0.5", true},
	})
}
