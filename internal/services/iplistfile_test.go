package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/wafiplist"
)

// TestMain：全包共享一个临时 IP 名单目录——@ipListFast 渲染改造后，凡含
// IP 名单的策略渲染都会经 writeIPListFile 落盘（fail-closed：写失败=渲染
// 报错）；默认 /app/waf/ip-lists 在开发机不可写，统一改指临时目录并把
// 算子白名单前缀对齐（算子构建期会真实读文件）。
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "lb-iplists-test")
	if err != nil {
		panic(err)
	}
	IPListDataDir = dir
	wafiplist.AllowedPathPrefix = dir + string(filepath.Separator)
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// readRenderedIPList 从渲染产物中抽取含 scopeMarker 的 @ipListFast 文件名
// 并读回文件内容——形状断言（id/动作/链结构）之外的名单内容断言入口，
// 取代旧内联 @ipMatch 的文本钉。
func readRenderedIPList(t *testing.T, directives, scopeMarker string) string {
	t.Helper()
	for _, line := range strings.Split(directives, "\n") {
		idx := strings.Index(line, "@ipListFast ")
		if idx < 0 || !strings.Contains(line, scopeMarker) {
			continue
		}
		rest := line[idx+len("@ipListFast "):]
		end := strings.IndexAny(rest, "\" \t")
		if end < 0 {
			end = len(rest)
		}
		content, err := os.ReadFile(rest[:end])
		if err != nil {
			t.Fatalf("读回渲染名单文件失败: %v", err)
		}
		return string(content)
	}
	t.Fatalf("渲染产物中未找到 scope=%s 的 @ipListFast 规则:\n%s", scopeMarker, directives)
	return ""
}

// writeIPListFile（v2.3.x）：内容寻址文件名（scope-sha256[:12]）、聚合后落盘、
// 原子写（tmp+rename）、幂等（同内容重复写返回同路径不产生第二份）、
// 空集合不写文件返回空串。
func TestWriteIPListFile_contentAddressedAtomic(t *testing.T) {
	// Given
	entries := []string{"10.0.0.128/25", "10.0.0.0/25", "203.0.113.7", "203.0.113.7"}

	// When
	path1, err := writeIPListFile("u-bl", entries)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Then：文件名 scope-哈希 形态，内容聚合（兄弟归并 10.0.0.0/24 + 归一 /32）
	base := filepath.Base(path1)
	if !strings.HasPrefix(base, "u-bl-") || !strings.HasSuffix(base, ".txt") {
		t.Fatalf("文件名 %q 不符 scope-hash.txt 形态", base)
	}
	content, err := os.ReadFile(path1)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "10.0.0.0/24\n203.0.113.7/32\n" {
		t.Fatalf("文件内容=%q, want 聚合排序形态", content)
	}
	// 幂等：同内容同路径
	path2, err := writeIPListFile("u-bl", entries)
	if err != nil || path2 != path1 {
		t.Fatalf("幂等写 path=%q err=%v, want %q", path2, err, path1)
	}
	// 原子写：无 .tmp 残留
	if leftovers, _ := filepath.Glob(filepath.Join(IPListDataDir, "*.tmp")); len(leftovers) > 0 {
		t.Fatalf("tmp 残留: %v", leftovers)
	}
	// 不同 scope 同内容 → 不同文件
	path3, err := writeIPListFile("p1-trust", entries)
	if err != nil || path3 == path1 || !strings.Contains(filepath.Base(path3), "p1-trust-") {
		t.Fatalf("scope 隔离失败: %q vs %q", path3, path1)
	}
}

func TestWriteIPListFile_emptyWritesNothing(t *testing.T) {
	path, err := writeIPListFile("u-empty", nil)
	if err != nil || path != "" {
		t.Fatalf("空集合 path=%q err=%v, want 空串不写文件", path, err)
	}
}
