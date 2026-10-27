package wafiplist

// 白名单路径边界门：`resolveAllowedPath` 的首道门必须是目录边界判定，而不是
// 裸字符串前缀。裸 HasPrefix 的正确性完全依赖 AllowedPathPrefix 恰好带尾
// 分隔符（包级 var，测试与未来装配方可改写）——一旦传入 `/app/waf`，同级的
// `/app/waf-other/x.iplist` 就会被当成白名单内路径。本文件把「两种前缀写法
// 语义一致」钉成断言，防止退回裸前缀形态。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// useAllowedPrefix 把白名单前缀设为 verbatim（不做任何补分隔符处理），
// 收尾复位。
func useAllowedPrefix(t *testing.T, prefix string) {
	t.Helper()
	old := AllowedPathPrefix
	AllowedPathPrefix = prefix
	t.Cleanup(func() { AllowedPathPrefix = old })
}

func TestResolveAllowedPathPrefixBoundaryIgnoresTrailingSeparator(t *testing.T) {
	dir := t.TempDir()
	siblingDir := dir + "-evil"
	if err := os.MkdirAll(siblingDir, 0o755); err != nil {
		t.Fatalf("mkdir sibling: %v", err)
	}
	insidePath := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(insidePath, []byte("10.0.0.1\n"), 0o644); err != nil {
		t.Fatalf("write inside list: %v", err)
	}
	outsidePath := filepath.Join(siblingDir, "allow.txt")
	if err := os.WriteFile(outsidePath, []byte("10.0.0.1\n"), 0o644); err != nil {
		t.Fatalf("write sibling list: %v", err)
	}
	// 尚不存在的同级文件：EvalSymlinks 失败 → 首道门是唯一判定点（symlink
	// 复检兜不住），这正是裸前缀会放行的形态。
	outsideMissing := filepath.Join(siblingDir, "not-yet-written.txt")

	for _, prefix := range []string{dir, dir + string(filepath.Separator)} {
		useAllowedPrefix(t, prefix)

		got, err := resolveAllowedPath(insidePath)
		if err != nil {
			t.Fatalf("prefix=%q 时白名单内路径被拒: %v", prefix, err)
		}
		if got != filepath.Clean(insidePath) {
			t.Fatalf("prefix=%q 归一结果 %q，want %q", prefix, got, filepath.Clean(insidePath))
		}

		if _, err := resolveAllowedPath(outsideMissing); err == nil {
			t.Fatalf("prefix=%q 时同级前缀目录下未创建的路径被放行（首道门不是目录边界判定）", prefix)
		}
		if _, err := resolveAllowedPath(outsidePath); err == nil {
			t.Fatalf("prefix=%q 时同级前缀目录 %q 被当作白名单内路径（边界判定退化为裸字符串前缀）", prefix, siblingDir)
		}
		if _, err := NormalizeAllowedPath(outsidePath); err == nil {
			t.Fatalf("prefix=%q 时导出入口 NormalizeAllowedPath 未拒绝同级前缀路径", prefix)
		}
	}
}

// 反向形状：前缀既非绝对路径也不带尾分隔符时，绝对路径仍按边界判定。
func TestResolveAllowedPathRejectsNonAbsoluteAndDotDot(t *testing.T) {
	dir := t.TempDir()
	useAllowedPrefix(t, dir)

	if _, err := resolveAllowedPath("relative/allow.txt"); err == nil {
		t.Fatal("相对路径必须被拒")
	}
	escape := filepath.Join(dir, "..", "outside.txt")
	if _, err := resolveAllowedPath(escape); err == nil {
		t.Fatalf("Clean 后越出白名单的路径必须被拒: %q", escape)
	}
}

// 守卫：默认前缀带尾分隔符（历史形态），两条入口共用同一判定。
func TestDefaultAllowedPathPrefixShape(t *testing.T) {
	if !strings.HasPrefix(AllowedPathPrefix, "/") {
		t.Fatalf("默认白名单前缀必须是绝对路径，got %q", AllowedPathPrefix)
	}
	if !strings.HasSuffix(AllowedPathPrefix, string(filepath.Separator)) {
		t.Fatalf("默认白名单前缀应以目录分隔符结尾（目录语义），got %q", AllowedPathPrefix)
	}
}
