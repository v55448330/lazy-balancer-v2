package mcpserver

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 白名单不得含死条目：标识符正则字符类不含 "="，"protocol=http" 永不匹配，
// 属旧 pattern 遗留——死条目会掩盖白名单腐化（新增项必须真实可命中）。
func TestPlaybookNonToolIdentifiers_noDeadEntries(t *testing.T) {
	for name := range playbookNonToolIdentifiers {
		if !playbookIdentifierPattern.MatchString("`" + name + "`") {
			t.Errorf("白名单项 %q 不可能被标识符正则命中（死条目）", name)
		}
	}
}

// goConstInt 从 Go 源码派生整型常量（跨包读 middleware 源码——限额常量未
// 导出，手抄字面量会在限额变更时静默漂移）。与 web/tests 的 goConstInt
// 同族范式：只认 const 声明的字面量值。
func goConstInt(t *testing.T, path, name string) int {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range valueSpec.Names {
				if ident.Name != name || i >= len(valueSpec.Values) {
					continue
				}
				literal, ok := valueSpec.Values[i].(*ast.BasicLit)
				if !ok || literal.Kind != token.INT {
					continue
				}
				value, err := strconv.Atoi(literal.Value)
				if err != nil {
					t.Fatalf("const %s 值不可解析: %v", name, err)
				}
				return value
			}
		}
	}
	t.Fatalf("未在 %s 找到整型常量 %s（改名/删除须同步本契约）", path, name)
	return 0
}

// 限流文案中的数字必须从 middleware 实现派生，不得手抄字面量。
func TestMCPRateLimitContractDerivesLimitFromMiddleware(t *testing.T) {
	limit := goConstInt(t, "../middleware/middleware.go", "mcpRateLimitPerMinute")
	if limit <= 0 {
		t.Fatalf("派生限额=%d，须为正数", limit)
	}
	playbook, err := os.ReadFile("playbook.md")
	if err != nil {
		t.Fatal(err)
	}
	docs, err := os.ReadFile("../../docs/mcp.zh-CN.md")
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"server instructions": serverInstructions,
		"playbook":            string(playbook),
		"user documentation":  string(docs),
	} {
		if !strings.Contains(text, strconv.Itoa(limit)) {
			t.Errorf("%s 缺少派生限额数字 %d（文案与实现漂移）", name, limit)
		}
	}
}

// 派生器自证：对合成源码必须取到声明值——取不到/取错时契约测试的「派生」
// 是假象（与字面量手抄无异的假绿）。
func TestGoConstInt_extractsDeclaredValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.go")
	source := "package sample\nconst (\n\talpha = 7\n\tbeta  = 42\n)\n"
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := goConstInt(t, path, "beta"); got != 42 {
		t.Fatalf("goConstInt(beta)=%d, want 42", got)
	}
	if got := goConstInt(t, path, "alpha"); got != 7 {
		t.Fatalf("goConstInt(alpha)=%d, want 7", got)
	}
}
