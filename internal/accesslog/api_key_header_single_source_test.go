package accesslog

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

// 头名单源守卫：REST 认证提取、MCP 内部转发、CORS、OpenAPI、注释与日志脱敏
// 必须共用 APIKeyHeaderName。任一侧回退成手写字面量，拼写/大小写分歧就会重新
// 变成「认证读的头与脱敏滤的头不是同一个」或文档/CORS 漂移。
//
// 字符串按包含匹配（CORS 列表与 YAML 不是独立头名串），注释也纳入；paths.go
// 允许保留唯一一处定义及自身示例。
func TestAPIKeyHeaderName_noHandWrittenLiterals(t *testing.T) {
	const definitionFile = "paths.go"
	packages := []string{".", filepath.Join("..", "apikey"), filepath.Join("..", "mcpserver"), filepath.Join("..", "middleware"), filepath.Join("..", "handlers")}
	for _, pkgDir := range packages {
		entries, err := os.ReadDir(pkgDir)
		if err != nil {
			t.Fatalf("读取 %s 目录: %v", pkgDir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			if pkgDir == "." && name == definitionFile {
				continue
			}
			path := filepath.Join(pkgDir, name)
			literals, err := headerNameLiterals(path)
			if err != nil {
				t.Fatalf("解析 %s: %v", path, err)
			}
			if len(literals) > 0 {
				t.Errorf("%s 手写了 %s 字符串字面量（第 %v 行）：改用 accesslog.APIKeyHeaderName，头名只允许一处定义",
					path, APIKeyHeaderName, literals)
			}
		}
	}
}

// headerNameLiterals 返回文件内包含 APIKeyHeaderName 的字符串或注释所在行号。
func headerNameLiterals(path string) ([]int, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var lines []int
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err != nil {
			return true
		}
		if strings.Contains(value, APIKeyHeaderName) {
			lines = append(lines, fset.Position(literal.Pos()).Line)
		}
		return true
	})
	for _, group := range file.Comments {
		for _, comment := range group.List {
			if strings.Contains(comment.Text, APIKeyHeaderName) {
				lines = append(lines, fset.Position(comment.Pos()).Line)
			}
		}
	}
	return lines, nil
}

func TestAPIKeyHeaderNameGuard_detectsEmbeddedStringsAndComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "contract.go")
	source := "package contract\n" +
		"// X-API-Key stale comment\n" +
		"const cors = \"Content-Type, X-API-Key\"\n" +
		"const openAPI = `name: X-API-Key`\n" +
		"const unrelated = \"Authorization\"\n"
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err := headerNameLiterals(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(lines), 3; got != want {
		t.Fatalf("detected lines=%v, want %d references", lines, want)
	}
}
