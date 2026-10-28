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

// 头名单源守卫：REST 认证提取、MCP 内部转发与日志脱敏必须共用
// APIKeyHeaderName。任一侧回退成手写字面量，拼写/大小写分歧就会重新变成
// 「认证读的头与脱敏滤的头不是同一个」这类静默失效。
//
// 只扫字符串字面量（go/ast），注释里的示例文本不算违规；paths.go 允许保留
// 唯一一处定义。
func TestAPIKeyHeaderName_noHandWrittenLiterals(t *testing.T) {
	const definitionFile = "paths.go"
	packages := []string{".", filepath.Join("..", "apikey"), filepath.Join("..", "mcpserver")}
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

// headerNameLiterals 返回文件内等于 APIKeyHeaderName 的字符串字面量所在行号。
func headerNameLiterals(path string) ([]int, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
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
		if value == APIKeyHeaderName {
			lines = append(lines, fset.Position(literal.Pos()).Line)
		}
		return true
	})
	return lines, nil
}
