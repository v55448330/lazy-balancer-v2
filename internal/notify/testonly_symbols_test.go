package notify

// 测试专用符号：通道注册表的替换入口（测试设施，不进产品编译单元）与本包
// 「产品文件不得携带测试设施」的机械守卫。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RegisterSenderForTest 测试用通道替换（注册表同名覆盖走后复原）。
func RegisterSenderForTest(t *testing.T, typ string, s Sender) {
	t.Helper()
	sendersMu.Lock()
	old, had := senders[typ]
	senders[typ] = s
	sendersMu.Unlock()
	t.Cleanup(func() {
		sendersMu.Lock()
		if had {
			senders[typ] = old
		} else {
			delete(senders, typ)
		}
		sendersMu.Unlock()
	})
}

// 产品文件不得依赖测试设施：`testing` 只属于 *_test.go，导出测试 API 只属于
// 测试文件（否则生产构建链接 testing、公共 API 面被测试设施占据）。守卫按 AST
// 扫本包产品文件：ImportSpec 命中 "testing"，或导出声明名以 ForTest 结尾即违规。
func TestPackageProductionFiles_doNotCarryTestFacilities(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob 包内文件: %v", err)
	}
	scanned := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("读取 %s: %v", file, err)
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, source, 0)
		if err != nil {
			t.Fatalf("解析 %s: %v", file, err)
		}
		scanned++
		for _, imported := range parsed.Imports {
			if imported.Path != nil && imported.Path.Value == `"testing"` {
				t.Errorf("%s:%d 产品文件导入 testing——测试设施必须留在 *_test.go",
					file, fset.Position(imported.Pos()).Line)
			}
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasSuffix(fn.Name.Name, "ForTest") {
				continue
			}
			if fn.Name.IsExported() {
				t.Errorf("%s:%d 产品文件导出测试入口 %s——测试 API 必须留在 *_test.go",
					file, fset.Position(fn.Pos()).Line, fn.Name.Name)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("未扫描任何产品文件——守卫对象漂移")
	}
}
