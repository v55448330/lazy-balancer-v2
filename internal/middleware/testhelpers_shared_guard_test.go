package middleware

// 夹具数据库句柄复位单源守卫：包内测试只能经 restoreTestDBHandles 复位三库
// 句柄（db.DB / db.MetricsDB / db.AuditDB + db.GetDB 原子视图）。
//
// 手写三元赋值（`db.DB, db.MetricsDB, db.AuditDB = …`）看似等价，却会让该
// 夹具与单源的复位语义分叉：单源新增一步（如原子视图复位）时手工副本不会
// 跟进，`-shuffle`/`-count=2` 下表现为跨用例顺序依赖的假红/假绿。守卫按 AST
// 统计「同一条赋值语句左侧命中 ≥2 个句柄选择子」——这正是手工复位的形态，
// 单句柄安装（`db.DB = database` + db.SetDB）不受影响。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dbHandleSelectors 是被单源接管的包级句柄选择子。
var dbHandleSelectors = map[string]bool{
	"db.DB":        true,
	"db.MetricsDB": true,
	"db.AuditDB":   true,
}

// 单源本体与守卫自身允许出现三元赋值。
var dbHandleRestoreExemptFiles = map[string]bool{
	"testhelpers_shared_test.go":       true,
	"testhelpers_shared_guard_test.go": true,
}

func TestFixtureDBHandleRestore_goesThroughSharedHelper(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatalf("glob 测试文件: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("未扫到任何测试文件——守卫对象漂移")
	}
	scanned := 0
	for _, file := range files {
		if dbHandleRestoreExemptFiles[file] {
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
		ast.Inspect(parsed, func(node ast.Node) bool {
			assign, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			handles := 0
			for _, lhs := range assign.Lhs {
				if dbHandleSelectors[selectorText(lhs)] {
					handles++
				}
			}
			if handles >= 2 {
				t.Errorf("%s:%d 手写多句柄赋值——夹具复位必须走 restoreTestDBHandles（单源）",
					file, fset.Position(assign.Pos()).Line)
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("未扫描任何夹具文件——守卫对象漂移")
	}
}

// selectorText 还原 `pkg.Name` 形态的选择子文本（其他形态返回空串）。
func selectorText(expr ast.Expr) string {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return strings.Join([]string{pkg.Name, selector.Sel.Name}, ".")
}
