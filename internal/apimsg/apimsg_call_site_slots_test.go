package apimsg

// Tf 传参点槽数对账钉测：调用方给 Tf 传了参数，词条模板就必须有足够占位槽
// 承接——codemod 迁移曾把 8 条「尾冒号 + 错误详情」词条的 %s 槽弄丢
// （zh/en 双语只剩悬空冒号，错误详情被静默丢弃，主错误通道丢载荷）。
// 本守卫机械扫描全仓 apimsg.Tf 传参点（AST 计数实参，排除 variadic 展开），
// 对照 catalog 的 zh/en 槽数（与 Tf 同口径：%s/%d/%v/%q 各占一槽，%% 是
// 转义字面量不占槽）：模板槽数 < 传参数即红。词条改回零槽或新增无槽传参
// 点此处必红，而不是等线上双语消息丢载荷。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/i18n"
)

// tplSlotCount 统计模板占位槽数（与 Tf 消费口径一致）。
func tplSlotCount(tpl string) int {
	n := 0
	for i := 0; i+1 < len(tpl); i++ {
		if tpl[i] != '%' {
			continue
		}
		switch tpl[i+1] {
		case '%':
			i++ // %% 转义字面量，不占槽
		case 's', 'd', 'v', 'q':
			n++
			i++
		}
	}
	return n
}

func TestTfCallSites_templateSlotsCoverArgs(t *testing.T) {
	root := ".."
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	sites := 0
	fset := token.NewFileSet()
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			// 只扫生产消费面：测试文件里的 Tf 调用是合成夹具（临时 Register
			// 的键不在 catalog），不属词条槽数契约。
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || call.Ellipsis != token.NoPos {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Tf" {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "apimsg" || len(call.Args) < 3 {
					return true
				}
				keyLit, ok := call.Args[1].(*ast.BasicLit)
				if !ok || keyLit.Kind != token.STRING {
					t.Errorf("%s: apimsg.Tf 的键不是字符串字面量，无法对账槽数", fset.Position(call.Pos()))
					return true
				}
				key, err := strconv.Unquote(keyLit.Value)
				if err != nil {
					t.Errorf("%s: 键字面量解码失败: %v", fset.Position(call.Pos()), err)
					return true
				}
				args := len(call.Args) - 2
				sites++
				if i18n.T(i18n.ZH, key) == key {
					// 键未登记（T 回落键本身）：拼写错/漏登记由调用方自身的
					// 回归测试拦，这里只对已登记词条做槽数对账。
					return true
				}
				for _, lang := range []string{i18n.ZH, i18n.EN} {
					tpl := i18n.T(lang, key)
					if got := tplSlotCount(tpl); got < args {
						t.Errorf("%s: apimsg.Tf(%q) 传 %d 参，%s 模板仅 %d 槽（参数被静默丢弃）: %q",
							fset.Position(call.Pos()), key, args, lang, got, tpl)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("扫描 %s: %v", dir, err)
		}
	}
	if sites < 9 {
		t.Fatalf("仅扫到 %d 个 apimsg.Tf 传参点——守卫对象漂移（已知 ≥9：8 条错误详情 + 集群节点动作 + 导入窗口动作）", sites)
	}
}
