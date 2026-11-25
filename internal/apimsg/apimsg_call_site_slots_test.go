package apimsg

// Tf 传参点槽数对账钉测：调用方给 Tf 传了参数，词条模板就必须有足够占位槽
// 承接——codemod 迁移曾把 8 条「尾冒号 + 错误详情」词条的 %s 槽弄丢
// （zh/en 双语只剩悬空冒号，错误详情被静默丢弃，主错误通道丢载荷）。
// 本守卫机械扫描全仓的传参点（AST 计数实参，排除 variadic 展开）：
//   - apimsg.Tf(c, key, args...)
//   - apimsg.Envelope(c, code, key, args...)——带键响应信封的构造入口，参数经它转给 Tf
// 对照 catalog 的 zh/en 槽数（与 Tf 同口径：%s/%d/%v/%q 各占一槽，%% 是
// 转义字面量不占槽）：模板槽数 < 传参数即红。词条改回零槽或新增无槽传参
// 点此处必红，而不是等线上双语消息丢载荷。

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
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

// argSite 一处带模板参数的取词条调用：apimsg.Tf(c, key, args...) 或
// apimsg.Envelope(c, code, key, args...)。
type argSite struct {
	pos  token.Position
	call string // "apimsg.Tf" / "apimsg.Envelope"
	key  string
	args int
}

// argumentSites 找出 file 里带模板参数的取词条调用点，并列出无法对账的形态
// （限定名不是 canonical 的 apimsg、键不是字符串字面量）。
func argumentSites(fset *token.FileSet, file *ast.File) (sites []argSite, problems []string) {
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || call.Ellipsis != token.NoPos {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		// 两种取词条的调用形态，键实参的位置不同。
		var keyIndex int
		var name string
		switch sel.Sel.Name {
		case "Tf":
			keyIndex, name = 1, "apimsg.Tf"
		case "Envelope":
			keyIndex, name = 2, "apimsg.Envelope"
		default:
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			problems = append(problems, fset.Position(call.Pos()).String()+": "+name+" 限定名不是包标识符（链式选择器/方法值形态无法对账槽数）")
			return true
		}
		if pkg.Name != "apimsg" {
			problems = append(problems, fmt.Sprintf("%s: %s 经非 canonical 限定名 %q 调用——别名导入会让槽数对账静默漏扫，请用 canonical 包名 apimsg", fset.Position(call.Pos()), name, pkg.Name))
			return true
		}
		if len(call.Args) <= keyIndex+1 {
			return true
		}
		keyLit, ok := call.Args[keyIndex].(*ast.BasicLit)
		if !ok || keyLit.Kind != token.STRING {
			problems = append(problems, fset.Position(call.Pos()).String()+": "+name+" 的键不是字符串字面量，无法对账槽数")
			return true
		}
		key, err := strconv.Unquote(keyLit.Value)
		if err != nil {
			problems = append(problems, fset.Position(call.Pos()).String()+": 键字面量解码失败: "+err.Error())
			return true
		}
		sites = append(sites, argSite{pos: fset.Position(call.Pos()), call: name, key: key, args: len(call.Args) - keyIndex - 1})
		return true
	})
	return sites, problems
}

// slotShortfalls 列出 site 的参数放不进模板的语言。键未登记（T 回落键本身）时不报：
// 拼写错/漏登记由登记守卫拦，这里只对已登记词条做槽数对账。
func slotShortfalls(site argSite) []string {
	if i18n.T(i18n.ZH, site.key) == site.key {
		return nil
	}
	var shortfalls []string
	for _, lang := range []string{i18n.ZH, i18n.EN} {
		tpl := i18n.T(lang, site.key)
		if got := tplSlotCount(tpl); got < site.args {
			shortfalls = append(shortfalls, fmt.Sprintf("%s(%q) 传 %d 参，%s 模板仅 %d 槽（参数被静默丢弃）: %q", site.call, site.key, site.args, lang, got, tpl))
		}
	}
	return shortfalls
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
			// import 块守卫：internal/apimsg 的别名/dot 导入会让 Tf 限定名
			// 偏离 canonical 包名，槽数对账静默漏扫。当前全仓零别名，此钉
			// 防回潮（下方的限定名守卫拦截调用点，本守卫拦截导入声明源）。
			for _, imp := range file.Imports {
				impPath, uerr := strconv.Unquote(imp.Path.Value)
				if uerr != nil || (!strings.HasSuffix(impPath, "/internal/apimsg") && impPath != "internal/apimsg") {
					continue
				}
				base := impPath[strings.LastIndex(impPath, "/")+1:]
				if imp.Name != nil && imp.Name.Name != base && imp.Name.Name != "_" {
					t.Errorf("%s: %q 以别名 %q 导入 internal/apimsg——别名限定名会让 apimsg.Tf 槽数对账静默漏扫，请用 canonical 包名", fset.Position(imp.Pos()), impPath, imp.Name.Name)
				}
			}
			found, problems := argumentSites(fset, file)
			for _, problem := range problems {
				t.Errorf("%s", problem)
			}
			for _, site := range found {
				sites++
				for _, shortfall := range slotShortfalls(site) {
					t.Errorf("%s: %s", site.pos, shortfall)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("扫描 %s: %v", dir, err)
		}
	}
	if sites < 9 {
		t.Fatalf("仅扫到 %d 个传参点——守卫对象漂移（已知 ≥9：8 条错误详情 + 集群节点动作 + 导入窗口动作）", sites)
	}
}

// 守卫自测：用合成源码钉住识别规则。Envelope 是带键响应的统一构造入口，带参数的
// 调用大都在它里面——识别规则漏了它，上面的全仓扫描就对绝大多数传参点失明。
func TestArgumentSites_coversEnvelopeCalls(t *testing.T) {
	source := `package synth

import "app/internal/apimsg"

func h(c int) {
	_ = apimsg.Tf(c, "notify.dailyItemUnknown", "x")
	_ = apimsg.Envelope(c, 400, "notify.dailyItemUnknown", "x")
	_ = apimsg.Envelope(c, 400, "notify.dailySendTimeInvalid", "x", "y")
	_ = apimsg.Envelope(c, 404, "user.notFound")
	_ = apimsg.Envelope(c, 400, "no.suchKey", "x")
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synth.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	sites, problems := argumentSites(fset, file)
	// 目标：带参数的调用四种情形都被找出（第 9 行无参数的不算）；出处行号、形态、键、参数个数逐一对应。
	var got []string
	for _, site := range sites {
		got = append(got, fmt.Sprintf("%d %s %s args=%d", site.pos.Line, site.call, site.key, site.args))
	}
	want := []string{
		"6 apimsg.Tf notify.dailyItemUnknown args=1",
		"7 apimsg.Envelope notify.dailyItemUnknown args=1",
		"8 apimsg.Envelope notify.dailySendTimeInvalid args=2",
		"10 apimsg.Envelope no.suchKey args=1",
	}
	if !slices.Equal(got, want) {
		t.Errorf("传参点\n got %v\nwant %v", got, want)
	}
	if len(problems) != 0 {
		t.Errorf("合成源码不该有无法对账的形态: %v", problems)
	}
	// 槽数对账：1 槽 1 参合规；0 槽 2 参（dailySendTimeInvalid 无占位符）中英文都要报；
	// 未登记键不在这里报（由登记守卫拦）。
	byLine := map[int]argSite{}
	for _, site := range sites {
		byLine[site.pos.Line] = site
	}
	for _, line := range []int{6, 7, 10} {
		if shortfalls := slotShortfalls(byLine[line]); len(shortfalls) != 0 {
			t.Errorf("第 %d 行不该报槽数不足: %v", line, shortfalls)
		}
	}
	if shortfalls := slotShortfalls(byLine[8]); len(shortfalls) != 2 || !strings.Contains(shortfalls[0], "传 2 参") {
		t.Errorf("第 8 行 0 槽 2 参必须中英文各报一次，got %v", shortfalls)
	}
}
