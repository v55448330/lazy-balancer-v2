package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// 消息键登记守卫：仓内非测试 Go 代码里每一处消息键的取值都必须已在目录登记。
//
// 为什么需要：未登记的键会被 T 原样返回，用户看到的就是原始键。2026-11-25 实测（线上
// 同构建）：PUT /notification/daily 带非法时间返回 message=k_f9986707，7 个报错分支自
// 引入起如此。既有的登记守卫按文件清单扫描，只覆盖导入/还原相关文件，漏掉了它们。
//
// 识别规则有两条，互补：
//   - 任意位置：字符串字面量形态是键、且名字部分含大写字母。能识别"在几个键里按条件
//     挑一个"这类不经 T/MessageKey 直接传参的间接用法。要求含大写，是为了与
//     "application/json" 这类同为"小写.小写"形态的普通字面量区分开。
//   - 键的位置：MessageKey 字段的取值、T/Tf 的键实参——字面量，或被这样引用的本包
//     字符串常量。补上名字全小写的键（rule.created 这类过去式）。

// messageKeyUse 一处未登记的消息键取值：键与出处。
type messageKeyUse struct {
	key string
	pos string // 源文件:行号
}

func hasUpperCaseNamePart(key string) bool {
	_, name, _ := strings.Cut(key, ".")
	return strings.ContainsFunc(name, unicode.IsUpper)
}

// stringLiteral 取字符串字面量的值；不是字符串字面量时 ok=false。
func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	return value, err == nil
}

// packageStringConstants 收集一个包内全部字符串常量：名 -> 值。
func packageStringConstants(files []*ast.File) map[string]string {
	constants := map[string]string{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				values, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range values.Names {
					if i >= len(values.Values) {
						continue // 无值声明（iota 式连写）：不是字符串常量
					}
					if value, ok := stringLiteral(values.Values[i]); ok {
						constants[name.Name] = value
					}
				}
			}
		}
	}
	return constants
}

// keyArgumentIndex 返回 call 里键实参的下标；不是取词条的调用返回 -1。
//   - apimsg.T / apimsg.Tf、i18n.T / i18n.Tf，以及 i18n 包内不带限定名的 T / Tf：
//     键是第二个实参（下标 1）；
//   - apimsg.Envelope(c, code, key, args...)：带键响应信封的构造入口，键是第三个
//     实参（下标 2）。
func keyArgumentIndex(call *ast.CallExpr, inI18nPackage bool) int {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		pkg, ok := fn.X.(*ast.Ident)
		if !ok || (pkg.Name != "apimsg" && pkg.Name != "i18n") {
			return -1
		}
		if fn.Sel.Name == "T" || fn.Sel.Name == "Tf" {
			return 1
		}
		if fn.Sel.Name == "Envelope" {
			return 2
		}
	case *ast.Ident:
		if inI18nPackage && (fn.Name == "T" || fn.Name == "Tf") {
			return 1
		}
	}
	return -1
}

// scanMessageKeyUses 扫描 packages（目录 -> 该目录下的 Go 文件），返回其中未登记的
// 消息键取值（同一键多处出现则逐处列出）与核对过的取值点总数。
func scanMessageKeyUses(packages map[string][]string) (uses []messageKeyUse, checked int) {
	type site struct {
		key string
		pos string
	}
	seen := map[site]bool{}
	for dir, paths := range packages {
		fset := token.NewFileSet()
		var files []*ast.File
		for _, path := range paths {
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				continue
			}
			files = append(files, file)
		}
		constants := packageStringConstants(files)
		// constantOrLiteral 取键值：字面量，或本包字符串常量；运行时变量取不到。
		constantOrLiteral := func(expr ast.Expr) (string, bool) {
			if value, ok := stringLiteral(expr); ok {
				return value, true
			}
			if ident, ok := expr.(*ast.Ident); ok {
				value, ok := constants[ident.Name]
				return value, ok
			}
			return "", false
		}
		// 枚举显示码（ruleset./task./block_page.）不是消息键：后端按裁定只下发
		// 语言无关标识，文案由前端词条渲染（web/src/locales），T() 不参与；它们的
		// 跨栈覆盖由 internal/services/enum_display_keys_guard_test.go 钉住。
		isEnumDisplayCode := func(key string) bool {
			for _, prefix := range []string{"ruleset.", "task.", "block_page."} {
				if strings.HasPrefix(key, prefix) {
					return true
				}
			}
			return false
		}
		record := func(key string, position token.Position) {
			if isEnumDisplayCode(key) {
				return
			}
			site := site{key, fmtSite(position)}
			if !seen[site] {
				seen[site] = true
				if T(ZH, key) == key {
					uses = append(uses, messageKeyUse{key, site.pos})
				}
			}
		}
		inI18nPackage := filepath.Base(dir) == "i18n"
		for _, file := range files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.BasicLit:
					if value, ok := stringLiteral(node); ok && IsMessageKey(value) && hasUpperCaseNamePart(value) {
						record(value, fset.Position(node.Pos()))
					}
				case *ast.KeyValueExpr:
					key, ok := node.Key.(*ast.Ident)
					if !ok || key.Name != "MessageKey" {
						return true
					}
					if value, ok := constantOrLiteral(node.Value); ok {
						record(value, fset.Position(node.Value.Pos()))
					}
				case *ast.CallExpr:
					index := keyArgumentIndex(node, inI18nPackage)
					if index < 0 || len(node.Args) <= index {
						return true
					}
					if value, ok := constantOrLiteral(node.Args[index]); ok {
						record(value, fset.Position(node.Args[index].Pos()))
					}
				}
				return true
			})
		}
	}
	return uses, len(seen)
}

// fmtSite 把 token.Position 压成「源文件:行号」；仓内文件用仓内相对路径。
func fmtSite(position token.Position) string {
	path := filepath.ToSlash(position.Filename)
	if _, rel, found := strings.Cut(path, "/lazy-balancer-v2/"); found {
		path = rel
	}
	return path + ":" + strconv.Itoa(position.Line)
}

func TestMessageKeyUses_areRegistered(t *testing.T) {
	// 扫描面：internal/ 与 cmd/ 的全部非测试 Go 文件，按目录归组。
	packages := map[string][]string{}
	for _, root := range []string{"../../internal", "../../cmd"} {
		// 绝对路径：出处才能压成仓内相对路径。
		root, err := filepath.Abs(root)
		if err != nil {
			t.Fatal(err)
		}
		err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if entry.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				packages[filepath.Dir(path)] = append(packages[filepath.Dir(path)], path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// 回归：扫描面缩水说明扫描方式失效——守卫会空过。
	if len(packages) < 20 {
		t.Fatalf("只扫到 %d 个包——扫描面漂移", len(packages))
	}
	uses, checked := scanMessageKeyUses(packages)
	if checked < 1500 {
		t.Fatalf("仅核对了 %d 处消息键取值——扫描面漂移", checked)
	}
	t.Logf("核对 %d 个包、%d 处消息键取值", len(packages), checked)
	first, count := map[string]string{}, map[string]int{}
	for _, use := range uses {
		if _, seen := first[use.key]; !seen {
			first[use.key] = use.pos
		}
		count[use.key]++
	}
	for _, key := range slices.Sorted(maps.Keys(first)) {
		t.Errorf("消息键 %q 未登记（%d 处引用，首处 %s）——T 会原样返回键，用户看到的就是这串键", key, count[key], first[key])
	}
}

// 守卫自测：用一份合成源码钉住两条识别规则的边界。少识别一处，守卫对那一类写法
// 就是空转。源码内的行号是相对 const scannerSource 首行的。
const scannerSource = `package synth

import "app/internal/apimsg"

const (
	msgPlain = "notify.created"
	msgUpper = "notify.fromUpperConst"
	notAKey  = "application/json"
	iotaStyle = iota
	alsoIota
)

func h(c int, runtimeKey string) {
	_ = apimsg.Tf(c, "rule.literalUpper", 1)
	_ = apimsg.T(c, "rule.lowercase")
	_ = pick(c, "backup.indirectRegistered", "backup.indirectUnregistered")
	_ = "config.yaml"
	_ = struct{ MessageKey string }{MessageKey: msgPlain}
	_ = struct{ MessageKey string }{MessageKey: "security.lowercaseField"}
	_ = struct{ MessageKey string }{MessageKey: runtimeKey}
	_ = apimsg.T(c, runtimeKey)
	_ = struct{ MessageKey string }{MessageKey: msgUpper}
	_ = apimsg.Envelope(c, 404, "rule.envelopeplain")
	_ = apimsg.Envelope(c, 400, "rule.envelopemissing", 1)
}
`

func TestScanMessageKeyUses_recognizesKeyPositions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "synth.go")
	if err := os.WriteFile(path, []byte(scannerSource), 0o644); err != nil {
		t.Fatal(err)
	}
	// 目录是包级全局表：登记合成源码里"应当已登记"的键，用完即撤。
	registered := []string{"notify.fromUpperConst", "rule.literalUpper", "rule.lowercase", "backup.indirectRegistered", "security.lowercaseField", "rule.envelopeplain"}
	for _, key := range registered {
		Register(key, "合成", "synthetic")
	}
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, key := range registered {
			delete(catalog, key)
		}
	})

	uses, checked := scanMessageKeyUses(map[string][]string{dir: {path}})

	// 目标：未登记的三处各被报一次，出处指向各自的行——
	//   第 16 行的间接用法（不经 T/MessageKey）靠"任意位置"规则；
	//   第 18 行的全小写键（notify.created，经常量引用）与第 24 行的全小写键
	//   （apimsg.Envelope 的第三个实参）靠"键的位置"规则。
	var got []string
	for _, use := range uses {
		got = append(got, use.key+" @ "+use.pos)
	}
	slices.Sort(got)
	want := []string{
		"backup.indirectUnregistered @ " + fmtSiteLine(path, 16),
		"notify.created @ " + fmtSiteLine(path, 18),
		"rule.envelopemissing @ " + fmtSiteLine(path, 24),
	}
	if !slices.Equal(got, want) {
		t.Errorf("未登记取值点\n got %v\nwant %v", got, want)
	}
	// 回归：每个应被识别的位置恰好计一次；"config.yaml"（全小写的普通字面量）、
	// 运行变量、无值常量都不计。notify.created 的常量声明处（第 6 行）不是键的位置，
	// 全小写名字在任意位置规则下也识别不到——所以它只有引用处那一个取值点；
	// rule.envelopeplain 同理，只有 Envelope 实参处那一个取值点。
	if checked != 10 {
		t.Errorf("核对取值点 %d 处，want 10", checked)
	}
}

func fmtSiteLine(path string, line int) string {
	return filepath.ToSlash(path) + ":" + strconv.Itoa(line)
}
