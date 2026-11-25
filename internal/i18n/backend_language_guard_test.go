package i18n

// 后端文案归属守卫（2026-11-25 项目所有者裁定，web/docs/I18N.md 第 0 节）：
// 后端只下发稳定键 + 结构化参数，展示文案只归前端。具体三件事：
//   1. 后端不存在「按请求语言选择」的机制：没有 Accept-Language / Content-Language
//      头处理，没有 Negotiate / FromCtx / CtxLangKey，没有中→英的错误模板翻译
//      （RegisterErrTpl / TrErr），没有 HasEnglish 这种「是否有英文译文」的判定。
//   2. 后端不存在英文译文：目录登记只有 (key, zh) 两参（编译期由签名挡住），
//      且中文母本槽位不得被英文散文占据。
//   3. 上述判据对本包与 internal/、cmd/ 的全部非测试源码生效。
//
// 判据读 AST（字符串字面量与标识符），不读注释——注释里解释「为什么不协商
// Accept-Language」不是违规。

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// forbiddenLanguageMechanisms 是「按请求语言渲染」机制的标识符名。
var forbiddenLanguageMechanisms = map[string]bool{
	"Negotiate":      true, // Accept-Language 协商
	"FromCtx":        true, // 从 gin 上下文取语言
	"CtxLangKey":     true, // 语言在上下文里的键
	"RegisterErrTpl": true, // 中→英错误模板登记
	"TrErr":          true, // 中文错误串翻英文
	"HasEnglish":     true, // 「键是否有独立英文译文」判定
}

// forbiddenLanguageHeaders 是「语言协商」涉及的 HTTP 头名。
var forbiddenLanguageHeaders = []string{"Accept-Language", "Content-Language"}

func backendProductionFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, root := range []string{"../../internal", "../../cmd"} {
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
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// 扫描面：包结构调整会让守卫空转。
	if len(files) < 100 {
		t.Fatalf("只扫到 %d 个生产源码文件——扫描面异常", len(files))
	}
	return files
}

// TestBackendHasNoLanguageNegotiation 后端生产代码里不得再出现「按请求语言渲染」
// 的机制：头处理、协商函数、上下文取语言、错误模板翻译、英文译文判定。
func TestBackendHasNoLanguageNegotiation(t *testing.T) {
	fset := token.NewFileSet()
	var offenders []string
	for _, path := range backendProductionFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("%s 解析失败: %v", path, err)
		}
		report := func(pos token.Position, format string, args ...any) {
			offenders = append(offenders, filepath.ToSlash(pos.String())+": "+fmt.Sprintf(format, args...))
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(node.Value)
				if err != nil {
					return true
				}
				for _, header := range forbiddenLanguageHeaders {
					if strings.Contains(value, header) {
						report(fset.Position(node.Pos()), "出现语言协商响应头字面量 %q", header)
					}
				}
			case *ast.Ident:
				if forbiddenLanguageMechanisms[node.Name] {
					report(fset.Position(node.Pos()), "出现语言选择机制标识符 %q", node.Name)
				}
			}
			return true
		})
	}
	if len(offenders) > 0 {
		t.Fatalf("后端仍存在按请求语言渲染的机制（%d 处）：\n  %s", len(offenders), strings.Join(offenders, "\n  "))
	}
}

// noHanChineseMother 是中文母本里不含汉字、但合规的纯符号/品牌模板（如 "%s"、"MFA"）。
// 这是刻意维护的基线：新出现一个不含汉字的「母本」= 有人把英文文案塞进了中文槽位，
// 或新增词条忘了写中文母本。
var noHanChineseMother = map[string]int{
	"%s":                 7,
	"API：%s→%s":          1,
	"MCP：%s→%s":          1,
	"IP：%s":              1,
	"MFA":                1,
	"%s(%s)":             1,
	"Client ID：%s→%s":    1,
	"「%s」":               1,
	"registration_id：%d": 1,
	"subject：%s":         1,
	"%s：%s":              1,
}

func sortedKeys(counts map[string]int) []string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// TestCatalogChineseMotherIsChinese 中文母本槽位必须真的是中文（或纯符号模板）：
// 英文散文（"Rule deleted successfully"）混进来会让英文界面出现「后端译文」，
// 也会让前端词条与后端母本分叉。
func TestCatalogChineseMotherIsChinese(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("catalog_*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("目录文件缺失: %v %v", files, err)
	}
	got := map[string]int{}
	total := 0
	for _, path := range files {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok || fn.Name != "Register" {
				return true
			}
			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			total++
			if !strings.ContainsFunc(text, func(r rune) bool { return r >= 0x4E00 && r <= 0x9FFF }) {
				got[text]++
			}
			return true
		})
	}
	if total < 1000 {
		t.Fatalf("只扫到 %d 条 Register——扫描面异常", total)
	}
	if len(got) != len(noHanChineseMother) {
		t.Fatalf("不含汉字的中文母本形态有 %d 种，基线是 %d 种：%v\n"+
			"新增形态要么是忘了写中文母本，要么是英文文案混进了后端目录（英文译文归前端词条）；"+
			"确认合规后同步更新 noHanChineseMother 基线", len(got), len(noHanChineseMother), sortedKeys(got))
	}
	for text, count := range got {
		if want := noHanChineseMother[text]; count != want {
			t.Errorf("中文母本 %q 出现 %d 次，基线 %d 次——目录新增了不含汉字的值", text, count, want)
		}
	}
}
