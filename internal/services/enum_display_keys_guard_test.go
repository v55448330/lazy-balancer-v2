package services

// 枚举显示键守卫（2026-11-25 用户裁定「后端只返回语言无关的稳定标识，界面文案
// 一律由前端词条渲染」）：
//
//  1. CRS 规则分类：CategorizeCRSFile 只产出 `ruleset.*` 稳定码；前端
//     common.app.crsCategory.<后缀> 覆盖全部码，且后端生产源码不得再持有中文
//     分类字典（AST 扫字符串常量）。
//  2. 内置拦截页显示键：models.BuiltinBlockPageIdentities 的 NameKey 唯一、
//     格式合法，前端 app.security.blockPages.builtin.<后缀>.{name,desc} 覆盖；
//     库存中文名只允许出现在 models 单源（AST 扫 internal 生产源码）。
//  3. 任务族显示键：注册表里每个任务都有稳定码、码唯一、格式合法，前端
//     common.app.taskNames/taskDesc 覆盖；码表不得残留未注册任务（死条目）。
//
// 缺词条/新增码未同步会让英文界面回落到码或缺字——本测试即卡口。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

var enumCodeFormat = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][A-Za-z0-9]*$`)

// hanPattern 判定字符串里是否含汉字（分类/显示文案不得由后端下发）。
var hanPattern = regexp.MustCompile(`\p{Han}`)

// readWebLocale 读取前端词条文件（缺失即失败——守卫依赖前端单源存在）。
func readWebLocale(t *testing.T, locale, file string) string {
	t.Helper()
	path := filepath.Join("..", "..", "web", "src", "locales", locale, file)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取前端词条失败 %s: %v", path, err)
	}
	return string(raw)
}

// assertLocaleEntry 断言词条文件里存在 `<key>: '…'` 或 `"<key>": {` 形态的条目。
func assertLocaleEntry(t *testing.T, content, locale, file, key, format string) {
	t.Helper()
	switch format {
	case "flat":
		quoted := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `: ['"]`)
		if !quoted.MatchString(content) {
			t.Errorf("%s/%s 缺词条 %s（后端稳定码已下发，前端必须同步）", locale, file, key)
		}
	case "object":
		quoted := regexp.MustCompile(`(?m)^\s*"` + regexp.QuoteMeta(key) + `": \{`)
		if !quoted.MatchString(content) {
			t.Errorf("%s/%s 缺词条对象 %s", locale, file, key)
		}
	default:
		t.Fatalf("未知词条形态 %q", format)
	}
}

// crsCategorySampleFilenames 覆盖 CategorizeCRSFile 的全部分支（含兜底）。
var crsCategorySampleFilenames = []string{
	"REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
	"REQUEST-921-PROTOCOL-ATTACK.conf",
	"REQUEST-922-MULTIPART-ATTACK.conf",
	"REQUEST-930-APPLICATION-ATTACK-LFI.conf",
	"REQUEST-931-APPLICATION-ATTACK-RFI.conf",
	"REQUEST-932-APPLICATION-ATTACK-RCE.conf",
	"REQUEST-933-APPLICATION-ATTACK-PHP.conf",
	"REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
	"REQUEST-941-APPLICATION-ATTACK-XSS.conf",
	"REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
	"REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
	"REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
	"REQUEST-949-BLOCKING-INBOUND-ANOMALY.conf",
	"RESPONSE-950-DATA-LEAKAGES.conf",
	"RESPONSE-951-DATA-LEAKAGES-SQL.conf",
	"RESPONSE-952-DATA-LEAKAGES-JAVA.conf",
	"RESPONSE-953-DATA-LEAKAGES-PHP.conf",
	"RESPONSE-954-DATA-LEAKAGES-IIS.conf",
	"RESPONSE-955-WEB-SHELLS.conf",
	"RESPONSE-956-DATA-LEAKAGES-RUBY.conf",
	"RESPONSE-959-BLOCKING-EVALUATION.conf",
	"RESPONSE-980-CORRELATION.conf",
	"REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf",
	"REQUEST-901-INITIALIZATION.conf",
	"REQUEST-905-COMMON-EXCEPTIONS.conf",
	"REQUEST-911-METHOD-ENFORCEMENT.conf",
	"REQUEST-913-SCANNER-DETECTION.conf",
	"REQUEST-915-APPLICATION-ATTACK-SCANNER.conf",
	"RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf",
	"REQUEST-000-UNKNOWN-GROUP.conf",
}

func TestCRSCategoryCodesAreStableAndLocalized(t *testing.T) {
	seen := map[string]string{}
	for _, filename := range crsCategorySampleFilenames {
		code := CategorizeCRSFile(filename)
		if hanPattern.MatchString(code) {
			t.Errorf("%s → %q 含汉字：后端只能下发稳定码", filename, code)
		}
		if !enumCodeFormat.MatchString(code) {
			t.Errorf("%s → %q 不符合稳定码形态（域.驼峰名）", filename, code)
		}
		if prev, ok := seen[code]; ok {
			t.Errorf("分类码 %q 被 %s 与 %s 共用（分类失去区分度）", code, prev, filename)
		}
		seen[code] = filename
	}
	if len(seen) != len(CRSCategoryCodes) {
		t.Fatalf("样本覆盖 %d 个分类码，CRSCategoryCodes 有 %d 个——样本/清单不同步", len(seen), len(CRSCategoryCodes))
	}
	for _, code := range CRSCategoryCodes {
		if _, ok := seen[code]; !ok {
			t.Errorf("CRSCategoryCodes 中的 %q 无样本覆盖（死码或样本缺失）", code)
		}
	}

	zh := readWebLocale(t, "zh", "common.ts")
	en := readWebLocale(t, "en", "common.ts")
	for _, code := range CRSCategoryCodes {
		suffix := strings.TrimPrefix(code, "ruleset.")
		assertLocaleEntry(t, zh, "zh", "common.ts", suffix, "flat")
		assertLocaleEntry(t, en, "en", "common.ts", suffix, "flat")
	}
}

// goStringLiterals 返回文件内全部字符串常量字面量（解转义；AST 口径，注释不计）。
func goStringLiterals(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s: %v", path, err)
	}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err == nil {
			out = append(out, value)
		}
		return true
	})
	return out
}

// TestCRSCategorySourceHasNoChineseDictionary 钉住分类字典只在码表：分类函数
// CategorizeCRSFile 的每个返回常量都必须是无汉字的 `ruleset.*` 稳定码（分类
// 中文已迁到前端词条）。函数体的其他中文字符串（日志/注释文案）不在本门内。
func TestCRSCategorySourceHasNoChineseDictionary(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "crs_rule_index.go", nil, 0)
	if err != nil {
		t.Fatalf("解析 crs_rule_index.go: %v", err)
	}
	var categorize *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "CategorizeCRSFile" {
			categorize = fn
			break
		}
	}
	if categorize == nil {
		t.Fatal("crs_rule_index.go 缺 CategorizeCRSFile（守卫定位失效）")
	}
	// 常量名 → 值（同文件的字符串常量声明）：分类函数通常返回命名常量。
	constValues := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if i >= len(value.Values) {
					continue
				}
				lit, ok := value.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if unquoted, err := strconv.Unquote(lit.Value); err == nil {
					constValues[name.Name] = unquoted
				}
			}
		}
	}
	codeSet := map[string]bool{}
	for _, code := range CRSCategoryCodes {
		codeSet[code] = true
	}
	returned := map[string]int{}
	returns := 0
	ast.Inspect(categorize.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		returns++
		var value string
		switch result := ret.Results[0].(type) {
		case *ast.BasicLit:
			if result.Kind != token.STRING {
				t.Errorf("CategorizeCRSFile 返回非字符串字面量 %s", result.Value)
				return true
			}
			unquoted, err := strconv.Unquote(result.Value)
			if err != nil {
				t.Errorf("CategorizeCRSFile 返回不可解字符串 %s: %v", result.Value, err)
				return true
			}
			value = unquoted
		case *ast.Ident:
			constValue, ok := constValues[result.Name]
			if !ok {
				t.Errorf("CategorizeCRSFile 返回未在本文件声明的标识符 %s（分类必须是固定码常量）", result.Name)
				return true
			}
			value = constValue
		default:
			t.Errorf("CategorizeCRSFile 返回非常量表达式（%T）：分类必须是固定码表", ret.Results[0])
			return true
		}
		if hanPattern.MatchString(value) || !enumCodeFormat.MatchString(value) {
			t.Errorf("CategorizeCRSFile 返回 %q——必须是 ruleset.* 稳定码（中文文案属前端词条）", value)
		}
		if !codeSet[value] {
			t.Errorf("CategorizeCRSFile 返回 %q 未登记在 CRSCategoryCodes（码表与分支不同步）", value)
		}
		returned[value]++
		return true
	})
	if returns != len(CRSCategoryCodes) {
		t.Errorf("CategorizeCRSFile 有 %d 个返回点，CRSCategoryCodes 有 %d 项——分支与码表不同步", returns, len(CRSCategoryCodes))
	}
	for code := range codeSet {
		if returned[code] == 0 {
			t.Errorf("CRSCategoryCodes 的 %q 无返回点（死码）", code)
		}
	}
}

func TestBuiltinBlockPageDisplayKeysAreStableAndLocalized(t *testing.T) {
	ids := map[int]bool{}
	keys := map[string]bool{}
	for _, identity := range models.BuiltinBlockPageIdentities {
		if ids[identity.ID] {
			t.Errorf("内置拦截页 id %d 重复登记", identity.ID)
		}
		ids[identity.ID] = true
		if keys[identity.NameKey] {
			t.Errorf("内置拦截页显示码 %q 重复", identity.NameKey)
		}
		keys[identity.NameKey] = true
		if hanPattern.MatchString(identity.NameKey) || !enumCodeFormat.MatchString(identity.NameKey) {
			t.Errorf("内置拦截页 %d 显示码 %q 不合规（应形如 block_page.xxx）", identity.ID, identity.NameKey)
		}
		if identity.Name == "" {
			t.Errorf("内置拦截页 %d 缺中文库存名（播种/自愈身份判据）", identity.ID)
		}
	}
	if !ids[models.BlockPageDefaultID] || !ids[models.BlockPageRatelimitQueueID] {
		t.Fatalf("内置页清单必须含默认页与排队等待页（id 1 / 9007），实际 %v", ids)
	}
	for _, id := range []int{9001, 9002, 9005, 9006} {
		if !ids[id] {
			t.Errorf("内置页清单缺 id %d", id)
		}
	}

	zh := readWebLocale(t, "zh", "security.ts")
	en := readWebLocale(t, "en", "security.ts")
	for key := range keys {
		suffix := strings.TrimPrefix(key, "block_page.")
		assertLocaleEntry(t, zh, "zh", "security.ts", suffix, "object")
		assertLocaleEntry(t, en, "en", "security.ts", suffix, "object")
	}
}

// TestBuiltinBlockPageNamesSingleSource 钉住库存中文名只存在 models 单源：
// 其余生产代码（internal 下非测试 Go 文件）不得再写一份。
func TestBuiltinBlockPageNamesSingleSource(t *testing.T) {
	// 只校验清单里的 5 个备选页库存名（默认页中文名仍在 schema INSERT 字面量里，
	// 该行身份=is_default=1、展示走同一个 models 显示码，见报告说明）。
	names := []string{"限流拦截页面", "系统维护页面", "滑块人机验证页面", "JS 人机验证页面", "限流排队等待页"}
	allowed := map[string]bool{
		filepath.Join("models", "security.go"): true,
	}
	root, err := filepath.Abs(filepath.Join(".."))
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if allowed[rel] {
			return nil
		}
		for _, literal := range goStringLiterals(t, path) {
			for _, name := range names {
				if strings.Contains(literal, name) {
					t.Errorf("%s 出现内置拦截页库存名 %q——身份单源在 models/security.go", rel, name)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("扫描 internal 生产源码: %v", err)
	}
}

func TestTaskDisplayKeysCoverRegisteredTasks(t *testing.T) {
	te := newWireTestEngine(t)
	registered := map[string]bool{}
	keys := map[string]bool{}
	for _, meta := range te.DescribeAll() {
		registered[meta.ID] = true
		key, ok := taskDisplayKeys[meta.ID]
		if !ok {
			t.Errorf("任务 %s（%s）缺显示稳定码——新任务族必须登记 taskDisplayKeys", meta.ID, meta.Name)
			continue
		}
		if hanPattern.MatchString(key) || !enumCodeFormat.MatchString(key) {
			t.Errorf("任务 %s 显示码 %q 不合规（应形如 task.xxx）", meta.ID, key)
		}
		if keys[key] {
			t.Errorf("任务显示码 %q 重复", key)
		}
		keys[key] = true
	}
	for id := range taskDisplayKeys {
		if !registered[id] {
			t.Errorf("taskDisplayKeys 登记了未注册的任务 id %q（死条目）", id)
		}
	}
	if len(registered) < 25 {
		t.Fatalf("注册任务仅 %d 个，注册表未装载完整——守卫会假绿", len(registered))
	}

	zhNames := readWebLocale(t, "zh", "misc.ts")
	enNames := readWebLocale(t, "en", "misc.ts")
	zhDesc := readWebLocale(t, "zh", "common.ts")
	enDesc := readWebLocale(t, "en", "common.ts")
	for key := range keys {
		suffix := strings.TrimPrefix(key, "task.")
		for locale, content := range map[string]string{"zh": zhNames, "en": enNames} {
			assertLocaleEntry(t, content, locale, "misc.ts", suffix, "flat")
		}
		for locale, content := range map[string]string{"zh": zhDesc, "en": enDesc} {
			assertLocaleEntry(t, content, locale, "common.ts", suffix, "flat")
		}
	}
}
