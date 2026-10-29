package services

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// testOnlyEntryList 是「宿主应在 *_test.go」的入口名单：产品文件以 FuncDecl
// 或包级 var/const 形态声明名单内名字、且声明文档未带 //testseam: 标记即违规。
//
// 两类登记通道：
//   - 名单：曾经迁移过/点名禁止回迁的入口（搬回产品文件即报错）；
//   - //testseam: 文档标记：有意留在产品文件的测试缝（跨包测试消费的导出
//     入口、生产路径自增的观测计数器等无法迁走的形态）就地登记——名单内
//     名字带标记视为已登记放行，不带即违规。标记用在名字不含 ForTest 的
//     声明上属误用，同样报错（防标记腐化）。
//
// 形态覆盖 FuncDecl（含方法）与 var/const（ValueSpec）：var 形态的测试缝
// （计数器/钩子变量）此前完全无机械拦截。
var testOnlyEntryList = map[string]bool{
	"StopLogRotate":         true,
	"logCleanupSummaryLine": true,
	"taskLogsHousekeeping":  true,
	"parseRuleLabelMetrics": true,
	"storeRuleMetricsText":  true,
	"updateOverview":        true,
	// 已迁到 *_test.go 的入口登记为绊线：搬回产品文件（含方法形态，
	// FuncDecl 同时覆盖 Recv!=nil）即报错。
	"parsePrometheusMetrics":     true,
	"estimateLatencyPercentiles": true,
	"upsertCrawlerIPList":        true,
	"upsertCrawlerIPListChanged": true,
	// 自动封禁单事件喂入测试缝（生产摄取只走 autobanObserveBatch）：
	// 宿主已迁到 autoban_testonly_helpers_test.go。
	"autobanObserveEvent":       true,
	"autobanObserveEventScoped": true,
	// 安全事件 spool 测试缝（有意留驻产品文件：Reset 入口被 handlers 测试
	// 跨包消费、计数器由生产读取路径自增供测试观测——宿主不可能在 *_test.go）。
	"ResetSecurityEventsSpoolStateForTest":           true,
	"resetSecurityEventsSpoolEntryCountCacheForTest": true,
	"securityEventsSpoolEntryReadBytesForTest":       true,
	// crawler 快照交换文件测试缝（导出入口被 handlers 测试跨包消费，返回
	// 还原闭包；同带 //testseam: 标记）。
	"SetCrawlerIPListFileForTest": true,
}

// productTestOnlyViolations 扫描单个产品文件源码，返回违规描述（空切片=通过）。
// 判定：
//  1. 名单内名字以 FuncDecl 或包级 var/const 形态声明、文档无 //testseam: → 违规；
//  2. 声明文档带 //testseam: 但名字不含 ForTest → 标记误用违规。
func productTestOnlyViolations(filename string, src []byte, list map[string]bool) []string {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		return []string{fmt.Sprintf("parse %s: %v", filename, err)}
	}
	hasTestseam := func(doc *ast.CommentGroup) bool {
		if doc == nil {
			return false
		}
		for _, comment := range doc.List {
			if strings.Contains(comment.Text, "testseam:") {
				return true
			}
		}
		return false
	}
	var violations []string
	flag := func(name, kind string, doc *ast.CommentGroup) {
		marked := hasTestseam(doc)
		if marked && !strings.Contains(name, "ForTest") {
			violations = append(violations, fmt.Sprintf(
				"%s:%s %q 带 //testseam: 标记但名字不含 ForTest——标记误用（只用于 test-only 缝登记）", filename, kind, name))
			return
		}
		if list[name] && !marked {
			violations = append(violations, fmt.Sprintf(
				"%s:%s %q 在绊线名单且无 //testseam: 登记——宿主应为 *_test.go，或就地加 //testseam: 标记（跨包消费/生产自增的留驻缝）",
				filename, kind, name))
		}
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			flag(d.Name.Name, "func", d.Doc)
		case *ast.GenDecl:
			if d.Tok != token.VAR && d.Tok != token.CONST {
				continue
			}
			for _, spec := range d.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				doc := valueSpec.Doc
				if doc == nil {
					doc = d.Doc
				}
				for _, name := range valueSpec.Names {
					flag(name.Name, d.Tok.String(), doc)
				}
			}
		}
	}
	return violations
}

// TestServicePackageHasNoProductionTestOnlyEntryPoints 产品文件（非 *_test.go）
// 不得承载未登记的 test-only 入口。留在生产文件里会让「生产调用面」判断
// 失真——误复用即把已被优化掉的旧形态重新拉回主链，且无调用点可核对。
func TestServicePackageHasNoProductionTestOnlyEntryPoints(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, violation := range productTestOnlyViolations(name, src, testOnlyEntryList) {
			t.Error(violation)
		}
	}
}

// 绊线自测：全形态覆盖——名单内名字的 var 形态必须被拦（此前只覆盖
// FuncDecl）、func 形态仍被拦、//testseam: 标记放行名单内名字、标记误用
// （标在非 ForTest 名字上）必须被拦。
func TestProductTestOnlyViolations_coversVarShapeAndTestseamMarker(t *testing.T) {
	list := map[string]bool{
		"autobanObserveEvent":                      true,
		"securityEventsSpoolEntryReadBytesForTest": true,
	}
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"名单函数形态仍被拦", "package services\n\nfunc autobanObserveEvent() {}\n", 1},
		{"名单 var 形态被拦", "package services\n\nvar autobanObserveEvent int\n", 1},
		{"名单 const 形态被拦", "package services\n\nconst autobanObserveEvent = 1\n", 1},
		{"标记放行名单内缝", "package services\n\n// testseam: 生产自增观测计数器。\nvar securityEventsSpoolEntryReadBytesForTest int\n", 0},
		{"标记误用被拦", "package services\n\n// testseam: 误标。\nvar notASeam = 1\n", 1},
		{"名单外无标记不拦", "package services\n\nvar someOtherVar = 1\n\nfunc someOtherFunc() {}\n", 0},
	}
	for _, tc := range cases {
		if got := len(productTestOnlyViolations("craft.go", []byte(tc.src), list)); got != tc.want {
			t.Fatalf("%s: violations=%d, want %d\nsrc:\n%s\nviolations: %v",
				tc.name, got, tc.want, tc.src, productTestOnlyViolations("craft.go", []byte(tc.src), list))
		}
	}
}
