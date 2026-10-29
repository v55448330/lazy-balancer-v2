package handlers

// handlers 包的产品文件（非 *_test.go）不得承载 test-only **入口**。
//
// 这些函数只被测试消费（复位缓存/退避/采样状态），宿主本是同包测试文件：
// 留在产品文件里会让「生产调用面」判断失真——排障时会以为它是生产路径的一环，
// 改动也只覆盖被测的那条；同时它扩展了包的导出面语义（同包测试不需要）。
//
// 注入型 seam（`var xxxForTest func(...)`）是唯一的例外：生产代码要读它决定
// 分支，只能留在产品文件。这类 seam 必须逐条登记（登记表=绊线），新增未登记
// 即报错，删除后残留登记同样报错。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"
)

// productionInjectionSeams 登记**必须**留在产品文件的注入型 seam（名字 → 生产
// 读取侧）。值只作说明，判据是键集与实测集合完全相等。
var productionInjectionSeams = map[string]string{
	"txCommitForTest":                           "submitTx 提交路径注入提交失败",
	"txRollbackForTest":                         "submitTx 回滚路径注入回滚失败",
	"ipListCommitTxForTest":                     "IP 名单提交路径注入提交失败",
	"mfaGenerateSecretForTest":                  "MFASetup 注入 TOTP 密钥生成失败",
	"pinLastGoodForTest":                        "规则生成注入「钉住 last-good」失败",
	"caddyMetricsSnapshotDoBeforeForTest":       "面板指标抓取在请求发出前注入观测/失败",
	"threatRuleNamePointQueriesForTest":         "威胁大屏按 id 点查计数（只增观测）",
	"toastSummaryBetweenMaxAndAggregateForTest": "toast 聚合区间注入并发切换",
}

func TestHandlersPackageHasNoProductionTestOnlyEntryPoints(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	scanned := 0
	forbiddenFuncs := make([]string, 0)
	foundSeams := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			switch node := decl.(type) {
			case *ast.FuncDecl:
				if strings.HasSuffix(node.Name.Name, "ForTest") {
					forbiddenFuncs = append(forbiddenFuncs, fset.Position(node.Pos()).String()+" "+node.Name.Name)
				}
			case *ast.GenDecl:
				if node.Tok != token.VAR {
					continue
				}
				for _, spec := range node.Specs {
					value, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, ident := range value.Names {
						if strings.HasSuffix(ident.Name, "ForTest") {
							foundSeams[ident.Name] = true
						}
					}
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("没有扫描到任何产品文件——目录枚举失效，本守卫会静默恒绿")
	}
	for _, entry := range forbiddenFuncs {
		t.Errorf("%s：产品文件声明 test-only 函数——请移到 *_test.go（同包测试可访问未导出符号）", entry)
	}
	registered := make([]string, 0, len(productionInjectionSeams))
	for name := range productionInjectionSeams {
		registered = append(registered, name)
	}
	found := make([]string, 0, len(foundSeams))
	for name := range foundSeams {
		found = append(found, name)
	}
	slices.Sort(registered)
	slices.Sort(found)
	if !slices.Equal(registered, found) {
		t.Fatalf("注入型 seam 登记表与实测不一致：\n登记=%v\n实测=%v\n新增 seam 必须登记（并说明生产读取侧），删除 seam 必须同步删登记", registered, found)
	}
}
