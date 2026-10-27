package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestServicePackageHasNoProductionTestOnlyEntryPoints 产品文件（非 *_test.go）
// 不得承载 test-only 入口：这些函数只被测试消费，宿主应是同包测试文件
// （编译进测试二进制，不进产品符号表）。留在生产文件里会让「生产调用面」
// 判断失真——误复用即把已被优化掉的旧形态（如每周期两次 DB 刷新的整包
// 入口）重新拉回主链，且无调用点可核对。
func TestServicePackageHasNoProductionTestOnlyEntryPoints(t *testing.T) {
	testOnly := map[string]bool{
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
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !testOnly[fn.Name.Name] {
				continue
			}
			t.Errorf("%s:%d 产品文件声明 test-only 入口 %s——请移到 *_test.go（同包测试可访问未导出符号）",
				name, fset.Position(fn.Pos()).Line, fn.Name.Name)
		}
	}
}
