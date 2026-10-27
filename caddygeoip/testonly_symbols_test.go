package caddygeoip

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// 产品文件（非 *_test.go）不得声明 test-only **入口**（函数/方法）。
// 本包此前的两种形态：导出的 ResetCrawlerVerifyCacheForTest 常驻生产符号表
// （可被误当成真实入口），以及生产路径调用名为 startAuditTimingSweeperForTest
// 的函数（命名把生产路径伪装成测试缝）。与 cmd/server / internal/services /
// internal/config 的同型守卫对齐。
//
// 判定面只覆盖 FuncDecl：`*ForTest` 命名的**计数变量**（geoipWarnCallsForTest、
// crawlerSnapshotLogCallsForTest 等）由生产路径自增、供测试观测，属合法形态，
// 不在此列。
func TestCaddyGeoIPHasNoProductionTestOnlyEntryPoints(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.Contains(fn.Name.Name, "ForTest") {
				continue
			}
			t.Errorf("%s:%d 产品文件声明 test-only 入口 %s——请移到 *_test.go（导出名同样禁止：生产符号表不得出现只有测试消费的函数）",
				name, fset.Position(fn.Pos()).Line, fn.Name.Name)
		}
	}
	// 正向控制：扫描面为空说明目录/后缀判定漂移，此时判定恒绿就是假门。
	if scanned == 0 {
		t.Fatal("未扫描到任何产品 .go 文件——守卫退化为空转")
	}
}
