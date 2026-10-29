package wafiplist

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// seamAllowlist 是「有意留驻产品文件的测试缝」名单：生产路径自增的观测
// 计数器与 os.Stat 的计数包装无法迁到 *_test.go（宿主即生产读写路径），
// 就地以 //testseam: 文档标记登记。名单与标记双向校验：
//   - 名单内名字出现在产品文件但文档无 //testseam: → 违规（登记被摘）；
//   - 产品文件新增带 ForTest 字样的声明而不在名单 → 违规（未登记的新缝）；
//   - 标记出现在名单外且名字不含 ForTest 的声明上 → 标记误用违规（防标记
//     腐化成任意豁免通道）。
//
// 与 internal/services / caddygeoip 的同型守卫对齐（本包此前无守卫，
// 测试计数缝驻留生产解析/热路径无机器登记）。名单内符号的既有测试语义
// （构建期去重、逐条目单次解析、stat 单飞）依赖其判定，禁止直接删除。
var seamAllowlist = map[string]bool{
	"parseCountForTest":      true,
	"parseEntryCallsForTest": true,
	"ipListStatCalls":        true,
	"statIPListFile":         true,
}

// productTestSeamViolations 扫描单个产品文件源码，返回违规描述（空切片=通过）。
func productTestSeamViolations(filename string, src []byte, allowlist map[string]bool) []string {
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
		inList := allowlist[name]
		switch {
		case inList && !marked:
			violations = append(violations, fmt.Sprintf(
				"%s:%s %q 在测试缝名单且无 //testseam: 登记——迁移宿主或就地补标记",
				filename, kind, name))
		case marked && !inList && !strings.Contains(name, "ForTest"):
			violations = append(violations, fmt.Sprintf(
				"%s:%s %q 带 //testseam: 标记但既不在名单、名字也不含 ForTest——标记误用（防任意豁免通道）",
				filename, kind, name))
		case strings.Contains(name, "ForTest") && !inList && !marked:
			violations = append(violations, fmt.Sprintf(
				"%s:%s %q 产品文件声明 test-only 符号未登记——迁到 *_test.go，或（生产路径自增的观测缝）就地加 //testseam: 并入名单",
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

// TestWafiplistHasNoUnregisteredTestOnlySymbols 产品文件（非 *_test.go）不得
// 承载未登记的 test-only 符号；名单内的缝必须保留 //testseam: 标记。
func TestWafiplistHasNoUnregisteredTestOnlySymbols(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for _, violation := range productTestSeamViolations(name, src, seamAllowlist) {
			t.Error(violation)
		}
	}
	// 正向控制：扫描面为空说明目录/后缀判定漂移，判定恒绿即假门。
	if scanned == 0 {
		t.Fatal("未扫描到任何产品 .go 文件——守卫退化为空转")
	}
}

// TestProductTestSeamViolations_shapes 守卫自测：名单缺标记被拦、标记误用
// 被拦、未登记 ForTest 新缝（var 与 func 双形态）被拦、名单外无标记放行。
func TestProductTestSeamViolations_shapes(t *testing.T) {
	list := map[string]bool{"parseCountForTest": true}
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"名单内缺标记被拦", "package wafiplist\n\nvar parseCountForTest int\n", 1},
		{"名单内带标记放行", "package wafiplist\n\n// testseam: 观测计数。\nvar parseCountForTest int\n", 0},
		{"标记误用被拦", "package wafiplist\n\n// testseam: 误标。\nvar notASeam int\n", 1},
		{"未登记 ForTest var 被拦", "package wafiplist\n\nvar newCounterForTest int\n", 1},
		{"未登记 ForTest func 被拦", "package wafiplist\n\nfunc helperForTest() {}\n", 1},
		{"名单外无标记放行", "package wafiplist\n\nvar plain int\n\nfunc plainFn() {}\n", 0},
	}
	for _, tc := range cases {
		got := productTestSeamViolations("craft.go", []byte(tc.src), list)
		if len(got) != tc.want {
			t.Fatalf("%s: violations=%d, want %d\nsrc:\n%s\nviolations: %v",
				tc.name, len(got), tc.want, tc.src, got)
		}
	}
}
