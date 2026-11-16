package handlers

// 任务日志截断提示行三载体对账钉：certjobs 证书任务日志端点与 taskmonitor
// 统一任务日志端点的截断提示必须同文案（用户跨端点排障时同一事实同一呈现），
// 且与 apidocs 披露的 256KB 预算口径一致。此前两写点字面量各自维护，
// 单侧改文案/预算另一侧静默分叉无守卫。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestTaskLogTruncationNotice_threeCarriersConsistent(t *testing.T) {
	const wantNotice = "[日志过长，仅显示最近 256KB]"
	fset := token.NewFileSet()
	carriers := map[string]string{
		"certjobs.go":    "GetCertJobLogs",
		"taskmonitor.go": "GetSystemTaskLogs",
	}
	found := 0
	for file, fn := range carriers {
		node, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		hit := false
		for _, decl := range node.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name.Name != fn {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if ok && lit.Kind == token.STRING && strings.Contains(lit.Value, "日志过长，仅显示最近") {
					if !strings.Contains(lit.Value, wantNotice) {
						t.Errorf("%s:%s 截断提示=%s, want 含 %q（三载体同文案）", file, fn, lit.Value, wantNotice)
					}
					hit = true
				}
				return true
			})
		}
		if !hit {
			t.Errorf("%s:%s 未找到截断提示写点——函数改名/提示移除须同步本钉", file, fn)
		} else {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("截断提示载体命中 %d/2——扫描面退化", found)
	}
}
