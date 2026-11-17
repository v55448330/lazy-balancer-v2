package handlers

// 任务日志截断提示行三载体对账钉：certjobs 证书任务日志端点、taskmonitor
// 统一任务日志端点与 apidocs 文档披露的截断提示必须同文案（用户跨端点排障
// 时同一事实同一呈现），且与 256KB 预算口径一致。mcpserver 的
// get_system_task_logs/get_cert_job_logs 工具描述复用同一提示行字面量
//（代理转发 handler，无独立截断实现）——第四面一并钉住。此前各写点字面量
// 各自维护，单侧改文案/预算另一侧静默分叉无守卫。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
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
	// 第三载体：apidocs 两条日志端点的披露文案必须含同一提示行与 256KB 预算。
	docsNode, err := parser.ParseFile(fset, "apidocs.go", nil, 0)
	if err != nil {
		t.Fatalf("parse apidocs.go: %v", err)
	}
	docHits := 0
	ast.Inspect(docsNode, func(n ast.Node) bool {
		comp, ok := n.(*ast.CompositeLit)
		if !ok || len(comp.Elts) < 8 {
			return true
		}
		route, ok := comp.Elts[1].(*ast.BasicLit)
		if !ok || route.Kind != token.STRING {
			return true
		}
		if route.Value != `"/system/tasks/:id/logs"` && route.Value != `"/certificates/jobs/:id/logs"` {
			return true
		}
		// 披露文案是条目末位字段（描述列）——提示行与预算口径在此钉。
		desc, ok := comp.Elts[len(comp.Elts)-1].(*ast.BasicLit)
		if !ok || !strings.Contains(desc.Value, wantNotice) || !strings.Contains(desc.Value, "256KB") {
			t.Errorf("apidocs %s 披露缺少截断提示/预算口径", route.Value)
		}
		docHits++
		return true
	})
	if docHits != 2 {
		t.Fatalf("apidocs 日志端点披露命中 %d/2——路由改名/披露移除须同步本钉", docHits)
	}
	found++
	// 第四面：mcpserver 工具描述复用同一提示行（get_system_task_logs 代理
	// GetSystemTaskLogs，无独立截断实现——钉复用接线文案一致性）。
	for _, file := range []string{"server.go", "tools.go"} {
		raw, err := os.ReadFile(filepath.Join("..", "mcpserver", file))
		if err != nil {
			t.Fatalf("read mcpserver/%s: %v", file, err)
		}
		for _, tool := range []string{"get_system_task_logs", "get_cert_job_logs"} {
			idx := strings.Index(string(raw), tool)
			if idx < 0 {
				t.Fatalf("mcpserver/%s 缺少 %s 工具登记", file, tool)
			}
			seg := string(raw)[idx:]
			if end := strings.Index(seg, "\n"); end > 0 {
				seg = seg[:end]
			}
			if !strings.Contains(seg, wantNotice) {
				t.Errorf("mcpserver/%s %s 描述缺少截断提示行 %q（复用接线文案分叉）", file, tool, wantNotice)
			}
		}
	}
	if found != 3 {
		t.Fatalf("截断提示载体命中 %d/3——扫描面退化", found)
	}
}
