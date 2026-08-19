package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 操作日志词汇硬卡控（系统标准：操作标签 ≤4 词、事件对象 ≤5 词，词制计数见
// auditVocabWords）。扫描 internal/ 全部非测试源码，提取 RecordAuditLog /
// recordAudit / recordSystemAudit 的字面量词条与 FormatAuditAction 的返回
// 字面量逐一校验——新增超标词条此测试直接红。变量词条仅放行已核清的动态
// 调用点，其余动态传参视为违规（强制新调用点用字面量，保持可扫描）。

// auditVocabDynamicAllowlist 是已人工核清的动态词条调用点（键为相对 internal/
// 的路径 + 参数下标）：
//   - handlers/audit.go 与 middleware 是 recordAudit/RecordAuditLog 的透传封装；
//   - handlers/caddy.go 的对象变量取自 GetConfigSection/GetConfigSourceSection
//     （ACME全局设置/Caddy全局配置/基础设置/全局配置/集群管理，均 ≤5 词）；
//   - handlers/cluster_registration.go 的动作形参实参仅有 审批/拒绝/删除/更新地址；
//   - handlers/config_backup.go 与 config_import_v1.go 的动作变量取值仅有
//     导入失败/部分失败；
//   - services/certificates.go 的动作变量取值仅有 续签排队/重试排队；
//   - services/downloadintegrity.go 的对象变量由调用方传入字面量（CRS规则库/
//     IP2Region数据库，已纳入扫描）。
var auditVocabDynamicAllowlist = map[string]map[int]bool{
	"handlers/audit.go":                {1: true, 2: true},
	"middleware/middleware.go":         {1: true, 2: true},
	"handlers/caddy.go":                {2: true},
	"handlers/cluster_registration.go": {1: true},
	"handlers/config_backup.go":        {1: true},
	"handlers/config_import_v1.go":     {1: true},
	"services/certificates.go":         {1: true},
	"services/downloadintegrity.go":    {2: true},
}

// auditVocabCallSpecs 给出各审计写入口的 动作/对象 参数下标。
var auditVocabCallSpecs = map[string][2]int{
	"RecordAuditLog":    {1, 2},
	"recordAudit":       {1, 2},
	"recordSystemAudit": {0, 1},
}

func auditVocabStringLit(e ast.Expr) (string, bool) {
	b, ok := e.(*ast.BasicLit)
	if !ok || b.Kind != token.STRING {
		return "", false
	}
	return strings.Trim(b.Value, "\""), true
}

func TestAuditVocabulary_wordLimits(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	var violations []string
	check := func(file string, line int, kind, value string, limit int) {
		if n := auditVocabWords(value); n > limit {
			violations = append(violations, file+":"+strconv.Itoa(line)+" "+kind+" "+strconv.Quote(value)+" 超上限（"+strconv.Itoa(n)+" 词 > "+strconv.Itoa(limit)+"）")
		}
	}
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Errorf("parse %s: %v", path, err)
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				var name string
				switch fn := node.Fun.(type) {
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				case *ast.Ident:
					name = fn.Name
				}
				spec, ok := auditVocabCallSpecs[name]
				if !ok {
					return true
				}
				for _, arg := range []struct {
					idx   int
					kind  string
					limit int
				}{{spec[0], "操作标签", auditActionMaxWords}, {spec[1], "事件对象", auditResourceMaxWords}} {
					if arg.idx >= len(node.Args) {
						continue
					}
					line := fset.Position(node.Pos()).Line
					if value, ok := auditVocabStringLit(node.Args[arg.idx]); ok {
						if value != "" {
							check(path, line, arg.kind, value, arg.limit)
						}
						continue
					}
					if !auditVocabDynamicAllowlist[rel][arg.idx] {
						violations = append(violations, path+":"+strconv.Itoa(line)+" "+arg.kind+" 为动态表达式且不在已核清白名单，请改用字面量词条")
					}
				}
			case *ast.FuncDecl:
				if node.Name.Name != "FormatAuditAction" || node.Body == nil {
					return true
				}
				ast.Inspect(node.Body, func(inner ast.Node) bool {
					ret, ok := inner.(*ast.ReturnStmt)
					if !ok || len(ret.Results) < 2 {
						return true
					}
					line := fset.Position(ret.Pos()).Line
					if value, ok := auditVocabStringLit(ret.Results[0]); ok && value != "" {
						check(path, line, "操作标签", value, auditActionMaxWords)
					}
					if value, ok := auditVocabStringLit(ret.Results[1]); ok && value != "" {
						check(path, line, "事件对象", value, auditResourceMaxWords)
					}
					return true
				})
				return false
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("操作日志词汇超标（标准：操作标签 ≤%d 词、事件对象 ≤%d 词）：\n%s", auditActionMaxWords, auditResourceMaxWords, strings.Join(violations, "\n"))
	}
}
