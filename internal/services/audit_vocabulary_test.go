package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// 操作日志词汇硬卡控（系统标准：操作标签 ≤4 词、事件对象 ≤5 词，词制计数见
// auditVocabWords）。扫描 internal/ 全部非测试源码，提取 RecordAuditLog /
// recordAudit / recordSystemAudit 的字面量词条与 FormatAuditAction 的返回
// 字面量逐一校验——新增超标词条此测试直接红。变量词条仅放行已核清的动态
// 调用点，其余动态传参视为违规（强制新调用点用字面量，保持可扫描）。

// auditVocabDynamicAllowlist 是已人工核清的动态词条调用点，粒度为
// 「相对 internal/ 的路径 + 参数下标 + 外层函数名」（R47 C-发现2：文件级
// 白名单会放行同文件内新增函数的动态传参，收紧到函数级后新增函数即违规）：
//   - handlers/audit.go recordAudit 与 middleware auditMiddleware 是
//     recordAudit/RecordAuditLog 的透传封装；
//   - handlers/caddy.go UpdateConfig 的对象变量取自
//     GetConfigSection/GetConfigSourceSection（ACME配置/Caddy配置/基础设置/
//     全局配置/集群管理，均 ≤5 词）；
//   - handlers/cluster_registration.go clusterNodeAction 的动作形参实参仅有
//     审批/拒绝/删除/更新地址；
//   - handlers/config_backup.go ImportConfigBackup 与 config_import_v1.go
//     ImportV1Config 的动作变量取值仅有 导入失败/部分失败；
//   - services/certificates.go renewExpiringCertificates 的动作变量取值仅有
//     续签排队/重试排队；
//   - handlers/handlers.go finishTxApply 的动作/对象取自 txApplyFinish 的字面量
//     字段（16 个调用点：动作 创建/更新/删除/写入+失败，对象 自定义规则/
//     拦截页面/安全策略/IP 地址列表，均 ≤ 上限；2026-09-06 裁定 ①② 家族 3
//     统一收尾）；
//   - services/downloadintegrity.go recordDownloadIntegrity 的对象变量由调用方
//     传入字面量（CRS规则库/IP数据库，已纳入扫描）；
var auditVocabDynamicAllowlist = map[string]map[int][]string{
	"handlers/audit.go":                {1: {"recordAudit"}, 2: {"recordAudit"}},
	"middleware/middleware.go":         {1: {"auditMiddleware"}, 2: {"auditMiddleware"}},
	"handlers/caddy.go":                {2: {"UpdateConfig"}},
	"handlers/cluster_registration.go": {1: {"clusterNodeAction"}},
	"handlers/config_backup.go":        {1: {"ImportConfigBackup"}},
	"handlers/config_import_v1.go":     {1: {"ImportV1Config"}},
	"handlers/handlers.go":             {1: {"finishTxApply"}, 2: {"finishTxApply"}},
	"services/certificates.go":         {1: {"renewExpiringCertificates"}},
	"services/downloadintegrity.go":    {2: {"recordDownloadIntegrity"}},
}

// auditVocabCallSpecs 给出各审计写入口的 动作/对象 参数下标。
// recordAuthenticationSecurityAudit 是 middleware.go:38 对 services.RecordAuditLog
// 的函数变量别名（R50 D-01：不登记则该调用点整点不被扫描，「认证拒绝」不进
// 后端动作集，danger 契约条目虚设）。
var auditVocabCallSpecs = map[string][2]int{
	"RecordAuditLog":                    {1, 2},
	"recordAudit":                       {1, 2},
	"recordSystemAudit":                 {0, 1},
	"recordAuthenticationSecurityAudit": {1, 2},
}

func auditVocabStringLit(e ast.Expr) (string, bool) {
	b, ok := e.(*ast.BasicLit)
	if !ok || b.Kind != token.STRING {
		return "", false
	}
	// 优先按 Go 语法反转义（转义形态按实际词数计数）；异常字面量回退原样剥引号。
	if unquoted, err := strconv.Unquote(b.Value); err == nil {
		return unquoted, true
	}
	return strings.Trim(b.Value, "\""), true
}

func TestAuditVocabulary_wordLimits(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	var violations []string
	// usedAllowlist 记录命中白名单的「文件|参数下标|函数」组合，测试末尾断言
	// 每个白名单条目都有真实动态调用点——条目失效（函数改名/调用点消失）即报错，
	// 防止白名单只增不减地淤积放行面。
	usedAllowlist := map[string]bool{}
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
		// checkCalls 扫描一棵子树内的审计写入口调用，违规动态传参按外层函数名
		// 归因（enclosing 为空表示包级初始化表达式，不在白名单即违规）。
		checkCalls := func(node ast.Node, enclosing string) {
			ast.Inspect(node, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var name string
				switch fn := call.Fun.(type) {
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
					if arg.idx >= len(call.Args) {
						continue
					}
					line := fset.Position(call.Pos()).Line
					if value, ok := auditVocabStringLit(call.Args[arg.idx]); ok {
						if value != "" {
							check(path, line, arg.kind, value, arg.limit)
						}
						continue
					}
					if !slices.Contains(auditVocabDynamicAllowlist[rel][arg.idx], enclosing) {
						violations = append(violations, path+":"+strconv.Itoa(line)+" "+arg.kind+" 为动态表达式且不在已核清白名单（函数 "+enclosing+"），请改用字面量词条")
					} else {
						usedAllowlist[rel+"|"+strconv.Itoa(arg.idx)+"|"+enclosing] = true
					}
				}
				return true
			})
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Name.Name == "FormatAuditAction" && d.Body != nil {
					ast.Inspect(d.Body, func(inner ast.Node) bool {
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
					continue
				}
				checkCalls(d.Body, d.Name.Name)
			case *ast.GenDecl:
				checkCalls(d, "")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
	for rel, byIndex := range auditVocabDynamicAllowlist {
		for idx, funcs := range byIndex {
			for _, fn := range funcs {
				if !usedAllowlist[rel+"|"+strconv.Itoa(idx)+"|"+fn] {
					t.Errorf("白名单条目 %s 参数 %d 函数 %s 未命中任何动态调用点——调用点已消失或改名，请同步收紧白名单", rel, idx, fn)
				}
			}
		}
	}
	if len(violations) > 0 {
		t.Fatalf("操作日志词汇超标（标准：操作标签 ≤%d 词、事件对象 ≤%d 词）：\n%s", auditActionMaxWords, auditResourceMaxWords, strings.Join(violations, "\n"))
	}
}
