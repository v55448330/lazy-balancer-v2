package services

// 审计动作 → 前端标签颜色映射契约（R49 D 域 S-1）：actionTagType 的颜色白名单
// 长期靠人肉与后端词条 diff 维护，已连续三轮审计（R47 漏 9、R48 漏 7、R49 漏 2）
// 发现漏映射。本测试把契约固化为 CI 卡口：
//  1. 用与 audit_vocabulary_test.go 相同的 AST 扫描提取后端全部可落库动作词条
//     （RecordAuditLog/recordAudit/recordSystemAudit 字面量 + FormatAuditAction
//     返回字面量 + 动态 allowlist 词条的取值解析）；
//  2. 解析 web/src/views/AuditLog.vue 的 actionTagType 三段 if 白名单；
//  3. 断言每个后端动作都有前端映射（任意颜色），且语义分类契约成立：
//     以「失败」结尾的动作与 {配置漂移, 应用失败, 部署失败, 认证拒绝, 提升失败}
//     必须落在 danger 行。新增未映射/误分类动作此测试直接红。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// auditMappingNeverPersisted 是提取到但永不落库、因此无需前端映射的动作：
// 「登录」仅是 FormatAuditAction 对 POST /api/v1/auth/login 的兜底映射——该路由
// 命中 middleware.go auditMiddleware 的 HasExplicitAuditEvent 跳过分支
// （auditpolicy.go:125），实际落库的是 auth.go 显式记录的 登录成功/登录失败。
var auditMappingNeverPersisted = map[string]bool{"登录": true}

// auditMappingDangerContract 是不以「失败」结尾但必须 danger 分类的动作（与
// 前端 danger 行的语义约定）。
var auditMappingDangerContract = map[string]bool{
	"配置漂移": true, "应用失败": true, "部署失败": true, "认证拒绝": true, "提升失败": true,
}

// auditDynamicCallSite 记录一个动作参数为动态表达式的审计写入口调用点。
type auditDynamicCallSite struct {
	enclosing string
	argIdent  string
}

// backendAuditActions 提取后端全部可落库动作词条，返回 动作 → 首处证据位置。
func backendAuditActions(t *testing.T) map[string]string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	actions := map[string]string{}
	add := func(file string, line int, value string) {
		if value == "" || auditMappingNeverPersisted[value] {
			return
		}
		if _, exists := actions[value]; !exists {
			rel, _ := filepath.Rel(root, file)
			actions[value] = rel + ":" + strconv.Itoa(line)
		}
	}
	type parsedFile struct {
		fset  *token.FileSet
		file  *ast.File
		funcs map[string]*ast.FuncDecl
	}
	parsed := map[string]*parsedFile{}
	var dynamicSites []auditDynamicCallSite
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
		pf := &parsedFile{fset: fset, file: f, funcs: map[string]*ast.FuncDecl{}}
		parsed[path] = pf
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.FuncDecl)
			if !ok || d.Body == nil {
				continue
			}
			pf.funcs[d.Name.Name] = d
			if d.Name.Name == "FormatAuditAction" {
				ast.Inspect(d.Body, func(inner ast.Node) bool {
					ret, ok := inner.(*ast.ReturnStmt)
					if !ok || len(ret.Results) < 1 {
						return true
					}
					if value, ok := auditVocabStringLit(ret.Results[0]); ok && value != "" {
						add(path, fset.Position(ret.Pos()).Line, value)
					}
					return true
				})
				continue
			}
			ast.Inspect(d.Body, func(n ast.Node) bool {
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
				if !ok || spec[0] >= len(call.Args) {
					return true
				}
				arg := call.Args[spec[0]]
				if value, ok := auditVocabStringLit(arg); ok {
					add(path, fset.Position(call.Pos()).Line, value)
					return true
				}
				if ident, ok := arg.(*ast.Ident); ok {
					dynamicSites = append(dynamicSites, auditDynamicCallSite{enclosing: d.Name.Name, argIdent: ident.Name})
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}

	// 解析动态动作实参的取值（auditVocabDynamicAllowlist 已核清的全部调用点）：
	//  1. 赋值解析：同一函数体内赋给该标识符的字符串字面量
	//     （renewExpiringCertificates 的 action、ImportConfigBackup/ImportV1Config
	//     的 auditAction）；
	//  2. 透传解析：动态实参是外层函数的形参时，按形参位次提取该函数全部调用点
	//     的字面量实参（clusterNodeAction 的 审批/拒绝/删除/更新地址、recordAudit
	//     封装——后者的调用点本身已在上面按字面量提取，重复收集无害）。
	// auditMiddleware 的动态值来自 FormatAuditAction（已按返回字面量提取），
	// 两种解析均为空属预期。
	for _, site := range dynamicSites {
		for path, pf := range parsed {
			fn, ok := pf.funcs[site.enclosing]
			if !ok {
				continue
			}
			// 赋值解析
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, lhs := range assign.Lhs {
					ident, ok := lhs.(*ast.Ident)
					if !ok || ident.Name != site.argIdent || i >= len(assign.Rhs) {
						continue
					}
					if value, ok := auditVocabStringLit(assign.Rhs[i]); ok {
						add(path, pf.fset.Position(assign.Pos()).Line, value)
					}
				}
				return true
			})
			// 形参位次
			paramPos := -1
			if fn.Type.Params != nil {
				pos := 0
				for _, field := range fn.Type.Params.List {
					for _, paramName := range field.Names {
						if paramName.Name == site.argIdent && paramPos < 0 {
							paramPos = pos
						}
						pos++
					}
				}
			}
			if paramPos < 0 {
				continue
			}
			for callerPath, callerPf := range parsed {
				ast.Inspect(callerPf.file, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok || paramPos >= len(call.Args) {
						return true
					}
					var name string
					switch fun := call.Fun.(type) {
					case *ast.SelectorExpr:
						name = fun.Sel.Name
					case *ast.Ident:
						name = fun.Name
					}
					if name != site.enclosing {
						return true
					}
					if value, ok := auditVocabStringLit(call.Args[paramPos]); ok {
						add(callerPath, callerPf.fset.Position(call.Pos()).Line, value)
					}
					return true
				})
			}
		}
	}
	return actions
}

var (
	auditTagColorLineRe  = regexp.MustCompile(`return '(success|warning|danger|info)'`)
	auditTagActionLineRe = regexp.MustCompile(`action === '([^']+)'`)
)

// frontendAuditTagMapping 解析 AuditLog.vue 的 actionTagType：逐行匹配
// `action === '...' || ... return '<color>'` 形态的白名单 if 行，返回 动作 → 颜色。
func frontendAuditTagMapping(t *testing.T) map[string]string {
	t.Helper()
	path := filepath.Join("..", "..", "web", "src", "views", "AuditLog.vue")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read AuditLog.vue: %v", err)
	}
	mapping := map[string]string{}
	colors := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		colorMatch := auditTagColorLineRe.FindStringSubmatch(line)
		if colorMatch == nil || !strings.Contains(line, "action ===") {
			continue
		}
		color := colorMatch[1]
		colors[color] = true
		for _, m := range auditTagActionLineRe.FindAllStringSubmatch(line, -1) {
			if _, exists := mapping[m[1]]; exists {
				t.Errorf("前端动作 %q 被映射到多个颜色（含 %s）——白名单重复", m[1], color)
				continue
			}
			mapping[m[1]] = color
		}
	}
	for _, want := range []string{"success", "warning", "danger"} {
		if !colors[want] {
			t.Fatalf("actionTagType 解析漂移：未找到 %s 行——actionTagType 结构已改变，请同步更新本测试的解析", want)
		}
	}
	if len(mapping) < 50 {
		t.Fatalf("actionTagType 解析漂移：仅提取到 %d 个动作映射（期望 ≥50）——actionTagType 结构已改变，请同步更新本测试的解析", len(mapping))
	}
	return mapping
}

func TestAuditActionMapping_backendActionsAllMapped(t *testing.T) {
	backend := backendAuditActions(t)
	frontend := frontendAuditTagMapping(t)
	var missing []string
	for action, evidence := range backend {
		if _, ok := frontend[action]; !ok {
			missing = append(missing, action+"（首见 "+evidence+"）")
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		t.Fatalf("后端动作未在 AuditLog.vue actionTagType 映射（落库后渲染为兜底 info 灰标）：\n%s", strings.Join(missing, "\n"))
	}
	// R50 D-04：info 是「无 action ===」的兜底行，任何后端动作被显式写进 info 行
	// （如 `if (action === 'X') return 'info'`）都能通过上面的映射检查而隐藏
	// 分类错误。此处强制 info 行词条数为零——当前 info 行本就无词条，零成本绊线。
	var infoMapped []string
	for action, evidence := range backend {
		if frontend[action] == "info" {
			infoMapped = append(infoMapped, action+"（首见 "+evidence+"）")
		}
	}
	if len(infoMapped) > 0 {
		slices.Sort(infoMapped)
		t.Fatalf("后端动作不得显式映射到 info 兜底色（info 行应保持零词条）：\n%s", strings.Join(infoMapped, "\n"))
	}
}

func TestAuditActionMapping_dangerClassificationContract(t *testing.T) {
	backend := backendAuditActions(t)
	frontend := frontendAuditTagMapping(t)
	var violations []string
	for action, evidence := range backend {
		if !strings.HasSuffix(action, "失败") && !auditMappingDangerContract[action] {
			continue
		}
		if color, ok := frontend[action]; ok && color != "danger" {
			violations = append(violations, action+"（首见 "+evidence+"，前端映射为 "+color+"）")
		}
	}
	if len(violations) > 0 {
		slices.Sort(violations)
		t.Fatalf("危险语义动作必须映射到 danger 行（失败后缀或 {配置漂移, 应用失败, 部署失败, 认证拒绝, 提升失败} 契约）：\n%s", strings.Join(violations, "\n"))
	}
}
