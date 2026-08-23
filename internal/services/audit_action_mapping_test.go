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
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
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

// genericRouteRegistry Generic 路由的 exactly-once 登记表（R65 D-N1 引入，R66
// D-N3 提升为包级供穷尽性绊线共用）：handlerMustRecord=true 表示 handler 显式
// 记录（FormatAuditAction 映射必须为空）；false 表示中间件经映射记录（映射
// 必须非空且 handler 不得记录）。
var genericRouteRegistry = []struct {
	path              string
	handlerFunc       string
	handlerMustRecord bool
}{
	{"/api/v1/config/reload", "ReloadCaddy", true},
	{"/api/v1/system/restart", "RestartService", true},
	{"/api/v1/caddy/start", "StartCaddy", false},
	{"/api/v1/caddy/stop", "StopCaddy", false},
	{"/api/v1/caddy/restart", "RestartCaddy", false},
}

// TestAuditGenericRoutesExactlyOnce Generic 路由 exactly-once 绊线（R65 D-N1）：
// Generic 分类的路由要么由中间件记录（FormatAuditAction 有映射、handler 不得
// 再记），要么由 handler 记录（映射为空、中间件跳过）——两侧同时激活即单次
// 动作双条 audit_log（/config/reload 曾如此）。
func TestAuditGenericRoutesExactlyOnce(t *testing.T) {
	if action, _, _ := FormatAuditAction(http.MethodPost, "/api/v1/config/reload"); action != "" {
		t.Fatalf("FormatAuditAction(/config/reload)=%q, want 空（handler ReloadCaddy 已显式记录，映射非空会双条）", action)
	}
	handlersRoot, err := filepath.Abs(filepath.Join("..", "handlers"))
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range genericRouteRegistry {
		t.Run(route.path, func(t *testing.T) {
			action, _, _ := FormatAuditAction(http.MethodPost, route.path)
			if route.handlerMustRecord && action != "" {
				t.Fatalf("FormatAuditAction 映射非空 %q——handler %s 已显式记录，会双条", action, route.handlerFunc)
			}
			if !route.handlerMustRecord && action == "" {
				t.Fatalf("FormatAuditAction 映射为空——handler %s 不记录，该路由将零审计", route.handlerFunc)
			}
			found, records := scanHandlerForAuditCallDirect(t, handlersRoot, route.handlerFunc)
			if !found {
				t.Fatalf("未找到 handler 函数 %s——路由→handler 映射表可能过期", route.handlerFunc)
			}
			if route.handlerMustRecord && !records {
				t.Fatalf("handler %s 必须显式记录审计（映射为空、中间件跳过，否则零审计）", route.handlerFunc)
			}
			if !route.handlerMustRecord && records {
				t.Fatalf("handler %s 直接记录了审计——中间件已映射记录该用户动作，会双条", route.handlerFunc)
			}
		})
	}
}

// TestAuditExplicitRoutesMappingEmpty Explicit 路由映射漂移哨兵（R66 D-N3）：
// Explicit 路由由 handler 显式记录且被 HasExplicitAuditEvent 前置短路——
// FormatAuditAction 对它们必须返回空；映射非空意味着清单漂移漏掉该路由时
// 中间件会恢复映射记录，与 handler 记录叠加成双条（R65 D-N1 缺陷形态）。
func TestAuditExplicitRoutesMappingEmpty(t *testing.T) {
	for route, policy := range auditRoutePolicies {
		if policy != AuditPolicyExplicit {
			continue
		}
		method, path, ok := strings.Cut(route, " ")
		if !ok {
			t.Fatalf("策略键格式异常: %q", route)
		}
		if action, _, _ := FormatAuditAction(method, path); action != "" {
			t.Errorf("Explicit 路由 %s 的 FormatAuditAction 映射非空（%q）——handler 已显式记录，双条风险", route, action)
		}
	}
}

// TestAuditGenericRoutesExhaustive Generic 路由穷尽性绊线（R66，C 域改进项）：
// auditRoutePolicies 中每条 Generic 路由必须登记进 genericRouteRegistry——
// 新增 Generic 路由未登记时其 exactly-once 契约对测试套件不可见。
func TestAuditGenericRoutesExhaustive(t *testing.T) {
	registered := make(map[string]bool, len(genericRouteRegistry))
	for _, route := range genericRouteRegistry {
		registered[route.path] = true
		if policy, ok := auditRoutePolicies["POST "+route.path]; !ok || policy != AuditPolicyGeneric {
			t.Errorf("登记表含非 Generic 路由 %s（策略=%v）——登记表与策略清单漂移", route.path, policy)
		}
	}
	for route, policy := range auditRoutePolicies {
		_, path, ok := strings.Cut(route, " ")
		if !ok {
			t.Fatalf("策略键格式异常: %q", route)
		}
		if policy == AuditPolicyGeneric && !registered[path] {
			t.Errorf("Generic 路由 %s 未登记进 genericRouteRegistry——exactly-once 契约对该路由不可见", route)
		}
	}
}

// TestAuditPolicyListsEqual 双 Explicit 清单集合相等绊线（R66 D-N3）：
// auditRoutePolicies（Explicit 子集）与 HasExplicitAuditEvent 的 switch 清单是
// 两份手工维护的重复清单——任一侧漂移（漏删/漏加）即：前者漏→中间件按 Skip
// 不记录且 handler 以为被短路（零审计）；后者漏→中间件不短路，若 FormatAuditAction
// 有映射即双条。AST 提取 switch 的 case 字面量做双向集合相等断言。
func TestAuditPolicyListsEqual(t *testing.T) {
	switchSet := extractHasExplicitAuditEventCases(t)
	explicitSet := make(map[string]bool)
	for route, policy := range auditRoutePolicies {
		if policy == AuditPolicyExplicit {
			explicitSet[route] = true
		}
	}
	for route := range explicitSet {
		if !switchSet[route] {
			t.Errorf("策略清单含 %s 但 HasExplicitAuditEvent switch 不含——中间件不短路，映射复活即双条", route)
		}
	}
	for route := range switchSet {
		if !explicitSet[route] {
			t.Errorf("HasExplicitAuditEvent switch 含 %s 但策略清单不含——该路由零审计（中间件 Skip 且无 handler 记录约定）", route)
		}
	}
}

// TestAuditExplicitHandlersRecord Explicit 路由 handler-必须记录绊线（R66 D-N2）：
// Explicit 路由的审计完全依赖 handler 显式记录——从中间件路由注册（AST 提取
// METHOD("/path", h.Handler)）解析路由→handler 映射，断言每个 Explicit 路由的
// handler 函数体（含一层 h.X 委托，如 clusterNodeAction）包含审计记录调用；
// handler 删除记录或经未登记 helper 绕过时该路由静默零审计，本测试直接红。
func TestAuditExplicitHandlersRecord(t *testing.T) {
	registry := extractRouteHandlerRegistry(t)
	handlersRoot, err := filepath.Abs(filepath.Join("..", "handlers"))
	if err != nil {
		t.Fatal(err)
	}
	missing := 0
	for route, policy := range auditRoutePolicies {
		if policy != AuditPolicyExplicit {
			continue
		}
		handler, ok := registry[route]
		if !ok {
			t.Errorf("路由 %s 未在中间件注册表中解析到 handler——注册形态变更请同步更新提取器", route)
			missing++
			continue
		}
		found, records := scanHandlerForAuditCall(t, handlersRoot, handler)
		if !found {
			t.Errorf("未找到 handler 函数 %s（路由 %s）——路由→handler 映射过期", handler, route)
			continue
		}
		if !records {
			t.Errorf("Explicit 路由 %s 的 handler %s 不含审计记录调用——中间件已短路，该路由零审计", route, handler)
		}
	}
	if missing > 0 {
		t.Fatalf("%d 条 Explicit 路由无法解析 handler", missing)
	}
}

// extractHasExplicitAuditEventCases AST 解析 auditpolicy.go 的
// HasExplicitAuditEvent switch，提取全部 "METHOD /path" case 字面量。
func extractHasExplicitAuditEventCases(t *testing.T) map[string]bool {
	t.Helper()
	path := filepath.Join(".", "auditpolicy.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read auditpolicy.go: %v", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parse auditpolicy.go: %v", err)
	}
	cases := make(map[string]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "HasExplicitAuditEvent" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			stmt, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			for _, clause := range stmt.Body.List {
				cc, ok := clause.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, expr := range cc.List {
					if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						cases[strings.Trim(lit.Value, "`\"")] = true
					}
				}
			}
			return false
		})
	}
	if len(cases) == 0 {
		t.Fatal("未能从 HasExplicitAuditEvent 提取任何 case——函数重命名或重构请同步更新提取器")
	}
	return cases
}

// extractRouteHandlerRegistry AST 解析 middleware.go 的路由注册
// （METHOD("/path", h.Handler) 形态，v1 组前缀 /api/v1），构建
// "METHOD /api/v1/path" → handler 函数名 映射。
func extractRouteHandlerRegistry(t *testing.T) map[string]string {
	t.Helper()
	path := filepath.Join("..", "middleware", "middleware.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read middleware.go: %v", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parse middleware.go: %v", err)
	}
	methods := map[string]bool{http.MethodPost: true, http.MethodPut: true, http.MethodDelete: true, http.MethodPatch: true}
	registry := make(map[string]string)
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !methods[sel.Sel.Name] {
			return true
		}
		// 注册形态：METHOD("/path"[, middleware...], h.Handler)——路径取首个
		//字符串字面量，handler 取末参选择子（R66：auth 组带 loginRateLimit
		// 中间件为 3 参形态）。
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		handlerSel, ok := call.Args[len(call.Args)-1].(*ast.SelectorExpr)
		if !ok {
			return true
		}
		routePath := strings.Trim(lit.Value, "`\"")
		registry[sel.Sel.Name+" /api/v1"+routePath] = handlerSel.Sel.Name
		return true
	})
	if len(registry) == 0 {
		t.Fatal("未能从 middleware.go 提取任何路由注册——注册形态变更请同步更新提取器")
	}
	return registry
}

// auditCallPattern / packageCallPattern：直接审计调用与包内函数调用的字面量匹配。
var (
	auditCallPattern   = regexp.MustCompile(`(recordAudit\(|RecordAuditLog\()`)
	packageCallPattern = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
)

// scanHandlerForAuditCallDirect 只查函数体自身是否含审计记录字面量——用于
// 「handler 不得记录」方向：调用图深处的系统级诊断审计（如 applyCaddyConfigE
// 失败留痕）与本路由的用户动作记录是不同动作，不构成双条，不得计入。
func scanHandlerForAuditCallDirect(t *testing.T, root, funcName string) (bool, bool) {
	t.Helper()
	bodies := indexHandlerPackageFuncs(t, root)
	body, found := bodies[funcName]
	if !found {
		return false, false
	}
	return true, auditCallPattern.Match(body)
}

// scanHandlerForAuditCall 在 handlers 包源码中定位指定方法名的函数，返回
// （是否找到, 是否可达一次审计记录调用）。可达性沿函数体内调用的包内函数
// （含 h.X 方法委托如 clusterNodeAction、包级 helper 如 createAPIKeyInternal）
// BFS 追踪至多 3 层——handler 把记录委托给 helper 时字面量在 helper 体内。
func scanHandlerForAuditCall(t *testing.T, root, funcName string) (bool, bool) {
	t.Helper()
	bodies := indexHandlerPackageFuncs(t, root)
	body, found := bodies[funcName]
	if !found {
		return false, false
	}
	if auditCallPattern.Match(body) {
		return true, true
	}
	visited := map[string]bool{funcName: true}
	queue := []string{}
	for _, m := range packageCallPattern.FindAllStringSubmatch(string(body), -1) {
		if callee, ok := bodies[m[1]]; ok && !visited[m[1]] {
			visited[m[1]] = true
			queue = append(queue, m[1])
			if auditCallPattern.Match(callee) {
				return true, true
			}
		}
	}
	for depth := 0; depth < 2 && len(queue) > 0; depth++ {
		next := queue
		queue = nil
		for _, name := range next {
			for _, m := range packageCallPattern.FindAllStringSubmatch(string(bodies[name]), -1) {
				if callee, ok := bodies[m[1]]; ok && !visited[m[1]] {
					visited[m[1]] = true
					queue = append(queue, m[1])
					if auditCallPattern.Match(callee) {
						return true, true
					}
				}
			}
		}
	}
	return true, false
}

// indexHandlerPackageFuncs 索引 handlers 包全部函数/方法的函数体字节
// （同名冲突取首个——绊线用途下足够）。R67 D-3：切出前按 AST 注释区间把
// 注释字节置零——字面量正则会命中「提及 recordAudit( 的注释」，删记录留
// 注释即假绿（零审计逃逸通道）；置零保持偏移对齐。
func indexHandlerPackageFuncs(t *testing.T, root string) map[string][]byte {
	t.Helper()
	bodies := make(map[string][]byte)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		stripped := make([]byte, len(src))
		copy(stripped, src)
		for _, group := range file.Comments {
			for _, comment := range group.List {
				start, end := fset.Position(comment.Pos()).Offset, fset.Position(comment.End()).Offset
				for i := start; i < end && i < len(stripped); i++ {
					stripped[i] = 0
				}
			}
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if _, exists := bodies[fn.Name.Name]; exists {
				continue
			}
			start, end := fset.Position(fn.Pos()).Offset, fset.Position(fn.End()).Offset
			bodies[fn.Name.Name] = stripped[start:end]
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk handlers: %v", err)
	}
	return bodies
}

// TestAuditInsertEntryPointsExhaustive 审计写入入口穷尽性绊线（R62 D-5）：
// 词汇/映射两个契约测试只扫描调用名命中 auditVocabCallSpecs 的调用点——若未来
// 新增绕过这 4 个入口、直接向 audit_log 表 INSERT 的低层写入函数，其动作词条对
// 两个契约测试均不可见（漏映射检查失效、超长词条不红，前端渲染兜底 info 灰标）。
// 本测试扫描 internal/ 全部生产代码中的 "INTO audit_log" 直接写入，断言其外围
// 函数 ∈ 允许集；新增写入函数时必须先走 RecordAuditLog/recordSystemAudit 等入口，
// 或同时更新两个契约测试的 auditVocabCallSpecs 并把函数名加入本允许集。
func TestAuditInsertEntryPointsExhaustive(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	allow := map[string]bool{
		"RecordAuditLog":       true, // services/auditlog.go —— auditVocabCallSpecs 已覆盖其调用点
		"flushSystemAuditLogs": true, // db/audit.go —— recordSystemAudit 缓冲的唯一落库点，无字面量动作
	}
	// R63 D-N3：SQL 关键字与表名大小写不敏感，正则加 (?i) 防 "insert into
	// audit_log" 等变体从文件级预筛静默漏过。
	pattern := regexp.MustCompile(`(?i)INTO\s+audit_log\b`)
	found := false
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !pattern.Match(src) {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				start, end := fset.Position(d.Pos()).Offset, fset.Position(d.End()).Offset
				if pattern.Match(src[start:end]) {
					found = true
					if !allow[d.Name.Name] {
						t.Errorf("%s: 函数 %s 直接 INSERT INTO audit_log——绕过了 auditVocabCallSpecs 所列入口，"+
							"其动作词条对词汇/映射契约测试不可见；请改走 RecordAuditLog/recordSystemAudit，"+
							"或同步更新两个契约测试并把函数名加入本允许集", rel, d.Name.Name)
					}
				}
			case *ast.GenDecl:
				// R63 D-N2：包级函数字面量（var x = func(){...INSERT...}）无外围
				// FuncDecl，允许集检查对其永不触发——按整段文本命中即红（包级
				// 裸写入点无法按函数名归因，契约上不应存在；确有需要先重构为
				// 命名函数并加入允许集）。
				start, end := fset.Position(d.Pos()).Offset, fset.Position(d.End()).Offset
				if pattern.Match(src[start:end]) {
					found = true
					t.Errorf("%s: 包级声明直接包含 INSERT INTO audit_log——绕过按函数名的允许集检查；请改走 RecordAuditLog/recordSystemAudit 并重构为命名函数", rel)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
	if !found {
		t.Fatal("未发现任何 INTO audit_log 生产写入点——允许集可能已失效（写入改为其他表名/形态），请人工复核 auditVocabCallSpecs 与本测试的允许集")
	}
}

// TestAuditEntryAliasExhaustive 审计入口别名穷尽性绊线（R63 D-N4）：两个契约
// 测试按「调用名 ∈ auditVocabCallSpecs」提取调用点——入口被函数变量别名后以
// 别名调用，别名未登记时该调用点对两测试整点不可见（动作词条不进后端动作集、
// 漏映射检查失明、danger 契约条目虚设；R50 D-01 的「认证拒绝」缺失即此类，
// 当时仅靠人工审计发现）。本测试扫描 internal/ 生产代码中 RHS 为入口名的
// var 值规格与赋值语句，断言 LHS 标识符 ∈ auditVocabCallSpecs；新别名未登记
// 即红。
func TestAuditEntryAliasExhaustive(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	entryNames := map[string]bool{
		"RecordAuditLog":    true,
		"recordAudit":       true,
		"recordSystemAudit": true,
	}
	rhsIsEntry := func(e ast.Expr) bool {
		switch v := e.(type) {
		case *ast.Ident:
			return entryNames[v.Name]
		case *ast.SelectorExpr:
			return entryNames[v.Sel.Name]
		}
		return false
	}
	found := false
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		rel, _ := filepath.Rel(root, path)
		line := func(n ast.Node) int { return fset.Position(n.Pos()).Line }
		ast.Inspect(file, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					return true
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 || !rhsIsEntry(vs.Values[0]) {
						continue
					}
					found = true
					if _, registered := auditVocabCallSpecs[vs.Names[0].Name]; !registered {
						t.Errorf("%s:%d: 入口别名 %s 未登记进 auditVocabCallSpecs——以别名调用时其动作词条对词汇/映射契约测试不可见；请同步登记或去掉别名", rel, line(vs), vs.Names[0].Name)
					}
				}
			case *ast.AssignStmt:
				if (d.Tok != token.ASSIGN && d.Tok != token.DEFINE) || len(d.Lhs) != 1 || len(d.Rhs) != 1 {
					return true
				}
				id, ok := d.Lhs[0].(*ast.Ident)
				if !ok || !rhsIsEntry(d.Rhs[0]) {
					return true
				}
				found = true
				if _, registered := auditVocabCallSpecs[id.Name]; !registered {
					t.Errorf("%s:%d: 入口别名 %s 未登记进 auditVocabCallSpecs——以别名调用时其动作词条对词汇/映射契约测试不可见；请同步登记或去掉别名", rel, line(d), id.Name)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
	if !found {
		t.Fatal("未发现任何审计入口别名——入口可能已被重命名/删除，请人工复核 auditVocabCallSpecs 与本测试")
	}
}
