package handlers

// 文档与写门的派生一致性（一次成形，杜绝「第 N 次扩张未跟进」）：
//   - 门集合从 handler 源码（rejectWriteDuringImport / rejectNodeWriteDuringImport
//     调用点，及正向 `if configImportBusy() {` 直门——certjobs/cluster_sync/
//     taskmonitor 的重试/删除/手动同步/任务 toggle/cancel/control 六处不经
//     reject* helper）与 middleware 路由注册双向派生；
//   - 文档集合是 apidocs 的 importWindowGatedDocRoutes；
//   - 两侧必须相等，且 OpenAPI 输出对每个受门且已登记的端点必须含
//     409 import_in_progress。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

func derivedImportWindowGatedRoutes(t *testing.T) map[string]string {
	t.Helper()
	// 门调用可能在 helper 里（clusterNodeAction / libAutoUpdate / updateLibSchedule
	// 等）：只扫「handler 函数体直接含门调用」会漏掉这些端点，于是文档永远缺
	// 409。两层派生：①直接含门调用的函数集合；②再沿一层调用边（h.X / X）扩张，
	// 得到「经 helper 间接受门」的 handler。
	directGated := map[string]bool{}
	callees := map[string]map[string]bool{}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read handlers dir: %v", err)
	}
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
			if !ok || fn.Body == nil {
				continue
			}
			name := fn.Name.Name
			out := callees[name]
			if out == nil {
				out = map[string]bool{}
				callees[name] = out
			}
			hit := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.IfStmt:
					// configImportBusy 直门只认正向守卫 `if configImportBusy() {`
					// （六处 409 fast-fail 全是此形）。反向形态
					// （`!configImportBusy()`——branding 门内跳过、coordinator
					// 探测）不是拒绝门，标记会造成文档 409 与实现不符。
					if call, ok := node.Cond.(*ast.CallExpr); ok {
						if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "configImportBusy" {
							hit = true
							return false
						}
					}
				case *ast.CallExpr:
					switch callee := node.Fun.(type) {
					case *ast.Ident:
						if callee.Name == "rejectWriteDuringImport" || callee.Name == "rejectNodeWriteDuringImport" {
							hit = true
							return false
						}
						out[callee.Name] = true
					case *ast.SelectorExpr:
						out[callee.Sel.Name] = true
					}
				}
				return true
			})
			if hit {
				directGated[name] = true
			}
		}
	}
	gated := map[string]bool{}
	for name := range directGated {
		gated[name] = true
	}
	for name, calls := range callees {
		if gated[name] {
			continue
		}
		for callee := range calls {
			if directGated[callee] {
				gated[name] = true
				break
			}
		}
	}
	middleware, err := os.ReadFile("../middleware/middleware.go")
	if err != nil {
		t.Fatalf("read middleware.go: %v", err)
	}
	// 两个登记组（adminGroup/business）都是 v1.Group("")，故注册路径即
	// apiDocRoutes 的相对路径。注册形态有两种：`("path", h.X)` 与
	// `("path", someMiddleware(), h.X)`（内联中间件，如限流/认证）——handler
	// 恒为最后一个参数，取实参区里最后一个 `h.<Name>`。
	// 用 AST 而非逐行正则：多行注册（实参分列、内联闭包）不会被行尾截断整体
	// 跳过——那类端点会同时逃过派生集合与手工清单两边校验，形成假绿。
	derived := map[string]string{}
	for key, registration := range middlewareRouteRegistrations(t, middleware) {
		if registration.handler != "" && gated[registration.handler] {
			derived[key] = registration.handler
		}
	}
	return derived
}

func TestAPIDocsImportWindow_derivedFromHandlerGates(t *testing.T) {
	derived := derivedImportWindowGatedRoutes(t)
	missing, extra := make([]string, 0), make([]string, 0)
	for key, handler := range derived {
		if _, ok := importWindowGatedDocRoutes[key]; !ok {
			// 未登记文档的受门路由同样必须进集合：集合是派生事实，不是
			// 「只登记已写文档的部分」。
			missing = append(missing, key+" ("+handler+")")
		}
	}
	for key := range importWindowGatedDocRoutes {
		if _, ok := derived[key]; !ok {
			extra = append(extra, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Fatalf("受导入窗口写门约束但未登记的路由（新增门后请同步 importWindowGatedDocRoutes）:\n%s", strings.Join(missing, "\n"))
	}
	if len(extra) > 0 {
		t.Fatalf("登记了导入窗口写门但源码中不存在该门的调用点（死条目）:\n%s", strings.Join(extra, "\n"))
	}
	if len(derived) == 0 {
		t.Fatal("门集合派生为空（扫描器退化 → 本用例恒绿，无鉴别力）")
	}
}

// 派生注入必须在真正给客户端看的 OpenAPI 输出里生效（不是仅内存集合）：
// 取一个此前手工漏登的族（规则写端点 + 集群登记）断言 409 描述存在。
func TestOpenAPIYAML_includesDerivedImportWindowError(t *testing.T) {
	yaml := buildOpenAPIYAML()
	for _, needle := range []string{
		"/rules:",
		"/cluster/register-tokens:",
	} {
		if !strings.Contains(yaml, needle) {
			t.Fatalf("OpenAPI YAML 缺路径 %s", needle)
		}
	}
	if !strings.Contains(yaml, "import_in_progress") {
		t.Fatal("OpenAPI YAML 未包含派生注入的 409 import_in_progress")
	}
	// 逐端点定位：/rules 段内必须出现该码（否则只有别的族命中，注入范围退化）。
	rulesStart := strings.Index(yaml, "  /rules:")
	if rulesStart < 0 {
		t.Fatal("OpenAPI YAML 缺 /rules 段")
	}
	rulesEnd := len(yaml)
	if next := strings.Index(yaml[rulesStart+1:], "\n  /"); next >= 0 {
		rulesEnd = rulesStart + 1 + next
	}
	if !strings.Contains(yaml[rulesStart:rulesEnd], "import_in_progress") {
		t.Fatalf("/rules 段未登记 409 import_in_progress")
	}
}

// restore 端点的错误面：413/400 校验失败/200+partial 都必须可被按文档生成的
// 客户端识别（此前文档只列 500 import_failed，客户端遇 413/400 会走错分支）。
func TestAPIDocRoutes_restoreDocumentsPartialAndBodyLimit(t *testing.T) {
	var route *apiDocRoute
	for i := range apiDocRoutes {
		if apiDocRoutes[i].Method == "POST" && apiDocRoutes[i].Path == "/auto-backup/:id/restore" {
			route = &apiDocRoutes[i]
			break
		}
	}
	if route == nil {
		t.Fatal("文档缺 POST /auto-backup/:id/restore")
	}
	joined := strings.Join(route.Errors, " | ")
	for _, want := range []string{"400 invalid_backup", "413 body_exceeds_128MB"} {
		if !strings.Contains(joined, want) {
			t.Errorf("restore 文档缺 %s: %v", want, route.Errors)
		}
	}
	if !strings.Contains(route.Description, "partial") {
		t.Errorf("restore 描述未说明 200+partial 形态: %q", route.Description)
	}
}

// 此前派生扫描器的两个盲区（内联中间件注册、门在 helper 里）让 8 类会返回 409
// 的端点文档缺码：集群机器接口（注册/确认/快照/规则库包/上报）与节点审批写、
// 成员写、API Key 自助写。逐端点断言 OpenAPI 输出里这些路径段含该码——只断言
// 「整份 YAML 某处出现 import_in_progress」会被别的族掩盖。
func TestOpenAPIYAML_gatedRouteFamiliesDocument409(t *testing.T) {
	yaml := buildOpenAPIYAML()
	paths := []string{
		"/cluster/register:",
		"/cluster/registration/confirm:",
		"/cluster/sync/snapshot:",
		"/cluster/sync/waf-files:",
		"/cluster/nodes/report:",
		"/cluster/nodes/{id}/approve:",
		"/cluster/nodes/{id}/reject:",
		"/cluster/nodes/{id}:",
		"/users/{id}:",
		"/users/{id}/reset-password:",
		"/api-keys:",
		"/security/crs/schedule:",
		// configImportBusy 直门族（certjobs/cluster_sync/taskmonitor）：
		// 证书任务重试/删除、手动同步、任务触发/调度开关/取消/常驻启停。
		"/certificates/jobs/{id}/retry:",
		"/certificates/jobs/{id}:",
		"/cluster/sync/pull:",
		"/system/tasks/{id}/trigger:",
		"/system/tasks/{id}/toggle:",
		"/system/tasks/{id}/cancel:",
		"/system/tasks/{id}/control:",
	}
	for _, path := range paths {
		start := strings.Index(yaml, "  "+path)
		if start < 0 {
			t.Errorf("OpenAPI YAML 缺路径 %s", path)
			continue
		}
		block := yaml[start+len(path):]
		if end := strings.Index(block, "\n  /"); end >= 0 {
			block = block[:end]
		}
		if !strings.Contains(block, "import_in_progress") {
			t.Errorf("路径 %s 的文档缺 409 import_in_progress（该端点实际受导入窗口写门约束）", path)
		}
	}
}
