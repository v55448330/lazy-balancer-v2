package handlers

// business 组 5xx 响应只回固定文案：底层错误（SQL 文本/表列名、文件路径与
// errno、Caddy admin 地址）只进运行日志与操作审计。4xx 配置拒绝类不受此约束
// （cli_validation_gate 等门禁依赖 400 内的 CLI/字段细节）。
// 两路钉：源码级（规则端点全部 5xx 写点不得拼接 err.Error()）+ 行为级
//（真实 DB 故障下响应体不含内部结构）。

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"lazy-balancer-v2/internal/db"
)

func TestRuleEndpoint5xxBodiesHideInternalErrors(t *testing.T) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "rules.go", nil, 0)
	if err != nil {
		t.Fatalf("parse rules.go: %v", err)
	}
	for _, leak := range collect5xxErrorTextLeaks(fset, parsed) {
		t.Errorf("rules.go: 5xx 响应拼接了内部错误文本: %s", leak)
	}

	// 配置域同政策：GetConfig（business 组）与聚合预校验的通用失败分支。
	caddyFile, err := parser.ParseFile(fset, "caddy.go", nil, 0)
	if err != nil {
		t.Fatalf("parse caddy.go: %v", err)
	}
	for _, fn := range caddyFile.Decls {
		decl, ok := fn.(*ast.FuncDecl)
		if !ok || (decl.Name.Name != "GetConfig" && decl.Name.Name != "writeConfigValidationFailure") {
			continue
		}
		for _, leak := range collect5xxErrorTextLeaks(fset, decl) {
			t.Errorf("caddy.go:%s: 5xx 响应拼接了内部错误文本: %s", decl.Name.Name, leak)
		}
	}

	// 规则指标历史端点（business 组）：读取/扫描/时间解析失败的 5xx 与
	// rules 族同政策——内部结构只进日志，响应只回固定文案。
	metricsFile, err := parser.ParseFile(fset, "metrics.go", nil, 0)
	if err != nil {
		t.Fatalf("parse metrics.go: %v", err)
	}
	for _, fn := range metricsFile.Decls {
		decl, ok := fn.(*ast.FuncDecl)
		if !ok || (decl.Name.Name != "GetRuleMetricsHistory" && decl.Name.Name != "GetMetricsHistory") {
			continue
		}
		for _, leak := range collect5xxErrorTextLeaks(fset, decl) {
			t.Errorf("metrics.go:%s: 5xx 响应拼接了内部错误文本: %s", decl.Name.Name, leak)
		}
	}

	// 共享事务收尾（business 组经 finishTxApply 收口：批量阶段页等）：5xx 与
	// 已提交视图恢复分支必须只回固定文案——错误详情由日志/审计承担。
	sharedFile, err := parser.ParseFile(fset, "handlers.go", nil, 0)
	if err != nil {
		t.Fatalf("parse handlers.go: %v", err)
	}
	for _, fn := range sharedFile.Decls {
		decl, ok := fn.(*ast.FuncDecl)
		if !ok || decl.Name.Name != "finishTxApply" {
			continue
		}
		for _, leak := range collect5xxErrorTextLeaks(fset, decl) {
			t.Errorf("handlers.go:%s: 5xx 响应拼接了内部错误文本: %s", decl.Name.Name, leak)
		}
	}
}

// 扫描器自检：识别能力本身必须被钉住——若匹配逻辑退化为恒空，上面的门禁
// 就成了假绿。合成形态覆盖直接 c.JSON、经局部变量传递的动态 status/message、
// 统一 writeInternalError 写点，以及固定文案/4xx/固定公共错误三类反形状。
func TestRuleEndpoint5xxLeakScannerDetectsLeaks(t *testing.T) {
	const source = `package p

func f(c *gin.Context, err error, status int) {
	c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "x: " + err.Error()})
	c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: fmt.Sprintf("%v", err.Error())})
	fail(http.StatusInternalServerError, "y: "+err.Error())
	failEnable("z: "+err.Error(), err)
	failUpdateWithStatus("w: "+err.Error(), http.StatusInternalServerError, err)
	failCertEnqueue("v: "+err.Error(), err)
	// 不经 .Error() 字面串的形态同样会泄露内部文本（SQL/路径/admin 地址）。
	c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("x: %v", err)})
	fail(http.StatusBadGateway, fmt.Errorf("y: %s", err))
	// 动态状态与经局部变量传递的错误文案不得绕过扫描。
	message := err.Error()
	c.JSON(status, models.APIResponse{Code: status, Message: message})
	localStatus := http.StatusInternalServerError
	localMessage := "export: " + err.Error()
	c.JSON(localStatus, models.APIResponse{Code: localStatus, Message: localMessage})
	writeInternalError(c, status, message, err)
	writeInternalError(c, http.StatusBadGateway, fmt.Sprintf("wrapped: %v", err), err)
	// 固定文案、4xx 与固定公共错误不算泄漏。
	c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
	writeInternalError(c, http.StatusInternalServerError, "fixed", err)
	writeInternalError(c, http.StatusBadRequest, message, err)
	writeInternalError(c, http.StatusInternalServerError, errTrustedProxyRead.Error(), err)
}`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "synthetic.go", source, 0)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	if leaks := collect5xxErrorTextLeaks(fset, parsed); len(leaks) != 12 {
		t.Fatalf("扫描器应捕获 12 处 5xx 泄漏，实际 %d: %v", len(leaks), leaks)
	}
}

// collect5xxErrorTextLeaks 返回 node 内全部 5xx 写点的泄漏源码快照：
//   - c.JSON(<5xx>, ...) 的响应参数；
//   - writeInternalError(c, <5xx>, message, cause) 的 message 参数；
//   - fail/failInternal/failUpdateWithStatus/failEnable/failEnableWithStatus/
//     failCertEnqueue 的文案参数（这些闭包最终写 c.JSON）。
//
// 动态 status 参数和已赋过 5xx 的局部变量按“可能为 5xx”处理；经局部变量
// 传递的 err.Error()/裸 err 格式化文本同样纳入，避免 helper 收口后逃逸。
func collect5xxErrorTextLeaks(fset *token.FileSet, node ast.Node) []string {
	switch scoped := node.(type) {
	case *ast.FuncDecl:
		return collect5xxErrorTextLeaksInScope(fset, scoped, scoped.Type.Params)
	case *ast.FuncLit:
		return collect5xxErrorTextLeaksInScope(fset, scoped, scoped.Type.Params)
	}
	leaks := make([]string, 0)
	ast.Inspect(node, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		leaks = append(leaks, collect5xxErrorTextLeaksInScope(fset, fn, fn.Type.Params)...)
		return false
	})
	return leaks
}

func collect5xxErrorTextLeaksInScope(fset *token.FileSet, scope ast.Node, params *ast.FieldList) []string {
	errorTextNames := map[string]bool{}
	dynamicStatusNames := map[string]bool{}
	noteParams := func(fields *ast.FieldList) {
		if fields == nil {
			return
		}
		for _, field := range fields.List {
			for _, name := range field.Names {
				dynamicStatusNames[name.Name] = true
			}
		}
	}
	noteParams(params)
	noteAssignment := func(lhs, rhs ast.Expr) {
		ident, ok := lhs.(*ast.Ident)
		if !ok {
			return
		}
		if isInternalStatusExpr(rhs) {
			dynamicStatusNames[ident.Name] = true
		}
		if mentionsErrorText(fset, rhs) {
			errorTextNames[ident.Name] = true
		}
	}
	ast.Inspect(scope, func(n ast.Node) bool {
		switch current := n.(type) {
		case *ast.FuncLit:
			noteParams(current.Type.Params)
		case *ast.AssignStmt:
			if len(current.Lhs) == len(current.Rhs) {
				for i := range current.Lhs {
					noteAssignment(current.Lhs[i], current.Rhs[i])
				}
			}
		case *ast.ValueSpec:
			if len(current.Names) == len(current.Values) {
				for i, name := range current.Names {
					if isInternalStatusExpr(current.Values[i]) {
						dynamicStatusNames[name.Name] = true
					}
					if mentionsErrorText(fset, current.Values[i]) {
						errorTextNames[name.Name] = true
					}
				}
			}
		}
		return true
	})
	hasInternalStatus := func(expr ast.Expr) bool {
		if isInternalStatusExpr(expr) {
			return true
		}
		ident, ok := expr.(*ast.Ident)
		return ok && dynamicStatusNames[ident.Name]
	}
	hasErrorText := func(expr ast.Expr) bool {
		if mentionsErrorText(fset, expr) {
			return true
		}
		found := false
		ast.Inspect(expr, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if ok && errorTextNames[ident.Name] {
				found = true
				return false
			}
			return !found
		})
		return found
	}
	leaks := make([]string, 0)
	ast.Inspect(scope, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		var receiver string
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
			if ident, ok := fun.X.(*ast.Ident); ok {
				receiver = ident.Name
			}
		default:
			return true
		}
		switch name {
		case "JSON":
			if receiver != "c" || len(call.Args) < 2 || !hasInternalStatus(call.Args[0]) {
				return true
			}
			for _, arg := range call.Args[1:] {
				if hasErrorText(arg) {
					leaks = append(leaks, printNode(fset, call))
					break
				}
			}
		case "writeInternalError":
			if len(call.Args) >= 3 && hasInternalStatus(call.Args[1]) && hasErrorText(call.Args[2]) &&
				printNode(fset, call.Args[2]) != "errTrustedProxyRead.Error()" {
				leaks = append(leaks, printNode(fset, call))
			}
		case "fail":
			if len(call.Args) >= 2 && hasInternalStatus(call.Args[0]) && hasErrorText(call.Args[1]) {
				leaks = append(leaks, printNode(fset, call))
			}
		case "failInternal", "failUpdateWithStatus", "failEnable", "failEnableWithStatus", "failCertEnqueue":
			if len(call.Args) > 0 && hasErrorText(call.Args[0]) {
				leaks = append(leaks, printNode(fset, call))
			}
		case "failRestoreFileAccess", "failAutoBackupAccess":
			// 实参形态为 (c, 动作词/download, subject, message, status, cause)。
			if len(call.Args) >= 5 && hasInternalStatus(call.Args[4]) && hasErrorText(call.Args[3]) {
				leaks = append(leaks, printNode(fset, call))
			}
		}
		return true
	})
	return leaks
}

func isInternalStatusExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		return e.Sel.Name == "StatusInternalServerError" || e.Sel.Name == "StatusBadGateway"
	case *ast.BasicLit:
		return e.Kind == token.INT && (e.Value == "500" || e.Value == "502")
	}
	return false
}

func mentionsErrorText(fset *token.FileSet, node ast.Node) bool {
	source := printNode(fset, node)
	if strings.Contains(source, ".Error()") {
		return true
	}
	return formatsRawErrorValue(node)
}

// formatsRawErrorValue 报告节点是否用 %v/%s/%w 直接格式化裸 err 标识符
// （fmt.Sprintf / fmt.Errorf 形态）——这类写法不产生 ".Error()" 字面串，
// 却同样把底层错误（SQL 文本/表列名、文件路径、admin 地址）拼进响应体。
func formatsRawErrorValue(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (selector.Sel.Name != "Sprintf" && selector.Sel.Name != "Errorf") {
			return true
		}
		formatLiteral, ok := call.Args[0].(*ast.BasicLit)
		if !ok || formatLiteral.Kind != token.STRING || !containsErrorVerb(formatLiteral.Value) {
			return true
		}
		for _, arg := range call.Args[1:] {
			if ident, ok := arg.(*ast.Ident); ok && ident.Name == "err" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// containsErrorVerb 报告格式串字面量是否含会打印错误文本的动词。
func containsErrorVerb(quotedFormat string) bool {
	for _, verb := range []string{"%v", "%s", "%w"} {
		if strings.Contains(quotedFormat, verb) {
			return true
		}
	}
	return false
}

func printNode(fset *token.FileSet, node ast.Node) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, node); err != nil {
		return ""
	}
	return buf.String()
}

// 行为钉：CreateRule 在写路径规则阶段遇到真实 DB 故障（表缺失）时，500 响应
// 只回固定文案——此前会带 "no such table: path_rules"（表名/列名泄露）。
func TestCreateRule_500BodyHidesSQLDetails(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	if _, err := db.DB.Exec(`DROP TABLE path_rules`); err != nil {
		t.Fatalf("drop path_rules: %v", err)
	}
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{"name":"leak","protocol":"http","domain":"leak.example.test","listen_port":19081,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, leak := range []string{"upstreams", "no such table", "SELECT", "sql:"} {
		if strings.Contains(body, leak) {
			t.Fatalf("500 body 泄露内部细节 %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "写入数据库失败") {
		t.Fatalf("500 body 缺少固定文案: %s", body)
	}
}

// 行为钉：GetConfig 读库失败时响应体不得带表名/SQL 细节。
func TestGetConfig_500BodyHidesSQLDetails(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	if _, err := db.DB.Exec(`DROP TABLE global_config`); err != nil {
		t.Fatalf("drop global_config: %v", err)
	}
	router := gin.New()
	router.GET("/config", handler.GetConfig)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, leak := range []string{"global_config", "no such table", "SELECT", "sql:"} {
		if strings.Contains(body, leak) {
			t.Fatalf("500 body 泄露内部细节 %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "获取全局配置失败") {
		t.Fatalf("500 body 缺少固定文案: %s", body)
	}
}

// caddyAdmin5xxDetailFunctions 是 admin 组 5xx「保留底层细节」的显式政策清单
// （不是默认放行）：只有登记在此的 handler 允许在 5xx 响应体拼接 err.Error()。
// 与 business 组「固定文案」政策并存——admin 端点是排障接口，需要区分 admin
// 不可达 / 响应超限 / 解析失败 / exec exit status / 路径权限。
//
// 清单的每一条都必须是 **admin 组**注册的端点：政策前提（管理员排障接口）由
// 路由组决定，登记一个 business 组端点进来就等于向任意登录用户披露内部细节
// （GET /caddy/logs 曾如此：清单里有它、路由却在 business 组）。路由组一致性
// 由 TestCaddyAdmin5xxDetailPolicyRoutesAreAdminGroup 机器判定。
var caddyAdmin5xxDetailFunctions = map[string]string{
	"UpdateConfig":   "配置 apply/commit 失败需管理员看到 Caddy 侧原因",
	"ValidateConfig": "校验回退后恢复运行配置失败需点名",
	"ReloadCaddy":    "手动重载失败原因",
	"GetCaddyConfig": "admin 不可达(502)/响应超限/解析失败必须可判",
	"PutCaddyConfig": "自定义配置逃生口排障",
	"StartCaddy":     "exec 失败原因与配置应用注记",
	"StopCaddy":      "exec 失败原因",
	"RestartCaddy":   "exec 失败原因与配置应用注记",
}

// caddyRouteGroupRegistrations 从 middleware.go 派生「handler 函数 → 注册路由组
// 集合」。组的身份取自 Group 变量名（admin / business / v1 等），与路由表同源，
// 避免维护第二份「端点属于哪个组」的清单。
func caddyRouteGroupRegistrations(t *testing.T) map[string]map[string]bool {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("..", "middleware", "middleware.go"))
	if err != nil {
		t.Fatalf("read middleware routes: %v", err)
	}
	registration := regexp.MustCompile(`(?m)^\s*(\w+)\.(GET|POST|PUT|DELETE|PATCH)\(\s*"[^"]*"\s*,\s*h\.(\w+)`)
	groups := map[string]map[string]bool{}
	for _, match := range registration.FindAllStringSubmatch(string(source), -1) {
		if groups[match[3]] == nil {
			groups[match[3]] = map[string]bool{}
		}
		groups[match[3]][match[1]] = true
	}
	// 正向控制：路由表解析必须真实命中（否则本门变假绿）。
	if len(groups) < 50 {
		t.Fatalf("路由表解析只命中 %d 个 handler——派生逻辑退化", len(groups))
	}
	return groups
}

// 政策前提门：清单里每个函数都必须在 admin 组注册，否则「保留内部细节」的
// 理由（管理员排障接口）不成立，business 组的固定文案政策被绕过。
func TestCaddyAdmin5xxDetailPolicyRoutesAreAdminGroup(t *testing.T) {
	registrations := caddyRouteGroupRegistrations(t)
	for name := range caddyAdmin5xxDetailFunctions {
		groups, ok := registrations[name]
		if !ok {
			t.Errorf("政策清单条目 %q 在 middleware.go 中没有任何路由注册（过期条目）", name)
			continue
		}
		if !groups["admin"] {
			t.Errorf("政策清单条目 %q 注册在 %v 组而不是 admin 组——5xx 细节会披露给非管理员", name, groups)
		}
	}
	// 反向控制：业务组端点不得进入清单（GetCaddyLogs 即此形态的修复样本）。
	if groups, ok := registrations["GetCaddyLogs"]; ok {
		if groups["admin"] {
			t.Fatalf("GetCaddyLogs 已移入 admin 组：若是有意变更，请同步本门的政策清单口径")
		}
		if _, listed := caddyAdmin5xxDetailFunctions["GetCaddyLogs"]; listed {
			t.Fatal("GetCaddyLogs 仍在 admin 细节清单内，但路由在 business 组（非管理员可读路径/errno）")
		}
	}
}

// 政策可判性门禁：caddy.go 里每个 5xx 拼接内部错误文本的函数都必须在政策
// 清单内（否则按 business 组口径固定文案），且清单条目必须仍存在（过期条目
// 会掩盖新端点的政策缺口）。4xx 配置拒绝类不受约束。
func TestCaddyAdmin5xxDetailPolicyIsExplicit(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "caddy.go", nil, 0)
	if err != nil {
		t.Fatalf("parse caddy.go: %v", err)
	}
	seen := map[string]bool{}
	matched := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		seen[fn.Name.Name] = true
		leaks := collect5xxErrorTextLeaks(fset, fn)
		if len(leaks) == 0 {
			continue
		}
		if _, allowed := caddyAdmin5xxDetailFunctions[fn.Name.Name]; !allowed {
			t.Errorf("caddy.go:%s 的 5xx 响应拼接了内部错误文本，且不在 admin 细节清单内（business 组必须固定文案；新增 admin 端点须登记理由）: %v", fn.Name.Name, leaks)
		} else {
			matched++
		}
	}
	// 扫描器自检：清单门必须真实命中至少一个函数——命中数为 0 说明识别逻辑
	// 退化（例如只认 .Error() 后写点全部改成别形态），门禁变成假绿。
	if matched == 0 {
		t.Fatal("admin 细节清单门未命中任何函数——5xx 泄漏扫描器可能已退化")
	}
	for name, reason := range caddyAdmin5xxDetailFunctions {
		if !seen[name] {
			t.Errorf("政策清单条目 %q 已不在 caddy.go（过期条目掩盖新端点的政策缺口）", name)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("政策清单条目 %q 缺少理由", name)
		}
	}
}

// 审计列表（business 组，任意登录用户可读）：5xx 只回固定文案——扫描/遍历
// 失败的表列名与驱动错误只进运行日志。此前同一函数的计数分支已固定文案、
// 明细两个分支却直接拼 err.Error()，口径分裂且暴露对象是全体登录用户。
func TestAuditLogEndpoint5xxBodiesHideInternalErrors(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "auditlog.go", nil, 0)
	if err != nil {
		t.Fatalf("parse auditlog.go: %v", err)
	}
	found := map[string]bool{"GetAuditLogs": false, "GetAuditLogOptions": false}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, want := found[fn.Name.Name]; !want {
			continue
		}
		found[fn.Name.Name] = true
		for _, leak := range collect5xxErrorTextLeaks(fset, fn) {
			t.Errorf("auditlog.go:%s 的 5xx 响应拼接了内部错误文本: %s", fn.Name.Name, leak)
		}
	}
	for name, ok := range found {
		if !ok {
			t.Errorf("auditlog.go 未找到 %s（扫描面漂移会让门禁假绿）", name)
		}
	}
}

// adminBusiness5xxDetailFunctions 是 caddy.go 之外 admin 组端点的 5xx「保留
// 底层细节」政策登记（键=文件名:函数名，值=理由）。admin 端点是排障接口：
// 自动备份需区分 DB 锁与备份目录 errno，管理面板 HTTPS 需点名哪一步材料
// 读失败，配置导入/还原需保留事务回滚原因。未登记即按 business 组口径
// （固定文案）——不存在「既不登记也不扫描」的真空区。
var adminBusiness5xxDetailFunctions = map[string]string{
	"autobackup.go:AutoBackupSettings":        "设置/备份列表读取失败需管理员看到 errno",
	"autobackup.go:UpdateAutoBackupSettings":  "设置事务写失败需点名（DB 锁/只读库）",
	"autobackup.go:RunAutoBackupNow":          "引擎触发失败需点名（admission/执行错误）",
	"autobackup.go:RestoreAutoBackup":         "备份文件读取失败需点名（权限/errno）",
	"autobackup.go:DownloadAutoBackup":        "备份文件读取失败需点名（权限/errno）",
	"admintls.go:UpdateAdminTLS":              "当前 HTTPS 配置读校验失败需点名，避免半套材料落库",
	"config_backup.go:ExportConfigBackup":     "导出失败需管理员区分备份内容错误与系统故障",
	"config_backup.go:failImportTx":           "导入/还原必须点名事务回滚原因（既有响应契约）",
	"config_backup.go:importConfigBackupCore": "导入/还原事务与文件回滚失败需管理员看到具体原因",
}

// 政策可判性门禁（admin 业务族）：登记文件里每个 5xx 拼接内部错误文本的函数
// 都必须在清单内，且清单条目必须仍存在并仍在拼接细节（过期白名单会掩盖新
// 端点的政策缺口）。4xx 配置拒绝类不受约束。
func TestAdminBusiness5xxDetailPolicyIsExplicit(t *testing.T) {
	registered := map[string]map[string]string{}
	for key, reason := range adminBusiness5xxDetailFunctions {
		file, fn, ok := strings.Cut(key, ":")
		if !ok || file == "" || fn == "" || strings.TrimSpace(reason) == "" {
			t.Fatalf("政策登记条目 %q 形态非法（want 文件:函数 + 非空理由）", key)
		}
		if registered[file] == nil {
			registered[file] = map[string]string{}
		}
		registered[file][fn] = reason
	}
	fset := token.NewFileSet()
	matched := 0
	for file, allowed := range registered {
		node, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		seen := map[string]bool{}
		leaking := map[string]bool{}
		for _, decl := range node.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			seen[fn.Name.Name] = true
			leaks := collect5xxErrorTextLeaks(fset, fn)
			if len(leaks) == 0 {
				continue
			}
			leaking[fn.Name.Name] = true
			if _, ok := allowed[fn.Name.Name]; !ok {
				t.Errorf("%s:%s 的 5xx 响应拼接了内部错误文本，且未登记 admin 细节清单（business 组必须固定文案；新增 admin 端点须登记理由）: %v", file, fn.Name.Name, leaks)
			} else {
				matched++
			}
		}
		for name := range allowed {
			if !seen[name] {
				t.Errorf("%s 政策条目 %q 已不存在（过期条目掩盖新端点的政策缺口）", file, name)
			} else if !leaking[name] {
				t.Errorf("%s:%s 已不再拼接内部错误文本，请删除过期政策条目", file, name)
			}
		}
	}
	if matched == 0 {
		t.Fatal("admin 业务细节清单门未命中任何函数——5xx 泄漏扫描器可能已退化")
	}
}
