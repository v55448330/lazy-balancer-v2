package handlers

// 路由注册派生扫描器（文档对账共用）：从 middleware.go 源码派生
// 「注册路径 → 末位处理器 + 所挂限流桶」。
//
// 用 go/ast 而非逐行正则：注册实参可跨行、处理器可为内联闭包，行级正则遇到
// 这些形态会整体跳过该注册——被跳过的端点同时逃过派生集合与手工清单两侧
// 校验，形成假绿。AST 遍历对单行/多行/闭包三种形态一视同仁。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type middlewareRouteRegistration struct {
	// handler 是注册末位处理器名（`h.X` 的 X）；无 h.X 的机器接口注册为空串。
	handler string
	// rateLimitKey/rateLimitPerMin 是注册处挂载的限流桶（loginRateLimit、
	// clusterRateLimit 与两个包装器 clusterRegisterRateLimit/
	// clusterMachineRateLimit）；未挂限流时 rateLimitPerMin 为 0。
	rateLimitKey     string
	rateLimitPerMin  int
	rateLimitMounted bool
	// rateLimitIPPerMin 是同一注册上的第二档（按来源 IP）限额：集群机器接口
	// 同时按凭证与 IP 计费；单档限流为 0。
	rateLimitIPPerMin  int
	rateLimitMessageCN string
	// group 是注册接收者名（v1/admin/business），line 是注册语句行号：
	// 「公开（注册于 v1.Use 认证链之前）/受保护」与「admin 组/business 组」
	// 两种装配态只能由注册位置派生，不能由测试另写一份路由组清单。
	group string
	line  int
	// middleware 是实参区出现的中间件/认证器名（apiKeyAuth、mcpAccessGuard、
	// clusterTokenAuth、registrationAuth…）——OpenAPI security 契约按真实认证链
	// 派生，逆向校验 public/mcp/机器端点标注。
	middleware map[string]bool
}

// middlewareFuncDecl 取具名函数的声明——限额派生必须读包装器的实现体，
// 测试里不复制常量。
func middlewareFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name && fn.Body != nil {
			return fn
		}
	}
	return nil
}

func middlewareIntExpression(file *ast.File, expr ast.Expr) (int, bool) {
	if literal, ok := expr.(*ast.BasicLit); ok && literal.Kind == token.INT {
		value, err := strconv.Atoi(literal.Value)
		return value, err == nil
	}
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return 0, false
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			values, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range values.Names {
				if name.Name == ident.Name && i < len(values.Values) {
					return middlewareIntExpression(file, values.Values[i])
				}
			}
		}
	}
	return 0, false
}

// clusterRateLimitCallLimit 从函数体内的 clusterRateLimit(scope, limit, msg)
// 调用派生限额：直接挂载与包装器共用同一实参口径。
func clusterRateLimitCallLimit(fn *ast.FuncDecl) int {
	limit := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); !ok || ident.Name != "clusterRateLimit" || len(call.Args) < 2 {
			return true
		}
		if lit, ok := call.Args[1].(*ast.BasicLit); ok && lit.Kind == token.INT {
			if value, err := strconv.Atoi(lit.Value); err == nil {
				limit = value
			}
		}
		return true
	})
	return limit
}

// clusterMachineRateLimitLimits 从实现体的常量块派生双档限额（凭证/IP）。
// 机器接口的限额是函数内常量，包装器实参里没有数字——只识别 callee 名或只读
// 实参的扫描器会把这一族整体漏掉。
func clusterMachineRateLimitLimits(fn *ast.FuncDecl) (credential, ip int) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		decl, ok := n.(*ast.GenDecl)
		if !ok || decl.Tok != token.CONST {
			return true
		}
		for _, spec := range decl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range valueSpec.Names {
				if i >= len(valueSpec.Values) {
					continue
				}
				lit, ok := valueSpec.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.INT {
					continue
				}
				value, err := strconv.Atoi(lit.Value)
				if err != nil {
					continue
				}
				switch name.Name {
				case "credentialLimit":
					credential = value
				case "ipLimit":
					ip = value
				}
			}
		}
		return true
	})
	return credential, ip
}

// loginRateLimitLimit 从 loginRateLimit 的实现体派生限额——文档对账的口径
// 必须与实参同源，不能在测试里再写一个常量副本。
func loginRateLimitLimit(file *ast.File) (int, bool) {
	fn := middlewareFuncDecl(file, "loginRateLimit")
	if fn == nil {
		return 0, false
	}
	limit := clusterRateLimitCallLimit(fn)
	return limit, limit > 0
}

func middlewareRouteRegistrations(t *testing.T, source []byte) map[string]middlewareRouteRegistration {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "middleware.go", source, 0)
	if err != nil {
		t.Fatalf("parse middleware.go: %v", err)
	}
	loginLimit, loginLimitKnown := loginRateLimitLimit(file)
	registerLimit := 0
	if fn := middlewareFuncDecl(file, "clusterRegisterRateLimit"); fn != nil {
		registerLimit = clusterRateLimitCallLimit(fn)
	}
	machineCredentialLimit, machineIPLimit := 0, 0
	if fn := middlewareFuncDecl(file, "clusterMachineRateLimit"); fn != nil {
		machineCredentialLimit, machineIPLimit = clusterMachineRateLimitLimits(fn)
	}
	verbs := map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}
	routes := map[string]middlewareRouteRegistration{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !verbs[selector.Sel.Name] || len(call.Args) < 2 {
			return true
		}
		pathLiteral, ok := call.Args[0].(*ast.BasicLit)
		if !ok || pathLiteral.Kind != token.STRING {
			return true
		}
		path, err := strconv.Unquote(pathLiteral.Value)
		if err != nil {
			return true
		}
		registration := middlewareRouteRegistration{
			line:       fset.Position(call.Pos()).Line,
			middleware: make(map[string]bool),
		}
		if ident, ok := selector.X.(*ast.Ident); ok {
			registration.group = ident.Name
		}
		for _, arg := range call.Args[1:] {
			// 处理器：实参区里最后一个 h.<Name>（内联闭包里的同样计入）。
			ast.Inspect(arg, func(node ast.Node) bool {
				sel, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "h" {
					registration.handler = sel.Sel.Name
				}
				return true
			})
			// 中间件/认证器名：实参区内的所有调用（顶层与内联闭包内的都计入）。
			ast.Inspect(arg, func(node ast.Node) bool {
				callExpr, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if ident, ok := callExpr.Fun.(*ast.Ident); ok {
					registration.middleware[ident.Name] = true
				}
				return true
			})
			// 限流中间件：loginRateLimit() 或 clusterRateLimit(scope, limit, message)。
			middlewareCall, ok := arg.(*ast.CallExpr)
			if !ok {
				continue
			}
			callee, ok := middlewareCall.Fun.(*ast.Ident)
			if !ok {
				continue
			}
			switch callee.Name {
			case "loginRateLimit":
				if !loginLimitKnown {
					continue
				}
				registration.rateLimitMounted = true
				registration.rateLimitKey = "login"
				registration.rateLimitPerMin = loginLimit
			case "clusterRegisterRateLimit":
				// 包装器：限额在实现体的 clusterRateLimit 实参里，callee 名本身
				// 不携带数字——只识别两个基础中间件名的扫描器会整族漏检。
				if registerLimit <= 0 {
					continue
				}
				registration.rateLimitMounted = true
				registration.rateLimitKey = "register"
				registration.rateLimitPerMin = registerLimit
			case "clusterMachineRateLimit":
				// 双档限额（凭证 + IP）来自实现体常量块；第一实参是桶作用域。
				if machineCredentialLimit <= 0 || machineIPLimit <= 0 {
					continue
				}
				if len(middlewareCall.Args) > 0 {
					if scopeLiteral, ok := middlewareCall.Args[0].(*ast.BasicLit); ok && scopeLiteral.Kind == token.STRING {
						if scope, err := strconv.Unquote(scopeLiteral.Value); err == nil {
							registration.rateLimitKey = scope
						}
					}
				}
				registration.rateLimitMounted = true
				registration.rateLimitPerMin = machineCredentialLimit
				registration.rateLimitIPPerMin = machineIPLimit
			case "mcpSourceRateLimit":
				limit, ok := middlewareIntExpression(file, &ast.Ident{Name: "mcpRateLimitPerMinute"})
				if !ok {
					continue
				}
				registration.rateLimitMounted = true
				registration.rateLimitIPPerMin = limit
			case "mcpAPIKeyRateLimit":
				limit, ok := middlewareIntExpression(file, &ast.Ident{Name: "mcpRateLimitPerMinute"})
				if !ok {
					continue
				}
				registration.rateLimitMounted = true
				registration.rateLimitKey = "mcp"
				registration.rateLimitPerMin = limit
			case "clusterRateLimit":
				if len(middlewareCall.Args) < 2 {
					continue
				}
				scopeLiteral, ok := middlewareCall.Args[0].(*ast.BasicLit)
				if !ok {
					continue
				}
				limit, ok := middlewareIntExpression(file, middlewareCall.Args[1])
				if !ok {
					continue
				}
				scope, err := strconv.Unquote(scopeLiteral.Value)
				if err != nil {
					continue
				}
				registration.rateLimitMounted = true
				registration.rateLimitKey = scope
				registration.rateLimitPerMin = limit
				if len(middlewareCall.Args) > 2 {
					if messageLiteral, ok := middlewareCall.Args[2].(*ast.BasicLit); ok {
						if message, err := strconv.Unquote(messageLiteral.Value); err == nil {
							registration.rateLimitMessageCN = message
						}
					}
				}
			}
		}
		routes[selector.Sel.Name+" "+path] = registration
		return true
	})
	return routes
}

func middlewareSourceForTest(t *testing.T) []byte {
	t.Helper()
	source, err := os.ReadFile("../middleware/middleware.go")
	if err != nil {
		t.Fatalf("read middleware.go: %v", err)
	}
	return source
}

// middlewareV1AuthChainLine 返回 v1 组首个 `v1.Use(...)` 的行号：该行之前的
// v1 注册即公开块（登录/初始化/OIDC/品牌/机器接口），之后才进入
// apiKeyAuth→jwtAuth→只读门 的认证链。增删公开块路由或把 Use 上移/下移都会
// 改变派生结果——security 契约反向门据此判定「文档宣称匿名可用」是否成立。
func middlewareV1AuthChainLine(t *testing.T, source []byte) int {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "middleware.go", source, 0)
	if err != nil {
		t.Fatalf("parse middleware.go: %v", err)
	}
	line := 0
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Use" {
			return true
		}
		ident, ok := selector.X.(*ast.Ident)
		if !ok || ident.Name != "v1" || len(call.Args) == 0 {
			return true
		}
		if position := fset.Position(call.Pos()).Line; line == 0 || position < line {
			line = position
		}
		return true
	})
	if line == 0 {
		t.Fatal("未能从 middleware.go 派生 v1.Use 认证链起点（装配形态变化，扫描器需跟进）")
	}
	return line
}

// 派生扫描器的鉴别力：闭包形态（/mcp）与多行注册都必须在集合里，且处理器
// 要能穿透闭包被解析出来；旧逐行正则在这两种形态上双双失明（多行注册整个
// 跳过、闭包注册只剩前缀实参解析不到 handler），任何挂在它们上的门都会双盲。
func TestMiddlewareRouteRegistrations_includesClosureAndMultiLineForms(t *testing.T) {
	routes := middlewareRouteRegistrations(t, middlewareSourceForTest(t))
	if len(routes) < 100 {
		t.Fatalf("派生注册数=%d，扫描器疑似退化", len(routes))
	}
	if _, ok := routes["POST /mcp"]; !ok {
		t.Error("缺 POST /mcp：内联闭包注册必须被 AST 扫描器覆盖")
	}
	if registration, ok := routes["GET /auth/setup"]; !ok || registration.handler != "GetSetupStatus" {
		t.Errorf("GET /auth/setup registration=%+v, want handler GetSetupStatus", registration)
	}

	// 合成源码钉两种行级正则必然失明的形态（未来新增注册即此形态），以及
	// 包装器限额的派生路径：clusterRegisterRateLimit 的实参在实现体内、
	// clusterMachineRateLimit 的限额在实现体常量块，callee 名都不带数字。
	// 合成常量取 7/77（与生产的 30/300 不同），派生数只能来自实现体。
	synthetic := []byte(`package middleware
const syntheticRateLimit = 43


func clusterRegisterRateLimit() gin.HandlerFunc {
	return clusterRateLimit("register", 7, "合成注册限流")
}

func clusterMachineRateLimit(scope string, source clusterCredentialSource) gin.HandlerFunc {
	const (
		credentialLimit = 7
		ipLimit         = 77
	)
	return nil
}

func assemble(v1 *Group, h *Handlers) {
	v1.POST(
		"/multi-line",
		someGuard(),
		h.GatedHandler,
	)
	v1.POST("/closure", guard(), func(c *Context) {
		h.ClosureHandler(c)
	})
	v1.GET("/limited", clusterRateLimit("synthetic", 42, "合成限流"), h.LimitedHandler)
	v1.POST("/register-limited", clusterRegisterRateLimit(), h.RegisterHandler)
	v1.GET("/machine-limited", clusterMachineRateLimit("synthetic-machine", clusterCredentialFromToken), h.MachineHandler)
	v1.GET("/named-constant-limited", clusterRateLimit("synthetic-const", syntheticRateLimit, "合成常量限流"), h.NamedConstantHandler)
}
`)
	syntheticRoutes := middlewareRouteRegistrations(t, synthetic)
	if got := syntheticRoutes["POST /multi-line"].handler; got != "GatedHandler" {
		t.Errorf("多行注册 handler=%q, want GatedHandler（行级扫描器会整条跳过）", got)
	}
	if got := syntheticRoutes["POST /closure"].handler; got != "ClosureHandler" {
		t.Errorf("闭包注册 handler=%q, want ClosureHandler（行级扫描器在前缀实参处截断）", got)
	}
	limited := syntheticRoutes["GET /limited"]
	if !limited.rateLimitMounted || limited.rateLimitKey != "synthetic" || limited.rateLimitPerMin != 42 {
		t.Errorf("限流挂载解析=%+v, want synthetic/42", limited)
	}
	namedConstant := syntheticRoutes["GET /named-constant-limited"]
	if !namedConstant.rateLimitMounted || namedConstant.rateLimitKey != "synthetic-const" || namedConstant.rateLimitPerMin != 43 {
		t.Errorf("命名常量限流解析=%+v, want synthetic-const/43", namedConstant)
	}
	register := syntheticRoutes["POST /register-limited"]
	if !register.rateLimitMounted || register.rateLimitKey != "register" || register.rateLimitPerMin != 7 {
		t.Errorf("clusterRegisterRateLimit 解析=%+v, want register/7（限额须来自实现体实参）", register)
	}
	machine := syntheticRoutes["GET /machine-limited"]
	if !machine.rateLimitMounted || machine.rateLimitKey != "synthetic-machine" || machine.rateLimitPerMin != 7 || machine.rateLimitIPPerMin != 77 {
		t.Errorf("clusterMachineRateLimit 解析=%+v, want synthetic-machine/7+77（双档限额须来自实现体常量）", machine)
	}
}

// rateLimitNumbersIn 抓 429 描述里以「N/min」形态出现的限额数字。未写数字的
// 条目保持自由文本：对账只要求登记 429，写了的数字则必须与注册实参全等
// （限额调整后文档静默过期是同一族的漏检面）。
var rateLimitNumberPattern = regexp.MustCompile(`(\d+)/min`)

func rateLimitNumbersIn(text string) map[int]struct{} {
	numbers := make(map[int]struct{}, 2)
	for _, match := range rateLimitNumberPattern.FindAllStringSubmatch(text, -1) {
		if value, err := strconv.Atoi(match[1]); err == nil {
			numbers[value] = struct{}{}
		}
	}
	return numbers
}

// 限流是运维可见面：凡在 middleware.go 挂限流（含两个包装器
// clusterRegisterRateLimit / clusterMachineRateLimit）的路由，OpenAPI 文档
// 必须登记 429——漏登记时按规格生成的 SDK/从节点客户端会把限流当未知状态
// （30/min 凭证或 300/min IP 会被误判为集群凭证失效/网络异常）。文档写了
// 数字的，数字必须与注册实参同源，限额漂移不得静默过期。
func TestAPIDocs_rateLimitedRoutesDocument429AndNumbers(t *testing.T) {
	documented := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		documented[route.Method+" "+route.Path] = route
	}
	limited, loginBucketRouted, machineFamilyRouted, mcpDualRouted := 0, false, false, false
	for key, registration := range middlewareRouteRegistrations(t, middlewareSourceForTest(t)) {
		if !registration.rateLimitMounted {
			continue
		}
		limited++
		if registration.rateLimitKey == "login" {
			loginBucketRouted = true
		}
		if registration.rateLimitIPPerMin > 0 {
			machineFamilyRouted = true
		}
		if key == "POST /mcp" && registration.rateLimitPerMin > 0 && registration.rateLimitIPPerMin > 0 {
			mcpDualRouted = true
		}
		route, ok := documented[key]
		if !ok {
			t.Errorf("%s 挂了限流桶 %s（%d/min）但文档无此路由", key, registration.rateLimitKey, registration.rateLimitPerMin)
			continue
		}
		var texts []string
		for _, routeError := range route.Errors {
			if strings.HasPrefix(routeError, "429") {
				texts = append(texts, routeError)
			}
		}
		if len(texts) == 0 {
			t.Errorf("%s 挂限流桶 %s（%d/min，%s），文档 Errors=%v 缺 429", key, registration.rateLimitKey, registration.rateLimitPerMin, registration.rateLimitMessageCN, route.Errors)
			continue
		}
		text := strings.Join(texts, "；")
		// 双档限流（凭证 + IP）是 clusterMachineRateLimit 的**失败预算**：
		// 401 保留额度、非 401 回滚（releaseRateLimitReservation），合法
		// 节点成功请求不消耗额度。文档写成无条件请求速率会让从节点把
		// 30/min 误当吞吐上限，或把连续 401 后的 429 误判为网络限流而非
		// 凭证失效。
		if registration.rateLimitIPPerMin > 0 {
			if !strings.Contains(text, "失败") || !strings.Contains(text, "401") {
				t.Errorf("%s 文档 429 未说明「仅 401 失败尝试计入」（该族是失败预算而非请求速率）: %s", key, text)
			}
		}
		numbers := rateLimitNumbersIn(text)
		if len(numbers) == 0 {
			continue
		}
		want := map[int]struct{}{registration.rateLimitPerMin: {}}
		if registration.rateLimitIPPerMin > 0 {
			want[registration.rateLimitIPPerMin] = struct{}{}
		}
		for number := range numbers {
			if _, expected := want[number]; !expected {
				t.Errorf("%s 文档 429 写了 %d/min，与注册实参 %v 不符: %s", key, number, sortedLimitKeys(want), text)
			}
		}
		for number := range want {
			if _, documented := numbers[number]; !documented {
				t.Errorf("%s 文档 429 缺限额数字 %d/min（注册实参）: %s", key, number, text)
			}
		}
	}
	if limited == 0 {
		t.Fatal("限流路由派生为空（扫描器退化 → 本用例恒绿，无鉴别力）")
	}
	if !loginBucketRouted {
		t.Fatal("未能从 middleware.go 的 loginRateLimit 派生限额（实现形态变化，扫描器需跟进）")
	}
	if !machineFamilyRouted {
		t.Fatal("未能从 middleware.go 派生集群机器接口双档限流（包装器形态变化，扫描器需跟进）")
	}
	if !mcpDualRouted {
		t.Fatal("未能从 middleware.go 派生 MCP 的 Key+IP 双档限流")
	}
}

// sortedLimitKeys 把限额期望集转成稳定顺序（错误信息可读且不抖动）。
func sortedLimitKeys(limits map[int]struct{}) []int {
	keys := make([]int, 0, len(limits))
	for limit := range limits {
		keys = append(keys, limit)
	}
	sort.Ints(keys)
	return keys
}

// 集群机器端点的 429 必须带双档限额：该族由从节点周期调用（注册轮询/
// 快照/规则库包/交付确认/健康上报），凭证 30/min 或 IP 300/min 超限时从节点
// 侧只有「429」而没有数字，会把限流误判为集群凭证失效。
func TestAPIDocsClusterMachineEndpointsRateLimitNumbers(t *testing.T) {
	registrations := middlewareRouteRegistrations(t, middlewareSourceForTest(t))
	documented := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		documented[route.Method+" "+route.Path] = route
	}
	machineRoutes := []string{
		"GET /cluster/register/:id/status",
		"POST /cluster/registration/confirm",
		"GET /cluster/sync/snapshot",
		"GET /cluster/sync/waf-files",
		"POST /cluster/nodes/report",
	}
	seen := 0
	for _, key := range machineRoutes {
		registration, ok := registrations[key]
		if !ok || !registration.rateLimitMounted || registration.rateLimitIPPerMin == 0 {
			t.Fatalf("%s 未挂上集群机器限流（派生=%+v）——族清单需按真实装配更新", key, registration)
		}
		seen++
		route, ok := documented[key]
		if !ok {
			t.Errorf("%s 文档无此路由", key)
			continue
		}
		var text strings.Builder
		for _, routeError := range route.Errors {
			if strings.HasPrefix(routeError, "429") {
				text.WriteString(routeError)
			}
		}
		numbers := rateLimitNumbersIn(text.String())
		for _, want := range []int{registration.rateLimitPerMin, registration.rateLimitIPPerMin} {
			if _, ok := numbers[want]; !ok {
				t.Errorf("%s 文档 429 缺 %d/min（凭证=%d、IP=%d）: %s",
					key, want, registration.rateLimitPerMin, registration.rateLimitIPPerMin, text.String())
			}
		}
	}
	if seen != len(machineRoutes) {
		t.Fatalf("机器端点派生 %d/%d", seen, len(machineRoutes))
	}
}
