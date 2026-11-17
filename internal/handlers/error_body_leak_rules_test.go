package handlers

// business 组 5xx 响应只回固定文案：底层错误（SQL 文本/表列名、文件路径与
// errno、Caddy admin 地址）只进运行日志与操作审计。4xx 配置拒绝类不受此约束
// （cli_validation_gate 等门禁依赖 400 内的 CLI/字段细节）。
// 两路钉：源码级（规则端点全部 5xx 写点不得拼接 err.Error()）+ 行为级
//（真实 DB 故障下响应体不含内部结构）。

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/tools/go/packages"
	"lazy-balancer-v2/internal/db"
)

func TestRuleEndpoint5xxBodiesHideInternalErrors(t *testing.T) {
	fset := token.NewFileSet()
	errNames := productionErrorIdentNames(t)
	parsed, err := parser.ParseFile(fset, "rules.go", nil, 0)
	if err != nil {
		t.Fatalf("parse rules.go: %v", err)
	}
	for _, leak := range collect5xxErrorTextLeaks(fset, parsed, errNames) {
		t.Errorf("rules.go: 5xx 响应拼接了内部错误文本: %s", leak)
	}

	// 配置域同政策：GetConfig（business 组）与聚合预校验的通用失败分支。
	// found-map 存在性断言（同 auditlog 门形态）：目标函数改名/搬走后循环
	// 会静默零执行成假绿，缺失即点名。
	caddyFile, err := parser.ParseFile(fset, "caddy.go", nil, 0)
	if err != nil {
		t.Fatalf("parse caddy.go: %v", err)
	}
	caddyFound := map[string]bool{"GetConfig": false, "writeConfigValidationFailure": false}
	for _, fn := range caddyFile.Decls {
		decl, ok := fn.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, want := caddyFound[decl.Name.Name]; !want {
			continue
		}
		caddyFound[decl.Name.Name] = true
		for _, leak := range collect5xxErrorTextLeaks(fset, decl, errNames) {
			t.Errorf("caddy.go:%s: 5xx 响应拼接了内部错误文本: %s", decl.Name.Name, leak)
		}
	}
	for name, found := range caddyFound {
		if !found {
			t.Errorf("caddy.go 未找到 %s（扫描面漂移会让门禁假绿）", name)
		}
	}

	// 规则指标历史端点（business 组）：读取/扫描/时间解析失败的 5xx 与
	// rules 族同政策——内部结构只进日志，响应只回固定文案。
	metricsFile, err := parser.ParseFile(fset, "metrics.go", nil, 0)
	if err != nil {
		t.Fatalf("parse metrics.go: %v", err)
	}
	metricsFound := map[string]bool{"GetRuleMetricsHistory": false, "GetMetricsHistory": false}
	for _, fn := range metricsFile.Decls {
		decl, ok := fn.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, want := metricsFound[decl.Name.Name]; !want {
			continue
		}
		metricsFound[decl.Name.Name] = true
		for _, leak := range collect5xxErrorTextLeaks(fset, decl, errNames) {
			t.Errorf("metrics.go:%s: 5xx 响应拼接了内部错误文本: %s", decl.Name.Name, leak)
		}
	}
	for name, found := range metricsFound {
		if !found {
			t.Errorf("metrics.go 未找到 %s（扫描面漂移会让门禁假绿）", name)
		}
	}

	// 共享事务收尾（business 组经 finishTxApply 收口：批量阶段页等）：5xx 与
	// 已提交视图恢复分支必须只回固定文案——错误详情由日志/审计承担。
	okNoteTargets := []struct {
		file  string
		fname string
		kind  string // "5xx" → collect5xxErrorTextLeaks | "oknote" → okFailureNoteLeaks
	}{
		{"handlers.go", "finishTxApply", "5xx"},
		{"handlers.go", "finishTxApply", "oknote"},
		// tryIPListHotPathApply 的强制重载收尾镜像 finishTxApply 三分支，
		// 200 失败注记同受脱敏契约约束。
		{"securityiplists.go", "tryIPListHotPathApply", "oknote"},
		// 热路径 5xx 面同受扫描（admin 细节政策登记在 adminBusiness5xxDetailFunctions，
		// 可判性门强制登记——消除「既不登记也不扫描」真空区）。
		{"securityiplists.go", "tryIPListHotPathApply", "5xx"},
		// IPv6 地理库开关 200 注记脱敏面（applyErr 不得直拼进成功响应）。
		{"security.go", "SetIP2RegionV6Enabled", "oknote"},
		// IPv6 地理库开关 5xx 写失败面（admin 组，未登记细节政策——固定文案）。
		{"security.go", "SetIP2RegionV6Enabled", "5xx"},
		// 从节点服务控制（v1 票据凭证端点，集群对端可见）：执行失败 5xx 与
		// 票据校验 5xx 同受扫描，不得直拼底层错误（admin 地址/exec 退出码）。
		{"cluster_service.go", "ClusterServiceControl", "5xx"},
		// 管理面板 HTTPS 落库失败面（admin 组已登记细节政策，豁免同
		// tryIPListHotPathApply；200 注记面不豁免）。
		{"admintls.go", "UpdateAdminTLS", "5xx"},
	}
	leaksOf := func(fs *token.FileSet, n ast.Node, kind string) []string {
		if kind == "oknote" {
			return okFailureNoteLeaks(fs, n, errNames)
		}
		return collect5xxErrorTextLeaks(fs, n, errNames)
	}
	// found-map 存在性断言：目标文件:函数改名/搬走后该条目静默零执行成假绿。
	okNoteFound := make(map[string]bool, len(okNoteTargets))
	for _, target := range okNoteTargets {
		key := target.file + ":" + target.fname
		parsedFile, err := parser.ParseFile(fset, target.file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", target.file, err)
		}
		for _, fn := range parsedFile.Decls {
			decl, ok := fn.(*ast.FuncDecl)
			if !ok || decl.Name.Name != target.fname {
				continue
			}
			okNoteFound[key] = true
			// admin 细节政策登记函数豁免 5xx 固定文案门（可判性门
			// TestAdminBusiness5xxDetailPolicyIsExplicit 强制登记+路由组门）；
			// 200 注记脱敏门（okFailureNoteLeaks）不豁免。
			if target.kind == "5xx" {
				if _, registered := adminBusiness5xxDetailFunctions[target.file+":"+target.fname]; registered {
					continue
				}
			}
			for _, leak := range leaksOf(fset, decl, target.kind) {
				t.Errorf("%s:%s: 响应拼接了未脱敏的内部错误文本: %s", target.file, decl.Name.Name, leak)
			}
		}
	}
	for _, target := range okNoteTargets {
		if !okNoteFound[target.file+":"+target.fname] {
			t.Errorf("%s 未找到 %s（扫描面漂移会让门禁假绿）", target.file, target.fname)
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
	c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "admission: " + err.Error()})
	c.JSON(http.StatusGatewayTimeout, models.APIResponse{Code: 504, Message: fmt.Sprintf("timeout: %v", err)})
	// 动态状态与经局部变量传递的错误文案不得绕过扫描。
	message := err.Error()
	c.JSON(status, models.APIResponse{Code: status, Message: message})
	localStatus := http.StatusInternalServerError
	localMessage := "export: " + err.Error()
	c.JSON(localStatus, models.APIResponse{Code: localStatus, Message: localMessage})
	writeInternalError(c, status, message, err)
	writeInternalError(c, http.StatusBadGateway, fmt.Sprintf("wrapped: %v", err), err)
	// 别名 err 形态：e2 := err 后经 %v/%w 格式化同样直出内部文本（SQL 文本/
	// admin 地址）。裸名字判据已 types 化（errorTypedIdentNames），只认字面
	// err 的旧判据捕不到这两处——别名识别能力借此钉住，退化即红。
	e2 := err
	c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: fmt.Sprintf("alias: %v", e2)})
	fail(http.StatusInternalServerError, fmt.Errorf("alias wrap: %w", e2))
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
	errNames := fixtureErrorIdentNames(t, fset, parsed)
	if leaks := collect5xxErrorTextLeaks(fset, parsed, errNames); len(leaks) != 16 {
		t.Fatalf("扫描器应捕获 16 处 5xx 泄漏（含 503/504 与 err 别名形态，识别名集合 %v），实际 %d: %v", errNames, len(leaks), leaks)
	}
}

// 「成功响应 + 失败注记」扫描器自检：未脱敏拼接错误文本的 200 写点必须被
// 捕获；经 RedactCaddyAdminEndpoint 脱敏的同一形态与固定文案/4xx 反形状
// 不得误报。若该扫描退化（恒空或恒报），finishTxApply 退化提交响应的
// 脱敏契约就失去机械守卫。
func TestOKFailureNoteScannerDetectsUnredactedSuccessBodies(t *testing.T) {
	const source = `package p

func f(c *gin.Context, err error, status int) {
	// 泄漏形态：成功响应直出错误文本（admin 地址在 /load 传输错误里）。
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已保存；但 Caddy 配置应用失败：" + err.Error()})
	c.JSON(200, models.APIResponse{Code: 0, Message: fmt.Sprintf("已保存；但应用失败：%v", err)})
	message := err.Error()
	c.JSON(status, models.APIResponse{Code: 0, Message: "已保存；但应用失败：" + message})
	// i18n 译文形态（apimsg.ErrMsg/Tf 注入）与 .Error() 直拼披露语义等价——
	// 与 5xx 扫描同政策，未脱敏即泄漏。
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.ErrMsg(c, err)})
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.Tf(c, "k_x", apimsg.ErrMsg(c, err))})
	// 合法形态：脱敏出口（含译文形态经脱敏包裹）。
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已保存；但 Caddy 配置应用失败：" + services.RedactCaddyAdminEndpoint(err.Error())})
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.Tf(c, "k_x", services.RedactCaddyAdminEndpoint(apimsg.ErrMsg(c, err)))})
	// 5xx 写点归 collect5xxErrorTextLeaks 管辖，本扫描不重复计。
	c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "x: " + err.Error()})
	// 4xx 配置拒绝类不受约束（同 5xx 扫描的反形状）：400/409 字面量与动态
	// 非成功状态都不算「成功响应」。
	c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
	c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "冲突：" + err.Error()})
	// 504 与 500/502/503 同属 5xx 管辖（isInternalStatusExpr 含 504）——
	// 状态集不对称会让 504 写点被本扫描双重管辖误报。
	c.JSON(http.StatusGatewayTimeout, models.APIResponse{Code: 504, Message: "x: " + err.Error()})
	c.JSON(504, models.APIResponse{Code: 504, Message: "x: " + err.Error()})
}`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "synthetic_ok.go", source, 0)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	errNames := fixtureErrorIdentNames(t, fset, parsed)
	leaks := okFailureNoteLeaks(fset, parsed, errNames)
	if len(leaks) != 5 {
		t.Fatalf("OK 注记扫描器应捕获 5 处未脱敏成功响应（含 ErrMsg/Tf 译文形态），实际 %d: %v", len(leaks), leaks)
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
func collect5xxErrorTextLeaks(fset *token.FileSet, node ast.Node, errNames map[string]bool) []string {
	switch scoped := node.(type) {
	case *ast.FuncDecl:
		return collect5xxErrorTextLeaksInScope(fset, scoped, scoped.Type.Params, errNames)
	case *ast.FuncLit:
		return collect5xxErrorTextLeaksInScope(fset, scoped, scoped.Type.Params, errNames)
	}
	leaks := make([]string, 0)
	ast.Inspect(node, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		leaks = append(leaks, collect5xxErrorTextLeaksInScope(fset, fn, fn.Type.Params, errNames)...)
		return false
	})
	return leaks
}

func collect5xxErrorTextLeaksInScope(fset *token.FileSet, scope ast.Node, params *ast.FieldList, errNames map[string]bool) []string {
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
		if mentionsErrorText(fset, rhs, errNames) {
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
					if mentionsErrorText(fset, current.Values[i], errNames) {
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
		// i18n 译文形态（apimsg.ErrMsg）与 .Error() 直拼同政策——识别谓词
		// 与 oknote 扫描单源共用（mentionsAPIMsgErrMsg）。
		if mentionsAPIMsgErrMsg(expr) || mentionsErrorText(fset, expr, errNames) {
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
		case "clusterError":
			// 实参形态 (c, status, message, err)——message 拼接内部文本即泄漏。
			if len(call.Args) >= 3 && hasInternalStatus(call.Args[1]) && hasErrorText(call.Args[2]) {
				leaks = append(leaks, printNode(fset, call))
			}
		case "clusterErrorKeyed":
			// 实参形态 (c, status, message, messageKey, err)。
			if len(call.Args) >= 4 && hasInternalStatus(call.Args[1]) && hasErrorText(call.Args[2]) {
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
		return e.Sel.Name == "StatusInternalServerError" || e.Sel.Name == "StatusBadGateway" ||
			e.Sel.Name == "StatusServiceUnavailable" || e.Sel.Name == "StatusGatewayTimeout"
	case *ast.BasicLit:
		return e.Kind == token.INT && (e.Value == "500" || e.Value == "502" || e.Value == "503" || e.Value == "504")
	}
	return false
}

func mentionsErrorText(fset *token.FileSet, node ast.Node, errNames map[string]bool) bool {
	source := printNode(fset, node)
	if strings.Contains(source, ".Error()") {
		return true
	}
	return formatsRawErrorValue(node, errNames)
}

// errorTypedIdentNames 从类型信息收集「类型实现 error 接口」的标识符名集合
// （变量/形参/:= 派生别名等一切有 Def 的名字），并恒保留字面 "err" 快路径。
// 名字集合是保守近似：不同作用域的同名标识符一并放行——识别面宁大勿漏
// （误报由「5xx 响应拼接内部错误文本」的政策语义兜底，正常代码不会把
// error 类型变量格式化进响应体）。
func errorTypedIdentNames(defs map[*ast.Ident]types.Object) map[string]bool {
	errIface, _ := types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	names := map[string]bool{"err": true}
	for ident, obj := range defs {
		if ident == nil || obj == nil || ident.Name == "_" || names[ident.Name] {
			continue
		}
		typ := obj.Type()
		if typ == nil || typ == types.Typ[types.Invalid] {
			continue
		}
		if types.Implements(typ, errIface) {
			names[ident.Name] = true
		}
	}
	return names
}

var (
	rawErrScanOnce  sync.Once
	rawErrScanNames map[string]bool
	rawErrScanErr   error
)

// productionErrorIdentNames 用 go/packages 对本包生产源码做一次完整类型检查
// （每测试进程缓存一次），返回裸错误文本识别的名字集合——生产代码的 err
// 别名（e2/wrapErr/applyErr 等）从此在册，不再只匹配字面 err。加载/类型
// 检查失败必须 fail-loud：静默退化为仅 "err" 匹配会让别名形态逃过 5xx 扫描。
func productionErrorIdentNames(t *testing.T) map[string]bool {
	t.Helper()
	rawErrScanOnce.Do(func() {
		cwd, err := os.Getwd()
		if err != nil {
			rawErrScanErr = err
			return
		}
		pkgs, err := packages.Load(&packages.Config{
			Mode:  packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo,
			Dir:   cwd,
			Tests: false,
		}, ".")
		if err != nil {
			rawErrScanErr = err
			return
		}
		names := map[string]bool{"err": true}
		for _, pkg := range pkgs {
			if len(pkg.Errors) > 0 {
				rawErrScanErr = fmt.Errorf("%s: %v", pkg.ID, pkg.Errors[0])
				return
			}
			if pkg.TypesInfo == nil {
				rawErrScanErr = fmt.Errorf("%s: TypesInfo 为空（加载模式漂移）", pkg.ID)
				return
			}
			for name := range errorTypedIdentNames(pkg.TypesInfo.Defs) {
				names[name] = true
			}
		}
		rawErrScanNames = names
	})
	if rawErrScanErr != nil {
		t.Fatalf("裸 err 判据 types 化失败（拒绝静默退化为字面名匹配）: %v", rawErrScanErr)
	}
	return rawErrScanNames
}

// fixtureErrorIdentNames 对合成夹具源码做宽松类型检查：外部包符号（gin/fmt/
// models 等）无法解析的报错经 Error 回调吞掉，universe 级 error 形参与其
// := 派生别名（e2 := err）仍可解析——夹具内的 err 别名据此在册，自检得以
// 钉住别名识别能力。夹具集合缺别名时由调用方的命中数断言点名（fail-loud）。
func fixtureErrorIdentNames(t *testing.T, fset *token.FileSet, file *ast.File) map[string]bool {
	t.Helper()
	info := &types.Info{Defs: make(map[*ast.Ident]types.Object)}
	conf := types.Config{Error: func(error) {}}
	_, _ = conf.Check("synthetic", fset, []*ast.File{file}, info)
	return errorTypedIdentNames(info.Defs)
}

// formatsRawErrorValue 报告节点是否用 %v/%s/%w 直接格式化裸错误标识符
// （fmt.Sprintf / fmt.Errorf 形态）——这类写法不产生 ".Error()" 字面串，
// 却同样把底层错误（SQL 文本/表列名、文件路径、admin 地址）拼进响应体。
// 判据是「类型实现 error 接口」的标识符名集合（errNames，types 化单源），
// 别名变量（e2/wrapErr 等）与字面 err 同罪。
func formatsRawErrorValue(node ast.Node, errNames map[string]bool) bool {
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
			if ident, ok := arg.(*ast.Ident); ok && errNames[ident.Name] {
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

// mentionsAPIMsgErrMsg 报告节点是否含 apimsg.ErrMsg 选择器——i18n 后错误明细
// 经译文形态注入，披露语义与 .Error() 直拼等价。5xx 扫描与 oknote 扫描共用
// 本谓词（单源）：两侧识别能力分叉会让译文形态从其中一侧逃逸。
func mentionsAPIMsgErrMsg(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "ErrMsg" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "apimsg" {
			found = true
			return false
		}
		return true
	})
	return found
}

// isExplicitNonOKStatusExpr 报告状态实参是否为字面 4xx/5xx（选择器或整数
// 字面量）——这些写点分属 5xx 扫描与 4xx 允许面，「成功响应 + 失败注记」
// 扫描只辖 2xx/动态 status 形态。
func isExplicitNonOKStatusExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		switch e.Sel.Name {
		case "StatusBadRequest", "StatusUnauthorized", "StatusForbidden", "StatusNotFound",
			"StatusConflict", "StatusGone", "StatusRequestEntityTooLarge", "StatusUnprocessableEntity",
			"StatusTooManyRequests", "StatusInternalServerError", "StatusNotImplemented",
			"StatusBadGateway", "StatusServiceUnavailable", "StatusGatewayTimeout":
			return true
		}
		return false
	case *ast.BasicLit:
		if e.Kind != token.INT {
			return false
		}
		switch e.Value {
		case "400", "401", "403", "404", "409", "410", "413", "422", "429", "500", "501", "502", "503", "504":
			return true
		}
		return false
	}
	return false
}

// okFailureNoteLeaks 扫描「成功响应 + 失败注记」形态：非 5xx 的 c.JSON 写点
// 若在响应体拼接错误文本且未经 RedactCaddyAdminEndpoint 脱敏，即为泄漏——
// 成功响应与 5xx 固定文案同一可见面（business 组任意登录用户），admin 地址
// 等内部结构不得直出。仅对显式列出的函数应用：collect5xxErrorTextLeaks 的
// 4xx 允许面（配置拒绝类回真实原因）不受影响，全量套用会把合法 400 形态
// 误判为泄漏。
func okFailureNoteLeaks(fset *token.FileSet, node ast.Node, errNames map[string]bool) []string {
	// 经局部变量中转的错误文本（message := err.Error()）与直拼同罪：先收集
	// 赋值面，再在响应实参里按标识符识别（与 collect5xxErrorTextLeaksInScope
	// 的 errorTextNames 同形）。
	errorTextNames := map[string]bool{}
	ast.Inspect(node, func(n ast.Node) bool {
		switch current := n.(type) {
		case *ast.AssignStmt:
			if len(current.Lhs) == 1 && len(current.Rhs) == 1 {
				if ident, ok := current.Lhs[0].(*ast.Ident); ok && mentionsErrorText(fset, current.Rhs[0], errNames) {
					errorTextNames[ident.Name] = true
				}
			}
		case *ast.ValueSpec:
			if len(current.Names) == 1 && len(current.Values) == 1 && mentionsErrorText(fset, current.Values[0], errNames) {
				errorTextNames[current.Names[0].Name] = true
			}
		}
		return true
	})
	containsErrorText := func(expr ast.Expr) bool {
		if mentionsAPIMsgErrMsg(expr) || mentionsErrorText(fset, expr, errNames) {
			return true
		}
		found := false
		ast.Inspect(expr, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && errorTextNames[ident.Name] {
				found = true
				return false
			}
			return !found
		})
		return found
	}
	leaks := make([]string, 0)
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "JSON" {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "c" || len(call.Args) < 2 {
			return true
		}
		// 5xx 写点归 collect5xxErrorTextLeaks 管辖；4xx 配置拒绝类是本测试
		// 文件头声明的允许面（cli_validation_gate 等门禁依赖 400 内的 CLI
		// 细节）。本扫描只看「成功响应 + 失败注记」形态。
		if isExplicitNonOKStatusExpr(call.Args[0]) {
			return true
		}
		for _, arg := range call.Args[1:] {
			if containsErrorText(arg) && !wrapsRedactCaddyAdminEndpoint(fset, arg, errNames) {
				leaks = append(leaks, printNode(fset, call))
				break
			}
		}
		return true
	})
	return leaks
}

// wrapsRedactCaddyAdminEndpoint 报告节点内的错误文本是否经 RedactCaddyAdminEndpoint
// 包裹（成功响应失败注记的唯一合法出口——脱敏后的文本才可直出）。
func wrapsRedactCaddyAdminEndpoint(fset *token.FileSet, node ast.Node, errNames map[string]bool) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "RedactCaddyAdminEndpoint" {
			return true
		}
		for _, arg := range call.Args {
			if mentionsAPIMsgErrMsg(arg) || mentionsErrorText(fset, arg, errNames) {
				found = true
				return false
			}
		}
		return true
	})
	return found
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
	errNames := productionErrorIdentNames(t)
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
		leaks := collect5xxErrorTextLeaks(fset, fn, errNames)
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
	errNames := productionErrorIdentNames(t)
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
		for _, leak := range collect5xxErrorTextLeaks(fset, fn, errNames) {
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
	"autobackup.go:AutoBackupSettings":                "设置/备份列表读取失败需管理员看到 errno",
	"autobackup.go:UpdateAutoBackupSettings":          "设置事务写失败需点名（DB 锁/只读库）",
	"autobackup.go:RunAutoBackupNow":                  "引擎触发失败需点名（admission/执行错误）",
	"autobackup.go:RestoreAutoBackup":                 "备份文件读取失败需点名（权限/errno）",
	"autobackup.go:DownloadAutoBackup":                "备份文件读取失败需点名（权限/errno）",
	"admintls.go:UpdateAdminTLS":                      "当前 HTTPS 配置读校验失败需点名，避免半套材料落库",
	"config_backup.go:ExportConfigBackup":             "导出失败需管理员区分备份内容错误与系统故障",
	"config_backup.go:failImportTx":                   "导入/还原必须点名事务回滚原因（既有响应契约）",
	"cluster_mode.go:SetClusterMode":                  "主从切换注册失败需管理员看到目标主节点不可达原因（网络/证书/拒绝）",
	"cluster_sync.go:PullClusterSnapshot":             "手动同步失败需管理员看到拉取/应用失败原因（排障契约）",
	"cluster_sync.go:ForgetClusterPins":               "清除指纹失败需点名（权限/只读目录）",
	"config_import_v1.go:ImportV1Config":              "v1 导入规则编号生成失败需点名（既有响应契约）",
	"taskmonitor.go:respondTaskTriggerAdmissionError": "任务触发 admission 失败需管理员看到引擎错误（503 default 分支；四写端点共用 helper）",
	"securityiplists.go:tryIPListHotPathApply":        "提交不确定态需管理员看到 commit/恢复原因（与 caddy.go 同口径；iplist_commit_recovery_test 钉住原文披露契约）",
	"cluster_mode.go:PromoteClusterNode":              "升主失败需管理员看到原因（角色/排干/拓扑事务）",
	"cluster_mode.go:UpdateClusterSettings":           "集群设置保存失败需点名（既有响应契约）",
	"taskmonitor.go:ToggleSystemTask":                 "调度偏好保存失败需管理员看到 DB 错误（词条携带详情槽）",
	"taskmonitor.go:ControlSystemTask":                "任务控制失败需管理员看到引擎错误（词条携带详情槽）",
}

// 政策前提门（admin 业务族）：清单条目必须是 admin 组的**路由处理器**——
// 「保留底层细节」的理由是管理员排障接口；条目被移入 business 组时同一政策
// 会向任意登录用户披露 DB errno/路径。此前只有 caddy 清单有组门，本清单缺，
// 105 轮修的正是「端点被移组而清单仍绿」这一形态。
//
// 清单里有两类条目：路由处理器（须在 admin 组注册）与无路由入口的内部辅助
// 函数（failImportTx/importConfigBackupCore，由同文件的处理器调用）——后者显式
// 列在 helper 白名单里并附理由，新增的未注册条目一律判红（不得靠沉默混过）。
func TestAdminBusiness5xxDetailPolicyRoutesAreAdminGroup(t *testing.T) {
	helpersWithoutRoutes := map[string]string{
		"config_backup.go:failImportTx":                   "导入事务回滚收尾的内部辅助函数，无独立路由入口",
		"securityiplists.go:tryIPListHotPathApply":        "名单热路径提交收尾的内部辅助函数，无独立路由入口（由各名单写端点调用）",
		"taskmonitor.go:respondTaskTriggerAdmissionError": "admission 错误映射的内部辅助函数，无独立路由入口（trigger/toggle/cancel/control 共用）",
	}
	registrations := caddyRouteGroupRegistrations(t)
	routed := 0
	for key := range adminBusiness5xxDetailFunctions {
		_, fn, ok := strings.Cut(key, ":")
		if !ok || fn == "" {
			t.Fatalf("政策登记条目 %q 形态非法（want 文件:函数）", key)
		}
		groups, registered := registrations[fn]
		if registered {
			routed++
			if !groups["admin"] {
				t.Errorf("政策清单条目 %q 注册在 %v 组而不是 admin 组——5xx 细节会披露给非管理员", key, groups)
			}
			if _, helper := helpersWithoutRoutes[key]; helper {
				t.Errorf("政策清单条目 %q 已注册路由，必须从「无路由辅助函数」白名单移除", key)
			}
			continue
		}
		if _, helper := helpersWithoutRoutes[key]; !helper {
			t.Errorf("政策清单条目 %q 在 middleware.go 中没有路由注册，也不在辅助函数白名单（过期条目或命名漂移）", key)
		}
	}
	// 正向控制：路由条目必须真实命中（否则组门退化为空转）。
	if routed < 7 {
		t.Fatalf("政策清单只有 %d 条命中路由注册（< 7）——路由表派生或清单漂移", routed)
	}
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
	errNames := productionErrorIdentNames(t)
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
			leaks := collect5xxErrorTextLeaks(fset, fn, errNames)
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
