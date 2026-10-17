package services

// 库值唯一真相（批 1+2）机制级反兜底钉测：
// 扫描 caddy.go 渲染函数体，断言不存在「零值守卫 + 字面量赋值」的写死
// 兜底模式（`if x <= 0 { x = <N> }` / `if x == 0 { x = <N> }`）。G3（第 74 轮）
// 形状扩展：字面量含 STRING（"5s"/"250ms" 类字符串兜底同在禁区）、命中面
// 扩到 else 链（`if x > 0 {…} else { x = "…" }` 的尾 else 兜底形态）、
// 赋值限定 plain `=`（:= 定义与 += 累加非兜底）。规则→全局变量回退
//（x = rule.GlobalY）与错误返回不属兜底（治理允许的分层缺省/fail-visible），
// 不在扫描命中面。允许列表逐条携带 Ruling（类型②省略型/治理范围外），
// 双向精确匹配：扫描出清单外命中=有人往渲染层塞了写死兜底（FAIL）；
// 清单条目在源码中消失=该条目已退役、清单过期（FAIL）——防允许列表腐化。

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// antiFallbackScanTargets 渲染层函数清单（写死兜底禁区），按源文件分组。
// 批 3 起扫描面扩展到 security.go 渲染函数与 caddy.go 安全渲染消费函数。
var antiFallbackScanTargets = map[string][]string{
	"caddy.go": {
		"generateCaddyConfigWithCertSource",
		"buildCaddyLogging",
		"resolveRuleOverrides",
		"resolveProxyTimeouts",
		"formatFlushInterval",
		"GenerateSingleRuleCaddyConfig",
		"generateHTTPRouteObjects",
		"buildHTTPHandleChain",
		"buildTCPProxyRoute",
		"buildTCPServer",
		"buildRateLimitHandler",
		"buildBlockPageAttributionRoute",
		"buildBlockPageErrorRoute",
		"buildStaticResponseHandler",
	},
	"security.go": {
		"BuildCorazaDirectives",
		"buildWafHandlerWithPolicy",
		"buildIPPrecheckDirectives",
		"emitBodyProcessorRules",
		"emitCustomRules",
		"emitCRSRuleGroupSelection",
		"emitScopedCRSExclusions",
	},
}

// antiFallbackAllowlist 允许列表：函数名 → 赋值形态 → Ruling。
// 类型②省略型/范围外字段的现行兜底，逐条披露于批 1+2/批 3 Ruling 报告。
var antiFallbackAllowlist = map[string]map[string]string{
	"generateCaddyConfigWithCertSource": {
		"weight = 1": "上游权重 weight<=0→1：upstreams.weight 非本批治理字段清单（范围外），原状保留；Caddy WRR 亦不接受零权重",
	},
	"buildHTTPHandleChain": {
		"weight = 1": "上游权重 weight<=0→1：同上（范围外，LB40-8 分组层归一删除后链构建层唯一存留点）",
		// G3（第 74 轮）Ruling：HTTP 侧 try_duration==0 → 5s/250ms——存量 HTTP 行
		// 恒 0（列语义「0=默认重试窗口」，2026-09 渲染审计+方案 C 协议分叉已披露
		// UI/文档），行为不变的非治理形态；TCP 侧同列 0/-1 走显性报错/显式禁用，
		// 协议分叉为披露语义非写死兜底。td==-1 分支发射 retries=0 为「显式禁用
		// 重试」语义载体（cond 非零值守卫，不在扫描命中面）。
		`loadBalancing["try_duration"] = "5s"`:                    "HTTP 侧 try_duration==0→5s：存量 HTTP 行恒 0（0=默认重试窗口语义），方案 C 协议分叉+UI 已披露——G3 Ruling 披露",
		`loadBalancing["try_interval"] = "250ms"`:                 "HTTP 侧 try_interval==0→250ms：同上（与 5s 窗口成对发射）——G3 Ruling 披露",
		`serverName = "{lb.upstream_sni}"`:                        "逐上游回源域名在场时 SNI 改走占位符（逐连接展开实证）——host_header 缺省形态的发射形态切换（占位符 vs 静态值），非无效库值兜底；upstream-sni-host 方案披露——G3 Ruling 披露",
		`hostFallback = "{http.reverse_proxy.upstream.hostport}"`: "Host 回退 TLS 池形态：host_header 未配置时绑定上游 hostport 占位符（LBS-A-L2 池形态分流），类型②省略型同族——G3 Ruling 披露",
		`hostFallback = "{http.request.hostport}"`:                "Host 回退常规池形态：host_header 未配置时绑定原始请求 hostport 占位符（现状复现）——G3 Ruling 披露",
		`sniFallback = "{http.reverse_proxy.upstream.host}"`:      "SNI 回退：host_header 未配置时绑定上游 host 占位符（stdlib 空 server_name 默认的同义载体）——G3 Ruling 披露",
	},
	// 批 3 Ruling：block_status_code=类型②省略型（0=未设置，跟随默认 403）。
	// static_response 必须显式携带状态码，「省略」只能以默认值替换实现；写侧
	// 0 为合法值（枚举 400/401/403/404/503 仅约束非零），非兜底写死常量。
	"buildBlockPageAttributionRoute": {
		"statusCode = 403": "block_status_code=0→403：类型②省略型（0=未设置跟随默认 403），写侧 0 合法——批 3 Ruling 披露",
	},
	"buildBlockPageErrorRoute": {
		"statusCode = 403": "block_status_code=0→403：同 buildBlockPageAttributionRoute（类型②省略型）——批 3 Ruling 披露",
	},
	// U12-F09（第 78 轮）覆盖面扫描新发现：路径规则 static_response 的状态码
	// 缺省形态（写侧允许 0=未配置，声明默认 200；空字符串守卫不在扫描命中面）。
	"buildStaticResponseHandler": {
		"status = 200": "path rule ResponseStatus=0→200：类型②省略型（写侧允许 0=未配置并声明默认），非无效库值兜底——U12-F09 Ruling 披露",
	},
	"buildIPPrecheckDirectives": {
		"denyStatus = 403": "阶段 1 预检 denyStatus=0→403：类型②省略型（0=规则未配阶段 1 拦截页，stage1BlockStatus 契约的未设置态；coraza deny 必须显式状态码，省略以默认 403 替换实现，保持 403 兜底归因边界）——批 3 Ruling 披露",
	},
}

func TestRenderLayer_hasNoHardcodedZeroFallbacks(t *testing.T) {
	fset := token.NewFileSet()

	scanned := map[string]bool{}
	violations := map[string]string{}
	for fileName, functions := range antiFallbackScanTargets {
		file, err := parser.ParseFile(fset, fileName, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", fileName, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if _, wanted := antiFallbackAllowlist[fn.Name.Name]; !wanted && !containsString(functions, fn.Name.Name) {
				continue
			}
			scanned[fn.Name.Name] = true
			for assign, pos := range fallbackAssignmentsInFunction(fset, fn) {
				violations[fn.Name.Name+":"+assign] = pos
			}
		}
	}

	// 双向核对：扫描面必须覆盖全部禁区函数（清单与源码同步）。
	for fileName, functions := range antiFallbackScanTargets {
		for _, name := range functions {
			if !scanned[name] {
				t.Errorf("scan list function %q not found in %s——清单与源码漂移，请更新 antiFallbackScanTargets", name, fileName)
			}
		}
	}

	// 方向一：清单外命中=新兜底混入渲染层。
	for key, pos := range violations {
		funcName, assign := splitScanKey(key)
		allowed, inAllowlist := antiFallbackAllowlist[funcName]
		reason, allowedAssign := allowed[assign]
		if !inAllowlist || !allowedAssign {
			t.Errorf("渲染函数 %s 出现清单外写死兜底 %q（%s）——库值唯一真相治理禁止在渲染层以数字字面量兜底无效库值；若为类型②省略型/范围外字段，请携 Ruling 加入 antiFallbackAllowlist", funcName, assign, pos)
			continue
		}
		_ = reason
	}

	// 方向二：清单条目必须仍存在于扫描命中（防允许列表腐化成死清单）。
	for funcName, entries := range antiFallbackAllowlist {
		for assign := range entries {
			if _, live := violations[funcName+":"+assign]; !live {
				t.Errorf("允许列表条目 %s:%q 在源码中已消失——兜底已退役，请同步删除该清单条目（防清单腐化）", funcName, assign)
			}
		}
	}

	// 方向三（U12-F09）：扫描包内全部非测试 .go——渲染族命名函数若出现兜底
	// 形态却未登记 antiFallbackScanTargets，说明新增渲染文件/函数绕过了扫描面。
	listed := map[string]bool{}
	for fileName, functions := range antiFallbackScanTargets {
		for _, name := range functions {
			listed[fileName+"|"+name] = true
		}
	}
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}
	for _, path := range goFiles {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !isRenderFamilyFunction(fn.Name.Name) {
				continue
			}
			if listed[path+"|"+fn.Name.Name] {
				continue
			}
			for assign, pos := range fallbackAssignmentsInFunction(fset, fn) {
				t.Errorf("渲染族函数 %s（%s）含兜底 %q（%s）但未登记 antiFallbackScanTargets——新增渲染函数必须纳入扫描面或携 Ruling 说明非渲染用途", fn.Name.Name, path, assign, pos)
			}
		}
	}
}

// fallbackAssignmentsInFunction 扫描函数体内的「零值守卫 + 字面量赋值」兜底
// 形态（G3 形状：INT/STRING 字面量、plain `=`、else 链纳入），返回
// 赋值文本 → 位置。
func fallbackAssignmentsInFunction(fset *token.FileSet, fn *ast.FuncDecl) map[string]string {
	hits := map[string]string{}
	if fn.Body == nil {
		return hits
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		// G3：零值守卫条件含 GTR（`x > 0 {…} else {兜底}` 形态的尾 else）。
		bin, ok := ifStmt.Cond.(*ast.BinaryExpr)
		if !ok || (bin.Op != token.EQL && bin.Op != token.LEQ && bin.Op != token.GTR) {
			return true
		}
		lit, ok := bin.Y.(*ast.BasicLit)
		if !ok || lit.Kind != token.INT || lit.Value != "0" {
			return true
		}
		scanAssigns := func(branch ast.Node) {
			ast.Inspect(branch, func(m ast.Node) bool {
				assign, ok := m.(*ast.AssignStmt)
				// G3：仅 plain `=`（:= 定义与 += 累加非兜底赋值）。
				if !ok || assign.Tok != token.ASSIGN {
					return true
				}
				for _, rhs := range assign.Rhs {
					// G3：STRING 字面量兜底（"5s"/"250ms" 形态）与 INT 同罪。
					if num, ok := rhs.(*ast.BasicLit); ok && (num.Kind == token.INT || num.Kind == token.STRING) {
						var buf bytes.Buffer
						_ = printer.Fprint(&buf, fset, assign)
						hits[buf.String()] = fset.Position(assign.Pos()).String()
						break
					}
				}
				return true
			})
		}
		scanAssigns(ifStmt.Body)
		// G3：else 链纳入命中面——逐级 else-if 体（同为零值守卫时）+
		// 终端 else 块（外层守卫的反向兜底形态）。
		els := ifStmt.Else
		for els != nil {
			switch e := els.(type) {
			case *ast.BlockStmt:
				scanAssigns(e)
				els = nil
			case *ast.IfStmt:
				if ebin, ok := e.Cond.(*ast.BinaryExpr); ok {
					if elit, ok := ebin.Y.(*ast.BasicLit); ok && elit.Kind == token.INT && elit.Value == "0" &&
						(ebin.Op == token.EQL || ebin.Op == token.LEQ || ebin.Op == token.GTR) {
						scanAssigns(e.Body)
					}
				}
				els = e.Else
			default:
				els = nil
			}
		}
		return true
	})
	return hits
}

// isRenderFamilyFunction 按命名识别渲染族函数（U12-F09 覆盖面扫描）：
// build*/generate*/emit*/resolve*/format* 前缀，或 Handler/Directives/Route 后缀。
func isRenderFamilyFunction(name string) bool {
	for _, prefix := range []string{"build", "Build", "generate", "Generate", "emit", "Emit", "resolve", "Resolve", "format", "Format"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	for _, suffix := range []string{"Handler", "Directives", "Route"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func splitScanKey(key string) (string, string) {
	for i := 0; i < len(key); i++ {
		if key[i] == ':' {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
