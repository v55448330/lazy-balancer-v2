package services

// 库值唯一真相（批 1+2）机制级反兜底钉测：
// 扫描 caddy.go 渲染函数体，断言不存在「零值守卫 + 字面量赋值」的写死
// 兜底模式（`if x <= 0 { x = <N> }` / `if x == 0 { x = <N> }`）。
// 形状扩展：字面量含 STRING（"5s"/"250ms" 类字符串兜底同在禁区）、命中面
// 扩到 else 链（`if x > 0 {…} else { x = "…" }` 的尾 else 兜底形态）、
// 赋值限定 plain `=`（:= 定义与 += 累加非兜底）。规则→全局变量回退
//（x = rule.GlobalY）与错误返回不属兜底（治理允许的分层缺省/fail-visible），
// 不在扫描命中面。允许列表逐条携带 Ruling（类型②省略型/治理范围外），
// 双向精确匹配：扫描出清单外命中=有人往渲染层塞了写死兜底（FAIL）；
// 清单条目在源码中消失=该条目已退役、清单过期（FAIL）——防允许列表腐化。
// 命中面扩展到 LSS(<0/<1)、NEQ(!=0)、GTR/GEQ 反向分支、
// switch/case 零值守卫与非 map 非空复合字面量默认值，并为每形态配夹具（
// TestFallbackScan_detectsEquivalentGuardShapes）——语义等价写法不得绕过机制。
// switch 面同时覆盖 tagged 形态（`switch x { case 0: x = 5 }` 用 Tag 与 case
// 值构造等值比较后复用同一判定），数值字面量按 go/constant 的数值比对 0/1
// （0x0 / 00 / 0_0 / 0b0 / 0e0 与 0 同值，源码文本比较会漏掉这些写法）。
// 复合条件（`&&`/`||`）取两侧兜底分支的并集、`!(cond)` 交换 if 体/else 块
// 同属命中面：`if x == 0 && flag { x = 5 }` 这类「零值守卫 + 附加条件」是
// 最常见的现实书写，只看顶层比较会让它们整段逃逸。
//
// 字符串列同属失效族（strategy/content_type/log level/protocol 等）：
// 空字符串守卫（`if s == "" { s = "x" }`）与反向操作数（`0 == x` / `"" == s`）
// 纳入命中面；守卫分支内的单一返回值字面量（`if v < 0 { return "-1s" }`）同属
// 写死默认值形态。
//
// 机制边界（有意不纳入）：右值为常量/selector（`x = models.DefaultX`）或算术
// （`x = 5 * time.Second`）——纯 AST 无法与普通变量/算术区分（`x = x + 1`），
// 纳入会产生大量误报；`x := <字面量>` 是影子变量定义，不改写库值来源。

import (
	"bytes"
	"go/ast"
	"go/constant"
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
		"buildTCPProxyHandler",
		"buildTCPServer",
		"buildRateLimitHandler",
		"buildBlockPageAttributionRoute",
		"buildBlockPageErrorRoute",
		"buildStaticResponseHandler",
		// 生产读路径（规则 TLS 就绪/策略投影）与发射面（日志 encoder、受信代理
		// 字段）——读面与运行态必须同判据，零值兜底同样不得写死。
		"buildAccessLogEncoder",
		"accessLogEncoderFields",
		"trustedProxyServerFields",
		"mergeTrustedProxyServerFields",
		"expandTrustedProxyRanges",
		"insertUpstreamPathRewrites",
		"upstreamPathRewriteHandlers",
		"blockPageContentType",
		"decodePathUpstreams",
	},
	"security.go": {
		"BuildCorazaDirectives",
		"buildCorazaDirectivesWithIndex",
		"buildIPPrecheckDirectives",
		"emitBodyProcessorRules",
		"emitCustomRules",
		"emitCRSRuleGroupSelection",
		"emitScopedCRSExclusions",
		"ParseCRSExcludedRules",
	},
	// 展示层：证书卡/规则证书字段的占位文案（非配置投影，但同属「无效库值 →
	// 写死常量」可见面，纳入扫描以防新增渲染文案绕过机制）。
	"certinfo.go": {
		"formatRuleCertInfo",
	},
}

// antiFallbackAllowlist 允许列表：函数名 → 赋值形态 → Ruling。
// 类型②省略型/范围外字段的现行兜底，逐条披露于批 1+2/批 3 Ruling 报告。
var antiFallbackAllowlist = map[string]map[string]string{
	// 只有旧版单条件行（target/operator/pattern 列）没有 conditions 数组；
	// OR 渲染需要把旧行还原成一条条件，属类型②省略型的兼容重建——写侧
	// 保存/导入会归一成 conditions，存量行由本兜底保持可渲染（Ruling 2026-10-27）。
	"emitCustomRules": {
		`conditions = []models.CustomRuleCondition{{Target: cr.Target, Operator: cr.Operator, Pattern: cr.Pattern}}`: "旧单条件行 conditions 为空 → 以 target/operator/pattern 重建一条条件：类型②省略型兼容（写侧/导入归一后恒有 conditions）——Ruling 2026-10-27",
	},
	"generateCaddyConfigWithCertSource": {
		"weight = 1": "上游权重 weight<=0→1：upstreams.weight 非本批治理字段清单（范围外），原状保留；Caddy WRR 亦不接受零权重",
		// 字符串列缺省（类型②省略型）：空串=未配置，默认值由 DB DEFAULT/写侧
		// 归一保证；渲染层必须替换以实现「省略」语义（否则引擎收到空值）。
		`r.Strategy = "weighted_round_robin"`: "负载策略空串=未配置→默认加权轮询：类型②省略型（写侧归一+DB DEFAULT 单源，渲染层承担省略替换）——G3 Ruling 披露",
		`protocol = "http"`:                   "上游协议空串=未配置→http：类型②省略型（写侧允许空并声明默认）——G3 Ruling 披露",
	},
	"trustedProxyServerFields": {
		`degraded = "受信代理已启用但没有任何有效网段（内联条目全部非法/过宽，或引用名单为空/全部悬空）：真实 IP 还原未生效，依赖真实 IP 的 IP 访问控制/限流/GeoIP 均按回源地址判定"`: "受信代理 enabled=1 但零有效网段：这是用户可见降级信号文案（字段形态不变，仅附加提示），不是用默认值替换无效库值；写侧允许该形态且需显性告知——Ruling 2026-10-28",
	},
	"buildCaddyLogging": {
		"level = \"info\"": "日志级别空串=未配置→info：类型②省略型（字符串缺省，写侧校验非空枚举但存量空值合法）——G3 Ruling 披露",
	},
	"formatFlushInterval": {
		"return \"-1s\"": "负值哨兵映射：Caddy flush_interval=-1s 表示「立即刷新」，v<0 映射为哨兵字符串而非库值兜底——G3 Ruling 披露",
	},
	"GenerateSingleRuleCaddyConfig": {
		`rule.Strategy = "weighted_round_robin"`: "负载策略空串=未配置→默认加权轮询：类型②省略型（与全量渲染同口径，单规则预览不得分叉）——G3 Ruling 披露",
	},
	"generateHTTPRouteObjects": {
		`rule.Strategy = "weighted_round_robin"`: "负载策略空串=未配置→默认加权轮询：类型②省略型（与全量渲染同口径）——G3 Ruling 披露",
	},
	"buildHTTPHandleChain": {
		"weight = 1": "上游权重 weight<=0→1：同上（范围外：分组层归一删除后链构建层唯一存留点）",
		// Ruling：HTTP 侧 try_duration==0 → 5s/250ms——存量 HTTP 行
		// 恒 0（列语义「0=默认重试窗口」，2026-09 渲染审计+方案 C 协议分叉已披露
		// UI/文档），行为不变的非治理形态；TCP 侧同列 0/-1 走显性报错/显式禁用，
		// 协议分叉为披露语义非写死兜底。td==-1 分支发射 retries=0 为「显式禁用
		// 重试」语义载体（cond 非零值守卫，不在扫描命中面）。
		`loadBalancing["try_duration"] = "5s"`:    "HTTP 侧 try_duration==0→5s：存量 HTTP 行恒 0（0=默认重试窗口语义），方案 C 协议分叉+UI 已披露——G3 Ruling 披露",
		`loadBalancing["try_interval"] = "250ms"`: "HTTP 侧 try_interval==0→250ms：同上（与 5s 窗口成对发射）——G3 Ruling 披露",
		`hcPath = "/"`:                     "主动健康检查路径空串=未配置→/：类型②省略型（字符串缺省，写侧允许空）——G3 Ruling 披露",
		`serverName = "{lb.upstream_sni}"`: "逐上游回源域名在场时 SNI 改走占位符（逐连接展开实证）——host_header 缺省形态的发射形态切换（占位符 vs 静态值），非无效库值兜底；upstream-sni-host 方案披露——G3 Ruling 披露",
		`hostFallback = "{http.reverse_proxy.upstream.hostport}"`: "Host 回退 TLS 池形态：host_header 未配置时绑定上游 hostport 占位符（池形态分流），类型②省略型同族——G3 Ruling 披露",
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
	// 命中面扩展（常量/选择器右值）后新增可见点：空值与白名单外值统一归一
	// 内置 html——这是内容类型白名单的双保险（带外通道脏值不得原样进响应头），
	// 且空值语义=未配置（类型②省略型），由 models.DefaultBlockPageContentType
	// 单源提供，渲染层不另写字面量——Ruling 2026-10-28。
	"blockPageContentType": {
		"return models.DefaultBlockPageContentType": "content_type 空/白名单外→内置 html：白名单双保险 + 空值省略型，默认值由 models 单源提供（写侧已归一，此处防带外脏值）——Ruling 2026-10-28",
	},
	// 覆盖面扫描新发现：路径规则 static_response 的状态码
	// 缺省形态（写侧允许 0=未配置，声明默认 200；空字符串守卫不在扫描命中面）。
	"buildStaticResponseHandler": {
		"status = 200":               "path rule ResponseStatus=0→200：类型②省略型（写侧允许 0=未配置并声明默认），非无效库值兜底——见该处 Ruling 披露",
		`contentType = "text/plain"`: "path rule ResponseContentType 空=未配置→text/plain：类型②省略型（写侧允许空并声明默认），非无效库值兜底——G3 Ruling 披露",
	},
	"buildTCPProxyHandler": {
		`strategy = "weighted_round_robin"`: "TCP 负载策略空串=未配置→默认加权轮询：类型②省略型（写侧归一单源，渲染层承担省略替换；cookie 策略对 layer4 不可用另行归一）——G3 Ruling 披露",
	},
	"formatRuleCertInfo": {
		`info.Error = "ACME 证书尚未签发或不存在"`: "展示层占位文案：ACME 证书未签发时证书卡说明（非配置投影）——G3 Ruling 披露",
		`info.Error = "证书不存在"`:           "展示层占位文案：manual 源无证书时证书卡说明（非配置投影）——G3 Ruling 披露",
		`info.Issuer = "-"`:              "展示层占位：签发者不可解析时以「-」占位（非配置投影）——G3 Ruling 披露",
	},
	"buildIPPrecheckDirectives": {
		"denyStatus = 403": "阶段 1 预检 denyStatus=0→403：类型②省略型（0=规则未配阶段 1 拦截页，stage1BlockStatus 契约的未设置态；coraza deny 必须显式状态码，省略以默认 403 替换实现，保持 403 兜底归因边界）——批 3 Ruling 披露",
	},
	// 可达性扫描登记（调用图内辅助函数的赋值形态兜底）：
	"decodePathUpstreams": {
		`protocol = "http"`: "路径规则上游存储投影缺省协议→http：类型②省略型（写侧允许空并在渲染层替换为具体值，否则引擎收到空协议）——可达性 Ruling 披露",
	},
	"ParseCRSExcludedRules": {
		`entry.Scope = "all"`: "CRS 排除项 scope 缺省→all：旧格式/缺字段（集群同步、带外改库、降级版本写入）的防御归一到全局限定，属类型②省略型归一而非无效库值兜底——可达性 Ruling 披露",
	},
	// buildCorazaDirectivesWithIndex 的「信任名单 + 绕过」复合条件条目已退役：
	// 该函数改为用单源布尔 emitTrustControl 开分支（不再以库值复合条件包裹
	// trustID 选择），扫描器不再把 `trustID = 5` 识别为守卫分支内兜底——编号
	// 二选一本来就是显式常量选择，不是库值兜底。
}

func TestRenderLayer_hasNoHardcodedZeroFallbacks(t *testing.T) {
	fset := token.NewFileSet()

	scanned := map[string]bool{}
	violations := map[string][]string{}
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
			consts := packageConstValues(file)
			for assign, positions := range fallbackAssignmentsInFunction(fset, fn, consts) {
				violations[fn.Name.Name+":"+assign] = positions
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
	for key, positions := range violations {
		funcName, assign := splitScanKey(key)
		allowed := antiFallbackAllowlist[funcName]
		if _, allowedAssign := allowed[assign]; !allowedAssign {
			t.Errorf("渲染函数 %s 出现清单外写死兜底 %q（%v）——库值唯一真相治理禁止在渲染层以字面量兜底无效库值；若为类型②省略型/范围外字段，请携 Ruling 加入 antiFallbackAllowlist", funcName, assign, positions)
			continue
		}
		// 允许列表按「赋值文本」登记，同文本出现多处时必须收窄后才可登记：
		// 次数上界=1，新增同文本兜底立即变红（原实现只判存在性，多写一处无人发现）。
		if len(positions) != 1 {
			t.Errorf("允许列表条目 %s:%q 命中 %d 处（%v）——同一文本多处出现，允许列表必须按守卫形态/位置收窄到单点后登记", funcName, assign, len(positions), positions)
		}
	}

	// 方向二：清单条目必须仍存在于扫描命中（防允许列表腐化成死清单）。
	for funcName, entries := range antiFallbackAllowlist {
		for assign := range entries {
			if _, live := violations[funcName+":"+assign]; !live {
				t.Errorf("允许列表条目 %s:%q 在源码中已消失——兜底已退役，请同步删除该清单条目（防清单腐化）", funcName, assign)
			}
		}
	}

	// 方向三：扫描包内全部非测试.go——渲染族命名函数若出现兜底
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
	// 调用图（同包内函数名 → 被调函数名），供方向四可达性判定。
	callGraph := map[string][]string{}
	defined := map[string]bool{}
	funcDecls := map[string]*ast.FuncDecl{}
	funcConsts := map[string]map[string]ast.Expr{}
	for _, path := range goFiles {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		fileConsts := packageConstValues(file)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			defined[fn.Name.Name] = true
			funcDecls[fn.Name.Name] = fn
			funcConsts[fn.Name.Name] = fileConsts
			var callees []string
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					callees = append(callees, fun.Name)
				case *ast.SelectorExpr:
					callees = append(callees, fun.Sel.Name)
				}
				return true
			})
			callGraph[fn.Name.Name] = callees
			if !isRenderFamilyFunction(fn.Name.Name) {
				continue
			}
			if listed[path+"|"+fn.Name.Name] {
				continue
			}
			for assign, positions := range fallbackAssignmentsInFunction(fset, fn, fileConsts) {
				t.Errorf("渲染族函数 %s（%s）含兜底 %q（%v）但未登记 antiFallbackScanTargets——新增渲染函数必须纳入扫描面或携 Ruling 说明非渲染用途", fn.Name.Name, path, assign, positions)
			}
		}
	}

	// 方向四：调用图可达性——仅靠命名启发式时，merge*/insert*/block* 这类
	// 名字会逃逸（如 mergeTrustedProxyServerFields）。从已登记入口出发做传递
	// 闭包，可达函数出现兜底形态必须登记（或移出渲染调用图）。
	listedByName := map[string]bool{}
	for _, functions := range antiFallbackScanTargets {
		for _, name := range functions {
			listedByName[name] = true
		}
	}
	reachable := map[string]bool{}
	queue := make([]string, 0, len(listedByName))
	for name := range listedByName {
		queue = append(queue, name)
	}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if reachable[name] {
			continue
		}
		reachable[name] = true
		for _, callee := range callGraph[name] {
			if defined[callee] && !reachable[callee] {
				queue = append(queue, callee)
			}
		}
	}
	for name := range reachable {
		if listedByName[name] || funcDecls[name] == nil {
			continue
		}
		for assign, positions := range fallbackAssignmentsInFunction(fset, funcDecls[name], funcConsts[name]) {
			// 可达性面只收「赋值形态」兜底：守卫分支内的 return 字面量在
			// 非渲染辅助函数里大量是校验错误文案/哨兵返回（如 return "空条件"），
			// 全量纳入会产生不可收敛的误报；显式登记的渲染函数仍按完整命中面扫描。
			if strings.HasPrefix(assign, "return ") {
				continue
			}
			t.Errorf("渲染入口可达函数 %s 含兜底 %q（%v）但未登记 antiFallbackScanTargets——命名启发式可被绕过的调用链同样必须纳入扫描面", name, assign, positions)
		}
	}
}

// fallbackAssignmentsInFunction 扫描函数体内的「零值守卫 + 字面量赋值」兜底
// 形态，返回赋值文本 → 位置。
// 形状：INT/STRING 字面量、plain `=`、else 链纳入。
// 扩展：LSS(<0/<1)、NEQ(!=0 的 else 链)、GEQ(>=1 的 else 链) 零值守卫、
// switch/case 的零值守卫分支、复合字面量默认值（`v = cfg{...}`）——原命中面
// 可被这些语义等价写法绕过，机制失效时无红灯。
func fallbackAssignmentsInFunction(fset *token.FileSet, fn *ast.FuncDecl, consts map[string]ast.Expr) map[string][]string {
	hits := map[string][]string{}
	// 嵌套守卫会让同一节点被外层与内层各扫一次——按「位置 + 文本」去重，
	// 保证位置清单与真实站点一一对应（允许列表的次数上界才有意义）。
	seen := map[string]bool{}
	if fn.Body == nil {
		return hits
	}
	record := func(text string, pos token.Pos) {
		position := fset.Position(pos).String()
		key := position + "|" + text
		if seen[key] {
			return
		}
		seen[key] = true
		hits[text] = append(hits[text], position)
	}
	scanBranch := func(branch ast.Node) {
		if branch == nil {
			return
		}
		ast.Inspect(branch, func(m ast.Node) bool {
			switch node := m.(type) {
			case *ast.AssignStmt:
				// 仅 plain `=`（:= 定义与 += 累加非兜底赋值）。
				if node.Tok != token.ASSIGN {
					return true
				}
				for i, rhs := range node.Rhs {
					if isLiteralDefault(rhs, consts) || (i < len(node.Lhs) && isStructFieldTarget(node.Lhs[i]) && isBoolOrNilLiteral(rhs)) {
						var buf bytes.Buffer
						_ = printer.Fprint(&buf, fset, node)
						record(buf.String(), node.Pos())
						break
					}
				}
			case *ast.ReturnStmt:
				// 守卫分支内的单一返回值字面量（哨兵值域映射等）同属写死默认值；
				// 多返回值 `return <零值>, err` 是错误路径，不纳入。
				if len(node.Results) != 1 || !isLiteralDefault(node.Results[0], consts) {
					return true
				}
				var buf bytes.Buffer
				_ = printer.Fprint(&buf, fset, node)
				record(buf.String(), node.Pos())
			}
			return true
		})
	}
	scanElseBlock := func(ifStmt *ast.IfStmt) {
		// 只扫终端 else 块；else-if 由链循环按各自守卫独立判定（直接 Inspect
		// else-if 节点会下钻其 body，把「非零值显式分支」误判为兜底）。
		if block, ok := ifStmt.Else.(*ast.BlockStmt); ok {
			scanBranch(block)
		}
	}
	// 常量夹取（clamp）：`if v > maxSize { v = maxSize }`——守卫是**范围上限**
	// 而非零值判据，故不在 comparisonGuardBranch 的零值域里，但赋值右值仍是
	// 写死常量（coraza 1GiB 上限即此形态）。判据=比较式为序关系、一侧非常量、
	// 另一侧解析到常量，且分支内把同一常量赋回——同常量双向出现才命中，
	// 普通阈值分支（`if len(x) > 3 {…}` 赋别值）不误报。
	scanClamp := func(cond ast.Expr, body *ast.BlockStmt) {
		if body == nil {
			return
		}
		bin, ok := unparenExpr(cond).(*ast.BinaryExpr)
		if !ok {
			return
		}
		switch bin.Op {
		case token.LSS, token.LEQ, token.GTR, token.GEQ:
		default:
			return
		}
		if _, boundedIsLiteral := resolveBasicLit(bin.X, consts); boundedIsLiteral {
			return
		}
		limit, ok := resolveBasicLit(bin.Y, consts)
		if !ok {
			return
		}
		limitValue := constant.MakeFromLiteral(limit.Value, limit.Kind, 0)
		if limitValue.Kind() == constant.Unknown {
			return
		}
		ast.Inspect(body, func(m ast.Node) bool {
			assign, ok := m.(*ast.AssignStmt)
			if !ok || assign.Tok != token.ASSIGN {
				return true
			}
			for _, rhs := range assign.Rhs {
				lit, ok := resolveBasicLit(rhs, consts)
				if !ok {
					continue
				}
				value := constant.MakeFromLiteral(lit.Value, lit.Kind, 0)
				if value.Kind() == constant.Unknown || !constant.Compare(value, token.EQL, limitValue) {
					continue
				}
				var buf bytes.Buffer
				_ = printer.Fprint(&buf, fset, assign)
				record(buf.String(), assign.Pos())
				break
			}
			return true
		})
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			// 逐级 else-if 链按各自守卫判定（外层守卫形态变化不改变
			// 内层判定的独立性）。
			matched := false
			for current := node; current != nil; {
				scanClamp(current.Cond, current.Body)
				switch guardBranchOf(current.Cond, consts) {
				case guardFallbackBody:
					scanBranch(current.Body)
					matched = true
				case guardFallbackElse:
					scanElseBlock(current)
					matched = true
				case guardFallbackBoth:
					scanBranch(current.Body)
					matched = true
				}
				next, ok := current.Else.(*ast.IfStmt)
				if !ok {
					break
				}
				current = next
			}
			if matched {
				// 守卫链的终端 else 块=链整体反向分支（旧实现同样纳入命中面：
				// `if td > 0 {…} else if td == -1 {…} else {5s}` 的兜底在此）。
				terminal := node
				for {
					next, ok := terminal.Else.(*ast.IfStmt)
					if !ok {
						break
					}
					terminal = next
				}
				if block, ok := terminal.Else.(*ast.BlockStmt); ok {
					scanBranch(block)
				}
			}
		case *ast.SwitchStmt:
			// case 体只在「零值可使 case 条件为真」时扫描；default 只在
			// 全部 case 条件于零值时确定为假、且至少存在一个已识别值守卫时
			// 扫描。这样既覆盖 default 兜底，也不会把纯分派或正分支误报。
			var defaultClause *ast.CaseClause
			sawGuard := false
			defaultReachableAtZero := true
			for _, stmt := range node.Body.List {
				clause, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				if len(clause.List) == 0 {
					defaultClause = clause
					continue
				}
				scanCase := false
				for _, expr := range clause.List {
					guardExpr := expr
					if node.Tag != nil {
						guardExpr = &ast.BinaryExpr{X: node.Tag, Y: expr, Op: token.EQL}
					}
					branch := switchGuardBranchOf(guardExpr, consts)
					if branch != guardNone {
						sawGuard = true
					}
					if branch != guardFallbackElse {
						defaultReachableAtZero = false
					}
					if branch == guardFallbackBody || branch == guardFallbackBoth {
						scanCase = true
					}
				}
				if scanCase {
					scanBranch(&ast.BlockStmt{List: clause.Body})
				}
			}
			if defaultClause != nil && sawGuard && defaultReachableAtZero {
				scanBranch(&ast.BlockStmt{List: defaultClause.Body})
			}
		}
		return true
	})
	return hits
}

// switchGuardBranchOf 按 case 条件的真值方向判定零值可达分支。与 if 扫描
// 不同，x>0 的 case 正分支不可能由零值进入，不能沿用 guardFallbackBoth
// 的兼容命中面；非零数值等值 case 则明确在零值时为假，使其 default 可见。
func switchGuardBranchOf(cond ast.Expr, consts map[string]ast.Expr) guardBranch {
	switch expr := unparenExpr(cond).(type) {
	case *ast.UnaryExpr:
		if expr.Op == token.NOT {
			return flippedGuardBranch(switchGuardBranchOf(expr.X, consts))
		}
		return guardNone
	case *ast.BinaryExpr:
		if expr.Op == token.LAND || expr.Op == token.LOR {
			return mergeGuardBranches(switchGuardBranchOf(expr.X, consts), switchGuardBranchOf(expr.Y, consts))
		}
		branch := comparisonGuardBranch(expr, consts)
		if branch == guardFallbackBoth {
			return guardFallbackElse
		}
		if branch != guardNone {
			return branch
		}

		normalized := flippedComparison(expr)
		if normalized.Op != token.EQL {
			return guardNone
		}
		lit, ok := resolveBasicLit(normalized.Y, consts)
		if !ok || (lit.Kind != token.INT && lit.Kind != token.FLOAT) {
			return guardNone
		}
		value := constant.MakeFromLiteral(lit.Value, lit.Kind, 0)
		if value.Kind() != constant.Unknown && !constant.Compare(value, token.EQL, constant.MakeInt64(0)) {
			return guardFallbackElse
		}
	}
	return guardNone
}

// guardBranch 枚举零值守卫的兜底分支位置。
type guardBranch int

const (
	guardNone guardBranch = iota
	guardFallbackBody
	guardFallbackElse
	guardFallbackBoth
)

// guardBranchOf 报告条件是否为零值/无效值守卫及其兜底赋值所在分支。整数域等价
// 形态：
//
//	x == 0 / x <= 0 / x < 0 / x < 1  → if 体
//	x != 0 / x >= 1                   → else 块
//	x > 0 → else 块 + if 体（命中面保留）
//
// 字符串域（无效库值=空串）：`s == ""` → if 体；`s != ""` → else 块。
// 操作数可交换（`0 == x` / `"" == s` 等价归一）——反向书写是最容易逃逸的
// 形态。`len(x) == 0` 由整数域 EQL 0 覆盖。
//
// GTR 保留 if 体扫描：`if len(x) > 0 { … }` 体内的字面量赋值由旧扫描器纳入，
// 收窄会让既有 allowlist 条目腐化——命中面只扩不收。
//
// 复合条件与逻辑取反同属等价形态（`x == 0 && flag`、`x == 0 || flag`、
// `!(x != 0)`）：只看顶层二元比较会让这种最常见的现实书写整段逃出命中面。
func guardBranchOf(cond ast.Expr, consts map[string]ast.Expr) guardBranch {
	switch expr := unparenExpr(cond).(type) {
	case *ast.UnaryExpr:
		if expr.Op == token.NOT {
			return flippedGuardBranch(guardBranchOf(expr.X, consts))
		}
		return guardNone
	case *ast.BinaryExpr:
		switch expr.Op {
		case token.LAND, token.LOR:
			// 合取/析取都取两侧兜底分支的并集：任一侧的值无效都会让该分支
			// 在库里值无效时可达（`x == 0 && flag` 的 if 体里 x 仍为 0；
			// `x != 0 || flag` 的 else 块里 x 仍为 0）。并集只扩命中面。
			return mergeGuardBranches(guardBranchOf(expr.X, consts), guardBranchOf(expr.Y, consts))
		}
		return comparisonGuardBranch(expr, consts)
	}
	return guardNone
}

// flippedGuardBranch 交换 `!cond` 的兜底分支：`!(x != 0)` ≡ `x == 0`，
// else 块与 if 体互换；Both/None 不变。
func flippedGuardBranch(branch guardBranch) guardBranch {
	switch branch {
	case guardFallbackBody:
		return guardFallbackElse
	case guardFallbackElse:
		return guardFallbackBody
	}
	return branch
}

// mergeGuardBranches 合并复合条件两侧命中的兜底分支。任一侧指向的分支都可能
// 在值无效时可达，故两侧不同时两边都扫描（宁严不松）。
func mergeGuardBranches(left, right guardBranch) guardBranch {
	if left == guardNone {
		return right
	}
	if right == guardNone || left == right {
		return left
	}
	return guardFallbackBoth
}

// comparisonGuardBranch 判定单条件（二元比较）的零值/无效值守卫分支。
// 比较右值可以是字面量，也可以是解析到字面量的具名常量（含 `T(x)` 转换
// 形态的包级 const）——`if v > corazaMax { v = corazaMax }` 这类常量夹取
// 同样是「写死兜底」，只认字面量会让整族逃逸。
func comparisonGuardBranch(bin *ast.BinaryExpr, consts map[string]ast.Expr) guardBranch {
	bin = flippedComparison(bin)
	lit, isLiteral := resolveBasicLit(bin.Y, consts)
	if !isLiteral {
		return guardNone
	}
	switch lit.Kind {
	case token.STRING:
		// 双引号与原始字符串按字面值判定：`` 与 "" 都是空串，源码文本
		// 比较会漏掉等价写法；非空原始字符串不得误报。
		value := constant.MakeFromLiteral(lit.Value, lit.Kind, 0)
		if value.Kind() == constant.Unknown || constant.StringVal(value) != "" {
			return guardNone
		}
		switch bin.Op {
		case token.EQL:
			return guardFallbackBody
		case token.NEQ:
			return guardFallbackElse
		}
		return guardNone
	case token.INT, token.FLOAT:
		// 整数域与浮点域同形（`x <= 0` / `x <= 0.0` / `x > 0.0`）——共用同一
		// 判定，按数值而非源码文本比较：0x0 / 00 / 0_0 / 0b0 / 0e0 等合法
		// 写法与 0 同值，文本比较会让这些等价形态整段逃出命中面。
		return numericLiteralGuardBranch(lit, bin.Op)
	}
	return guardNone
}

// numericLiteralGuardBranch 以常量数值判定数值字面量（整数/浮点）与 0/1 的
// 关系，供 comparisonGuardBranch 在 EQL/LEQ/LSS/NEQ/GTR/GEQ 上复用同一张
// 分支表。进制、前导零、下划线分组与指数写法都由 go/constant 归一，源码
// 文本不参与判定；无法解析的字面量（常量为 Unknown）不计命中。
func numericLiteralGuardBranch(lit *ast.BasicLit, op token.Token) guardBranch {
	value := constant.MakeFromLiteral(lit.Value, lit.Kind, 0)
	if value.Kind() == constant.Unknown {
		return guardNone
	}
	isZero := constant.Compare(value, token.EQL, constant.MakeInt64(0))
	isOne := constant.Compare(value, token.EQL, constant.MakeInt64(1))
	switch op {
	case token.EQL, token.LEQ:
		if isZero {
			return guardFallbackBody
		}
	case token.LSS:
		if isZero || isOne {
			return guardFallbackBody
		}
	case token.NEQ:
		if isZero {
			return guardFallbackElse
		}
	case token.GTR:
		if isZero {
			return guardFallbackBoth
		}
	case token.GEQ:
		if isOne {
			return guardFallbackElse
		}
	}
	return guardNone
}

// flippedComparison 把「字面量在左」的比较归一为「变量在左」：
// `0 == x` → `x == 0`、`"" != s` → `s != ""`（关系运算符同步翻转）。
func flippedComparison(bin *ast.BinaryExpr) *ast.BinaryExpr {
	if !isLiteralOperand(bin.X) || isLiteralOperand(bin.Y) {
		return bin
	}
	flipped := &ast.BinaryExpr{X: bin.Y, Y: bin.X}
	switch bin.Op {
	case token.LSS:
		flipped.Op = token.GTR
	case token.GTR:
		flipped.Op = token.LSS
	case token.LEQ:
		flipped.Op = token.GEQ
	case token.GEQ:
		flipped.Op = token.LEQ
	default:
		flipped.Op = bin.Op
	}
	return flipped
}

func isLiteralOperand(expr ast.Expr) bool {
	lit, ok := unparenExpr(expr).(*ast.BasicLit)
	return ok && (lit.Kind == token.INT || lit.Kind == token.FLOAT || lit.Kind == token.STRING)
}

// unparenExpr 剥掉包裹表达式的外层括号：`(x == 0)` / `0 == (x)` 与无括号
// 形态语义等价，不剥会让零值守卫整段逃出命中面。
func unparenExpr(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

// builtinScalarTypes 是「T(x) 转换形态」识别面里的内置标量类型名。
var builtinScalarTypes = map[string]bool{
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"uintptr": true, "float32": true, "float64": true, "complex64": true,
	"complex128": true, "string": true, "bool": true, "byte": true, "rune": true,
}

// packageConstValues 收集文件级 const 名 → 右值表达式（含 const 块/iota 组；
// 无右值的重复项跳过）。渲染层写 `v = 具名常量`（如 `v = corazaMax`）与写
// 字面量等价——没有这张表，isLiteralDefault / 守卫比较对常量族整体失明。
func packageConstValues(file *ast.File) map[string]ast.Expr {
	values := map[string]ast.Expr{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if i >= len(value.Values) {
					continue
				}
				values[name.Name] = value.Values[i]
			}
		}
	}
	return values
}

// resolveBasicLit 把表达式解析成字面量：直接字面量、解析到字面量的具名常量、
// 以及单实参类型转换（`int64(1073741824)`）三种形态归一。
func resolveBasicLit(expr ast.Expr, consts map[string]ast.Expr) (*ast.BasicLit, bool) {
	return resolveBasicLitDepth(unparenExpr(expr), consts, 0)
}

func resolveBasicLitDepth(expr ast.Expr, consts map[string]ast.Expr, depth int) (*ast.BasicLit, bool) {
	if depth > 8 { // 常量别名链有界（防循环定义导致栈溢出）
		return nil, false
	}
	switch value := expr.(type) {
	case *ast.BasicLit:
		return value, true
	case *ast.Ident:
		if target, ok := consts[value.Name]; ok {
			return resolveBasicLitDepth(unparenExpr(target), consts, depth+1)
		}
	case *ast.CallExpr:
		// T(x) 转换形态：转换目标为内置标量或包限定导出类型（time.Duration 等）。
		if len(value.Args) == 1 && isConversionTarget(value.Fun) {
			return resolveBasicLitDepth(unparenExpr(value.Args[0]), consts, depth+1)
		}
	}
	return nil, false
}

// isConversionTarget 报告表达式是否为转换目标类型（内置标量名或包限定导出
// 类型 `pkg.Type`）。普通函数调用（`computed(z)`）返回 false——反向形状依赖
// 这条区分。
func isConversionTarget(fun ast.Expr) bool {
	switch typed := fun.(type) {
	case *ast.Ident:
		return builtinScalarTypes[typed.Name]
	case *ast.SelectorExpr:
		return ast.IsExported(typed.Sel.Name)
	}
	return false
}

// isLiteralDefault 报告赋值右值是否为写死字面量默认值（INT/FLOAT/STRING 字面量、
// 非空命名/匿名结构的复合字面量或非空切片字面量、布尔/具名常量、`T(x)` 转换）。
// 排除：
//   - map 字面量（`m["k"] = map[string]interface{}{...}` 是结构装配，不是库值兜底）；
//   - 空复合字面量（`struct{}{}` 集合插入惯用法、`[]string{}` 非 nil 空切片 flag）；
//   - 普通函数调用/变量标识符（`x = computed(z)` 是数据流，不是写死值）。
//
// 第五链的盲区修复：此前只认 BasicLit/CompositeLit/ParenExpr/一元符号，
// 「常量夹取 / 常量别名 / 类型转换 / bool 兜底」整族失明——`x = db默认值常量`、
// `x = int64(5)`、`enabled = true` 四方向全绿。
func isLiteralDefault(rhs ast.Expr, consts map[string]ast.Expr) bool {
	switch value := rhs.(type) {
	case *ast.BasicLit:
		return value.Kind == token.INT || value.Kind == token.FLOAT || value.Kind == token.STRING
	case *ast.CompositeLit:
		if _, isMap := value.Type.(*ast.MapType); isMap {
			return false
		}
		return len(value.Elts) > 0
	case *ast.ParenExpr:
		// 括号包裹的字面量（`(0)` / `(5)`）与无括号形态等价。
		return isLiteralDefault(value.X, consts)
	case *ast.UnaryExpr:
		// 带符号字面量（-1 / +5）与一元取反同属字面量默认值。
		return (value.Op == token.SUB || value.Op == token.ADD) && isLiteralDefault(value.X, consts)
	case *ast.Ident:
		// 具名常量（解析到字面量）同属写死值；裸 true/false/nil 只在「结构体
		// 字段写入」形态下算兜底（见 isBoolOrNilLiteral / isStructFieldTarget）：
		// 局部变量与 map 条目的 `= true` 是簿记状态（seen/failed[id]/
		// provinces[...]），不是输出值兜底，一律纳入会产生不可收敛的误报。
		if target, ok := consts[value.Name]; ok {
			return isLiteralDefault(target, consts)
		}
		return false
	case *ast.SelectorExpr:
		// 包级默认值常量引用（`db.DefaultHealthCheckInterval` 等）：渲染层直读
		// db 内置默认值同样绕过了「库值唯一真相」，按命名面识别（Default 前缀/
		// 中缀），避免把普通 `pkg.SomeValue` 一律纳入。
		return strings.Contains(value.Sel.Name, "Default")
	case *ast.CallExpr:
		// `T(x)` 转换形态：转换目标为类型、单实参，且实参本身解析到字面量
		// （`int64(5)` / `int64(maxSize)`）——`json.RawMessage(customRules)`
		// 这类「转换目标类型、实参是变量」是数据流而非写死值，不得误报。
		if len(value.Args) != 1 || !isConversionTarget(value.Fun) {
			return false
		}
		if isBoolOrNilLiteral(value.Args[0]) {
			return true
		}
		_, resolves := resolveBasicLit(value.Args[0], consts)
		return resolves
	}
	return false
}

// isBoolOrNilLiteral 报告表达式是否为裸 true/false/nil 标识符。
func isBoolOrNilLiteral(expr ast.Expr) bool {
	ident, ok := unparenExpr(expr).(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "true" || ident.Name == "false" || ident.Name == "nil"
}

// isStructFieldTarget 报告赋值左值是否为结构体字段/选择器（`x.Enabled = true`）。
// 局部变量（seen）/map 条目（failed[id]）/切片元素不是输出值兜底目标。
func isStructFieldTarget(lhs ast.Expr) bool {
	_, ok := unparenExpr(lhs).(*ast.SelectorExpr)
	return ok
}

// isRenderFamilyFunction 按命名识别渲染族函数
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

// 兜底扫描命中面必须覆盖语义等价写法——原实现只认
// `EQL/LEQ/GTR 对比 INT 0` 的 if 体，以下形态全部逃逸（机制失效时无红灯）：
//   - `x < 1`（LSS 对比 1，整数域等价 x<=0）；
//   - `x != 0 { … } else { x = 7 }`（NEQ 对比 0，兜底在 else 链）；
//   - `switch { case x <= 0: x = 10 }`（switch/case 零值守卫）；
//   - `if x == 0 { v = c{Timeout: 5} }`（复合字面量默认值）；
//   - `if (x == 0) { … }` / `if x == (0)` / `if 0 == (x)`（括号包裹的等价形态，
//     不剥括号会让整个守卫逃出命中面）；
//   - `x = +5`（一元正号字面量）。
//
// 每个形态一个夹具：扫描器必须命中（否则「渲染层无写死兜底」第五链可被改写绕过）。
func TestFallbackScan_detectsEquivalentGuardShapes(t *testing.T) {
	fixtures := []struct {
		name   string
		source string
	}{
		{
			name:   "less-than-one",
			source: "package p\nfunc f(x int) int { if x < 1 { x = 5 }; return x }\n",
		},
		{
			name:   "not-equal-zero-else",
			source: "package p\nfunc f(x int) int { if x != 0 { x = x } else { x = 7 }; return x }\n",
		},
		{
			name:   "switch-case-zero-guard",
			source: "package p\nfunc f(x int) int { switch { case x <= 0: x = 10 }; return x }\n",
		},
		{
			name:   "composite-literal",
			source: "package p\ntype c struct{ Timeout int }\nfunc f(x int) c { var v c; if x == 0 { v = c{Timeout: 5} }; return v }\n",
		},
		{
			name:   "empty-string-guard",
			source: "package p\nfunc f(s string) string { if s == \"\" { s = \"x\" }; return s }\n",
		},
		{
			name:   "reversed-empty-string-guard",
			source: "package p\nfunc f(s string) string { if \"\" == s { s = \"x\" }; return s }\n",
		},
		{
			name:   "reversed-zero-int-guard",
			source: "package p\nfunc f(x int) int { if 0 == x { x = 5 }; return x }\n",
		},
		{
			name:   "len-zero-guard",
			source: "package p\nfunc f(v []int) []int { if len(v) == 0 { v = []int{5} }; return v }\n",
		},
		{
			name:   "not-empty-string-else",
			source: "package p\nfunc f(s string) string { if s != \"\" { s = s } else { s = \"y\" }; return s }\n",
		},
		{
			name:   "literal-return-in-guard",
			source: "package p\nfunc f(x int) string { if x == 0 { return \"d\" }; return \"z\" }\n",
		},
		{
			name:   "float-zero-guard",
			source: "package p\nfunc f(x float64) float64 { if x <= 0.0 { x = 5.0 }; return x }\n",
		},
		{
			name:   "float-reversed-zero-guard",
			source: "package p\nfunc f(x float64) float64 { if 0.0 == x { x = 2.5 }; return x }\n",
		},
		{
			name:   "parenthesized-condition",
			source: "package p\nfunc f(x int) int { if (x == 0) { x = 5 }; return x }\n",
		},
		{
			name:   "parenthesized-literal-operand",
			source: "package p\nfunc f(x int) int { if x == (0) { x = 5 }; return x }\n",
		},
		{
			name:   "parenthesized-reversed-guard",
			source: "package p\nfunc f(x int) int { if 0 == (x) { x = 5 }; return x }\n",
		},
		{
			name:   "unary-plus-literal-default",
			source: "package p\nfunc f(x int) int { if x == 0 { x = +5 }; return x }\n",
		},
		{
			name:   "conjunction-guard",
			source: "package p\nfunc f(x int, flag bool) int { if x == 0 && flag { x = 5 }; return x }\n",
		},
		{
			name:   "disjunction-guard",
			source: "package p\nfunc f(x, y int) int { if x <= 1 || y == 0 { x = 5 }; return x }\n",
		},
		{
			name:   "negated-guard",
			source: "package p\nfunc f(s string) string { if !(s != \"\") { s = \"x\" }; return s }\n",
		},
		{
			name:   "tagged-switch-zero-case",
			source: "package p\nfunc f(x int) int { switch x { case 0: x = 5 }; return x }\n",
		},
		{
			name:   "tagged-switch-multi-case-zero",
			source: "package p\nfunc f(x int) int { switch x { case 2, 0: x = 5 }; return x }\n",
		},
		{
			name:   "hex-zero-guard",
			source: "package p\nfunc f(x int) int { if x == 0x0 { x = 5 }; return x }\n",
		},
		{
			name:   "binary-zero-guard",
			source: "package p\nfunc f(x int) int { if x == 0b0 { x = 5 }; return x }\n",
		},
		{
			name:   "legacy-octal-zero-guard",
			source: "package p\nfunc f(x int) int { if x == 00 { x = 5 }; return x }\n",
		},
		{
			name:   "underscore-zero-guard",
			source: "package p\nfunc f(x int) int { if x == 0_0 { x = 5 }; return x }\n",
		},
		{
			name:   "hex-zero-not-equal-else",
			source: "package p\nfunc f(x int) int { if x != 0x0 { x = x } else { x = 7 }; return x }\n",
		},
		{
			name:   "raw-empty-string-guard",
			source: "package p\nfunc f(s string) string { if s == `` { s = \"x\" }; return s }\n",
		},
		{
			name:   "reversed-raw-empty-string-guard",
			source: "package p\nfunc f(s string) string { if `` == s { s = \"x\" }; return s }\n",
		},
		{
			name:   "tagged-switch-raw-empty-string-case",
			source: "package p\nfunc f(s string) string { switch s { case ``: s = \"x\" }; return s }\n",
		},
		{
			name:   "expressionless-switch-positive-case-default",
			source: "package p\nfunc f(x int) int { switch { case x > 0: x = x; default: x = 5 }; return x }\n",
		},
		{
			name:   "tagged-switch-non-zero-case-default",
			source: "package p\nfunc f(x int) int { switch x { case 1: x = x; default: x = 7 }; return x }\n",
		},
		{
			name:   "expressionless-switch-len-positive-default",
			source: "package p\nfunc f(v []int) []int { switch { case len(v) > 0: v = v; default: v = []int{5} }; return v }\n",
		},
		{
			// 常量夹取：`if v > max { v = max }`，守卫侧与右值两侧都靠常量表解析。
			name:   "const-clamp",
			source: "package p\nconst maxSize = int64(1073741824)\nfunc f(v int64) int64 { if v > maxSize { v = maxSize }; return v }\n",
		},
		{
			// 常量别名（const 引用 const）。
			name:   "const-alias",
			source: "package p\nconst baseLimit = 5\nconst limitAlias = baseLimit\nfunc f(x int) int { if x == 0 { x = limitAlias }; return x }\n",
		},
		{
			// 类型转换右值：`x = int64(5)`。
			name:   "type-conversion-rhs",
			source: "package p\nfunc f(x int64) int64 { if x == 0 { x = int64(5) }; return x }\n",
		},
		{
			// bool 兜底：结构体字段写 true（输出值兜底）。守卫用零值比较（bool
			// 守卫 `if !o.Enabled` 不在守卫识别面——见 guardBranchOf 的语义边界）；
			// 局部变量/ map 条目的 `= true` 属簿记状态，按 isStructFieldTarget 排除。
			name:   "bool-default",
			source: "package p\ntype opts struct{ Enabled bool; Timeout int }\nfunc f(o *opts) *opts { if o.Timeout == 0 { o.Enabled = true }; return o }\n",
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, fixture.name+".go", fixture.source, 0)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			var fn *ast.FuncDecl
			for _, decl := range file.Decls {
				if candidate, ok := decl.(*ast.FuncDecl); ok && candidate.Name.Name == "f" {
					fn = candidate
					break
				}
			}
			if fn == nil {
				t.Fatal("fixture function f not found")
			}
			if hits := fallbackAssignmentsInFunction(fset, fn, packageConstValues(file)); len(hits) == 0 {
				t.Fatalf("等价兜底形态未被扫描命中——机制存在绕过路径: %s", fixture.source)
			}
		})
	}
}

// 反向形状：正常业务分支的数值赋值（非零值守卫）不得被误判为兜底。
func TestFallbackScan_ignoresNonZeroGuardBranches(t *testing.T) {
	fixtures := []struct {
		name   string
		source string
	}{
		{
			name:   "non-zero-comparison",
			source: "package p\nfunc f(x int) int { if x == 1 { x = 5 }; return x }\n",
		},
		{
			name:   "non-zero-hex-comparison",
			source: "package p\nfunc f(x int) int { if x == 0x1 { x = 5 }; return x }\n",
		},
		{
			name:   "tagged-switch-non-zero-case",
			source: "package p\nfunc f(x int) int { switch x { case 1: x = 5 }; return x }\n",
		},
		{
			name:   "non-empty-raw-string-comparison",
			source: "package p\nfunc f(s string) string { if s == `x` { s = \"y\" }; return s }\n",
		},
		{
			name:   "expressionless-switch-positive-case",
			source: "package p\nfunc f(x int) int { switch { case x > 0: x = 5 }; return x }\n",
		},
		{
			name:   "tagged-switch-zero-case-default",
			source: "package p\nfunc f(x int) int { switch x { case 0: x = x; default: x = 7 }; return x }\n",
		},
		{
			name:   "identifier-dispatch-default",
			source: "package p\nfunc f(x, other int) int { switch x { case other: x = 5; default: x = 7 }; return x }\n",
		},
		{
			name:   "string-dispatch-default",
			source: "package p\nfunc f(s string) string { switch s { case \"ready\": s = s; default: s = \"unknown\" }; return s }\n",
		},
		{
			// 反形状：数据流调用/变量复制不是写死值——常量面与转换面扩展不得把它拖进来。
			name:   "computed-call-is-not-default",
			source: "package p\nfunc computed(z int) int { return z }\nfunc f(x, z int) int { if x == 0 { x = computed(z) }; return x }\n",
		},
		{
			name:   "variable-copy-is-not-default",
			source: "package p\nfunc f(x, other int) int { if x == 0 { x = other }; return x }\n",
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, fixture.name+".go", fixture.source, 0)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != "f" {
					continue
				}
				if hits := fallbackAssignmentsInFunction(fset, fn, packageConstValues(file)); len(hits) != 0 {
					t.Fatalf("非零值守卫被误报为兜底: %v", hits)
				}
			}
		})
	}
}
