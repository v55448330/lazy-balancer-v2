package services

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 上游启用谓词单源：整个 services 包只允许一处 IIF 字面量（常量定义），
// 渲染上游装载 / 单规则服务上下文预览 / 看门狗发布谓词必须复用常量——
// 新增第二处字面量（单侧漂移面）即红。
// 判定在「去注释 + SQL 归一」后进行：注释里的引用不误红，引号/空白/大小写/
// 别名等等价写法不得逃逸。
func TestUpstreamEnabledPredicateHasOneLiteral(t *testing.T) {
	src, err := os.ReadFile("caddy.go")
	if err != nil {
		t.Fatalf("read caddy.go: %v", err)
	}
	code := stripGoComments(string(src))
	if got := strings.Count(normalizeSQL(code), "u.enabled in("); got != 1 {
		t.Fatalf("caddy.go 含 %d 处上游启用 IIF 字面量, want 1（只允许 upstreamEnabledSQLValue 定义，注释不计）", got)
	}
	// 发布规则集合谓词必须引用常量而非内联表达式。
	if got := strings.Count(code, "u.rule_id = lb_rules.caddy_id AND ` + UpstreamEnabledSQLPredicate + `"); got != 1 {
		t.Fatalf("publishableRulesSQLPredicate 引用单源谓词 %d 处, want 1", got)
	}
	if !constExprUsesIdent(t, "caddy.go", "publishableRulesSQLPredicate", "UpstreamEnabledSQLPredicate") {
		t.Fatal("publishableRulesSQLPredicate 必须引用 UpstreamEnabledSQLPredicate 常量")
	}
	if !fileUsesIdent(t, "cluster_snapshot.go", "UpstreamEnabledSQLValue") {
		t.Fatal("cluster_snapshot.go 的上游启用投影必须引用 UpstreamEnabledSQLValue")
	}
	// 除常量定义文件外，services 包任何生产文件都不得内联上游启用谓词。
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read services dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "caddy.go" {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, violation := range upstreamEnabledViolations(string(data)) {
			t.Fatalf("%s 内联了上游启用表达式（应复用单源常量）: %s", name, violation)
		}
	}
	for _, path := range []string{"configwatchdog.go"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(normalizeSQL(stripGoComments(string(data))), "u.enabled in(") {
			t.Fatalf("%s 内联了上游启用表达式（应复用单源谓词）", path)
		}
	}

	// handlers 侧同族守卫（上游启用判定全仓收敛后）：别名限定直写
	// （u./up./upstreams.enabled）一律禁止；upstreams 查询字面量内的投影
	// （enabled IN(...)）与 WHERE 直写（enabled=1）同样禁止——一律引用
	// services.UpstreamEnabledSQLValue / UpstreamEnabledSQLPredicate。
	// 注意 lb_rules.enabled（规则启用列）不属本族，不在禁止范围。
	entries, err = os.ReadDir("../handlers")
	if err != nil {
		t.Fatalf("read handlers dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile("../handlers/" + name)
		if err != nil {
			t.Fatalf("read handlers/%s: %v", name, err)
		}
		for _, violation := range upstreamEnabledViolations(string(data)) {
			t.Fatalf("handlers/%s %s（应引用 services.UpstreamEnabledSQLValue/Predicate）", name, violation)
		}
	}
}

var (
	// Go 源码中的 SQL 字符串字面量（raw 与解释两种形态）。
	sqlStringLiteral = regexp.MustCompile("(?s:`[^`]*`)|\"([^\"\\\\]|\\\\.)*\"")
	// SQL 归一后的「未限定 enabled 投影」：前一位不是 '.' 或标识符字符，
	// 避免把 u.enabled / lb_rules.enabled 误判为本族。
	unqualifiedEnabledProjection = regexp.MustCompile(`(^|[^.\w])enabled in\(`)
	unqualifiedEnabledFilter     = regexp.MustCompile(`(^|[^.\w])enabled=1`)
)

// stripGoComments 去掉 Go 源码注释，保留字符串/字符字面量内容：注释里的
// 谓词引用不得触发守卫，而字符串里的 SQL 必须原样参与判定。
func stripGoComments(src string) string {
	var out strings.Builder
	out.Grow(len(src))
	for i := 0; i < len(src); {
		switch {
		case src[i] == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case src[i] == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return out.String()
			}
			i += 2 + end + 2
		case src[i] == '`', src[i] == '"', src[i] == '\'':
			quote := src[i]
			start := i
			i++
			for i < len(src) {
				if src[i] == '\\' && quote != '`' {
					i += 2
					continue
				}
				if src[i] == quote {
					i++
					break
				}
				i++
			}
			if i > len(src) {
				i = len(src)
			}
			out.WriteString(src[start:i])
		default:
			out.WriteByte(src[i])
			i++
		}
	}
	return out.String()
}

var sqlOperatorSpacing = regexp.MustCompile(`\s*([(),=])\s*`)

// normalizeSQL 归一化 SQL 文本：小写、去标识符/字面量引号与方括号、折叠
// 空白并移除括号/逗号/等号两侧空白——使 `enabled IN('1',1)`、
// `enabled  in ( 1 )`、`ENABLED = '1'` 落到同一形态。
func normalizeSQL(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		switch r {
		case '"', '\'', '`', '[', ']':
			return -1
		}
		if r == '\n' || r == '\t' || r == '\r' {
			return ' '
		}
		return r
	}, s)
	s = sqlOperatorSpacing.ReplaceAllString(s, "$1")
	return strings.Join(strings.Fields(s), " ")
}

// constExprUsesIdent 在指定文件的包级 const 表达式内查找名称引用（AST，
// 不受换行/括号/字符串拼接排版影响）。
func constExprUsesIdent(t *testing.T, filename, constName, identName string) bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	found := false
	for _, declaration := range file.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok || generic.Tok != token.CONST {
			continue
		}
		for _, spec := range generic.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, name := range valueSpec.Names {
				if name.Name != constName || index >= len(valueSpec.Values) {
					continue
				}
				ast.Inspect(valueSpec.Values[index], func(node ast.Node) bool {
					if ident, ok := node.(*ast.Ident); ok && ident.Name == identName {
						found = true
					}
					return !found
				})
			}
		}
	}
	return found
}

func fileUsesIdent(t *testing.T, filename, identName string) bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		if ident, ok := node.(*ast.Ident); ok && ident.Name == identName {
			found = true
		}
		return !found
	})
	return found
}

// upstreamEnabledViolations 扫描一段 Go 源码中违反「上游启用谓词单源」的
// 写法，返回违规描述（空=合规）。
func upstreamEnabledViolations(src string) []string {
	code := stripGoComments(src)
	normalized := normalizeSQL(code)
	var violations []string
	for _, pattern := range []string{
		"u.enabled=1", "u.enabled in(",
		"up.enabled=1", "up.enabled in(",
		"upstreams.enabled=1", "upstreams.enabled in(",
	} {
		if strings.Contains(normalized, pattern) {
			violations = append(violations, fmt.Sprintf("内联上游启用谓词 %q", pattern))
		}
	}
	for _, literal := range sqlStringLiteral.FindAllString(code, -1) {
		normalizedLiteral := normalizeSQL(literal)
		if !strings.Contains(normalizedLiteral, "from upstreams") {
			continue
		}
		if unqualifiedEnabledProjection.MatchString(normalizedLiteral) {
			violations = append(violations, fmt.Sprintf("upstreams 查询内联启用投影: %.80q", literal))
			continue
		}
		subquery := normalizedLiteral[strings.LastIndex(normalizedLiteral, "from upstreams"):]
		if unqualifiedEnabledFilter.MatchString(subquery) {
			violations = append(violations, fmt.Sprintf("upstreams 查询内联启用过滤: %.80q", literal))
		}
	}
	return violations
}

// 归一化守卫的自检矩阵：等价写法（大小写/引号/无空格/别名/跨行/包级常量）
// 全部命中；注释引用与 lb_rules.enabled（规则启用列）不误报。
func TestUpstreamEnabledGuard_detectsEquivalentForms(t *testing.T) {
	bad := []string{
		"SELECT 1 FROM upstreams WHERE enabled = 1",
		"SELECT 1 FROM upstreams WHERE enabled = '1'",
		"SELECT 1 FROM upstreams WHERE enabled IN('1',1)",
		"SELECT 1,\n\t enabled IN ( 1 ) FROM upstreams",
		"SELECT 1 FROM upstreams u WHERE u.enabled=1",
		"SELECT 1 FROM upstreams up WHERE up.enabled = 1",
		"SELECT 1 FROM upstreams WHERE upstreams.enabled = 1",
	}
	for _, sql := range bad {
		src := "rows, err := db.Query(`" + sql + "`)\n_ = rows\n_ = err\n"
		if violations := upstreamEnabledViolations(src); len(violations) == 0 {
			t.Fatalf("等价形态未命中: %q", sql)
		}
	}
	good := []string{
		"// 与上游启用谓词 u.enabled IN ('1',1) 同口径\nrows, _ := db.Query(`SELECT 1 FROM upstreams u WHERE ` + services.UpstreamEnabledSQLPredicate)\n",
		"rows, _ := db.Query(`SELECT 1 FROM lb_rules WHERE enabled = 1 AND ` + services.UpstreamEnabledSQLPredicate)\n",
		"rows, _ := db.Query(`SELECT host FROM upstreams u WHERE rule_id = ?`, id)\n",
	}
	for _, src := range good {
		if violations := upstreamEnabledViolations(src); len(violations) != 0 {
			t.Fatalf("合规形态误报: %v（src=%q）", violations, src)
		}
	}
}

// 规则日志发射面随发布集收窄：未发布规则（零启用上游 / TLS 证书未就绪）
// 不建 logger_names，也不建 logging.logs 条目；已发布规则两者齐备。
func TestGenerateCaddyConfig_logSurfaceFollowsPublishSet(t *testing.T) {
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_log_pub", "pub.example.test", 8080)
	if _, err := database.Exec(`UPDATE lb_rules SET log_enabled=1 WHERE caddy_id='lb_log_pub'`); err != nil {
		t.Fatalf("enable log for published rule: %v", err)
	}

	// 未发布 A：启用上游数为零（渲染跳过）。
	seedHTTPRuleForGeneration(t, database, "lb_log_noup", "noup.example.test", 9090)
	if _, err := database.Exec(`UPDATE upstreams SET enabled=0 WHERE rule_id='lb_log_noup';
		UPDATE lb_rules SET log_enabled=1 WHERE caddy_id='lb_log_noup'`); err != nil {
		t.Fatalf("seed upstreamless rule: %v", err)
	}

	// 未发布 B：启用 TLS 但证书未就绪（整条规则 fail-closed 跳过）。
	seedHTTPRuleForGeneration(t, database, "lb_log_tlswait", "tlswait.example.test", 9091)
	if _, err := database.Exec(`UPDATE lb_rules SET log_enabled=1, enable_tls=1, tls_source='manual', tls_cert='', tls_key='' WHERE caddy_id='lb_log_tlswait'`); err != nil {
		t.Fatalf("seed tls-waiting rule: %v", err)
	}

	cfg := generateCaddyConfigFromStore(database)
	if message, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	servers := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["http"], "http")["servers"], "servers")
	for _, port := range []string{"http_9090", "http_9091"} {
		if _, exists := servers[port]; exists {
			t.Fatalf("未发布规则仍占用 server %s（发布集收窄失效）", port)
		}
	}

	published := mustMap(t, servers["http_8080"], "http_8080")
	loggerNames := mustMap(t, mustMap(t, mustMap(t, published["logs"], "logs")["logger_names"], "logger_names"), "logger_names")
	if got := loggerNames["pub.example.test"]; got != "rule_lb_log_pub" {
		t.Fatalf("已发布规则 logger_names=%v, want pub.example.test→rule_lb_log_pub", loggerNames)
	}

	rootLogs := mustMap(t, mustMap(t, cfg["logging"], "logging")["logs"], "logging.logs")
	if _, exists := rootLogs["rule_lb_log_pub"]; !exists {
		t.Fatalf("已发布规则缺 logging.logs 条目: %v", rootLogs)
	}
	for _, unpublished := range []string{"rule_lb_log_noup", "rule_lb_log_tlswait"} {
		if _, exists := rootLogs[unpublished]; exists {
			t.Fatalf("未发布规则 %s 仍占用 logging.logs 条目（日志写盘面虚增）", unpublished)
		}
	}
}

// 默认站（:80 落地页）必须与规则 server 同构关闭引擎自动 HTTPS：否则 Caddy
// 会对 :80 追加 catch-all 308，与落地页路由竞争产生 superfluous WriteHeader。
func TestGenerateCaddyConfig_defaultSiteDisablesAutomaticHTTPS(t *testing.T) {
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_autohttps", "auto.example.test", 8080)
	cfg := generateCaddyConfigFromStore(database)
	if message, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	servers := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["http"], "http")["servers"], "servers")
	for _, serverName := range []string{"http_80", "http_8080"} {
		server := mustMap(t, servers[serverName], serverName)
		automaticHTTPS := mustMap(t, server["automatic_https"], serverName+" automatic_https")
		if automaticHTTPS["disable"] != true {
			t.Fatalf("%s.automatic_https.disable=%v, want true", serverName, automaticHTTPS["disable"])
		}
	}
}

// 预检 directives 不读请求体（因此 request_body 限额只约束「会读体的」策略级
// 引擎顺序）：预检恒发 SecRequestBodyAccess Off，且全部 SecRule 都是 phase:1
// REMOTE_ADDR/健康检查形态，不引用任何请求体容器。
func TestIPPrecheckDirectivesDoNotReadRequestBody(t *testing.T) {
	policy := &models.SecurityPolicy{
		ID:             9,
		Mode:           "off",
		GeoIPMode:      "deny",
		GeoIPCountries: json.RawMessage(`["海外"]`),
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{policy}, 403, "lb_precheck_body"))
	if directives == "" {
		t.Fatal("预检 directives 为空（无法断言不变量）")
	}
	if !strings.Contains(directives, "SecRequestBodyAccess Off") {
		t.Fatalf("预检 directives 未显式关闭请求体访问:\n%s", directives)
	}
	for _, banned := range []string{"SecRequestBodyAccess On", "REQUEST_BODY", "ARGS_POST", "XML:/*", "SecRuleRequestBody"} {
		if strings.Contains(directives, banned) {
			t.Fatalf("预检 directives 含读体标记 %q（request_body 顺序不变量收窄前提被破坏）:\n%s", banned, directives)
		}
	}
	for _, line := range strings.Split(directives, "\n") {
		if !strings.HasPrefix(line, "SecRule ") {
			continue
		}
		if !strings.Contains(line, "phase:1") {
			t.Fatalf("预检 SecRule 非 phase:1（可能读体）: %s", line)
		}
	}
}

// Host 大小写是规则访问日志的可观测边界（引擎事实：Caddy 用原始 Host 做
// 区分大小写精确查找 logger_names，未命中落默认 logger http.log.access，而
// default writer 的 exclude 含 "http" 前缀 → 该条目零落盘）。本钉有两个目的：
//
//	① logger_names 键必须全小写（与 host matcher 同口径）；
//	② default writer 必须继续排除 "http"——若有人为「修日志丢失」移除该排除，
//	   规则行会在 caddy.log 重复（命名 logger 前缀同为 http.*），本断言即红，
//	   逼迫改动者面对「零落盘 ↔ 日志翻倍」的权衡而不是静默改行为。
func TestGenerateCaddyConfig_ruleLogSurfaceDependsOnLowercaseHost(t *testing.T) {
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_logcase", "Mixed.Case.Example.Test", 8080)
	if _, err := database.Exec(`UPDATE lb_rules SET log_enabled=1, domain='Mixed.Case.Example.Test' WHERE caddy_id='lb_logcase'`); err != nil {
		t.Fatalf("enable log: %v", err)
	}
	cfg := generateCaddyConfigFromStore(database)
	if message, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	servers := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["http"], "http")["servers"], "servers")
	server := mustMap(t, servers["http_8080"], "http_8080")
	loggerNames := mustMap(t, mustMap(t, mustMap(t, server["logs"], "logs")["logger_names"], "logger_names"), "logger_names")
	if len(loggerNames) == 0 {
		t.Fatalf("log_enabled 规则必须有 logger_names: %v", server["logs"])
	}
	for host := range loggerNames {
		if host != strings.ToLower(host) {
			t.Fatalf("logger_names 键 %q 非小写（与 host matcher 规范不一致）", host)
		}
	}
	rootLogs := mustMap(t, mustMap(t, cfg["logging"], "logging")["logs"], "logging.logs")
	defaultWriter := mustMap(t, rootLogs["default"], "logging.logs.default")
	exclude, _ := defaultWriter["exclude"].([]string)
	if len(exclude) == 0 || exclude[0] != "http" {
		t.Fatalf("default writer exclude=%v, want 以 \"http\" 开头（大写 Host 访问日志零落盘是显式权衡，不得静默移除）", exclude)
	}
}
