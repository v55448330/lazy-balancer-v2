package handlers

// OpenAPI security 契约的反向门：`apiDocContracts.security` 的每个非空值都曾靠
// 手工登记，机器校验只对集群机器端点（clusterToken/registrationSecret）做了
// 反向对账；public/mcp 两态只有「这几条必须为空」的正向断言，任何 JWT 管理写
// 路由被误标 public 时生成规格会宣称匿名可用，且该路由同时脱出 428（step-up）
// 与 403（角色）两道生成门——测试全绿。
//
// 本文件从 middleware.go 的真实注册派生 security：注册在 v1.Use 认证链之前的
// 为公开；携带 mcpAccessGuard 的为 MCP 专用 Key；携带 clusterTokenAuth/
// registrationAuth 的为集群机器凭证；其余走 bearerAuth（security 为空）。
//
// 同一派生口径还用于 API Key 文档行的「方法集合 + 路由组」校验：豁免清单含
// DELETE（大屏采集租约释放），且其中三项注册在 admin 组（非管理员属主的只读
// Key 恒 403）——文案必须按这两点表述，否则会把可用的 DELETE 判成必失败、把
// admin 组项误当成非管理员可用。

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// apiDocRouteUsesNonJWTAuth 报告该文档路由的 security 是否表示「非 JWT 身份
// 面」（公开/机器/MCP）。生成门的跳过条件按枚举判定：新增未知 security 值不会
// 像「非空即跳过」那样被静默放过。
func apiDocRouteUsesNonJWTAuth(route apiDocRoute) bool {
	switch apiDocContractFor(route).security {
	case "public", "mcp", "cluster", "registration":
		return true
	}
	return false
}

// apiDocSecurityFromRegistration 按注册实参派生 security 契约值：
//   - mcpAccessGuard：POST /mcp 只接受 API Key（mcpApiKey scheme）；
//   - registrationAuth / clusterTokenAuth：集群机器凭证；
//   - group=v1 且注册行早于首个 v1.Use：公开块（登录/初始化/OIDC/品牌/注册）；
//   - 其余：bearerAuth 默认（security 为空）。
func apiDocSecurityFromRegistration(registration middlewareRouteRegistration, authChainLine int) string {
	switch {
	case registration.middleware["mcpAccessGuard"]:
		return "mcp"
	case registration.middleware["registrationAuth"]:
		return "registration"
	case registration.middleware["clusterTokenAuth"]:
		return "cluster"
	case registration.group == "v1" && registration.line < authChainLine:
		return "public"
	}
	return ""
}

func TestAPIDocContractsSecurityMatchesRegistrationSurface(t *testing.T) {
	source := middlewareSourceForTest(t)
	registrations := middlewareRouteRegistrations(t, source)
	authChainLine := middlewareV1AuthChainLine(t, source)

	checked, publicCount, authenticatedCount := 0, 0, 0
	for _, route := range apiDocRoutes {
		key := route.Method + " " + route.Path
		registration, ok := registrations[key]
		if !ok {
			// 路由↔文档双向集合对账由 apidocs_routes_test 负责，此处只校验
			// security 口径；未注册的文档路由在那道门报红。
			continue
		}
		want := apiDocSecurityFromRegistration(registration, authChainLine)
		if got := apiDocContractFor(route).security; got != want {
			t.Errorf("%s security=%q, 注册派生=%q（组=%s 行=%d 中间件=%v）——public/mcp/机器标注必须与真实认证链一致",
				key, got, want, registration.group, registration.line, registration.middleware)
		}
		checked++
		if want == "" {
			authenticatedCount++
		} else {
			publicCount++
		}
	}
	if checked < 100 || publicCount == 0 || authenticatedCount == 0 {
		t.Fatalf("派生覆盖 checked=%d 非 JWT=%d JWT=%d，扫描器疑似退化", checked, publicCount, authenticatedCount)
	}
}

// readOnlyWhitelistRoutes 从 services/auditpolicy.go 的 readOnlyWriteRoutes 声明
// 块派生全部 "METHOD /api/v1..." 键——测试不复制第二份豁免清单。
func readOnlyWhitelistRoutes(t *testing.T) map[string]struct{} {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("..", "services", "auditpolicy.go"))
	if err != nil {
		t.Fatalf("读 services/auditpolicy.go: %v", err)
	}
	const header = "var readOnlyWriteRoutes = map[string]struct{}{"
	start := strings.Index(string(source), header)
	if start < 0 {
		t.Fatalf("未找到 %s", header)
	}
	block := string(source)[start:]
	if end := strings.Index(block, "\n}"); end >= 0 {
		block = block[:end]
	}
	routes := make(map[string]struct{})
	for _, line := range strings.Split(block, "\n") {
		// 注释里常引用「已移除」的路由（如 POST /api/v1/mcp），派生清单只认
		// 真实条目行，否则已撤除的豁免会被当成现行契约。
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		for _, match := range regexp.MustCompile(`"([A-Z]+) (/api/v1[^"]+)"`).FindAllStringSubmatch(line, -1) {
			routes[match[1]+" "+match[2]] = struct{}{}
		}
	}
	if len(routes) == 0 {
		t.Fatal("只读语义写豁免清单派生为空——扫描器与声明形态漂移")
	}
	return routes
}

// API 文档的 Key 鉴权行必须按「方法集合 + 路由组」表述豁免清单：豁免清单含
// DELETE 时不得只写「只读语义 POST」；清单中注册在 admin 组的项必须带
// 「仅管理员属主」限定（非管理员属主 Key 在 admin 组恒 403，不构成放行）。
func TestAPIDocs_readOnlyKeyClaimMatchesWhitelistMethodsAndGroups(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "docs", "api.zh-CN.md"))
	if err != nil {
		t.Fatalf("读 docs/api.zh-CN.md: %v", err)
	}
	var row string
	for _, line := range strings.Split(string(source), "\n") {
		if strings.HasPrefix(line, "| API Key |") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("docs/api.zh-CN.md 缺 API Key 鉴权行")
	}

	registrations := middlewareRouteRegistrations(t, middlewareSourceForTest(t))
	whitelist := readOnlyWhitelistRoutes(t)

	// 文档短语 → 豁免路由：键集必须与派生清单的「路径集合」相等——
	// 新增/删除豁免项（含方法变化）都会使本表失配而报红。
	docPhrases := map[string]string{
		"/api/v1/certificates/parse":                        "解析证书",
		"/api/v1/certificates/jobs/current":                 "批量查询证书任务",
		"/api/v1/rules/cert-info":                           "规则证书信息",
		"/api/v1/security/overview/threat-screen/collector": "大屏采集租约",
		"/api/v1/config/preview":                            "配置预览",
		"/api/v1/config/import/validate":                    "导入校验",
		"/api/v1/settings/oidc/test":                        "OIDC 发现探测",
	}
	groups := make(map[string]string) // path → 注册组（admin/business）
	derivedPaths := make(map[string]struct{})
	methods := make(map[string]struct{})
	for key := range whitelist {
		method, path, found := strings.Cut(key, " ")
		if !found {
			t.Fatalf("豁免键形态异常: %q", key)
		}
		methods[method] = struct{}{}
		derivedPaths[path] = struct{}{}
		registration, ok := registrations[method+" "+strings.TrimPrefix(path, "/api/v1")]
		if !ok {
			t.Errorf("豁免路由 %s 在 middleware.go 无注册——清单与装配漂移", key)
			continue
		}
		if previous, exists := groups[path]; exists && previous != registration.group {
			t.Errorf("豁免路由 %s 同时注册在 %s 与 %s 组", path, previous, registration.group)
		}
		groups[path] = registration.group
	}
	if len(methods) < 2 {
		t.Fatalf("豁免清单只含 %v 一种方法，方法集合断言失效", methods)
	}
	if len(docPhrases) != len(derivedPaths) {
		t.Errorf("文档短语表覆盖 %d 条豁免路径，派生清单 %d 条——新增/删除豁免项必须同步文档与守卫表",
			len(docPhrases), len(derivedPaths))
	}
	for path := range derivedPaths {
		if _, ok := docPhrases[path]; !ok {
			t.Errorf("豁免路径 %s 未在文档短语表登记", path)
		}
	}
	for path := range docPhrases {
		if _, ok := derivedPaths[path]; !ok {
			t.Errorf("文档短语表含 %s，但它已不在只读语义写豁免清单", path)
		}
	}

	// 同一子句内的限定词作用于其点名的全部项：按「；」切分后逐项校验。
	clauseFor := func(phrase string) (string, bool) {
		for _, clause := range strings.Split(row, "；") {
			if strings.Contains(clause, phrase) {
				return clause, true
			}
		}
		return "", false
	}
	for path, phrase := range docPhrases {
		clause, found := clauseFor(phrase)
		if !found {
			t.Errorf("API Key 行未点名豁免项 %s（%q）", path, phrase)
			continue
		}
		switch groups[path] {
		case "admin":
			if !strings.Contains(clause, "仅管理员属主") {
				t.Errorf("豁免项 %s 注册在 admin 组（非管理员属主 Key 恒 403），文案须带「仅管理员属主」限定: %q", path, clause)
			}
		case "business":
			if strings.Contains(clause, "仅管理员属主") {
				t.Errorf("豁免项 %s 在 business 组（非管理员属主 Key 可达），不得限定为仅管理员属主: %q", path, clause)
			}
		default:
			t.Errorf("豁免项 %s 的注册组=%q，未预期（守卫挂载面变化须重新核对文案）", path, groups[path])
		}
	}

	if _, hasDelete := methods["DELETE"]; hasDelete {
		if !strings.Contains(row, "DELETE") {
			t.Errorf("豁免清单含 DELETE 方法，API Key 行不得只写「只读语义 POST」: %s", row)
		}
	}
	if strings.Contains(row, "「只读语义 POST」") {
		t.Errorf("API Key 行仍只声明 POST 豁免（DELETE 释放采集租约同样放行）: %s", row)
	}
}

// syncedGlobalConfigWriterDocs 是「写 global_config 同步列」的 admin 组端点，
// 与 middleware 的 isSynchronizedWrite 清单同集合（该处判定 bump 集群版本）。
// 这些端点的从节点写门挂在网关（admin 组 readOnlyGuard），handler 内没有
// requireMasterNode 之类的二次判定——文档若只写 403 admin_required，排障会把
// 「从节点只读」误读成「权限不足」。
var syncedGlobalConfigWriterDocs = []string{
	"PUT /config",
	"PUT /caddy/config",
	"PUT /cluster/settings",
	"PUT /admin-tls",
	"PUT /settings/auto-backup",
	"PUT /settings/oidc",
	"DELETE /settings/oidc",
}

// 写门文档一致性：同步列写端点的 403 必须点名「从节点只读」（写门在网关），
// 只写 admin_required 会让从节点侧保存失败被误归因为角色问题。
func TestAPIDocs_syncedConfigWritersDocumentSlaveReadOnly(t *testing.T) {
	index := map[string]apiDocRoute{}
	for _, route := range apiDocRoutes {
		index[route.Method+" "+route.Path] = route
	}
	for _, key := range syncedGlobalConfigWriterDocs {
		route, ok := index[key]
		if !ok {
			t.Errorf("文档缺少路由 %s", key)
			continue
		}
		documented := false
		for _, entry := range route.Errors {
			if !strings.HasPrefix(entry, "403") {
				continue
			}
			if strings.Contains(entry, "从节点只读") || strings.Contains(entry, "slave") {
				documented = true
				break
			}
		}
		if !documented {
			t.Errorf("%s 的 403 未点名「从节点只读」（写门在网关 readOnlyGuard）errors=%v", key, route.Errors)
		}
	}
}
