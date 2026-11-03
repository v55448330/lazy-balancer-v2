package services

// path 作用域 CRS 排除（scope=path）：读侧归一、渲染发射、发射预算、渲染守卫
// 与引擎级实证（R-10：验证终点=coraza NewWAF 接受 + 真实事务行为）。契约：
//   条目 {target, scope:"path", path}；渲染
//   SecRule REQUEST_URI "@beginsWith <path>" "id:<同族引擎id>,phase:1,pass,nolog,ctl:ruleRemoveById=<mapped>"
// 引擎 id 与 ip/list 同段共享 crsScopedExclusionIDBase，并共享同一发射行预算。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"lazy-balancer-v2/internal/models"
)

func pathScopePolicy(raw string) *models.SecurityPolicy {
	return &models.SecurityPolicy{ID: 9, Name: "path-scope", AnomalyThreshold: 5, Mode: "blocking",
		CRSExcludedRules: json.RawMessage(raw)}
}

// 读侧归一：path 字段保留；去重键必须含 path（同 target 不同 path 是两条）。
func TestParseCRSExcludedRules_pathScopeDedupesByPath(t *testing.T) {
	entries := ParseCRSExcludedRules(`[
		{"target":"942100","scope":"path","path":"/api/public"},
		{"target":"942100","scope":"path","path":"/api/admin"}
	]`)
	if len(entries) != 2 {
		t.Fatalf("不同 path 的同 target 条目不得被去重合并，got %d: %+v", len(entries), entries)
	}
	if entries[0].Path != "/api/public" || entries[1].Path != "/api/admin" {
		t.Fatalf("path 字段必须原样保留: %+v", entries)
	}
	// 同 {target,scope,path} 仍去重（与家族口径一致）
	dup := ParseCRSExcludedRules(`[
		{"target":"942100","scope":"path","path":"/api"},
		{"target":"942100","scope":"path","path":"/api"}
	]`)
	if len(dup) != 1 {
		t.Fatalf("完全相同条目必须去重，got %d: %+v", len(dup), dup)
	}
}

// 渲染：单 ID 条目 → REQUEST_URI @beginsWith 运行时 ctl 行，形状与契约逐字一致。
func TestBuildCorazaDirectives_pathScopeEmitsBeginsWithCtl(t *testing.T) {
	scopedExclusionFixture(t)
	directives := mustDirectives(BuildCorazaDirectives(
		pathScopePolicy(`[{"target":"942100","scope":"path","path":"/api/public"}]`), nil, "", false, 0, "lb_path"))
	want := `SecRule REQUEST_URI "@beginsWith /api/public" "id:2000001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"`
	if !strings.Contains(directives, want) {
		t.Fatalf("path 作用域必须发射 @beginsWith ctl 行:\n%s", directives)
	}
	if strings.Contains(directives, "SecRuleRemoveById ") {
		t.Fatal("path 作用域是运行时 ctl，不得发射配置期 SecRuleRemoveById")
	}
	compileForEngineGate(t, directives)
}

// 渲染：组号条目逐 ID 展开（同族引擎 id 连号），且 ctl 行位于 CRS Include 之前
// （运行时 ctl 必须先于被禁规则执行——与 ip/list 同一顺序不变量）。
func TestBuildCorazaDirectives_pathScopeGroupExpandsWithSharedIDs(t *testing.T) {
	scopedExclusionFixture(t)
	directives := mustDirectives(BuildCorazaDirectives(
		pathScopePolicy(`[{"target":"42","scope":"path","path":"/api/public"}]`), nil, "", false, 0, "lb_path"))
	want := []string{
		`"id:2000001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"`,
		`"id:2000002,phase:1,pass,nolog,ctl:ruleRemoveById=942550"`,
	}
	last := -1
	for _, line := range want {
		idx := strings.Index(directives, line)
		if idx < 0 {
			t.Fatalf("missing ctl line %q in:\n%s", line, directives)
		}
		if idx < last {
			t.Fatalf("ctl lines out of order: %q", line)
		}
		last = idx
	}
	if includeIdx := strings.Index(directives, "Include /app/waf/crs/"); includeIdx < 0 || last > includeIdx {
		t.Fatalf("ctl:ruleRemoveById must precede the CRS Include (ctlIdx=%d includeIdx=%d):\n%s", last, includeIdx, directives)
	}
	compileForEngineGate(t, directives)
}

// 渲染：混合 ip+path 条目——ip 行形状零变化（REMOTE_ADDR @ipListFast 投影 +
// id 2000001），path 行接入同一 id 族（2000002）。
func TestBuildCorazaDirectives_pathScopeMixedWithIPSharesIDFamily(t *testing.T) {
	scopedExclusionFixture(t)
	directives := mustDirectives(BuildCorazaDirectives(
		pathScopePolicy(`[{"target":"942100","scope":"ip","ips":"1.1.1.1"},{"target":"942100","scope":"path","path":"/api/public"}]`),
		nil, "", false, 0, "lb_path"))
	if !strings.Contains(directives, `SecRule REMOTE_ADDR "@ipListFast `) ||
		!strings.Contains(directives, `"id:2000001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"`) {
		t.Fatalf("ip 作用域行形状必须零变化（id 2000001）:\n%s", directives)
	}
	if !strings.Contains(directives, `SecRule REQUEST_URI "@beginsWith /api/public" "id:2000002,phase:1,pass,nolog,ctl:ruleRemoveById=942100"`) {
		t.Fatalf("path 行必须接入同族 id 段（2000002）:\n%s", directives)
	}
	compileForEngineGate(t, directives)
}

// 渲染守卫（防御深度，拦带外直写）：非法 path（不以 / 开头/双引号/反斜杠/
// 空白/控制字符/超 256 字符）逐条跳过，不发射；未知 scope 守卫保持
// （不降级为全局排除）。
func TestBuildCorazaDirectives_pathScopeRenderGuards(t *testing.T) {
	scopedExclusionFixture(t)
	bad := []string{"api/no-slash", `/api"quote`, `/api\back`, `/api space`, "/api\ttab", "/api\x00ctl"}
	for _, path := range bad {
		raw, err := json.Marshal([]map[string]string{{"target": "942100", "scope": "path", "path": path}})
		if err != nil {
			t.Fatal(err)
		}
		directives := mustDirectives(BuildCorazaDirectives(pathScopePolicy(string(raw)), nil, "", false, 0, "lb_path"))
		if strings.Contains(directives, "@beginsWith") || strings.Contains(directives, "ctl:ruleRemoveById") {
			t.Fatalf("非法 path %q 必须被渲染守卫跳过:\n%s", path, directives)
		}
	}
	over := "/" + strings.Repeat("a", 256) // 257 字符 > 上限 256
	raw, _ := json.Marshal([]map[string]string{{"target": "942100", "scope": "path", "path": over}})
	directives := mustDirectives(BuildCorazaDirectives(pathScopePolicy(string(raw)), nil, "", false, 0, "lb_path"))
	if strings.Contains(directives, "@beginsWith") {
		t.Fatalf("超长 path 必须被渲染守卫跳过:\n%s", directives)
	}
	// 回归钉：未知 scope 不降级为 any 发射路径（不进 scoped、不进 path、不进 all）
	directives = mustDirectives(BuildCorazaDirectives(
		pathScopePolicy(`[{"target":"942100","scope":"weird"}]`), nil, "", false, 0, "lb_path"))
	if strings.Contains(directives, "ctl:ruleRemoveById") || strings.Contains(directives, "SecRuleRemoveById 942100") {
		t.Fatalf("未知 scope 不得发射任何排除:\n%s", directives)
	}
}

// 发射预算：path 与 ip/list 共享同一 ctl 行预算（超预算截断告警同口径）。
// 预算缩到 3：ip 组条目展开 2 行 + path 组条目只能发射首行（第三行被截断）。
func TestBuildCorazaDirectives_pathScopeSharesBudgetWithIPList(t *testing.T) {
	scopedExclusionFixture(t)
	oldBudget := crsScopedExclusionMaxDirectives
	crsScopedExclusionMaxDirectives = 3
	t.Cleanup(func() { crsScopedExclusionMaxDirectives = oldBudget })

	directives := mustDirectives(BuildCorazaDirectives(
		pathScopePolicy(`[{"target":"42","scope":"ip","ips":"10.1.1.1"},{"target":"42","scope":"path","path":"/api/public"}]`),
		nil, "", false, 0, "lb_budget"))

	ctlLines := 0
	beginsWithLines := 0
	for _, line := range strings.Split(directives, "\n") {
		if strings.Contains(line, "ctl:ruleRemoveById=") {
			ctlLines++
		}
		if strings.Contains(line, "@beginsWith") {
			beginsWithLines++
		}
	}
	if ctlLines != 3 {
		t.Fatalf("共享预算下 ctl 行数=%d, want 3（ip 展开 2 行 + path 首行，其余被预算截断）:\n%s", ctlLines, directives)
	}
	if beginsWithLines != 1 {
		t.Fatalf("@beginsWith 行数=%d, want 1（预算耗尽后 path 条目停止发射）:\n%s", beginsWithLines, directives)
	}
	compileForEngineGate(t, directives)
}

// R-10 引擎级实证（编译）：含 path 作用域排除的完整渲染产物被 coraza 接受。
// （形状用例内已各自 compileForEngineGate——本用例补一条组展开+混合+预算边界的
// 组合编译钉。）
func TestEngineGate_pathScopeMixedDirectivesCompile(t *testing.T) {
	scopedExclusionFixture(t)
	directives := mustDirectives(BuildCorazaDirectives(
		pathScopePolicy(`[{"target":"42","scope":"path","path":"/api/public"},{"target":"942550","scope":"path","path":"/api/admin/export"},{"target":"942100","scope":"all"}]`),
		nil, "", false, 0, "lb_path"))
	if !strings.Contains(directives, `SecRuleRemoveById 942100`) {
		t.Fatalf("scope=all 条目照常走配置期删除:\n%s", directives)
	}
	compileForEngineGate(t, directives)
}

// R-10 引擎级实证（行为）：真实 NewWAF + 真实事务——
//
//	前缀内路径携带触发 942100 的载荷 → 不拦（ctl 排除生效）；
//	前缀外同载荷 → 照常拦（排除不越界）；
//	基线（无排除）→ 两路径都拦（证明桩规则在该事务驱动方式下真实生效）。
func TestEngineBehavior_pathScopeRemovesRuleOnlyUnderPrefix(t *testing.T) {
	root := t.TempDir()
	rules := filepath.Join(root, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"rules/REQUEST-901-INITIALIZATION.conf":          "SecAction \"id:901001,phase:1,pass,nolog\"\n",
		"rules/REQUEST-949-BLOCKING-EVALUATION.conf":     "SecAction \"id:949110,phase:2,pass,log\"\n",
		"rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf": "SecRule ARGS \"@rx union select\" \"id:942100,phase:2,deny,status:403,log,msg:'SQLi'\"\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldDir := crsDirectivesDir
	crsDirectivesDir = root
	t.Cleanup(func() { crsDirectivesDir = oldDir })
	seedCRSRuleIndexFixture(t) // 索引：942100 存在（逐 ID 展开/陈旧过滤消费）

	seedWAF := func(policy *models.SecurityPolicy) coraza.WAF {
		t.Helper()
		directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_path"))
		rewritten := strings.ReplaceAll(directives, "/app/waf/crs", root)
		// 与 compileForEngineGate 同口径过滤环境依赖行：SecAuditLog 路径在
		// 开发/CI 不存在、SecAuditLogType lbfile 插件仅存在于 xcaddy 构建的
		// Caddy 二进制。Include 保留（改写到夹具树）——被测对象含 CRS 桩规则
		// 与 path 排除 ctl 的真实加载与执行。
		var kept []string
		for _, line := range strings.Split(rewritten, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "SecAuditLog ") || strings.HasPrefix(trimmed, "SecAuditLogType ") {
				continue
			}
			kept = append(kept, line)
		}
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join(kept, "\n")))
		if err != nil {
			t.Fatalf("coraza 引擎拒绝渲染指令: %v\n--- directives ---\n%s", err, strings.Join(kept, "\n"))
		}
		return waf
	}
	interrupted := func(waf coraza.WAF, uri string) bool {
		t.Helper()
		tx := waf.NewTransaction()
		defer func() { _ = tx.Close() }()
		tx.ProcessConnection("203.0.113.9", 5555, "127.0.0.1", 80)
		tx.ProcessURI(uri, "GET", "HTTP/1.1")
		if tx.ProcessRequestHeaders() != nil {
			return true
		}
		it, _ := tx.ProcessRequestBody()
		return it != nil
	}
	const payloadURI = "/api/public/list?id=1+union+select"

	// 基线：无排除 → 两路径同载荷都拦（桩规则真实生效）。
	baseline := seedWAF(&models.SecurityPolicy{ID: 9, Name: "baseline", AnomalyThreshold: 5, Mode: "blocking"})
	if !interrupted(baseline, payloadURI) {
		t.Fatal("基线：无排除时 942100 必须拦截同载荷（否则断言无意义）")
	}

	// path 作用域：前缀内不拦，前缀外照常拦。
	scoped := seedWAF(pathScopePolicy(`[{"target":"942100","scope":"path","path":"/api/public"}]`))
	if interrupted(scoped, payloadURI) {
		t.Fatal("前缀内路径携带同载荷必须被 ctl:ruleRemoveById 排除（不拦）")
	}
	if !interrupted(scoped, "/api/admin/list?id=1+union+select") {
		t.Fatal("前缀外同载荷必须照常拦（排除不得越界）")
	}
	// 前缀真语义：仅前缀命中，"7/api/public" 等非边界路径不受豁免。
	if interrupted(scoped, "/api/private/list?id=1+union+select") == false {
		t.Fatal("前缀外的 /api/private 必须照常拦")
	}
}
