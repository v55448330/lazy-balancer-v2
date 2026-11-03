package services

// 拦截页全量逐策略归因（2026-11 用户裁定）的阶段 1 预检链拆分与抬码钉测。
//
// 语义：触发哪条策略 → 显示该策略自己配置的拦截页；该策略未配页 → 兜底
// （首个启用且有页策略，buildBlockPageErrorRoute）；全部无页 → Caddy 默认 403。
// 阶段 1 预检按触发子源拆分：
//   - ACL deny 并集（旧 id:2）/ 遗留黑名单并集（旧 id:4）拆为逐策略链
//     （新 id 段 1500000+policyID / 1510000+policyID），有页策略 deny 抬码
//     各自合成码（483+i），无页策略保持 403 落兜底路由；
//   - GeoIP 逐策略链（既有 800000+policyID）denyStatus 同口径逐策略；
//   - 白名单交集外拒绝（id:7）维持兜底（交集跨策略无归属语义）；
//   - 限流 429 维持兜底（buildRateLimitErrorRoute，技术边界）。
// 规则级阶段页（481/482）停用：渲染链零 481/482。
//
// 引擎级实证：矩阵中每个触发子源 × 有页/无页的组合都以真实 coraza 事务
// （与镜像 coraza-caddy 同版）断言中断状态码——字符串形状不构成行为验证。

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"lazy-balancer-v2/internal/models"
)

// attribCtx 构造带合成码的生成上下文：p1→483、p2→484，其余策略未获码。
func attribCtx(pages map[int]string, synthetic map[int]int) *securityPolicyContext {
	return &securityPolicyContext{
		blockPageByID:     pages,
		blockPageTypeByID: map[int]string{},
		policySynthetic:   synthetic,
	}
}

func attribDenyPolicy(id int, cidr string) *models.SecurityPolicy {
	return &models.SecurityPolicy{ID: id, Mode: "off", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["` + cidr + `"]`}
}

func attribBlacklistPolicy(id int, ip string) *models.SecurityPolicy {
	return &models.SecurityPolicy{ID: id, Mode: "off", IPBlacklist: json.RawMessage(`["` + ip + `"]`)}
}

func attribGeoPolicy(id int, mode string) *models.SecurityPolicy {
	return &models.SecurityPolicy{ID: id, Mode: "off", GeoIPMode: mode, GeoIPCountries: json.RawMessage(`["海外"]`)}
}

// —— 拆链形状 ——

func TestPrecheckAttribution_aclDenySplitChains(t *testing.T) {
	p1 := attribDenyPolicy(1, "203.0.113.0/24")
	p2 := attribDenyPolicy(2, "203.0.114.0/24")
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2}, "lb_x",
		attribCtx(map[int]string{10: "<page>"}, map[int]int{1: 483})))
	// 逐策略链 id 段与各自抬码：有页 483，无页 403。
	if !strings.Contains(directives, `"id:1500001,phase:1,deny,status:483,log,msg:'IP 黑名单拒绝'`) {
		t.Fatalf("policy 1 deny chain must lift 483:\n%s", directives)
	}
	if !strings.Contains(directives, `"id:1500002,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝'`) {
		t.Fatalf("policy 2 (no page) deny chain must keep 403:\n%s", directives)
	}
	// 旧合并并集形状必须消失（u-deny 投影 scope 与共享 id:2 段）。
	if strings.Contains(directives, "u-deny-") || strings.Contains(directives, "id:2,") {
		t.Fatalf("merged deny union (id:2 / u-deny scope) must be gone:\n%s", directives)
	}
	compileForEngineGate(t, directives)
}

func TestPrecheckAttribution_blacklistSplitChains(t *testing.T) {
	p1 := attribBlacklistPolicy(1, "198.51.100.9")
	p2 := attribBlacklistPolicy(2, "198.51.100.10")
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2}, "lb_x",
		attribCtx(map[int]string{10: "<page>"}, map[int]int{2: 484})))
	if !strings.Contains(directives, `"id:1510001,phase:1,deny,status:403,log,msg:'IP 黑名单'`) {
		t.Fatalf("policy 1 (no page) blacklist chain must keep 403:\n%s", directives)
	}
	if !strings.Contains(directives, `"id:1510002,phase:1,deny,status:484,log,msg:'IP 黑名单'`) {
		t.Fatalf("policy 2 (page) blacklist chain must lift 484:\n%s", directives)
	}
	if strings.Contains(directives, "u-bl-") || strings.Contains(directives, "id:4,") {
		t.Fatalf("merged blacklist union (id:4 / u-bl scope) must be gone:\n%s", directives)
	}
	compileForEngineGate(t, directives)
}

func TestPrecheckAttribution_allowIntersectionStaysFallback(t *testing.T) {
	// allow 交集外拒绝（id:7）不抬码：交集跨策略无归属语义，恒落兜底路由
	// ——即使 allow 策略自身配有拦截页（获合成码）也不抬。
	p1 := &models.SecurityPolicy{ID: 1, Mode: "off", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["198.51.100.7"]`}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p1}, "lb_x",
		attribCtx(map[int]string{10: "<page>"}, map[int]int{1: 483})))
	if !strings.Contains(directives, `"id:7,phase:1,deny,status:403,log,msg:'IP 白名单拒绝'`) {
		t.Fatalf("allow intersection-out reject must stay 403 fallback:\n%s", directives)
	}
	compileForEngineGate(t, directives)
}

func TestPrecheckAttribution_geoipChainsLiftPerPolicy(t *testing.T) {
	p1 := attribGeoPolicy(1, "deny")
	p2 := attribGeoPolicy(2, "deny")
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2}, "lb_x",
		attribCtx(map[int]string{10: "<page>"}, map[int]int{2: 484})))
	if !strings.Contains(directives, `"id:800001,phase:1,deny,log,msg:'GeoIP 区域拦截'`) {
		t.Fatalf("policy 1 (no page) geoip chain head must stay without status (default 403):\n%s", directives)
	}
	if !strings.Contains(directives, `"id:800002,phase:1,deny,status:484,log,msg:'GeoIP 区域拦截'`) {
		t.Fatalf("policy 2 (page) geoip chain head must lift 484:\n%s", directives)
	}
	compileForEngineGate(t, directives)
}

// —— 引擎行为矩阵（真实 coraza 事务断言中断状态码）——

// runPrecheckTx 编译预检指令并跑一个来自 clientIP 的请求（可携带 GeoIP 定位头）。
func runPrecheckTx(t *testing.T, directives, clientIP string, geoLoc string) *types.Interruption {
	t.Helper()
	// 审计输出行与 Include 在单测环境无插件/无 CRS 树，逐字送编译会被拒；
	// 过滤口径与 compileForEngineGate 同源（其余 SecRule 形状零裁剪）。
	var kept []string
	for _, line := range strings.Split(directives, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "SecAuditLog ") || strings.HasPrefix(trimmed, "SecAuditLogType ") {
			continue
		}
		kept = append(kept, line)
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join(kept, "\n")))
	if err != nil {
		t.Fatalf("engine must compile precheck directives: %v\n%s", err, directives)
	}
	tx := waf.NewTransaction()
	defer func() { _ = tx.Close() }()
	tx.ProcessConnection(clientIP, 5555, "127.0.0.1", 80)
	tx.ProcessURI("/anything", "GET", "HTTP/1.1")
	if geoLoc != "" {
		tx.AddRequestHeader("X-LB-GeoIP-Loc", geoLoc)
	}
	return tx.ProcessRequestHeaders()
}

func TestEngineBehavior_precheckAttributionMatrix(t *testing.T) {
	// 矩阵：触发子源 × 有页/无页 → 中断状态码（触发策略页码 / 403 兜底）。
	t.Run("acl deny with page lifts synthetic", func(t *testing.T) {
		directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{attribDenyPolicy(1, "203.0.113.0/24")}, "lb_x",
			attribCtx(map[int]string{10: "<page>"}, map[int]int{1: 483})))
		it := runPrecheckTx(t, directives, "203.0.113.9", "")
		if it == nil || it.Status != 483 {
			t.Fatalf("deny-list IP must interrupt with policy 1 synthetic 483, got %#v", it)
		}
	})
	t.Run("acl deny without page keeps 403", func(t *testing.T) {
		directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{attribDenyPolicy(1, "203.0.113.0/24")}, "lb_x",
			attribCtx(nil, nil)))
		it := runPrecheckTx(t, directives, "203.0.113.9", "")
		if it == nil || it.Status != 403 {
			t.Fatalf("deny-list IP with pageless policy must interrupt 403 (fallback), got %#v", it)
		}
	})
	t.Run("blacklist with page lifts synthetic", func(t *testing.T) {
		directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{attribBlacklistPolicy(2, "198.51.100.9")}, "lb_x",
			attribCtx(map[int]string{10: "<page>"}, map[int]int{2: 484})))
		it := runPrecheckTx(t, directives, "198.51.100.9", "")
		if it == nil || it.Status != 484 {
			t.Fatalf("blacklisted IP must interrupt with policy 2 synthetic 484, got %#v", it)
		}
	})
	t.Run("geoip deny with page lifts synthetic", func(t *testing.T) {
		directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{attribGeoPolicy(1, "deny")}, "lb_x",
			attribCtx(map[int]string{10: "<page>"}, map[int]int{1: 483})))
		it := runPrecheckTx(t, directives, "203.0.113.9", "海外")
		if it == nil || it.Status != 483 {
			t.Fatalf("geo-denied IP must interrupt with policy 1 synthetic 483, got %#v", it)
		}
	})
	t.Run("geoip deny without page keeps 403", func(t *testing.T) {
		directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{attribGeoPolicy(1, "deny")}, "lb_x",
			attribCtx(nil, nil)))
		it := runPrecheckTx(t, directives, "203.0.113.9", "海外")
		if it == nil || it.Status != 403 {
			t.Fatalf("geo-denied IP with pageless policy must interrupt 403 (fallback), got %#v", it)
		}
	})
	t.Run("allow intersection reject stays 403", func(t *testing.T) {
		p := &models.SecurityPolicy{ID: 1, Mode: "off", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["198.51.100.7"]`}
		directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p}, "lb_x",
			attribCtx(map[int]string{10: "<page>"}, map[int]int{1: 483})))
		it := runPrecheckTx(t, directives, "203.0.113.9", "")
		if it == nil || it.Status != 403 {
			t.Fatalf("allow intersection-out IP must interrupt 403 (fallback semantics), got %#v", it)
		}
	})
}

// —— 规则级阶段页停用 ——

func TestGenerateCaddyConfig_stagePageColumnsAreDead(t *testing.T) {
	// 存量行带 stage 页列值（旧版本遗留）：渲染链必须零消费——无 481/482
	// 阶段路由，且 483+ 归因路由不被压制（原「规则配 stage3 页就不发归因
	// 路由」的耦合门随阶段页停用消失）。
	stubSecurityLibsAvailable(t)
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_sp", "sp.test", 8080)
	seedSecurityBlockPage(t, database, 10, "<page-p10>")
	mpGenBindPolicy(t, database, "lb_sp", "pol", mpGenPolicySpec{enabled: true, blockPageID: 10, blockStatusCode: 451, ipACLEnabled: true, ipACLMode: "deny", ipACLList: `["203.0.113.0/24"]`})
	if _, err := database.Exec(`UPDATE lb_rules SET block_page_stage1_id=10, block_page_stage1_status=403, block_page_stage3_id=10, block_page_stage3_status=503 WHERE caddy_id='lb_sp'`); err != nil {
		t.Fatal(err)
	}
	config := generateCaddyConfigFromStore(database)
	if message, failed := config[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	errorRouteValues, _ := serverErrorRoutes(t, config, "http_8080")
	var allRoutes []interface{}
	allRoutes = append(allRoutes, errorRouteValues...)
	rendered := ""
	for _, r := range allRoutes {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal route: %v", err)
		}
		rendered += string(b) + "\n"
	}
	if strings.Contains(rendered, "== 481") || strings.Contains(rendered, "== 482") {
		t.Fatalf("stage routes (481/482) must be gone even for legacy rows carrying stage page columns:\n%s", rendered)
	}
	if !strings.Contains(rendered, "== 483") {
		t.Fatalf("per-policy attribution route (483) must be emitted without the stage3 suppression gate:\n%s", rendered)
	}
}
