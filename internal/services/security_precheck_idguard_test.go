package services

// U1-3（第 45 轮审计）：GeoIP 预检链 id 上界守卫。policyID 过大使
// 800000+policyID 落入 CRS 保留段（900000+）时必须跳过该策略链并告警——
// 危害是事件归因/分桶错位（securityEventsPolicyContainsRule 的 800xxx case
// 与 stage-stats 分桶都不再命中），而非编译失败（预检是独立 coraza 配置，
// 段内 id 彼此唯一，无同 id 冲突）。测试仍以引擎编译作回归面（R-10）。

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestEngineGate_precheckGeoipPolicyIDGuard(t *testing.T) {
	// 越界形状：ID=100000 → 预检 id=900000 撞 CRS 保留段，必须整链跳过。
	pBig := &models.SecurityPolicy{ID: 100000, Mode: "off", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["CN"]`)}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{pBig}, 0, "lb_test"))
	if strings.Contains(directives, "id:900000") {
		t.Fatalf("policy id 100000 must skip its precheck geoip chain (900000 collides CRS reserved space), got:\n%s", directives)
	}
	compileForEngineGate(t, directives)
	// 回归形状：常规 ID=42 照常发射 id:800042（与 precheckGeoipChainShapes 同口径）。
	pOK := &models.SecurityPolicy{ID: 42, Mode: "off", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["CN"]`)}
	dOK := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{pOK}, 0, "lb_test"))
	if !strings.Contains(dOK, "id:800042,") {
		t.Fatalf("policy id 42 must still emit id:800042 chain, got:\n%s", dOK)
	}
	compileForEngineGate(t, dOK)
}

// ---- 第 78 轮 A 域：RG-SEC-PRECHECK-ID-ENCODE / RG-SEC-PRECHECK-SCORE ----

func precheckRuleIDList(directives string) []int {
	var out []int
	for _, m := range regexp.MustCompile(`\bid:(\d+)`).FindAllStringSubmatch(directives, -1) {
		n, err := strconv.Atoi(m[1])
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}

// crawlerRenderPolicy 构造启用爬虫豁免的 GeoIP 预检策略（引擎清单空=全部）。
func crawlerRenderPolicy(id int) *models.SecurityPolicy {
	return &models.SecurityPolicy{
		ID:                 id,
		Mode:               "off",
		GeoIPMode:          "deny",
		GeoIPCountries:     json.RawMessage(`["CN"]`),
		GeoIPCrawlerExempt: true,
	}
}

func TestPrecheckRuleID_crossFamilyUniqueness(t *testing.T) {
	// 形状 1/2：编号越界撞族（2666*16+10 落进伪装段且与自身伪装 id 相同；
	// 2500 起豁免 id 全部落进伪装段）。编码边界显式化后越界规则跳过+告警，
	// 绝不发射重复/跨族 id。
	for _, pid := range []int{2666, 2500} {
		directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{crawlerRenderPolicy(pid)}, 0, "lb_test"))
		ids := precheckRuleIDList(directives)
		seen := make(map[int]bool, len(ids))
		for _, id := range ids {
			if seen[id] {
				t.Fatalf("policy %d rendered duplicate SecRule id %d:\n%s", pid, id, directives)
			}
			seen[id] = true
		}
		// 豁免规则越界必须被拒（不得以伪装段的数值发射豁免规则）。
		if strings.Contains(directives, "搜索引擎爬虫放行") {
			t.Fatalf("policy %d: crawler exemption id overflows its family but was rendered:\n%s", pid, directives)
		}
		if !strings.Contains(directives, "搜索引擎爬虫伪装") {
			t.Fatalf("policy %d: spoof rule must still be rendered:\n%s", pid, directives)
		}
		compileForEngineGate(t, directives)
	}

	// 边界形状：2499 是豁免族最后一个可编码策略（每策略 16 槽），不得误报。
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{crawlerRenderPolicy(2499)}, 0, "lb_test"))
	ids := precheckRuleIDList(directives)
	seen := make(map[int]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("boundary policy 2499 rendered duplicate SecRule id %d:\n%s", id, directives)
		}
		seen[id] = true
	}
	if !strings.Contains(directives, "搜索引擎爬虫放行") {
		t.Fatalf("policy 2499 (last encodable exempt policy) must still emit exemption rules:\n%s", directives)
	}
	// 末槽 id = 810000+2499*16+14 = 849998 < 850000（伪装族基址）。
	if !strings.Contains(directives, "id:849998,") {
		t.Fatalf("policy 2499 last engine slot id:849998 missing:\n%s", directives)
	}
	compileForEngineGate(t, directives)
}

func TestPolicyAttribution_crawlerExemptOwnership(t *testing.T) {
	// Given：多 GeoIP 策略绑定；810048 = 810000+3*16+0 → 属 policy 3。
	p1 := &models.SecurityPolicy{ID: 1, Mode: "off", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["CN"]`)}
	p3 := &models.SecurityPolicy{ID: 3, Mode: "off", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["CN"]`)}
	policyByID := map[int]*models.SecurityPolicy{1: p1, 3: p3}
	bindings := map[string][]int{"lb_x": {1, 3}}
	pid, _ := securityEventsAttributePolicy("lb_x", "810048", "logged", "198.51.100.9", policyByID, bindings)
	if pid != 3 {
		t.Fatalf("crawler exempt 810048 attributed to policy %d, want 3", pid)
	}
	if securityEventsPolicyContainsRule(p1, "810048", "198.51.100.9") {
		t.Fatal("policy 1 must not claim policy 3's crawler exemption id")
	}
	// 伪装 850003 属 policy 3。
	if !securityEventsPolicyContainsRule(p3, "850003", "") || securityEventsPolicyContainsRule(p1, "850003", "") {
		t.Fatal("spoof id 850003 must belong to policy 3 only")
	}
}

func securityEventsScoringFixture(t *testing.T, ruleID string, messages string) *securityEventRecord {
	t.Helper()
	if messages == "" {
		// 规则 ID 来自首条消息（Coraza 审计形态）；raw 不含 setvar 评分动作，
		// 让固定语义分分支成为唯一评分来源。
		messages = fmt.Sprintf(`[{"message":"rule %s","data":{"id":%s,"raw":"id:%s,phase:1,deny,log"}}]`, ruleID, ruleID, ruleID)
	}
	raw := fmt.Sprintf(`{
  "transaction": {
    "timestamp": "2026/08/11 19:16:57",
    "unix_timestamp": 1786447017,
    "id": "tx-score-%s",
    "client_ip": "198.51.100.9",
    "server_id": "go029.com",
    "request": { "method": "GET", "uri": "/", "headers": { "host": ["go029.com"] } },
    "is_interrupted": true
  },
  "messages": %s
}`, ruleID, messages)
	rec, err := securityEventsParseTransaction(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("parse fixture for rule %s: %v", ruleID, err)
	}
	return rec
}

func TestSecurityEventScoring_matrix(t *testing.T) {
	cases := []struct {
		rule string
		want int
	}{
		{"2", 12},     // IP ACL 预检
		{"8", 6},      // 遗留共享 GeoIP
		{"800001", 6}, // GeoIP 精确段
		{"810000", 6}, // 越界/无属主形态：不得被当爬虫豁免得 0
		{"810048", 0}, // 有效爬虫豁免：审计轨迹不计威胁分
		{"850001", 12},
		{"850003", 12},
		{"429", 6},
		{"10001", 0},  // 自定义规则：无消息分数即 0
		{"942100", 0}, // CRS：无评分消息时保持既有 0
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			rec := securityEventsScoringFixture(t, tc.rule, "")
			if rec.AnomalyScore != tc.want {
				t.Fatalf("rule %s score=%d, want %d", tc.rule, rec.AnomalyScore, tc.want)
			}
		})
	}
	// 回归形状：CRS 评分消息的原始分不得被固定分覆盖。
	msgs := `[{"message":"SQL Injection","data":{"id":942100,"raw":"SecRule ARGS \"@detectSQLi\" \"id:942100,phase:2,block,log,setvar:tx.inbound_anomaly_score_pl1=+5\""}}]`
	rec := securityEventsScoringFixture(t, "942100", msgs)
	if rec.AnomalyScore != 5 {
		t.Fatalf("CRS 942100 with scoring message=%d, want 5 (original score preserved)", rec.AnomalyScore)
	}
}

func TestSecurityEventScoring_geoIPPolicy10000NotCrawler(t *testing.T) {
	if securityEventsIsCrawlerExemptRule("810000") {
		t.Fatal("810000 must not be classified as a crawler exemption id (policy 10000 geoip boundary)")
	}
	if securityEventsIsCrawlerSpoofRule("850000") {
		t.Fatal("850000 must not be classified as a crawler spoof id (no policy 0)")
	}
}
