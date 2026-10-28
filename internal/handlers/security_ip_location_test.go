package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/geoipnames"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

func TestFormatIP2RegionLocation(t *testing.T) {
	cases := []struct {
		name   string
		region string
		want   string
	}{
		{"full china region", "中国|广东省|深圳市|电信|CN", "中国·广东·深圳·电信"},
		{"municipality", "中国|北京市|北京市|联通|CN", "中国·北京·北京·联通"},
		{"autonomous region", "中国|广西壮族自治区|南宁市|电信|CN", "中国·广西·南宁·电信"},
		{"sar no isp", "中国|香港特别行政区|九龙|0|CN", "中国·香港·九龙"},
		{"province only", "中国|山东省|0|0|CN", "中国·山东"},
		{"unknown province city", "中国|0|0|0|CN", "中国"},
		{"overseas country only", "美国|0|0|0|US", "美国"},
		{"overseas with region and idc", "United States|California|0|Google LLC|US", "美国·California·Google LLC"},
		{"overseas with city and idc", "Australia|Queensland|Brisbane|Cloudflare|AU", "澳大利亚·Queensland·Brisbane·Cloudflare"},
		{"overseas full shape", "Japan|Tokyo|Shibuya|NTT|JP", "日本·Tokyo·Shibuya·NTT"},
		// 未收录国名回退原名（CountryChinese 兜底语义——未来 xdb 新增国名
		// 优雅降级英文，不产生死条目/空段）。
		{"overseas unmapped fallback", "Xanadu|Region|City|0|XX", "Xanadu·Region·City"},
		{"reserved v4 from xdb", "Reserved|Reserved|Reserved|0|0", "保留地址"},
		{"unknown region", "0|0|0|0|0", ""},
		{"empty", "", ""},
		{"too few fields", "中国|广东省", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatIP2RegionLocation(tc.region); got != tc.want {
				t.Fatalf("formatIP2RegionLocation(%q)=%q, want %q", tc.region, got, tc.want)
			}
		})
	}
}

func TestEnrichIPLocation_reservedIPs(t *testing.T) {
	// Given: 保留/私网/回环地址(含 IPv6——xdb 仅 IPv4,靠 net.ParseIP 前置拦截)
	for _, ip := range []string{"::1", "127.0.0.1", "192.168.1.1", "10.0.0.1", "169.254.1.1", "fe80::1", "0.0.0.0", "0.0.0.1", "100.64.0.1", "192.0.0.1", "198.18.0.1", "224.0.0.1", "240.0.0.1", "2001:db8::1", "ff02::1",
		// RFC 5737 文档示例段——公网不可路由，与私网同待遇（事件富化/大屏
		// 排除/封禁建议富化/活跃源计数同源生效）。
		"192.0.2.1", "198.51.100.1", "203.0.113.1"} {
		// When: 归属地富化
		got := enrichIPLocation(ip)
		// Then: 识别为保留地址
		if got != "保留地址" {
			t.Fatalf("enrichIPLocation(%q)=%q, want 保留地址", ip, got)
		}
	}
}

func TestThreatLocationParts_reservedIsNotCountry(t *testing.T) {
	country, province := threatLocationParts("保留地址")
	if country != "" || province != "" {
		t.Fatalf("reserved location must not aggregate as a country: (%q,%q)", country, province)
	}
}

// zone 形态 IPv6(fe80::1%eth0)netip 接受但 coraza
// @ipMatch 静默丢弃——validIPOrCIDR 必须拒绝,防零留痕落库。
func TestValidIPOrCIDR_rejectsZoneForm(t *testing.T) {
	if validIPOrCIDR("fe80::1%eth0") {
		t.Fatal("zone-form IPv6 must be rejected (coraza @ipMatch silently drops)")
	}
	if !validIPOrCIDR("fe80::1") {
		t.Fatal("plain IPv6 fe80::1 must be accepted")
	}
	if !validIPOrCIDR("192.168.1.1") {
		t.Fatal("IPv4 must be accepted")
	}
	if !validIPOrCIDR("10.0.0.0/8") {
		t.Fatal("CIDR must be accepted")
	}
}

func TestEnrichIPLocation_emptyWithoutDatabaseNeverErrors(t *testing.T) {
	// Given: no xdb loaded (test process never installs one)
	// When / Then: lookups degrade to "" instead of failing
	if got := enrichIPLocation("93.184.216.1"); got != "" {
		t.Fatalf("enrichIPLocation without xdb=%q, want empty", got)
	}
	if got := enrichIPLocation(""); got != "" {
		t.Fatalf("enrichIPLocation(empty ip)=%q, want empty", got)
	}
}

// v2.3.7 修正：GetIP2RegionRegions 响应携带 country_names_cn——海外国家英文→
// 中文映射（单源 geoipnames.CountryNamesCN 全表透传），前端级联「海外国家」
// 子节点中文标签依赖此字段；provinces/cities/countries 旧形态不变（存量消费
// 方零破坏，前端对缺失字段回退英文标签）。
func TestGetIP2RegionRegions_carriesCountryNamesCN(t *testing.T) {
	// Given：无 xdb 环境（树兜底形态）——zh 映射是二进制静态表，不随库装载
	// 状态缺席，任何形态都必须在场
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/security/ip2region/regions", nil)

	// When
	h.GetIP2RegionRegions(c)

	// Then：envelope 内 countries 仍是字符串数组（旧形态），country_names_cn
	// 并行在场且代表性映射正确
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Countries      []string          `json:"countries"`
			CountryNamesCN map[string]string `json:"country_names_cn"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal regions response: %v", err)
	}
	if resp.Data.CountryNamesCN == nil {
		t.Fatal("country_names_cn missing——前端海外国家中文标签将整体回退英文")
	}
	for en, want := range map[string]string{"United States": "美国", "Japan": "日本", "Russia": "俄罗斯"} {
		if got := resp.Data.CountryNamesCN[en]; got != want {
			t.Errorf("country_names_cn[%q]=%q; want %q", en, got, want)
		}
	}
	if len(resp.Data.CountryNamesCN) != len(geoipnames.CountryNamesCN) {
		t.Errorf("country_names_cn entries=%d; want %d（单源全表透传，不得截断）", len(resp.Data.CountryNamesCN), len(geoipnames.CountryNamesCN))
	}
}

func TestListSecurityEvents_carriesIPLocationField(t *testing.T) {
	// Given: one seeded event (no xdb in tests → location stays empty, never 500)
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	seedSecurityEvent(t, "2026-08-12 10:00:01", "lb_loc1", 1, "942100", "SQL Injection")

	// When
	recorder := getRequest(t, router, "/security/events")

	// Then: the response carries an ip_location field on every event
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Events []struct {
				ClientIP   string `json:"client_ip"`
				IPLocation string `json:"ip_location"`
			} `json:"events"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Data.Events) != 1 {
		t.Fatalf("events = %s", recorder.Body.String())
	}
	if resp.Data.Events[0].ClientIP != "185.199.109.9" || resp.Data.Events[0].IPLocation != "" {
		t.Fatalf("event ip/ip_location = %q/%q, want 185.199.109.9/\"\" without xdb", resp.Data.Events[0].ClientIP, resp.Data.Events[0].IPLocation)
	}
}

func TestGetSecurityOverview_topIPsCarryIPLocationField(t *testing.T) {
	// Given: one recent event feeding the table
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	seedSecurityEvent(t, time.Now().UTC().Format("2006-01-02 15:04:05"), "lb_loc2", 1, "942100", "SQL Injection")

	// When
	recorder := getRequest(t, router, "/security/overview")

	// Then: every top_ips entry carries ip_location (empty without xdb, never 500)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			TopIPs []struct {
				IP         string `json:"ip"`
				IPLocation string `json:"ip_location"`
			} `json:"top_ips"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Data.TopIPs) != 1 {
		t.Fatalf("top_ips = %s", recorder.Body.String())
	}
	if resp.Data.TopIPs[0].IP != "185.199.109.9" || resp.Data.TopIPs[0].IPLocation != "" {
		t.Fatalf("top ip/ip_location = %q/%q, want 185.199.109.9/\"\" without xdb", resp.Data.TopIPs[0].IP, resp.Data.TopIPs[0].IPLocation)
	}
}

// ListSecurityPolicies 的 rule_caddy_id 过滤按绑定表筛出该规则绑定的
// 策略（IP 归属地弹窗按当前规则收敛可选策略列表所依赖的口径）。
func TestListSecurityPolicies_ruleCaddyIDFilter(t *testing.T) {
	// Given：两条启用策略，仅甲绑定到规则 lb_filter1
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, enabled) VALUES ('过滤甲', 1), ('过滤乙', 1)`); err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) SELECT 'lb_filter1', id FROM security_policies WHERE name='过滤甲'`); err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	// When：按 rule_caddy_id 过滤
	recorder := getRequest(t, router, "/security/policies?rule_caddy_id=lb_filter1")

	// Then：仅返回绑定的策略
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Data) != 1 || resp.Data[0].Name != "过滤甲" {
		t.Fatalf("policies = %s, want only 过滤甲", recorder.Body.String())
	}

	// And：未绑定任何策略的规则返回空列表
	empty := getRequest(t, router, "/security/policies?rule_caddy_id=lb_nobind")
	var emptyResp struct {
		Code int `json:"code"`
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(empty.Body.Bytes(), &emptyResp); err != nil {
		t.Fatalf("parse empty response: %v", err)
	}
	if len(emptyResp.Data) != 0 {
		t.Fatalf("unbound rule policies = %s, want empty", empty.Body.String())
	}
}

func TestListSecurityPolicies_enabledFilter(t *testing.T) {
	// Given: one enabled and one disabled policy
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, enabled) VALUES ('启用策略', 1), ('禁用策略', 0)`); err != nil {
		t.Fatalf("seed policies: %v", err)
	}

	// When: listing with enabled=true
	recorder := getRequest(t, router, "/security/policies?enabled=true")

	// Then: only the enabled policy is returned
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Data) != 1 || resp.Data[0].Name != "启用策略" || !resp.Data[0].Enabled {
		t.Fatalf("policies = %s, want only 启用策略", recorder.Body.String())
	}

	// And: without the flag both come back (backwards compatible)
	all := getRequest(t, router, "/security/policies")
	var allResp struct {
		Code int `json:"code"`
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(all.Body.Bytes(), &allResp); err != nil {
		t.Fatalf("parse all response: %v", err)
	}
	if len(allResp.Data) != 2 {
		t.Fatalf("policies without filter = %s, want both", all.Body.String())
	}
}

// 归属地富化缓存：同一 IP 重复富化只查一次库（大屏逐行富化同一批攻击源
// IP）；xdb 代际变化（库热换/重置）后旧值失效重查。
func TestEnrichIPLocation_cachesPerIPUntilGenerationChange(t *testing.T) {
	old := enrichIPLocationLookup
	calls := 0
	enrichIPLocationLookup = func(string) string {
		calls++
		return "美国|0|0|0|US"
	}
	t.Cleanup(func() { enrichIPLocationLookup = old })
	enrichLocationCache.Lock()
	enrichLocationCache.entries = make(map[string]enrichLocationCacheEntry)
	enrichLocationCache.Unlock()
	t.Cleanup(func() {
		enrichLocationCache.Lock()
		enrichLocationCache.entries = make(map[string]enrichLocationCacheEntry)
		enrichLocationCache.Unlock()
	})

	const ip = "93.184.216.77"
	if got := enrichIPLocation(ip); got != "美国" {
		t.Fatalf("enrichIPLocation=%q, want 美国", got)
	}
	if got := enrichIPLocation(ip); got != "美国" {
		t.Fatalf("enrichIPLocation(2nd)=%q, want 美国", got)
	}
	if calls != 1 {
		t.Fatalf("lookup calls=%d, want 1（同 IP 缓存命中，不再逐行查库）", calls)
	}
	// 代际变化（searcher 重置/热换）后必须重查——旧库归属地不得脏读。
	services.ResetIP2RegionSearcherForTest()
	if got := enrichIPLocation(ip); got != "美国" {
		t.Fatalf("enrichIPLocation(after generation change)=%q, want 美国", got)
	}
	if calls != 2 {
		t.Fatalf("lookup calls=%d, want 2（代际变化后缓存失效）", calls)
	}
}
