package geoipnames

import (
	"net/netip"
	"strings"
	"testing"
)

// officialUAs 每引擎一条官方 UA fixture（来源=各厂商官方爬虫文档）。
// Sogou 正则此前只允许 `+` 分隔（官方 UA 是空格分隔）→「搜狗」豁免静默失效；
// 注册表无「每引擎一条官方 UA」合集断言，同族 bug 无绊线。本表与
// 注册表一一对应——新增引擎不补 fixture 即跳红。
var officialUAs = map[string]string{
	"googlebot":     "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"bingbot":       "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"baiduspider":   "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
	"sogouspider":   "Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)",
	"so360spider":   "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36; 360Spider",
	"yisouspider":   "Mozilla/5.0 (compatible; YisouSpider/1.0; +http://www.shenma.com/spider.html)",
	"petalbot":      "Mozilla/5.0 (compatible; PetalBot; +https://webmaster.petalsearch.com/site/petalbot)",
	"duckduckbot":   "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
	"yandexbot":     "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
	"gptbot":        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
	"deepseekbot":   "Mozilla/5.0 (compatible; DeepSeekBot/1.0)",
	"claudebot":     "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
	"perplexitybot": "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
	"kimisearchbot": "Kimi-SearchBot/1.0",
	"bytespider":    "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)",
}

// 搜狗官方 UA 形状（空格分隔，以及历史上少数 `+` 分隔变体）必须命中；
// 无分隔的垃圾串不再视为爬虫。
func TestMatchCrawlerEngine_sogouOfficialUAs(t *testing.T) {
	for _, ua := range []string{
		"Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)",
		"Sogou inst spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)",
		"Mozilla/5.0 (compatible; Sogou web spider/4.0; +http://www.sogou.com/docs/help/webmasters.htm#07)",
		"Sogou spider",
		"Sogou+web+spider",
		"sogou WEB spider/4.0",
	} {
		if got := MatchCrawlerEngine(ua); got != "sogouspider" {
			t.Errorf("MatchCrawlerEngine(%q)=%q, want sogouspider", ua, got)
		}
	}
	for _, ua := range []string{"Sogouwebspider", "Mozilla/5.0 Sogou", "SogouBot/1.0"} {
		if got := MatchCrawlerEngine(ua); got != "" {
			t.Errorf("MatchCrawlerEngine(%q)=%q, want \"\"（非官方 UA 形状）", ua, got)
		}
	}
}

// 注册表结构不变量——ID 唯一/非空、UARegex 非 nil、每条官方 UA
// fixture 命中且只命中本引擎、PTR 后缀以 "." 开头（防 evilgooglebot.com
// 类后缀误命中）、iprange 引擎必须有可解析 IP 段、ptr 引擎必须有后缀。
func TestCrawlerEngines_registryInvariants(t *testing.T) {
	engines := CrawlerEngines()
	seen := make(map[string]bool, len(engines))
	for _, e := range engines {
		if e.ID == "" {
			t.Error("引擎 ID 不得为空")
		}
		if seen[e.ID] {
			t.Errorf("引擎 ID 重复: %q（CrawlerEngineVerifyMethod/ValidCrawlerEngineID 语义歧义）", e.ID)
		}
		seen[e.ID] = true
		if e.Name == "" {
			t.Errorf("%s: Name 不得为空", e.ID)
		}
		if e.UARegex == nil {
			t.Errorf("%s: UARegex 不得为 nil", e.ID)
		}
		for _, suf := range e.PTRSuffixes {
			if !strings.HasPrefix(suf, ".") {
				t.Errorf("%s: PTR 后缀 %q 必须以 \".\" 开头（否则 evil<domain> 误命中）", e.ID, suf)
			}
			if suf != strings.ToLower(suf) {
				t.Errorf("%s: PTR 后缀 %q 必须为小写（匹配器小写化后比较）", e.ID, suf)
			}
		}
		switch e.VerifyMethod {
		case "":
			if len(e.PTRSuffixes) == 0 {
				t.Errorf("%s: ptr 验证引擎必须声明 PTRSuffixes", e.ID)
			}
		case CrawlerVerifyIPRange:
			if len(e.IPRanges) == 0 {
				t.Errorf("%s: iprange 验证引擎必须声明 IPRanges", e.ID)
			}
			for _, cidr := range e.IPRanges {
				if p, err := netip.ParsePrefix(cidr); err != nil || !p.Addr().Is4() {
					t.Errorf("%s: IPRanges 条目 %q 非法: %v", e.ID, cidr, err)
				}
			}
		default:
			t.Errorf("%s: 未知 VerifyMethod %q", e.ID, e.VerifyMethod)
		}

		ua, ok := officialUAs[e.ID]
		if !ok {
			t.Errorf("%s: 缺官方 UA fixture（officialUAs 须与注册表一一对应）", e.ID)
			continue
		}
		if got := MatchCrawlerEngine(ua); got != e.ID {
			t.Errorf("官方 UA %q 命中 %q, want %q", ua, got, e.ID)
		}
	}
	for id := range officialUAs {
		if !seen[id] {
			t.Errorf("fixture %q 无对应引擎（注册表删引擎须同步删 fixture）", id)
		}
	}
	for _, id := range DefaultCrawlerEngines() {
		if !ValidCrawlerEngineID(id) {
			t.Errorf("DefaultCrawlerEngines 含非法 ID %q", id)
		}
	}
}

// PTR 后缀锚定 + FQDN 尾点容忍（消费方会剥尾点，库层亦不应因尾点
// 失效）；空串、根域、无主机标签、跨引擎后缀全部不命中。
func TestCrawlerEnginePTRMatch_anchoringAndTrailingDot(t *testing.T) {
	cases := []struct {
		engine string
		ptr    string
		want   bool
	}{
		{"googlebot", "crawl-66-249-66-1.googlebot.com", true},
		{"googlebot", "crawl-66-249-66-1.googlebot.com.", true}, // FQDN 尾点
		{"googlebot", "CRAWL-66-249-66-1.GOOGLEBOT.COM", true},  // 大小写
		{"googlebot", "evilgooglebot.com", false},               // 无点边界
		{"googlebot", "googlebot.com", false},                   // 无主机标签
		{"googlebot", ".googlebot.com", false},
		{"googlebot", "", false},
		{"googlebot", "x.googlebot.com.evil.attacker.tld", false}, // 必须锚定尾部
		{"bingbot", "crawl-66-249-66-1.googlebot.com", false},     // 跨引擎
		{"nope", "x.googlebot.com", false},                        // 未知引擎
	}
	for _, tc := range cases {
		if got := CrawlerEnginePTRMatch(tc.engine, tc.ptr); got != tc.want {
			t.Errorf("CrawlerEnginePTRMatch(%q,%q)=%v, want %v", tc.engine, tc.ptr, got, tc.want)
		}
	}
}

// CrawlerEngines 的「副本」必须深拷贝（裸 copy 只复制结构体，
// PTRSuffixes/IPRanges 仍共享底层数组——out[i].PTRSuffixes[0]=… 会写穿全局）。
func TestCrawlerEngines_returnsDeepCopy(t *testing.T) {
	first := CrawlerEngines()
	for i := range first {
		if first[i].UARegex == crawlerEngines[i].UARegex {
			t.Fatalf("engine %q UARegex 仍与全局注册表共享指针", first[i].ID)
		}
		if first[i].SpoofUARegex != nil && first[i].SpoofUARegex == crawlerEngines[i].SpoofUARegex {
			t.Fatalf("engine %q SpoofUARegex 仍与全局注册表共享指针", first[i].ID)
		}
		first[i].UARegex.Longest()
		if first[i].SpoofUARegex != nil {
			first[i].SpoofUARegex.Longest()
		}
		if len(first[i].PTRSuffixes) > 0 {
			first[i].PTRSuffixes[0] = ".evil.example"
		}
		if len(first[i].IPRanges) > 0 {
			first[i].IPRanges[0] = "0.0.0.0/0"
		}
		first[i].ID = "tampered"
	}
	if !CrawlerEnginePTRMatch("googlebot", "crawl-1.googlebot.com") {
		t.Fatal("调用方改写返回切片写穿了全局注册表（PTRSuffixes 未深拷贝）")
	}
	if ValidCrawlerEngineID("tampered") {
		t.Fatal("调用方改写返回结构体写穿了全局注册表")
	}
	for _, e := range CrawlerEngines() {
		if e.ID == "so360spider" && e.IPRanges[0] != "42.236.8.0/21" {
			t.Fatalf("调用方改写 IPRanges 写穿了全局注册表: %v", e.IPRanges)
		}
	}
}

// 省/市规范化的表驱动语义单源（geoipnames）——选项树（tree）与
// 发射（emit）两端共用同一 core，策略差异仅在两端显式声明处。此前
// internal/services 与 caddygeoip 各持一份手工镜像，语义分叉靠调用点补偿。
func TestNormalizeRegion_singleSourceSemantics(t *testing.T) {
	provinceCases := []struct {
		raw        string
		tree, emit string
	}{
		{"", "", ""},
		{"0", "", ""},
		{"  0  ", "", ""},
		{"上海", "上海市", "上海市"},
		{"上海市", "上海市", "上海市"},
		{"广西", "广西壮族自治区", "广西壮族自治区"},
		{"UEruemqi", "新疆维吾尔自治区", "新疆维吾尔自治区"}, // 别名命中 → ASCII 回收
		{"台中市", "", "台湾省"},                   // 台湾城市：树侧归并、发射侧补省
		{" 台北市 ", "", "台湾省"},
		{"Guangdong", "", "Guangdong"}, // 未映射 ASCII：树侧过滤、发射侧原样（恒不命中）
		{"广东", "广东", "广东"},
	}
	for _, tc := range provinceCases {
		if got := ProvinceForTree(tc.raw); got != tc.tree {
			t.Errorf("ProvinceForTree(%q)=%q, want %q", tc.raw, got, tc.tree)
		}
		if got := ProvinceForEmit(tc.raw); got != tc.emit {
			t.Errorf("ProvinceForEmit(%q)=%q, want %q", tc.raw, got, tc.emit)
		}
	}

	cityCases := []struct {
		raw        string
		tree, emit string
	}{
		{"", "", ""},
		{"0", "", ""},
		{"Wulumuqi", "乌鲁木齐市", "乌鲁木齐市"},
		{"Guangzhou Shi", "广州市", "广州市"},
		{"大理", "大理白族自治州", "大理白族自治州"},
		{"UnknownCity", "", "UnknownCity"}, // 未映射 ASCII：树侧过滤、发射侧原样
		{"广州市", "广州市", "广州市"},
	}
	for _, tc := range cityCases {
		if got := CityForTree(tc.raw); got != tc.tree {
			t.Errorf("CityForTree(%q)=%q, want %q", tc.raw, got, tc.tree)
		}
		if got := CityForEmit(tc.raw); got != tc.emit {
			t.Errorf("CityForEmit(%q)=%q, want %q", tc.raw, got, tc.emit)
		}
	}
}
