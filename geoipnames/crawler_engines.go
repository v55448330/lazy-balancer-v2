// Package geoipnames —— 搜索引擎爬虫注册表（v2.3.8 地域拦截爬虫豁免）。
// 单源供两端消费：caddygeoip（UA 匹配 + PTR 双跳验证器）与
// internal/services（豁免规则按引擎生成 @streq 消费）。
//
// 验证语义（防 UA 伪造，2026-10-17 用户裁定方案 B）：
//  1. UA 正则命中引擎 → 2. PTR 反查客户端 IP 且后缀属该引擎域 →
//  3. 正向回验 PTR 域名解析包含客户端 IP。任一失败 = fail-closed（维持拦截）。
package geoipnames

import (
	"net"
	"regexp"
)

// CrawlerEngine 搜索引擎爬虫定义。UA/PTR/IP 段来源=各厂商官方文档
// （2026-10-17 逐家核实：Google developers.google.com、OpenAI openai.com/
// gptbot.json、Anthropic claude.com/crawling/bots.json、Perplexity
// perplexity.ai/perplexitybot.json、字节 zhanzhang.toutiao.com（PTR=*.byted.org）、
// 360 so.com/help/spider_ip.html（官方声明不支持 nslookup→IP 段验证）、
// Kimi kimi.ai/policies/kimi-crawlers）。无官方爬虫页的厂商（DeepSeek/
// PetalBot）按厂商域名验证并在 Name 标注「观察级」。
type CrawlerEngine struct {
	// ID 引擎标识（X-LB-Crawler-Verified 头值 + 规则 @streq 消费值；
	// 稳定字符串，勿改动——已入库策略的 geoip_crawler_engines 引用此值）。
	ID string
	// Name 中文展示名（策略向导勾选组）。
	Name string
	// UARegex User-Agent 匹配（预编译，大小写不敏感）。
	UARegex *regexp.Regexp
	// VerifyMethod 验证方式：ptr（默认，双跳反查）/ iprange（官方声明
	// 不支持 nslookup 的厂商，如 360，用官方公布 IP 段）。
	VerifyMethod string
	// PTRSuffixes 该引擎官方爬虫出口 IP 的 PTR 域名后缀（小写）。
	PTRSuffixes []string
	// IPRanges VerifyMethod=iprange 时的官方 CIDR 段。
	IPRanges []string
}

// 引擎验证方式常量。
const (
	CrawlerVerifyPTR     = "ptr"
	CrawlerVerifyIPRange = "iprange"
)

// crawlerEngines 引擎注册表（顺序=向导展示顺序）。
var crawlerEngines = []CrawlerEngine{
	{
		ID:          "googlebot",
		Name:        "Google",
		UARegex:     regexp.MustCompile(`(?i)Googlebot`),
		PTRSuffixes: []string{".googlebot.com", ".google.com"},
	},
	{
		ID:          "bingbot",
		Name:        "Bing",
		UARegex:     regexp.MustCompile(`(?i)bingbot`),
		PTRSuffixes: []string{".search.msn.com"},
	},
	{
		ID:          "baiduspider",
		Name:        "百度",
		UARegex:     regexp.MustCompile(`(?i)Baiduspider`),
		PTRSuffixes: []string{".crawl.baidu.com", ".baidu.com"},
	},
	{
		ID:          "sogouspider",
		Name:        "搜狗",
		UARegex:     regexp.MustCompile(`(?i)Sogou\+?(web|inst)?\+?spider`),
		PTRSuffixes: []string{".sogou.com"},
	},
	{
		ID:      "so360spider",
		Name:    "360",
		UARegex: regexp.MustCompile(`(?i)360Spider`),
		// 官方声明不支持 nslookup（so.com/help/spider_ip.html）——IP 段验证；
		// 段=官方公布全表归纳（42.236.10-15.x 归纳为 /21，含表外少量同段位）
		VerifyMethod: CrawlerVerifyIPRange,
		IPRanges:     []string{"42.236.8.0/21", "180.163.220.0/24"},
	},
	{
		ID:          "yisouspider",
		Name:        "神马",
		UARegex:     regexp.MustCompile(`(?i)YisouSpider`),
		PTRSuffixes: []string{".shenma.cn"},
	},
	{
		ID:          "petalbot",
		Name:        "华为 PetalBot（观察级）",
		UARegex:     regexp.MustCompile(`(?i)PetalBot`),
		PTRSuffixes: []string{".petalbot.com"},
	},
	{
		ID:          "duckduckbot",
		Name:        "DuckDuckGo",
		UARegex:     regexp.MustCompile(`(?i)DuckDuckBot|DuckDuckGo-Favicons-Bot`),
		PTRSuffixes: []string{".duckduckgo.com"},
	},
	{
		ID:          "yandexbot",
		Name:        "Yandex",
		UARegex:     regexp.MustCompile(`(?i)YandexBot`),
		PTRSuffixes: []string{".yandex.com", ".yandex.ru"},
	},
	// ---- AI 企业爬虫（2026-10-17 用户裁定增补；默认不勾选，用户按需启用） ----
	{
		ID:          "gptbot",
		Name:        "OpenAI（GPTBot/OAI-SearchBot）",
		UARegex:     regexp.MustCompile(`(?i)GPTBot|OAI-SearchBot|ChatGPT-User`),
		PTRSuffixes: []string{".openai.com"},
	},
	{
		ID:          "deepseekbot",
		Name:        "DeepSeek（观察级，无官方爬虫页）",
		UARegex:     regexp.MustCompile(`(?i)DeepSeekBot|DeepSeek`),
		PTRSuffixes: []string{".deepseek.com"},
	},
	{
		ID:          "claudebot",
		Name:        "Anthropic Claude",
		UARegex:     regexp.MustCompile(`(?i)ClaudeBot|Claude-SearchBot|Claude-User|Claude-Web|anthropic-ai`),
		PTRSuffixes: []string{".anthropic.com", ".claude.ai"},
	},
	{
		ID:          "perplexitybot",
		Name:        "Perplexity",
		UARegex:     regexp.MustCompile(`(?i)PerplexityBot|Perplexity-User`),
		PTRSuffixes: []string{".perplexity.ai", ".perplexity.com"},
	},
	{
		ID:          "kimisearchbot",
		Name:        "Kimi（观察级）",
		UARegex:     regexp.MustCompile(`(?i)Kimi-SearchBot`),
		PTRSuffixes: []string{".moonshot.cn", ".moonshot.ai"},
	},
	{
		ID:          "bytespider",
		Name:        "字节 Bytespider",
		UARegex:     regexp.MustCompile(`(?i)Bytespider`),
		PTRSuffixes: []string{".byted.org", ".bytedance.com"},
	},
}

// CrawlerEngines 返回引擎注册表（只读切片副本，防调用方篡改全局）。
func CrawlerEngines() []CrawlerEngine {
	out := make([]CrawlerEngine, len(crawlerEngines))
	copy(out, crawlerEngines)
	return out
}

// MatchCrawlerEngine UA → 引擎 ID（未命中返回空串）。
func MatchCrawlerEngine(userAgent string) string {
	for _, e := range crawlerEngines {
		if e.UARegex.MatchString(userAgent) {
			return e.ID
		}
	}
	return ""
}

// CrawlerEnginePTRMatch 引擎 ID + PTR 域名 → 后缀是否属该引擎官方域。
func CrawlerEnginePTRMatch(engineID, ptrName string) bool {
	if ptrName == "" {
		return false
	}
	// 小写化并右侧补点保证后缀语义（"abc.googlebot.com" 对 ".googlebot.com"）
	n := len(ptrName)
	for i := n - 1; i >= 0; i-- {
		if ptrName[i] >= 'A' && ptrName[i] <= 'Z' {
			lowered := make([]byte, n)
			for j := 0; j < n; j++ {
				c := ptrName[j]
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				lowered[j] = c
			}
			ptrName = string(lowered)
			break
		}
	}
	for _, e := range crawlerEngines {
		if e.ID != engineID {
			continue
		}
		for _, suf := range e.PTRSuffixes {
			if len(ptrName) > len(suf) && ptrName[len(ptrName)-len(suf):] == suf {
				return true
			}
		}
		return false
	}
	return false
}

// CrawlerEngineIPMatch 引擎 ID + IP → 是否落在官方 IP 段（VerifyMethod=
// iprange 的引擎用；解析失败/超界一律 false）。
func CrawlerEngineIPMatch(engineID, ipStr string) bool {
	for _, e := range crawlerEngines {
		if e.ID != engineID || e.VerifyMethod != CrawlerVerifyIPRange {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return false
		}
		for _, cidr := range e.IPRanges {
			if _, network, err := net.ParseCIDR(cidr); err == nil && network.Contains(ip) {
				return true
			}
		}
		return false
	}
	return false
}

// CrawlerEngineVerifyMethod 引擎验证方式（""=默认 ptr）。
func CrawlerEngineVerifyMethod(engineID string) string {
	for _, e := range crawlerEngines {
		if e.ID == engineID {
			return e.VerifyMethod
		}
	}
	return ""
}

// ValidCrawlerEngineID 引擎 ID 是否合法（策略保存校验用）。
func ValidCrawlerEngineID(id string) bool {
	for _, e := range crawlerEngines {
		if e.ID == id {
			return true
		}
	}
	return false
}

// DefaultCrawlerEngines 向导默认勾选（主流 SEO 场景：Google/Bing/百度）。
var DefaultCrawlerEngines = []string{"googlebot", "bingbot", "baiduspider"}
