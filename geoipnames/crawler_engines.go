// Package geoipnames —— 搜索引擎爬虫注册表（v2.3.8 地域拦截爬虫豁免）。
// 单源供两端消费：caddygeoip（UA 匹配 + PTR 双跳验证器）与
// internal/services（豁免规则按引擎生成 @streq 消费）。
//
// 验证语义（防 UA 伪造，2026-10-17 用户裁定方案 B）：
//  1. UA 正则命中引擎 → 2. PTR 反查客户端 IP 且后缀属该引擎域 →
//  3. 正向回验 PTR 域名解析包含客户端 IP。任一失败 = fail-closed（维持拦截）。
package geoipnames

import (
	"regexp"
	"strings"
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
	// UARegex 匹配（预编译，大小写不敏感）。只读：注册表共享同一 *Regexp，
	// 禁止调用变异方法（Longest 等）——会改全局匹配语义。
	UARegex *regexp.Regexp
	// SpoofUARegex 是「伪装证据」的 UA 加严门：UA 只命中宽标记（厂商品牌串/
	// 对话式标记，如裸 DeepSeek、ChatGPT-User）不足以单独判定伪装——这类
	// 标记会出现在普通浏览器或第三方工具 UA 里，据此发射伪装头会制造大量
	// 伪安全事件。Spoof 结论只有在 UA 同时命中本门时才作为证据（Verified
	// 路径不受影响：PTR 双跳已自证）。nil = 该引擎的 UA 标记本身就是厂商
	// 专有爬虫 token，无需加严。不变量：非 nil 时必须 ⊆ UARegex 的匹配面。
	SpoofUARegex *regexp.Regexp
	// VerifyMethod 验证方式：ptr（默认，双跳反查）/ iprange（官方声明
	// 不支持 nslookup 的厂商，如 360，用官方公布 IP 段）。
	VerifyMethod string
	// PTRSuffixes 该引擎官方爬虫出口 IP 的 PTR 域名后缀（小写）。
	PTRSuffixes []string
	// IPRanges 该引擎官方公布的 CIDR 段（Ruling：保留为**唯一权威
	// 数据源**——运行期 360 验证走 crawler-ip-lists.json 快照，而快照内容由
	// crawler_seed_parity_test 断言必须落在本字段声明的段内，二者不得分叉）。
	// 消费面绑定 VerifyMethod：仅 iprange 引擎（当前只有 so360spider）读运行
	// 快照名单判定；PTR 引擎名单快照仅作展示/存档，不参与验证（改动此处前先
	// 确认验证器分支，避免把名单误当 PTR 引擎的判定依据）。
	IPRanges []string
}

// 引擎验证方式常量（未使用的 CrawlerVerifyPTR 已删除——空串即默认
// PTR 双跳验证）。
const CrawlerVerifyIPRange = "iprange"

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
		ID:   "sogouspider",
		Name: "搜狗",
		// 官方 UA 以空格分隔（"Sogou web spider/4.0"、"Sogou inst spider/4.0"），
		// 仅历史上少数变体用 "+" 分隔；两种分隔符都允许，无分隔的垃圾串不认。
		UARegex:     regexp.MustCompile(`(?i)Sogou[\s+]+(?:web[\s+]+|inst[\s+]+)?spider`),
		PTRSuffixes: []string{".sogou.com"},
	},
	{
		ID:      "so360spider",
		Name:    "360",
		UARegex: regexp.MustCompile(`(?i)360Spider`),
		// 官方声明不支持 nslookup（so.com/help/spider_ip.html）——IP 段验证；
		// 段=官方公布全表归纳（42.236.10-15.x 归纳为 /21，含表外少量同段位；
		// 历史补齐 17.* / 101.* / 180.153.236.*）
		VerifyMethod: CrawlerVerifyIPRange,
		IPRanges:     []string{"42.236.8.0/21", "42.236.17.0/24", "42.236.101.0/24", "180.153.236.0/24", "180.163.220.0/24"},
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
		// ChatGPT-User 是对话式标记（用户触发的浏览请求），不是爬虫出口
		// 自证；伪装证据只认官方爬虫 token。
		SpoofUARegex: regexp.MustCompile(`(?i)GPTBot|OAI-SearchBot`),
	},
	{
		ID:          "deepseekbot",
		Name:        "DeepSeek（观察级，无官方爬虫页）",
		UARegex:     regexp.MustCompile(`(?i)DeepSeekBot|DeepSeek`),
		PTRSuffixes: []string{".deepseek.com"},
		// 裸品牌串 DeepSeek 出现在普通 UA 中不构成伪装证据。
		SpoofUARegex: regexp.MustCompile(`(?i)DeepSeekBot`),
	},
	{
		ID:          "claudebot",
		Name:        "Anthropic Claude",
		UARegex:     regexp.MustCompile(`(?i)ClaudeBot|Claude-SearchBot|Claude-User|Claude-Web|anthropic-ai`),
		PTRSuffixes: []string{".anthropic.com", ".claude.ai"},
		// Claude-Web 已停用、anthropic-ai 是通用 SDK/库标记：仅作 UA 匹配面
		// （Verified 路径不受影响），伪装证据只认现行官方爬虫 token。
		SpoofUARegex: regexp.MustCompile(`(?i)ClaudeBot|Claude-SearchBot|Claude-User`),
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

// CrawlerSpoofEvidence 判定 Spoof 结论能否作为伪装证据发射：引擎已注册加严门
// 时，UA 还必须命中该门（宽品牌标记/对话式标记单独命中不算证据）；未注册
// 加严门的引擎（UA 标记本身即厂商专有爬虫 token）恒为证据。未知引擎返回
// false——调用方只在 MatchCrawlerEngine 命中后询问，未知值表示调用方传错。
func CrawlerSpoofEvidence(engineID, userAgent string) bool {
	for _, e := range crawlerEngines {
		if e.ID != engineID {
			continue
		}
		if e.SpoofUARegex == nil {
			return true
		}
		return e.SpoofUARegex.MatchString(userAgent)
	}
	return false
}

// CrawlerEngines 返回引擎注册表的**深拷贝**（防调用方篡改全局）：结构体与
// 其中的 PTRSuffixes/IPRanges 切片都重新分配——只复制结构体的浅拷贝会让
// out[i].PTRSuffixes[j] = … 写穿到全局注册表。
//
// 例外（只读契约）：UARegex/SpoofUARegex 两个 *regexp.Regexp 指针与全局
// 注册表**共享**（正则不可变数据，按值复制无意义）。调用方**禁止**对返回值
// 调变异方法（Longest 等）——那会改变全局匹配语义，让所有规则的爬虫豁免/
// 伪装证据判定口径被静默改写且无任何测试会红。需要匹配请用包内
// MatchCrawlerEngine / crawlerUAPrefilter。
func CrawlerEngines() []CrawlerEngine {
	out := make([]CrawlerEngine, len(crawlerEngines))
	for i := range crawlerEngines {
		out[i] = crawlerEngines[i]
		if s := crawlerEngines[i].PTRSuffixes; s != nil {
			out[i].PTRSuffixes = append([]string(nil), s...)
		}
		if r := crawlerEngines[i].IPRanges; r != nil {
			out[i].IPRanges = append([]string(nil), r...)
		}
	}
	return out
}

// crawlerUAPrefilter 是全部引擎 UA 正则的合并交替式（init 时由注册表**单源**
// 派生）：非爬虫 UA 一次匹配即可短路，免去逐引擎 N 次 MatchString。它只回答
// 「是否有任一引擎可能命中」，命中后仍走逐引擎顺序匹配取引擎 ID（首个命中
// 语义不变，与逐条匹配逐字节等价）。
//
// 不能用字面子串预筛（bot|spider|crawl 之类）：注册表里有裸 DeepSeek、
// ChatGPT-User、Claude-Web、anthropic-ai 等不含
// spider/bot 字样的标记，字面预筛会把这些引擎整族漏掉。
var crawlerUAPrefilter = buildCrawlerUAPrefilter()

// buildCrawlerUAPrefilter 从注册表派生合并交替式：每条引擎正则自带 (?i)，
// 这里整体再包一层 (?i) 并逐条加非捕获组，保证交替式与逐条匹配同语义
// （注册表是唯一数据源，新增引擎自动进入预筛）。
func buildCrawlerUAPrefilter() *regexp.Regexp {
	patterns := make([]string, 0, len(crawlerEngines))
	for i := range crawlerEngines {
		patterns = append(patterns, "(?:"+crawlerEngines[i].UARegex.String()+")")
	}
	return regexp.MustCompile("(?i)" + strings.Join(patterns, "|"))
}

// crawlerUAMaxLen 是参与引擎匹配的 UA 长度上限：真实 UA 远小于此（注册表
// 全部样例 <200B），超长 UA 只可能是攻击者在启用爬虫豁免的规则上灌入的
// ~1MB 头部——合并交替正则是 O(len) 线性扫描，每请求成本随头部线性放大。
// 超限一律判未命中（不豁免、不判伪装；安全方向=不因爬虫标记放行）。
const crawlerUAMaxLen = 512

// MatchCrawlerEngine UA → 引擎 ID（未命中返回空串）。
func MatchCrawlerEngine(userAgent string) string {
	if len(userAgent) > crawlerUAMaxLen {
		return ""
	}
	// 预筛：绝大多数流量不是爬虫，单次合并匹配即可判定未命中。
	if !crawlerUAPrefilter.MatchString(userAgent) {
		return ""
	}
	for _, e := range crawlerEngines {
		if e.UARegex.MatchString(userAgent) {
			return e.ID
		}
	}
	return ""
}

// CrawlerEnginePTRMatch 引擎 ID + PTR 域名 → 后缀是否属该引擎官方域。
func CrawlerEnginePTRMatch(engineID, ptrName string) bool {
	// FQDN 尾点容忍（库层单源：消费方虽已剥尾点，直接调用不得因尾点失效）。
	ptrName = strings.TrimRight(ptrName, ".")
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

// DefaultCrawlerEngines 返回向导默认勾选集（主流 SEO 场景：
// Google/Bing/百度）的新副本——默认值不对外暴露可变切片，消费方就地排序/追加
// 不会污染全局默认。
func DefaultCrawlerEngines() []string {
	return append([]string(nil), defaultCrawlerEngines...)
}

var defaultCrawlerEngines = []string{"googlebot", "bingbot", "baiduspider"}
