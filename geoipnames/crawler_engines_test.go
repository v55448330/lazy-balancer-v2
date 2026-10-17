package geoipnames

import "testing"

func TestCrawlerEngines_matchAndVerify(t *testing.T) {
	// Given/When/Then: UA 匹配、PTR 后缀绑定（跨引擎不认）、合法 ID
	cases := []struct {
		ua   string
		want string
	}{
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "googlebot"},
		{"Mozilla/5.0 (compatible; bingbot/2.0)", "bingbot"},
		{"Mozilla/5.0 (compatible; Baiduspider/2.0)", "baiduspider"},
		{"Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)", "gptbot"},
		{"Mozilla/5.0 (compatible; DeepSeekBot/1.0)", "deepseekbot"},
		{"Mozilla/5.0 (compatible; Bytespider)", "bytespider"},
		{"Mozilla/5.0 (Macintosh) Chrome/120.0 Safari", ""},
	}
	for _, c := range cases {
		if got := MatchCrawlerEngine(c.ua); got != c.want {
			t.Errorf("MatchCrawlerEngine(%q)=%q, want %q", c.ua, got, c.want)
		}
	}
	// PTR：本引擎后缀认、跨引擎后缀不认（GCP googleusercontent.com 也不认）
	if !CrawlerEnginePTRMatch("googlebot", "crawl-66-249-66-1.googlebot.com") {
		t.Error("googlebot 官方 PTR 应匹配")
	}
	if CrawlerEnginePTRMatch("googlebot", "xx.bc.googleusercontent.com") {
		t.Error("GCP PTR 不应匹配 googlebot（机房伪装墙）")
	}
	if CrawlerEnginePTRMatch("bingbot", "crawl-66-249-66-1.googlebot.com") {
		t.Error("跨引擎 PTR 不应匹配")
	}
	if CrawlerEnginePTRMatch("gptbot", "gpt.example.openai.com.evil.attacker.tld") {
		t.Error("后缀必须锚定在域名尾部")
	}
	if !ValidCrawlerEngineID("gptbot") || ValidCrawlerEngineID("fakebot") {
		t.Error("引擎 ID 校验错误")
	}
}
