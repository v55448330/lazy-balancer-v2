package services

import (
	"sort"
	"strings"
	"testing"
)

// 真实官网片段（2026-10-19 抓取）：UA 示例含 Chrome/140.0.0.0、官方段全为
// 通配形态。旧实现把版本串收成 140.0.0.0/32、且无法解析 a.b.c.* → 首次更新
// 即用单条无关地址覆盖正确名单。
func TestParseCrawlerCIDRsForFormat_360OfficialWildcardPage(t *testing.T) {
	body := `<html><body>
<p>示例 UA：Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0</p>
<table>
<tr><td>42.236.10.*</td><td>42.236.12.*</td><td>42.236.17.*</td></tr>
<tr><td>42.236.101.*</td><td>180.153.236.*</td><td>180.163.220.*</td></tr>
</table></body></html>`
	got, err := parseCrawlerCIDRsForFormat(body, "html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{
		"42.236.10.0/24", "42.236.12.0/24", "42.236.17.0/24",
		"42.236.101.0/24", "180.153.236.0/24", "180.163.220.0/24",
	}
	gotSorted := append([]string(nil), got...)
	wantSorted := append([]string(nil), want...)
	sort.Strings(gotSorted)
	sort.Strings(wantSorted)
	if strings.Join(gotSorted, ",") != strings.Join(wantSorted, ",") {
		t.Fatalf("parsed=%v, want %v（通配段按 /24 归一，版本串必须过滤）", gotSorted, wantSorted)
	}
	for _, bad := range got {
		if strings.HasPrefix(bad, "140.0.0.0") {
			t.Fatalf("UA 版本串被收为网段: %v", got)
		}
	}
}

// URL/版本前缀的四段数字（Chrome/…、Edg/…、v…）不得作为网段；
// 合法 URL 路径中的 IP 仍可提取（不过度拒绝）。
func TestParseCrawlerCIDRsForFormat_versionPrefixesRejected(t *testing.T) {
	body := "Chrome/140.0.0.0 v1.2.3.4 Edg/141.0.0.1 deny http://203.0.113.9/path\n"
	got, err := parseCrawlerCIDRsForFormat(body, "html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, bad := range []string{"140.0.0.0/32", "1.2.3.4/32", "141.0.0.1/32"} {
		if containsString(got, bad) {
			t.Fatalf("版本串被误收为 %s: %v", bad, got)
		}
	}
	if !containsString(got, "203.0.113.9/32") {
		t.Fatalf("URL 路径中的合法 IP 被过度拒绝: %v", got)
	}
}

// 非结构化源的合理性门——解析结果须落在引擎声明的官方段内，
// 「子集 + 覆盖」（见 crawler_regression_02_test.go 的超网/截断/JSON 形状）。
func TestValidateCrawlerEntriesSanity(t *testing.T) {
	if _, err := validateCrawlerEntriesSanity("so360spider", []string{"140.0.0.0/32"}); err == nil {
		t.Fatal("与官方段无关的解析结果必须拒绝（错误页/版本串污染）")
	}
	// （错误页单条替换整份名单形态，收紧前的旧断言已按裁定反转）。
	if _, err := validateCrawlerEntriesSanity("so360spider", []string{"42.236.10.0/24"}); err == nil {
		t.Fatal("仅一条官方段内 IP 的截断名单必须拒绝（覆盖门）")
	}
	if _, err := validateCrawlerEntriesSanity("so360spider", nil); err == nil {
		t.Fatal("空解析结果必须拒绝")
	}
	// 未声明官方段的引擎无可对照口径，不套用子集/覆盖门（收缩门兜底）。
	if _, err := validateCrawlerEntriesSanity("googlebot", []string{"203.0.113.0/24"}); err != nil {
		t.Fatalf("未声明官方段的引擎不应套用段一致性门: %v", err)
	}
}

// ---- 内置源 canonical URL/format 刷新到存量部署 ----

func TestRefreshCrawlerSources_preservesTimestampWhenCanonicalValueUnchanged(t *testing.T) {
	// Given one already-canonical row and one stale row, both with a stable
	// historical timestamp that makes an unconditional rewrite observable.
	_, database := newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_crawler_sources SET updated_at='2001-02-03 04:05:06'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_crawler_sources SET url='https://old.example/spider.html', format='plain' WHERE name='so360spider'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_crawler_sources SET url='', format='' WHERE name='bingbot'`); err != nil {
		t.Fatal(err)
	}
	var unchangedBefore string
	if err := database.QueryRow(`SELECT updated_at FROM security_crawler_sources WHERE name='googlebot'`).Scan(&unchangedBefore); err != nil {
		t.Fatal(err)
	}

	// When startup refreshes canonical source definitions.
	if err := refreshCrawlerSources(); err != nil {
		t.Fatal(err)
	}

	// Then an unchanged row keeps its snapshot-fingerprint input, while a real
	// URL/format correction still receives a fresh updated_at value.
	var unchangedTimestamp string
	if err := database.QueryRow(`SELECT updated_at FROM security_crawler_sources WHERE name='googlebot'`).Scan(&unchangedTimestamp); err != nil {
		t.Fatal(err)
	}
	if unchangedTimestamp != unchangedBefore {
		t.Fatalf("unchanged source updated_at=%q, want %q preserved", unchangedTimestamp, unchangedBefore)
	}
	var changedTimestamp string
	if err := database.QueryRow(`SELECT updated_at FROM security_crawler_sources WHERE name='so360spider'`).Scan(&changedTimestamp); err != nil {
		t.Fatal(err)
	}
	if changedTimestamp == "2001-02-03 04:05:06" || changedTimestamp == "" {
		t.Fatalf("changed source updated_at=%q, want refresh timestamp", changedTimestamp)
	}
	var emptyRepairTimestamp string
	if err := database.QueryRow(`SELECT updated_at FROM security_crawler_sources WHERE name='bingbot'`).Scan(&emptyRepairTimestamp); err != nil {
		t.Fatal(err)
	}
	if emptyRepairTimestamp == "2001-02-03 04:05:06" || emptyRepairTimestamp == "" {
		t.Fatalf("empty source fields must be repaired with a fresh timestamp, got %q", emptyRepairTimestamp)
	}
}

func TestRefreshCrawlerSources_refreshesCanonicalURLAndPreservesState(t *testing.T) {
	_, database := newClusterTestService(t)
	// 存量行：旧 URL/格式 + 用户关闭自动更新。
	if _, err := database.Exec(`INSERT INTO security_crawler_sources (name, display_name, url, format, update_enabled)
		VALUES ('so360spider', '360', 'https://old.example/spider.html', 'plain', 0)`); err != nil {
		t.Fatal(err)
	}

	if err := refreshCrawlerSources(); err != nil {
		t.Fatalf("refreshCrawlerSources: %v", err)
	}

	var url, format string
	var enabled int
	if err := database.QueryRow(`SELECT url, format, update_enabled FROM security_crawler_sources WHERE name='so360spider'`).
		Scan(&url, &format, &enabled); err != nil {
		t.Fatal(err)
	}
	wantURL, wantFormat, _ := CanonicalCrawlerSource("so360spider")
	if url != wantURL || format != wantFormat {
		t.Fatalf("url/format=(%q,%q), want canonical (%q,%q)", url, format, wantURL, wantFormat)
	}
	if enabled != 0 {
		t.Fatalf("update_enabled=%d, want 0（用户开关必须保留）", enabled)
	}
}

// display_name 与 url/format 同为代码文案的 canonical 投影：只做 ALTER/INSERT
// 种子时，代码改名永远到不了存量库（源表展示名与名单名同源不变量在存量行上
// 长期分叉）。启动刷新必须把存量行的 display_name 归一到代码文案，且不得触碰
// 用户开关与状态列。
func TestRefreshCrawlerSources_refreshesCanonicalDisplayName(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_crawler_sources (name, display_name, url, format, update_enabled, update_status, entry_count)
		VALUES ('gptbot', 'GPTBot（旧文案）', 'https://openai.com/gptbot.json', 'json', 1, 'success', 42)`); err != nil {
		t.Fatal(err)
	}

	if err := refreshCrawlerSources(); err != nil {
		t.Fatalf("refreshCrawlerSources: %v", err)
	}

	var displayName, updateStatus string
	var enabled, entryCount int
	if err := database.QueryRow(`SELECT display_name, update_enabled, update_status, entry_count FROM security_crawler_sources WHERE name='gptbot'`).
		Scan(&displayName, &enabled, &updateStatus, &entryCount); err != nil {
		t.Fatal(err)
	}
	if want := crawlerDisplayName("gptbot"); displayName != want {
		t.Fatalf("display_name=%q, want 代码文案 %q（改名必须到达存量库）", displayName, want)
	}
	if enabled != 1 || updateStatus != "success" || entryCount != 42 {
		t.Fatalf("用户开关/状态列被改写: enabled=%d update_status=%q entry_count=%d", enabled, updateStatus, entryCount)
	}
}
