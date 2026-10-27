package services

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"lazy-balancer-v2/geoipnames"
)

// 爬虫地址库内置首版的单一事实源。
//
// 历史形态：镜像资产 config/crawler-ip-lists.seed.json + services 内另存一份
// 手写 Go 表。两份分叉——手写表 gptbot 仅 3 条（含官方已不发布的
// 20.191.0.0/16 超网），镜像种子 18 条。修复后数据文件移入 geoipnames 并随包
// 嵌入，services 的回退直接取同一份字节；本测试锁定「回退 == 权威种子」，
// 任何重新引入第二份手写表的改动都会在此失败。
func TestCrawlerBuiltinSnapshot_derivedFromCanonicalSeed(t *testing.T) {
	canonical := geoipnames.BuiltinCrawlerIPLists()
	if len(canonical) == 0 {
		t.Fatal("geoipnames 内置爬虫种子为空")
	}
	if !reflect.DeepEqual(crawlerBuiltinSnapshot, canonical) {
		t.Fatalf("services 内置回退与 geoipnames 权威种子分叉: fallback=%v canonical=%v",
			summary(crawlerBuiltinSnapshot), summary(canonical))
	}
	// 镜像种子文件缺失/损坏分支（容器内 /app/waf.dist 被挂载覆盖等形态）：
	// 回退必须仍是同一份权威数据，不得退化为「最小手写表」。
	old := crawlerDistSeedFile
	crawlerDistSeedFile = filepath.Join(t.TempDir(), "absent.seed.json")
	defer func() { crawlerDistSeedFile = old }()
	if got := loadCrawlerBundledSeed(); !reflect.DeepEqual(got, canonical) {
		t.Fatalf("镜像种子缺失时的回退与权威种子分叉: fallback=%v canonical=%v",
			summary(got), summary(canonical))
	}
}

func summary(lists map[string][]string) map[string]int {
	out := make(map[string]int, len(lists))
	for engineID, entries := range lists {
		out[engineID] = len(entries)
	}
	return out
}

// TestCrawlerSeedIPRanges_alignWithGeoIPNames 段集不变量
// geoipnames.CrawlerEngine.IPRanges 是「官方 IP 段」的唯一权威声明，
//  1. 声明了官方段的引擎（iprange 验证）：每个内置 CIDR 必须落在某个官方段内
//     （⊆），且每个官方段至少被一个内置 CIDR 覆盖（不得漏段）；
//  2. 未声明官方段的引擎：必须是 PTR 双跳验证（VerifyMethod 为空）——否则就是
//     「走 iprange 验证却没有可校验段集」的 fail-open 形态，必须显式声明段集。
//
// 修复前本测试对 len(IPRanges)==0 的引擎直接 continue：googlebot/bingbot/gptbot
// 全被静默跳过，「覆盖缺口」正是因此长期不可见。现在「跳过」必须由引擎自身的
// 验证方式解释，未知引擎 ID 同样失败。
func TestCrawlerSeedIPRanges_alignWithGeoIPNames(t *testing.T) {
	seed := geoipnames.BuiltinCrawlerIPLists()
	declaredByID := make(map[string][]string)
	verifyByID := make(map[string]string)
	for _, engine := range geoipnames.CrawlerEngines() {
		declaredByID[engine.ID] = engine.IPRanges
		verifyByID[engine.ID] = engine.VerifyMethod
	}
	for engineID, entries := range seed {
		declared, known := declaredByID[engineID]
		if !known {
			t.Errorf("内置种子含未知引擎 %q（不在 geoipnames.CrawlerEngines 注册表内）", engineID)
			continue
		}
		if len(entries) == 0 {
			t.Errorf("引擎 %q 内置种子为空", engineID)
			continue
		}
		if len(declared) == 0 {
			if verifyByID[engineID] == geoipnames.CrawlerVerifyIPRange {
				t.Errorf("引擎 %q 走 iprange 验证但未声明 IPRanges——无可校验段集即 fail-open", engineID)
			}
			continue
		}
		prefixes := make([]netip.Prefix, 0, len(entries))
		for _, entry := range entries {
			prefixes = append(prefixes, parseSeedPrefix(t, "seed", engineID, entry))
		}
		officials := make([]netip.Prefix, 0, len(declared))
		for _, official := range declared {
			officials = append(officials, parseSeedPrefix(t, "geoipnames", engineID, official))
		}
		for i, prefix := range prefixes {
			contained := false
			for _, official := range officials {
				if official.Bits() <= prefix.Bits() && official.Contains(prefix.Addr()) {
					contained = true
					break
				}
			}
			if !contained {
				t.Errorf("引擎 %q 种子条目 %s 超出 geoipnames.IPRanges %v", engineID, entries[i], declared)
			}
		}
		for _, official := range officials {
			// 覆盖门复用运行期同一判定（每官方段 ≥1/8 地址空间）：
			// 「任一更具体条目」的弱门会让「每段一个 /32」的种子测试仍绿，
			// 却在运行期被 validateCrawlerEntriesSanity 永久拒绝。
			if !crawlerPrefixCoverageSufficient(official, prefixes) {
				t.Errorf("引擎 %q 种子对官方段 %s 的地址覆盖不足 1/8（声明 %v）", engineID, official, declared)
			}
		}
	}
	// 反向遍历（注册表 → 种子）：上面只遍历种子 map，注册表新增一个
	// VerifyMethod=CrawlerVerifyIPRange 的引擎却忘记加种子行时循环看不到它，
	// 「走 iprange 验证却没有可校验段集」的 fail-open 形态不会被检出。反方向
	// （种子里有未知/未声明段集的引擎）已由上面的断言覆盖，两个方向都要钉。
	for _, engine := range geoipnames.CrawlerEngines() {
		if engine.VerifyMethod != geoipnames.CrawlerVerifyIPRange {
			continue
		}
		if len(seed[engine.ID]) == 0 {
			t.Errorf("引擎 %q 走 iprange 验证但内置种子缺该引擎名单（fail-open：无可校验段集）", engine.ID)
		}
	}
}

// TestCrawlerSeedFile_matchesEmbeddedAuthority 打包契约：Dockerfile 从本路径
// COPY 到 /app/waf.dist，services 在文件缺失时回退到同一份嵌入数据——仓库内
// 文件必须就是被嵌入的那一份（防止「COPY 源换了、嵌入源没换」或路径漂移）。
func TestCrawlerSeedFile_matchesEmbeddedAuthority(t *testing.T) {
	path := filepath.Join("..", "..", "geoipnames", "crawler-ip-lists.seed.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取镜像种子文件失败（Dockerfile COPY 源）: %v", err)
	}
	var parsed map[string][]string
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("解析镜像种子文件失败: %v", err)
	}
	if !reflect.DeepEqual(parsed, geoipnames.BuiltinCrawlerIPLists()) {
		t.Fatalf("镜像种子文件与嵌入数据不一致: file=%v embedded=%v",
			summary(parsed), summary(geoipnames.BuiltinCrawlerIPLists()))
	}
}

func parseSeedPrefix(t *testing.T, source, engineID, value string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		t.Fatalf("%s: engine %q invalid CIDR %q: %v", source, engineID, value, err)
	}
	return prefix
}
