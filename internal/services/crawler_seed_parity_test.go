package services

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/geoipnames"
)

// U13-01（第 78 轮）：爬虫 IP 段的唯一权威源是 geoipnames.CrawlerEngine.IPRanges
// （UA+PTR/IP 段验证与策略豁免同源）。镜像内置种子 config/crawler-ip-lists.seed.json
// 曾把 360Spider 写成 140.0.0.0/32（Google Cloud 地址）——新实例/离线实例的
// iprange 引擎豁免恒不命中，且把无关地址当「已验证爬虫」。本钉测锁定两个内置
// 数据源（种子文件 + Go 内置回退）与 geoipnames 的段集同覆盖：
//   - 每个内置 CIDR 必须落在该引擎某个官方段内（⊆ IPRanges）；
//   - 每个官方段必须至少被一个内置 CIDR 覆盖（不得漏段）。
func TestCrawlerSeedIPRanges_alignWithGeoIPNames(t *testing.T) {
	seedPath := filepath.Join("..", "..", "config", "crawler-ip-lists.seed.json")
	data, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatalf("read crawler seed: %v", err)
	}
	var seed map[string][]string
	if err := json.Unmarshal(data, &seed); err != nil {
		t.Fatalf("parse crawler seed: %v", err)
	}

	sources := []struct {
		name    string
		entries map[string][]string
	}{
		{"seed file", seed},
		{"builtin fallback", crawlerBuiltinSnapshot},
	}
	for _, source := range sources {
		for _, engine := range geoipnames.CrawlerEngines() {
			if len(engine.IPRanges) == 0 {
				continue
			}
			entries := source.entries[engine.ID]
			if len(entries) == 0 {
				t.Errorf("%s: engine %q has no entries; geoipnames declares %v", source.name, engine.ID, engine.IPRanges)
				continue
			}
			prefixes := make([]netip.Prefix, 0, len(entries))
			for _, entry := range entries {
				prefixes = append(prefixes, parseSeedPrefix(t, source.name, engine.ID, entry))
			}
			officials := make([]netip.Prefix, 0, len(engine.IPRanges))
			for _, official := range engine.IPRanges {
				officials = append(officials, parseSeedPrefix(t, "geoipnames", engine.ID, official))
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
					t.Errorf("%s: engine %q entry %s is outside geoipnames.IPRanges %v", source.name, engine.ID, entries[i], engine.IPRanges)
				}
			}
			for _, official := range officials {
				covered := false
				for _, prefix := range prefixes {
					if prefix.Bits() >= official.Bits() && official.Contains(prefix.Addr()) {
						covered = true
						break
					}
				}
				if !covered {
					t.Errorf("%s: engine %q has no entry covering official range %s (declared %v)", source.name, engine.ID, official, engine.IPRanges)
				}
			}
		}
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
