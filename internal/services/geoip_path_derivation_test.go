package services

import "testing"

//  GeoIP 路径派生/爬虫快照路径派生 钉测：xdb 与爬虫快照路径必须随 data_dir 派生并发射进
// geoip2region handler。非默认形态下若渲染侧不发射，Caddy 侧 caddygeoip 插件
// 按自身 Provision 兜底默认（/app/data/...）读库——自定义 data_dir 部署的
// GeoIP 解析与爬虫 IP 段豁免静默失效（写侧已随 data_dir 派生，读侧却读 /app）。

// TestBuildGeoipHandler_derivedPathsEmitted：非默认哨兵 data_dir 完成派生后，
// 渲染产物必须显式携带派生的 xdb_path 与 crawler_ip_list_file。
func TestBuildGeoipHandler_derivedPathsEmitted(t *testing.T) {
	// Given：非默认哨兵 data_dir（/tmp/custom 形态）经 ConfigureWafDirs 派生
	saveWafPathVars(t)
	ConfigureWafDirs("/tmp/custom/data")

	// When：渲染 geoip handler
	h := buildGeoipHandler(false)

	// Then：派生路径显式发射（插件不再依赖自身兜底默认）
	if got := h["xdb_path"]; got != "/tmp/custom/data/ip2region.xdb" {
		t.Fatalf("xdb_path=%v, want /tmp/custom/data/ip2region.xdb（未发射则自定义 data_dir 部署 GeoIP 静默失效）", got)
	}
	if got := h["crawler_ip_list_file"]; got != "/tmp/custom/data/crawler-ip-lists.json" {
		t.Fatalf("crawler_ip_list_file=%v, want /tmp/custom/data/crawler-ip-lists.json（未发射则爬虫 IP 段豁免读错路径）", got)
	}
}

// TestBuildGeoipHandler_defaultPathsOmitted：容器默认形态（data_dir=/app/data）
// 渲染字节不变裁定——派生值与插件 Provision 默认一致时省略两键，geoip2region
// handler 字节形态与修复前逐字节一致（loadConfig 同字节短路不变量依赖之，
// 防止默认部署因新增键触发无意义重载）。
func TestBuildGeoipHandler_defaultPathsOmitted(t *testing.T) {
	// Given：容器默认形态——显式设置并先行断言出厂默认值（不依赖其他用例
	// 的 saveWafPathVars 清理；「默认 ⇒ 省略键」的期望值由此显式成立）
	saveWafPathVars(t)
	t.Cleanup(OverrideWafLivePathsForTest(crsLiveDir, defaultIP2RegionLivePath))
	crawlerIPListFile = defaultCrawlerIPListFile
	if ip2regionLivePath != "/app/data/ip2region.xdb" || crawlerIPListFile != "/app/data/crawler-ip-lists.json" {
		t.Fatalf("默认路径常量漂移: xdb=%q crawler=%q", ip2regionLivePath, crawlerIPListFile)
	}

	// When：渲染 geoip handler
	h := buildGeoipHandler(true)

	// Then：两键省略（默认由插件 Provision 兜底，渲染产物逐字节不变）
	if _, ok := h["xdb_path"]; ok {
		t.Fatalf("默认形态必须省略 xdb_path（字节稳定裁定），got %#v", h)
	}
	if _, ok := h["crawler_ip_list_file"]; ok {
		t.Fatalf("默认形态必须省略 crawler_ip_list_file（字节稳定裁定），got %#v", h)
	}
}
