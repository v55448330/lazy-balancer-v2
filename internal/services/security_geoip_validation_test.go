package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateGeoIPCountries_rejectsUnknownProvinceWhenCacheLoaded(t *testing.T) {
	// Given：ip2region 省份缓存已加载但 live searcher 未加载（缓存文件存在、
	// live xdb 不存在——R57 B-#1 的 xdb 损坏/带外替换形态）
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))
	cachePath := live + ".provinces.json"
	if err := os.WriteFile(cachePath, []byte(`["广东","北京","海外"]`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(cachePath) })

	// When/Then（R57 B-#1）：live 未加载时校验判据以 live 为准——缓存里的
	// 省份（广东）与未知省份（火星）都按 fail-closed「未加载」拒绝。旧语义
	// 用缓存判 loaded 会放行已知省份，而发射端占位变量从未设置（CEL 恒假）
	// → deny 地域拦截静默零强制。
	if err := ValidateGeoIPCountries(`["火星"]`, "deny"); err == nil || !strings.Contains(err.Error(), "未加载") {
		t.Fatalf("non-海外 entry with dead live searcher must be rejected with 未加载, got %v", err)
	}
	if err := ValidateGeoIPCountries(`["广东"]`, "deny"); err == nil || !strings.Contains(err.Error(), "未加载") {
		t.Fatalf("cache-known province with dead live searcher must ALSO be rejected (emission cannot match), got %v", err)
	}
	// R72 二十七次 N5（用户裁决覆盖 R57 海外放行）：海外拦截同样依赖 live
	// searcher 设置占位变量，缺库时 CEL 恒假零强制——未加载时一并拒绝。
	if err := ValidateGeoIPCountries(`["海外"]`, "deny"); err == nil || !strings.Contains(err.Error(), "未加载") {
		t.Fatalf("海外 with dead live searcher must be rejected with 未加载, got %v", err)
	}
	if err := ValidateGeoIPCountries(`["   "]`, "deny"); err == nil {
		t.Fatalf("blank entry must be rejected")
	}
}

func TestValidateGeoIPCountries_rejectsUnknownProvinceWhenNothingLoaded(t *testing.T) {
	// Given：ip2region 未加载（searcher 为空、无缓存文件，live 与缓存兜底均只
	// 返回 ["海外"]）
	dir := t.TempDir()
	withIP2RegionPaths(t, filepath.Join(dir, "ip2region.xdb"), filepath.Join(dir, "missing-dist.xdb"))

	// When：条目为任意非空省份名
	err := ValidateGeoIPCountries(`["未知省"]`, "deny")
	// Then：拒绝并提示未加载——fail-closed，避免 deny 模式地域拦截静默失效
	if err == nil || !strings.Contains(err.Error(), "未加载") {
		t.Fatalf("unknown province without loaded database must be rejected with 未加载, got %v", err)
	}
	// And："海外" 是唯一可判定归属的条目，放行；空条目仍拒绝
	// R72 二十七次 N5（用户裁决覆盖 R57 海外放行）：海外拦截同样依赖 live
	// searcher 设置占位变量，缺库时 CEL 恒假零强制——未加载时一并拒绝。
	if err := ValidateGeoIPCountries(`["海外"]`, "deny"); err == nil || !strings.Contains(err.Error(), "未加载") {
		t.Fatalf("海外 without loaded database must be rejected with 未加载, got %v", err)
	}
	if err := ValidateGeoIPCountries(`[""]`, "deny"); err == nil {
		t.Fatalf("empty entry must be rejected")
	}
}

// TestValidateGeoIPCountries_modeOff_shapeOnly：off 态名单是保留数据（开关
// 重开即复用），跳过可用性门——缺库时关闭/保留名单的保存不得被 400 卡死。
// 非法 JSON 形状在 off 态同样拒绝。
func TestValidateGeoIPCountries_modeOff_shapeOnly(t *testing.T) {
	dir := t.TempDir()
	withIP2RegionPaths(t, filepath.Join(dir, "ip2region.xdb"), filepath.Join(dir, "missing-dist.xdb"))

	if err := ValidateGeoIPCountries(`["广东","海外"]`, "off"); err != nil {
		t.Fatalf("off-mode retained countries must pass without xdb, got %v", err)
	}
	if err := ValidateGeoIPCountries(`火星`, "off"); err == nil {
		t.Fatal("off-mode must still reject non-JSON-array shape")
	}
}

func TestGetIP2RegionProvinceList_prefersLiveOverStaleCache(t *testing.T) {
	// Given：live searcher 已加载（含中国|广东 段），缓存文件被写成陈旧内容
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, live, []xdbSegment{
		{startIP: 0x01000100, endIP: 0x010001FF, region: "中国|广东|0|0|CN"},
	})
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))
	InitIP2Region()
	cachePath := live + ".provinces.json"
	if err := os.WriteFile(cachePath, []byte(`["北京","海外"]`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(cachePath) })

	// When：获取省份列表
	got := GetIP2RegionProvinceList()
	// Then：live searcher 优先，陈旧缓存不得覆盖（校验端与 UI 端同源）
	if len(got) < 2 || got[0] != "广东" || got[len(got)-1] != "海外" {
		t.Fatalf("province list=%v, want live [广东 海外] (stale cache 北京 must not win)", got)
	}
}
