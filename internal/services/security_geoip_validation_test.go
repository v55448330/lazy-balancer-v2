package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateGeoIPCountries_rejectsUnknownProvinceWhenCacheLoaded(t *testing.T) {
	// Given：ip2region 省份缓存已加载（写入临时缓存文件模拟）
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing-dist.xdb"))
	cachePath := live + ".provinces.json"
	if err := os.WriteFile(cachePath, []byte(`["广东","北京","海外"]`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(cachePath) })

	// When：条目不在已知省份列表
	err := ValidateGeoIPCountries(`["火星"]`)
	// Then：拒绝——未知省份在发射端永不匹配，静默削弱地域控制
	if err == nil || !strings.Contains(err.Error(), "未知省份") {
		t.Fatalf("unknown province must be rejected with 未知省份, got %v", err)
	}

	// And：已知省份与"海外"放行，空条目仍拒绝
	if err := ValidateGeoIPCountries(`["广东","海外"]`); err != nil {
		t.Fatalf("known provinces must pass, got %v", err)
	}
	if err := ValidateGeoIPCountries(`["   "]`); err == nil {
		t.Fatalf("blank entry must be rejected")
	}
}

func TestValidateGeoIPCountries_rejectsUnknownProvinceWhenNothingLoaded(t *testing.T) {
	// Given：ip2region 未加载（searcher 为空、无缓存文件，live 与缓存兜底均只
	// 返回 ["海外"]）
	dir := t.TempDir()
	withIP2RegionPaths(t, filepath.Join(dir, "ip2region.xdb"), filepath.Join(dir, "missing-dist.xdb"))

	// When：条目为任意非空省份名
	err := ValidateGeoIPCountries(`["未知省"]`)
	// Then：拒绝并提示未加载——fail-closed，避免 deny 模式地域拦截静默失效
	if err == nil || !strings.Contains(err.Error(), "未加载") {
		t.Fatalf("unknown province without loaded database must be rejected with 未加载, got %v", err)
	}
	// And："海外" 是唯一可判定归属的条目，放行；空条目仍拒绝
	if err := ValidateGeoIPCountries(`["海外"]`); err != nil {
		t.Fatalf("海外 must pass without loaded database, got %v", err)
	}
	if err := ValidateGeoIPCountries(`[""]`); err == nil {
		t.Fatalf("empty entry must be rejected")
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
