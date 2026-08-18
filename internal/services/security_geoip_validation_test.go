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

func TestValidateGeoIPCountries_allowsAnyNonEmptyWhileCacheEmpty(t *testing.T) {
	// Given：ip2region 未加载（searcher 为空、无缓存文件，GetCachedProvinces
	// 仅返回 ["海外"]）
	dir := t.TempDir()
	withIP2RegionPaths(t, filepath.Join(dir, "ip2region.xdb"), filepath.Join(dir, "missing-dist.xdb"))

	// When：条目为任意非空省份名
	// Then：放行——启动期无法判定条目归属，跳过成员校验只查非空，避免误拒
	if err := ValidateGeoIPCountries(`["未知省"]`); err != nil {
		t.Fatalf("unknown province while cache empty must pass, got %v", err)
	}
	// And：非 JSON / 空条目仍拒绝
	if err := ValidateGeoIPCountries(`[""]`); err == nil {
		t.Fatalf("empty entry must be rejected")
	}
}
