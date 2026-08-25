package services

import (
	"os"

	"encoding/json"

	"lazy-balancer-v2/internal/models"
	"strings"
	"testing"
)

// R72 二十三次：xdb 段索引全量扫描的省→城市树契约（用生产容器同版 v3.17.0
// xdb；缺失时跳过——本地开发可能无库）。
func TestIP2RegionRegionTree_scan(t *testing.T) {
	// 测试 seam：指向真实 live xdb（容器内 /app/data/ip2region.xdb；本地仓库
	// 无库则跳过）。
	path := ip2regionLivePath
	if _, err := os.Stat(path); err != nil {
		// 本地仓库无库：借用容器拷贝的副本（CI 环境无副本则跳过）。
		path = "/tmp/test_ip2region.xdb"
		if _, err := os.Stat(path); err != nil {
			t.Skip("no xdb available")
		}
	}
	tree := regionTreeFromXDB(path)
	if tree == nil {
		t.Fatal("scan returned nil tree for a valid xdb")
	}
	// 34 个省级行政区 + 海外由 ProvinceList 渠道保证；树只含中国省份。
	if len(tree.Provinces) < 30 {
		t.Fatalf("provinces=%d, want >=30（中国省级行政区）", len(tree.Provinces))
	}
	// 直辖市/大省必有城市。
	foundCity := false
	for _, cities := range tree.Cities {
		if len(cities) > 0 {
			foundCity = true
			break
		}
	}
	if !foundCity {
		t.Fatal("no cities found in tree（xdb 段含城市列，扫描应产出至少一省的城市集）")
	}
	// 排序不变量。
	for i := 1; i < len(tree.Provinces); i++ {
		if tree.Provinces[i-1] >= tree.Provinces[i] {
			t.Fatalf("provinces not sorted: %q >= %q", tree.Provinces[i-1], tree.Provinces[i])
		}
	}
}

// CEL 双形态：纯省 = 整省匹配；省/市 = 联合匹配。
func TestBuildGeoipMatchExpression_cityForm(t *testing.T) {
	policy := &models.SecurityPolicy{GeoIPCountries: json.RawMessage(`["福建省","广东省/深圳市","海外"]`)}
	expr := buildGeoipMatchExpression(policy)
	if !strings.Contains(expr, `{http.vars.geoip.province} == "福建省"`) {
		t.Fatalf("province form missing: %s", expr)
	}
	if !strings.Contains(expr, `({http.vars.geoip.province} == "广东省" && {http.vars.geoip.city} == "深圳市")`) {
		t.Fatalf("city joint form missing: %s", expr)
	}
	if !strings.Contains(expr, `{http.vars.geoip.country_name} != "中国"`) {
		t.Fatalf("overseas form missing: %s", expr)
	}
}
