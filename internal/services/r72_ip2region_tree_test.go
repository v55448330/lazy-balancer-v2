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
	// 排序不变量：前 n-1（省份）严格递增，海外固定末位。
	for i := 1; i < len(tree.Provinces)-1; i++ {
		if tree.Provinces[i-1] >= tree.Provinces[i] {
			t.Fatalf("provinces not sorted: %q >= %q", tree.Provinces[i-1], tree.Provinces[i])
		}
	}
	if tree.Provinces[len(tree.Provinces)-1] != "海外" {
		t.Fatalf("海外 must be last, got %q", tree.Provinces[len(tree.Provinces)-1])
	}
	// R72 二十五次：未映射 ASCII 段清零断言——当前 v3.17.0 全部拼音/英文段已
	// 映射；未来 xdb 版本新增未映射段时计数 >0，此断言失败提醒补映射表
	//（丢失可见而非静默过滤）。
	if tree.DroppedASCIIProvinces != 0 || tree.DroppedASCIICities != 0 {
		t.Fatalf("unmapped ASCII segments dropped: prov=%d city=%d — 映射表需为新版 xdb 补条目", tree.DroppedASCIIProvinces, tree.DroppedASCIICities)
	}
	// r26（R72 二十八次，用户反馈）：少数民族自治州简称必须映射为全称——
	// 云南大理/怒江、四川凉山等 30 个自治州；「大理」这类简称不得残留。
	assertCity := func(prov, want string) {
		for _, c := range tree.Cities[prov] {
			if c == want {
				return
			}
		}
		t.Fatalf("%s 缺 %q", prov, want)
	}
	assertCity("云南省", "大理白族自治州")
	assertCity("云南省", "怒江傈僳族自治州")
	assertCity("四川省", "凉山彝族自治州")
	assertCity("新疆维吾尔自治区", "伊犁哈萨克自治州")
	assertCity("青海省", "海西蒙古族藏族自治州")
	assertCity("甘肃省", "临夏回族自治州")
	for _, bad := range []string{"大理", "怒江", "凉山"} {
		for prov, cities := range tree.Cities {
			for _, c := range cities {
				if c == bad {
					t.Fatalf("%s 残留自治州简称 %q", prov, bad)
				}
			}
		}
	}

	// r25：UEruemqi 段回收——新疆/乌鲁木齐市 必须在位（此前整段被丢）；
	// revision 机制保证旧缓存自动重建。
	if tree.Revision != treeCacheRevision {
		t.Fatalf("tree revision=%q, want %q", tree.Revision, treeCacheRevision)
	}
	foundUrumqi := false
	for _, c := range tree.Cities["新疆维吾尔自治区"] {
		if c == "乌鲁木齐市" {
			foundUrumqi = true
			break
		}
	}
	if !foundUrumqi {
		t.Fatal("新疆维吾尔自治区 缺 乌鲁木齐市（UEruemqi 段未回收）")
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
