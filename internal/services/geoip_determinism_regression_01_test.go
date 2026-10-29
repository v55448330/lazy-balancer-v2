package services

//
//   geoipLocOperator「海外」展开集此前直接遍历 exactSet map——迭代序
//     非确定，同 DB 视图两次渲染产出不同算子字节 → errSameConfig 同字节短路
//     门失效（每次写路径真重载+预检池键漂移）。钉测：同输入多次编译逐字节
//     相同 + 展开段按字典序。
//   混选「海外+国名」时展开集与显式国名条目去重，不产生重复
//     alternative（重复条目无害但构成渲染非单源形态，且干扰字节比对）。
//   geoip_countries 畸形 JSON 渲染按无地域规则处理（不 fail-visible，
//     推演披露见段），但必须 WARN 留痕——静默丢弃使「UI 宣称
//     地域拦截在用、实际零强制」不可见。
//
// 渲染确定性（同 DB 视图两次渲染逐字节相同）在
// TestRenderDeterminism_geoipViewByteIdentical 钉全链路（树缓存→策略→指令）。

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestGeoipLocOperator_expansionDeterministicAndDeduped(t *testing.T) {
	exact := map[string]bool{
		"United States": true, "Japan": true, "France": true, "Germany": true, "Brazil": true,
	}
	countries := []string{"海外", "Japan", "广东省", "广东省"}

	// GOLDEN：海外哨兵在最前、展开段字典序、显式国名条目与展开集去重（Japan
	// 仅出现一次）、省份条目保持后缀形态、重复输入条目去重。修复前 map 迭代序
	// 使展开段顺序随机、Japan 重复两次——两个缺陷同时被本断言拦截。
	want := `@rx ^(?:海外|Brazil|France|Germany|Japan|United States|广东省(?:/.*)?)$`
	for range 200 {
		if got := geoipLocOperator(countries, false, exact); got != want {
			t.Fatalf("operator must be deterministic sorted/deduped:\n got %s\nwant %s", got, want)
		}
	}
	if strings.Count(geoipLocOperator(countries, true, exact), "Japan") != 1 {
		t.Fatal("allow mode: 混选海外+国名不得产生重复 alternative（历史修复）")
	}
}

// TestRenderDeterminism_geoipViewByteIdentical：同 DB 视图（同一策略行+同一
// 地域树缓存）两次 BuildCorazaDirectives 渲染必须逐字节相同——geoipLocOperator
// 展开集定序后的全链路确定性钉。
func TestRenderDeterminism_geoipViewByteIdentical(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedGeoipPolicyBound(t, database, "lb-det", `["海外","Japan","广东省"]`, "deny", 0, 0)
	policy := GetSecurityPolicyForRule("lb-det")
	if policy == nil {
		t.Fatal("expected bound geoip policy to load")
	}

	// 地域树缓存兜底形态：ip2regionLivePath 指向不存在文件（Stat 失败→读
	// <path>.regions.json 缓存），Countries 数组故意乱序——修复前 exactSet
	// map 迭代序使两次渲染字节随机；定序后两次渲染恒等。
	countries := []string{
		"Zimbabwe", "France", "Japan", "Brazil", "United States", "Germany",
		"Iceland", "Norway", "Chile", "Egypt", "India", "Kenya",
	}
	treeJSON, err := json.Marshal(map[string]interface{}{
		"revision":  "fixture",
		"provinces": []string{"广东省", "海外"},
		"cities":    map[string][]string{"广东省": {"深圳市"}},
		"countries": countries,
	})
	if err != nil {
		t.Fatalf("marshal tree: %v", err)
	}
	dir := t.TempDir()
	t.Cleanup(OverrideWafLivePathsForTest(crsLiveDir, filepath.Join(dir, "ip2region.xdb")))
	if err := os.WriteFile(ip2regionLivePath+".regions.json", treeJSON, 0o644); err != nil {
		t.Fatalf("write tree cache: %v", err)
	}

	// 验收钉在 buildIPPrecheckDirectives（geoipLocOperator 的发射落点——
	// 阶段 1 预检引擎段）：同 DB 视图两次渲染逐字节相同。
	first, err := buildIPPrecheckDirectives([]*models.SecurityPolicy{policy}, 403, "lb_test")
	if err != nil {
		t.Fatalf("first render: %v", err)
	}
	if !strings.Contains(first, "Brazil") || !strings.Contains(first, "海外") {
		t.Fatalf("geoip expansion missing from directives:\n%s", first)
	}
	for range 50 {
		again, err := buildIPPrecheckDirectives([]*models.SecurityPolicy{policy}, 403, "lb_test")
		if err != nil {
			t.Fatalf("re-render: %v", err)
		}
		if again != first {
			t.Fatal("same DB view must render byte-identical directives ")
		}
	}
}

// TestGeoipCountries_malformedJSONLogsWarn：畸形 JSON 不再静默——
// WARN 留痕（按无地域规则渲染不 fail-visible，推演披露：单策略脏 TEXT 列
// 不得阻断整份配置生成，与裁定同向）。
func TestGeoipCountries_malformedJSONLogsWarn(t *testing.T) {
	var logBuf bytes.Buffer
	oldLog := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(oldLog) })

	p := &models.SecurityPolicy{ID: 7, Name: "broken-geoip", GeoIPCountries: []byte(`{"not":"an array"`)}
	if got := geoipCountries(p); len(got) != 0 {
		t.Fatalf("malformed JSON must render as no geoip entries, got %v", got)
	}
	if !strings.Contains(logBuf.String(), "geoip_countries 畸形") {
		t.Fatalf("malformed geoip_countries must leave a WARN trail , log:\n%s", logBuf.String())
	}
}
