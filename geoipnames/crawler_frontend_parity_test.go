package geoipnames

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// 引擎注册表（单源）与前端镜像的机械对齐绊线：展示名不在 Go 侧，策略向导
// 消费 SecurityPolicies.vue 的 crawlerEngineOptions（按 ID 对齐）；两处前端
// 默认勾选集字面量（defaultForm 新建 / openDialog 缺省回填）必须与
// defaultCrawlerEngines 一致。任一侧漂移（新增引擎未同步镜像、默认集分叉、
// 顺序错位）即红——没有这道绊线时，前端少一个选项或默认集改写都是静默的。

// crawlerVueSource 读取策略页源码（镜像与默认集的唯一前端载体）。
func crawlerVueSource(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "web", "src", "views", "security", "SecurityPolicies.vue"))
	if err != nil {
		t.Fatalf("read SecurityPolicies.vue: %v", err)
	}
	return string(data)
}

// crawlerOptionsBlock 切出 crawlerEngineOptions 数组字面量（到行首 `]`）。
var crawlerOptionsBlock = regexp.MustCompile(`(?s)const crawlerEngineOptions = \[(.*?)\n\]`)

// crawlerOptionID 捕获镜像条目的 id 字面量。
var crawlerOptionID = regexp.MustCompile(`\{ id: '([^']+)'`)

func TestCrawlerEngineOptions_mirrorMatchesRegistry(t *testing.T) {
	src := crawlerVueSource(t)
	block := crawlerOptionsBlock.FindStringSubmatch(src)
	if block == nil {
		t.Fatal("SecurityPolicies.vue 切不出 crawlerEngineOptions 数组：切块正则漂移会让本门静默空转")
	}
	hits := crawlerOptionID.FindAllStringSubmatch(block[1], -1)
	if len(hits) == 0 {
		t.Fatal("crawlerEngineOptions 切块内未解析出任何 id 字面量：条目形态漂移会让本门静默空转")
	}
	mirror := make([]string, len(hits))
	for i, h := range hits {
		mirror[i] = h[1]
	}
	// 顺序=向导展示顺序（注册表注释契约），ID 集合与顺序都必须逐位一致。
	if want := CrawlerEngineIDs(); !reflect.DeepEqual(mirror, want) {
		t.Fatalf("前端镜像与引擎注册表分叉：\n前端=%v\n注册表=%v", mirror, want)
	}
}

// crawlerDefaultArray 匹配 geoip_crawler_engines 字段的默认勾选集字面量
// （['googlebot', ...] 形态），捕获数组体。锚定字段名以免误中其它字符串
// 数组（如 stage 列表）；defaultForm 内联与 openDialog 三元回填两处同形，
// 中间允许空白/换行与 `? `。
var crawlerDefaultArray = regexp.MustCompile(`(?s)geoip_crawler_engines:.{0,120}?\[\s*('[a-z0-9]+'(?:,\s*'[a-z0-9]+')*)\s*\]`)

func TestCrawlerDefaultEngines_frontendMirrorsMatchGo(t *testing.T) {
	src := crawlerVueSource(t)
	want := DefaultCrawlerEngines()
	if len(want) == 0 {
		t.Fatal("默认勾选集不得为空")
	}
	// 两处前端默认字面量：defaultForm（新建策略）与 openDialog（字段缺失回填）。
	// 逐处对账，缺一即分叉；新增同形默认落点同样纳入（必须同口径）。
	hits := crawlerDefaultArray.FindAllStringSubmatch(src, -1)
	if len(hits) < 2 {
		t.Fatalf("SecurityPolicies.vue 只切出 %d 处默认引擎字面量（want ≥2：defaultForm + openDialog 回填）", len(hits))
	}
	for _, h := range hits {
		var got []string
		for _, part := range strings.Split(h[1], ",") {
			got = append(got, strings.Trim(strings.TrimSpace(part), "'"))
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("前端默认勾选集 [%s] 与 Go defaultCrawlerEngines %v 分叉", h[1], want)
		}
	}
}
