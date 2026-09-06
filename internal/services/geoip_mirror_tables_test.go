package services

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// W12 守门绊线：caddygeoip/handler.go 与 internal/services/ip2region.go 各持一套
// GeoIP 规范化表（叶子 Caddy 模块不可 import internal 包，只能手工双份维护）——
//   provinceAliases / cityPinyinFixes / autonomousPrefectures：本包侧构建策略
//   「区域选择」选项树（regionTreeFromXDB → GetIP2RegionRegions），caddygeoip 侧
//   用于发射 X-GeoIP-Loc 匹配键；taiwanCities：两侧同判「台湾城市误入省列」。
// 漂移失效形态：选项树提供某省/市而发射变量发另一形态（或反之）→ 城市级地域
// 规则（coraza 锚定正则全值匹配）对受影响段静默恒不命中且无任何报错——历史
// 已发生一次（R72 二十六次 W3-4：provinceAliases 曾缺 11 条）。两侧表修改必须
// 同步；本测试读取对侧源文件文本解析 map 字面量逐条比对（不依赖跨模块 import），
// 当前两侧一致（22/13/45/31 条）应恒绿，任何单侧改动立即在此绊线。
//
// 注：测试运行目录为 internal/services，对侧源文件相对路径 ../../caddygeoip/handler.go。

var geoipMirrorEntryRe = regexp.MustCompile(`"([^"]+)"\s*:\s*(?:"([^"]*)"|true\b)`)

// parseCaddygeoipMapLiteral 从 caddygeoip/handler.go 源文本中解析 var <name> = map[...]{...}
// 字面量为 key→value 映射（taiwanCities 的 true 值归一为空串，仅比较键集合）。
// 对每行先剥离 // 注释尾部再匹配（现有表值均为中文地名/拉丁转写，不含 "//" 与
// 转义引号，该简化在注释中声明假设）。
func parseCaddygeoipMapLiteral(t *testing.T, src, varName string) map[string]string {
	t.Helper()
	startRe := regexp.MustCompile(`(?m)^var ` + varName + ` = map`)
	loc := startRe.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("caddygeoip/handler.go 中未找到 var %s 定义", varName)
	}
	block := src[loc[1]:]
	end := strings.Index(block, "\n}")
	if end < 0 {
		t.Fatalf("var %s 的 map 字面量未找到列 0 闭合 '}'", varName)
	}
	block = block[:end]

	parsed := map[string]string{}
	for _, line := range strings.Split(block, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		for _, m := range geoipMirrorEntryRe.FindAllStringSubmatch(line, -1) {
			key, value := m[1], m[2]
			if _, dup := parsed[key]; dup {
				t.Fatalf("var %s 中键 %q 重复出现", varName, key)
			}
			parsed[key] = value
		}
	}
	if len(parsed) == 0 {
		t.Fatalf("var %s 解析结果为空（源文件格式变化导致解析失效，守门测试自身需要维护）", varName)
	}
	return parsed
}

func TestGeoIPMirrorTables_matchAcrossModules(t *testing.T) {
	const mirrorSrc = "../../caddygeoip/handler.go"
	src, err := os.ReadFile(mirrorSrc)
	if err != nil {
		t.Fatalf("读取 %s 失败（测试须自 internal/services 包目录运行）: %v", mirrorSrc, err)
	}

	stringTables := []struct {
		mirrorVar string
		local     map[string]string
	}{
		{"provinceAliases", ip2ProvinceAliases},
		{"cityPinyinFixes", ip2PinyinCityFixes},
		{"autonomousPrefectures", ip2AutonomousPrefectures},
	}
	for _, table := range stringTables {
		parsed := parseCaddygeoipMapLiteral(t, string(src), table.mirrorVar)
		assertMirrorStringMap(t, table.mirrorVar, parsed, table.local)
	}

	// taiwanCities 两侧均为 set 语义（值恒 true）：仅比较键集合。
	taiwanMirror := parseCaddygeoipMapLiteral(t, string(src), "taiwanCities")
	taiwanLocal := map[string]string{}
	for city := range ip2TaiwanCities {
		taiwanLocal[city] = ""
	}
	assertMirrorStringMap(t, "taiwanCities", taiwanMirror, taiwanLocal)
}

// assertMirrorStringMap 逐条比对镜像表，失败时列出差异键值并给出同步指引。
func assertMirrorStringMap(t *testing.T, name string, mirror, local map[string]string) {
	t.Helper()
	diff := false
	for key, want := range local {
		got, ok := mirror[key]
		if !ok {
			t.Errorf("%s：caddygeoip 侧缺少键 %q（本包侧值 %q）", name, key, want)
			diff = true
		} else if got != want {
			t.Errorf("%s：键 %q 两侧值不一致——caddygeoip=%q, services=%q", name, key, got, want)
			diff = true
		}
	}
	for key, got := range mirror {
		if _, ok := local[key]; !ok {
			t.Errorf("%s：caddygeoip 侧多出键 %q（值 %q）", name, key, got)
			diff = true
		}
	}
	if diff {
		t.Errorf("%s 两模块镜像表发生漂移——选项树（services 侧）与 X-GeoIP-Loc 发射变量（caddygeoip 侧）将不一致，城市级地域规则对受影响段静默恒不命中；请两侧同步修改 caddygeoip/handler.go 与 internal/services/ip2region.go", name)
	}
}
