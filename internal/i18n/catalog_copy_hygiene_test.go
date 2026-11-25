package i18n

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// catalog 守卫共用的调用扫描器：登记调用形状唯一（Register(key, zh)），判据测试与
// 形态测试共用同一扫描口径，避免各写一份正则漂移。
// 字符串组必须用 Go 字面量完整形态 "(?:[^"\\]|\\.)*":惰性 ".*?" 遇
// 词条内部 \") 序列会提前闭合捕获组,截断字面量无法解码、尾部判据失明。
const goStrLit = `"(?:[^"\\]|\\.)*"`

// catalogEntryRe 只认两参形态：第三参（英文译文）已从后端目录删除，
// 出现第三参说明有人往母本里塞译文——由形态守卫直接判红。
var catalogEntryRe = regexp.MustCompile(`Register\((` + goStrLit + `), (` + goStrLit + `)\)`)

// 扫描器必须完整捕获含转义引号的词条:惰性 ".*?" 遇词条内部的 \") 形态
// 会提前闭合捕获组,截断后的字面量以反斜杠结尾无法解码。
func TestCatalogHygieneScannerHandlesEscapedQuotes(t *testing.T) {
	source, err := os.ReadFile("catalog_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	matches := catalogEntryRe.FindAllStringSubmatch(string(source), -1)
	if len(matches) == 0 {
		t.Fatal("catalog_gen.go 未扫到任何 Register——守卫对象漂移")
	}
	found := 0
	for _, m := range matches {
		if strings.Contains(m[2], `\"`) {
			found++
		}
	}
	if found == 0 {
		t.Fatal("catalog_gen.go 里没有含转义引号的词条——扫描器自检失去对象")
	}
}

// 每一行 Register 都必须恰好两参：第三参是英文译文，后端已不再登记译文
// （2026-11-25 裁定：后端只有键 + 中文母本，英文归前端词条）。
// 编译期已由 Register(key, zh string) 挡住三参调用；这里守住「用字符串拼接
// 等方式绕过类型」与「注释里遗留三参样例被误当登记」两种文本面漂移。
func TestCatalogRegistrationsCarryChineseOnly(t *testing.T) {
	files, err := filepath.Glob("catalog_*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("目录文件缺失: %v %v", files, err)
	}
	threeArg := regexp.MustCompile(`Register\(` + goStrLit + `, ` + goStrLit + `, ` + goStrLit + `\)`)
	total := 0
	for _, name := range files {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)
		if hits := threeArg.FindAllString(text, -1); len(hits) > 0 {
			shown := hits
			if len(shown) > 3 {
				shown = shown[:3]
			}
			t.Errorf("%s 出现 %d 处三参 Register（英文译文不得留在后端）: %v", name, len(hits), shown)
		}
		total += len(catalogEntryRe.FindAllString(text, -1))
	}
	if total < 1000 {
		t.Fatalf("目录只扫到 %d 条 Register——扫描面异常，守卫会假绿", total)
	}
}
