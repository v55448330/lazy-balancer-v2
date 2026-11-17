package i18n

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// catalog/errtpl 守卫共用的调用扫描器:两个生成文件的登记调用形状唯一,
// 判据测试与占位符对齐测试共用同一扫描口径,避免各写一份正则漂移。
// 字符串组必须用 Go 字面量完整形态 "(?:[^"\\]|\\.)*":惰性 ".*?" 遇
// 词条内部 \") 序列会提前闭合捕获组,截断字面量无法解码、尾部判据失明。
const goStrLit = `"(?:[^"\\]|\\.)*"`

var (
	catalogEntryRe = regexp.MustCompile(`Register\(` + goStrLit + `, (` + goStrLit + `), (` + goStrLit + `)\)`)
	errTplEntryRe  = regexp.MustCompile(`RegisterErrTpl\((` + goStrLit + `), (` + goStrLit + `)\)`)
)

// 英文词条不得携带词间双空格（":  %s"、"Task restarted  %s" 等）——中文母本
// 不动。旧判据只认冒号后双空格，"restarted  %s" 这类词间形态漏网
// （前轮修了冒号族、词间残留 4 条）。判据：非空白字符之间的连续 ≥2
// 空格；行首缩进/行尾空白不属词间形态，不误报。
func TestCatalogEnglishEntriesNoDoubleSpaceAfterColon(t *testing.T) {
	source, err := os.ReadFile("catalog_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	matches := catalogEntryRe.FindAllStringSubmatch(string(source), -1)
	if len(matches) == 0 {
		t.Fatal("catalog_gen.go 未扫到任何 Register——守卫对象漂移")
	}
	wordDoubleSpace := regexp.MustCompile(`\S {2,}\S`)
	for _, m := range matches {
		en, err := strconv.Unquote(m[2])
		if err != nil {
			t.Fatalf("英文词条解码失败: %v", err)
		}
		if wordDoubleSpace.MatchString(en) {
			t.Errorf("英文词条含词间双空格: %q", en)
		}
	}
}

// 英文错误模板不得残留中文标点（全角括号/破折号等）——zh 母本保留中文标点。
func TestErrTplEnglishNoChinesePunctuation(t *testing.T) {
	source, err := os.ReadFile("errtpl_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	matches := errTplEntryRe.FindAllStringSubmatch(string(source), -1)
	if len(matches) == 0 {
		t.Fatal("errtpl_gen.go 未扫到任何 RegisterErrTpl——守卫对象漂移")
	}
	for _, m := range matches {
		en, err := strconv.Unquote(m[2])
		if err != nil {
			t.Fatalf("英文模板解码失败: %v", err)
		}
		if strings.Contains(en, "——") {
			t.Errorf("英文模板残留中文双破折号: %q", en)
		}
		if i := strings.IndexAny(en, "（）：，。；！？「」"); i >= 0 {
			t.Errorf("英文模板残留中文标点 %q: %q", en[i:i+3], en)
		}
	}
}

// 自动备份水位线关停守卫错误串必须登记英文模板（与同函数兄弟消息
// 「读取/更新自动备份水位线（槽 %s）失败」同口径）：句柄注销与已关闭句柄
// 两个显性失败面，英文用户不得回落中文。
func TestTrErr_autoBackupWatermarkShutdownGuardsTranslate(t *testing.T) {
	cases := []struct{ msg, want string }{
		{"推进自动备份水位线失败：数据库未初始化或已关闭", "failed to advance the auto-backup watermark: database not initialized or already closed"},
		{"推进自动备份水位线失败（数据库不可用）: disk I/O error", "failed to advance the auto-backup watermark (database unavailable): disk I/O error"},
	}
	for _, c := range cases {
		if got := TrErr(c.msg, EN); got != c.want {
			t.Errorf("TrErr(%q)=%q, want %q", c.msg, got, c.want)
		}
		if got := TrErr(c.msg, ZH); got != c.msg {
			t.Errorf("zh 应原样回落: TrErr(%q)=%q", c.msg, got)
		}
	}
}

// 扫描器必须完整捕获含转义引号的词条:惰性 ".*?" 遇词条内部的 \") 形态
// 会提前闭合捕获组,截断后的字面量以反斜杠结尾无法解码,词条尾部的
// 双空格/中文标点判据永远看不到。构造转义引号后带词间双空格的词条,
// 断言扫描器捕获完整原文且判据命中(钉消费终态,不只钉匹配数)。
func TestCatalogHygieneScannerHandlesEscapedQuotes(t *testing.T) {
	zh := `甲"x") 乙`
	en := `say "hi")  tail` // 转义引号序列之后的词间双空格
	src := "Register(" + strconv.Quote("k_esc") + ", " + strconv.Quote(zh) + ", " + strconv.Quote(en) + ")\n"
	ms := catalogEntryRe.FindAllStringSubmatch(src, -1)
	if len(ms) != 1 {
		t.Fatalf("含转义引号词条应被扫到 1 条, got %d", len(ms))
	}
	gotZh, err := strconv.Unquote(ms[0][1])
	if err != nil {
		t.Fatalf("zh 捕获被截断,解码失败: %v (raw=%s)", err, ms[0][1])
	}
	gotEn, err := strconv.Unquote(ms[0][2])
	if err != nil {
		t.Fatalf("en 捕获被截断,解码失败: %v (raw=%s)", err, ms[0][2])
	}
	if gotZh != zh || gotEn != en {
		t.Fatalf("捕获不完整: zh=%q en=%q, want %q / %q", gotZh, gotEn, zh, en)
	}
	if !regexp.MustCompile(`\S {2,}\S`).MatchString(gotEn) {
		t.Fatalf("完整捕获后词间双空格判据应命中: %q", gotEn)
	}
	// errtpl 扫描器同口径:转义引号模板同样不得截断。
	tplSrc := "RegisterErrTpl(" + strconv.Quote(zh) + ", " + strconv.Quote(en) + ")\n"
	tms := errTplEntryRe.FindAllStringSubmatch(tplSrc, -1)
	if len(tms) != 1 {
		t.Fatalf("含转义引号模板应被扫到 1 条, got %d", len(tms))
	}
	tplEn, err := strconv.Unquote(tms[0][2])
	if err != nil || tplEn != en {
		t.Fatalf("errtpl en 捕获不完整: %q err=%v, want %q", tplEn, err, en)
	}
}
