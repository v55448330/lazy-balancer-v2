package i18n

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// RED:语言协商——Accept-Language 解析,仅支持 zh/en,默认 zh。
func TestNegotiate(t *testing.T) {
	cases := []struct{ header, want string }{
		{"", "zh"},
		{"zh-CN,zh;q=0.9", "zh"},
		{"en-US,en;q=0.9", "en"},
		{"fr-FR,zh-CN;q=0.7,en;q=0.8", "en"}, // 权重优先
		{"ja-JP", "zh"},                      // 未支持语言回落默认
		{"EN", "en"},                         // 大小写不敏感
	}
	for _, c := range cases {
		if got := Negotiate(c.header); got != c.want {
			t.Errorf("Negotiate(%q)=%q want %q", c.header, got, c.want)
		}
	}
}

// RED:目录查词——命中返回对应语言,缺译回落中文。
func TestCatalogLookup(t *testing.T) {
	Register("t.hello", "你好", "hello")
	if got := T("zh", "t.hello"); got != "你好" {
		t.Errorf("zh=%q", got)
	}
	if got := T("en", "t.hello"); got != "hello" {
		t.Errorf("en=%q", got)
	}
	if got := T("en", "t.missing"); got != "t.missing" {
		t.Errorf("缺译应回落 key 本身, got %q", got)
	}
}

// RED:错误模板匹配——服务层中文错误串按模板(含占位符)翻成英文,未命中原样返回。
func TestErrTemplate(t *testing.T) {
	RegisterErrTpl("规则 %s 不存在", "rule %s does not exist")
	RegisterErrTpl("端口被占用", "port already in use")
	if got := TrErr("端口被占用", "en"); got != "port already in use" {
		t.Errorf("exact=%q", got)
	}
	if got := TrErr(`规则 "web" 不存在`, "en"); got != `rule "web" does not exist` {
		t.Errorf("template=%q", got)
	}
	if got := TrErr("完全未知的内容", "en"); got != "完全未知的内容" {
		t.Errorf("未命中应原样, got %q", got)
	}
	if got := TrErr("端口被占用", "zh"); got != "端口被占用" {
		t.Errorf("zh 原样=%q", got)
	}
}

// catalog 唯一性守卫——重复 Register(同键)为 map 覆盖语义,
// 单边编辑副本会静默分叉。守卫必须对 Register 调用计数(生成文件里
// 重复的 Register 行),而不是遍历 map 键(map 键天然唯一,恒真)。
func TestCatalogKeysUnique(t *testing.T) {
	source, err := os.ReadFile("catalog_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	dups := 0
	for _, line := range strings.Split(string(source), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Register(") {
			continue
		}
		key := strings.TrimPrefix(line, "Register(")
		if i := strings.IndexByte(key, ','); i >= 0 {
			key = key[:i]
		}
		key = strings.Trim(key, `"`)
		if seen[key] {
			dups++
			continue
		}
		seen[key] = true
	}
	if len(seen) == 0 {
		t.Fatal("catalog_gen.go 未扫到任何 Register 调用——守卫对象漂移")
	}
	if dups != 0 {
		t.Fatalf("catalog_gen.go 存在 %d 处重复 Register 键——单边编辑副本将静默分叉", dups)
	}
}

// 生成管线的转义回归:含双引号的词条在用户侧必须是裸引号,
// 不得出现反斜杠(双重转义会让用户看到 {\"all\": true})。
func TestCatalogQuotedEntriesRenderWithoutBackslashes(t *testing.T) {
	for _, key := range []string{"k_a1f26fc3", "k_d2bed58b"} {
		for _, lang := range []string{ZH, EN} {
			got := T(lang, key)
			if strings.Contains(got, `\`) {
				t.Errorf("T(%q,%q)=%q 含反斜杠——词条被双重转义", lang, key, got)
			}
		}
	}
	if got := T(ZH, "k_a1f26fc3"); !strings.Contains(got, `{"all": true}`) {
		t.Errorf("zh 词条应含裸引号 JSON 示例, got %q", got)
	}
}

// 错误模板 zh/en 占位符数量必须一致:不一致时 matchTpl 恒不命中,
// 英文用户永远回落中文。反斜杠示例必须保留字面量 \$(单反斜杠)。
func TestErrTplPlaceholderParity(t *testing.T) {
	source, err := os.ReadFile("errtpl_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`RegisterErrTpl\((".*?"), (".*?")\)`)
	matches := re.FindAllStringSubmatch(string(source), -1)
	if len(matches) == 0 {
		t.Fatal("errtpl_gen.go 未扫到任何 RegisterErrTpl——守卫对象漂移")
	}
	for _, m := range matches {
		zh, err1 := strconv.Unquote(m[1])
		en, err2 := strconv.Unquote(m[2])
		if err1 != nil || err2 != nil {
			t.Fatalf("字面量解码失败: %v / %v", err1, err2)
		}
		if nz, ne := strings.Count(zh, "%s"), strings.Count(en, "%s"); nz != ne {
			t.Errorf("占位符数不一致 zh=%d en=%d: %q", nz, ne, zh)
		}
	}
}

// 运行时形状:带百分号字面量的服务层错误(可解析率/宏语法)必须能翻成英文。
func TestTrErr_percentLiteralTemplatesTranslate(t *testing.T) {
	cases := []struct{ msg, want string }{
		{"可解析行比例 3/10 低于 50%——疑似错页或劫持", "parseable line ratio 3/10 is below 50%——error page or hijack suspected"},
		{"威胁名单 feed-a 文本可解析率 3/10 低于 50% 且 .fast 不可读: boom", "threat list feed-a text parseable ratio 3/10 below 50% and the .fast is unreadable: boom"},
		{"威胁名单 feed-a 文本可解析率 3/10 低于 50% 且无 .fast 可回退（等待下次威胁库更新重建）", "threat list feed-a text parseable ratio 3/10 below 50% and no .fast to fall back to（waiting for the next threat feed update to rebuild）"},
		{"威胁名单 feed-a 的 .fast 不可读且文本可解析率 3/10 低于 50%: boom", "the .fast of threat list feed-a is unreadable and its text parseable ratio 3/10 is below 50%: boom"},
		{"该运算符不支持 %{...} 宏语法；如需匹配字面量请使用正则运算符并转义 %", "this operator does not support %{...} macro syntax; to match a literal, use the regex operator and escape %"},
	}
	for _, c := range cases {
		if got := TrErr(c.msg, EN); got != c.want {
			t.Errorf("TrErr(%q)=%q, want %q", c.msg, got, c.want)
		}
	}
}

// 反斜杠结尾提示:zh 母本与 en 译文都必须保留字面量 \$ 示例(单反斜杠),
// 且 zh 原文精确命中(服务层错误串与模板逐字一致)。
func TestTrErr_backslashHintPreservesLiteral(t *testing.T) {
	zhMsg := "该运算符不支持以反斜杠结尾的匹配内容，请改用正则运算符（如 `\\$`）表达"
	if got := TrErr(zhMsg, ZH); got != zhMsg {
		t.Fatalf("zh 原样=%q", got)
	}
	got := TrErr(zhMsg, EN)
	if !strings.Contains(got, "`\\$`") {
		t.Fatalf("en=%q, want 含字面量 `\\$` 示例", got)
	}
	if strings.Contains(got, `\\`) {
		t.Fatalf("en=%q 含双反斜杠——示例被双重转义", got)
	}
}

// q 值解析:集外 q(0.3/0.95 等)必须按真实权重排序,不得默认 1.0;
// 非法/越界 q 钳到 [0,1]。
func TestNegotiate_qValues(t *testing.T) {
	cases := []struct{ header, want string }{
		{"zh;q=0.3,en;q=0.8", EN},   // 集外 q:0.8 > 0.3
		{"en;q=0.2,zh;q=0.9", ZH},   // 0.9 > 0.2
		{"zh;q=0.95,en;q=0.96", EN}, // 两位小数
		{"en;q=0,zh;q=0.1", ZH},     // q=0 不选
		{"zh;q=abc,en;q=0.5", EN},   // 非法 q 按 0 处理,不得默认 1.0
		{"zh;q=2,en;q=0.5", ZH},     // 越界钳到 1
		{"en;q=-1,zh;q=0.1", ZH},    // 负值钳到 0
	}
	for _, c := range cases {
		if got := Negotiate(c.header); got != c.want {
			t.Errorf("Negotiate(%q)=%q want %q", c.header, got, c.want)
		}
	}
}
