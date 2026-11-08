package i18n

import "testing"

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
