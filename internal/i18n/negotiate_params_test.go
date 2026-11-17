package i18n

import "testing"

// q 参数可出现在分号分隔的任意位置（RFC 9110 的 Accept-Language 扩展参数
// 不保证 q 在首段）：此前只识别分段首个参数，"en;foo=bar;q=0.9" 被按 1.0
// 权重处理，语言排序失真。
func TestNegotiate_qParameterInAnyPosition(t *testing.T) {
	cases := []struct{ header, want string }{
		{"en;foo=bar;q=0.2,zh;q=0.9", ZH},
		{"zh;foo=bar;q=0.2,en;q=0.9", EN},
		{"en;q=0.2;foo=bar,zh;q=0.9", ZH}, // q 在首段仍须识别（回归形状）
		{"zh;foo=bar,en;q=0.5", ZH},       // 无 q 分段按 1.0（回归形状）
	}
	for _, c := range cases {
		if got := negotiate(c.header); got != c.want {
			t.Errorf("negotiate(%q)=%q want %q", c.header, got, c.want)
		}
	}
}

// RFC 9110：q=0 显式声明「不可接受」——q=0 候选不得参与择优；全零候选
// 回落默认 zh（此前 q=0 仍按 score≈0 参与择优，"en;q=0" 返回 en）。
func TestNegotiate_zeroQualityNotAcceptable(t *testing.T) {
	cases := []struct{ header, want string }{
		{"en;q=0", ZH},
		{"en;q=0,zh;q=0", ZH},
		{"zh;q=0,en;q=0.0", ZH},
		{"fr-FR;q=0,en;q=0", ZH},
		{"en;q=0,zh;q=0.1", ZH}, // 回归形状：正权重候选仍正常择优
		{"en;q=0.1,zh;q=0", EN}, // q=0 的 zh 被拒，正权重 en 胜出
	}
	for _, c := range cases {
		if got := negotiate(c.header); got != c.want {
			t.Errorf("negotiate(%q)=%q want %q", c.header, got, c.want)
		}
	}
}

// RFC 9110 参数名大小写不敏感：Q= 与 q= 同义。此前参数名前缀比较
// 大小写敏感，"zh;Q=0.3" 被按缺 q 默认 1.0，语言排序失真。
func TestNegotiate_qParameterNameCaseInsensitive(t *testing.T) {
	cases := []struct{ header, want string }{
		{"zh;Q=0.3,en;q=0.8", EN},
		{"en;Q=0.2,zh;q=0.9", ZH},
		{"zh;foo=bar;Q=0.2,en;q=0.9", EN}, // 大写 Q 在任意参数位
		{"en;Q=0", ZH},                    // 大写 Q=0 同样声明不可接受
		{"en;q=0.2,zh;q=0.9", ZH},         // 小写回归形状
	}
	for _, c := range cases {
		if got := negotiate(c.header); got != c.want {
			t.Errorf("negotiate(%q)=%q want %q", c.header, got, c.want)
		}
	}
}
