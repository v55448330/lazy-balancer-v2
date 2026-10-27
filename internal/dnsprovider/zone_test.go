package dnsprovider

import "testing"

// zone 解析单源。输入域用于 challenge FQDN，provider 调用
// 必须用可注册根域（PSL）；两层后缀（co.uk）、委派子域与非法输入在此固化语义。
func TestResolveZone_table(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "root domain", input: "example.com", want: "example.com"},
		{name: "www subdomain", input: "www.example.com", want: "example.com"},
		{name: "deep subdomain", input: "a.b.example.com", want: "example.com"},
		{name: "trailing dot", input: "www.example.com.", want: "example.com"},
		{name: "surrounding spaces", input: "  www.example.com  ", want: "example.com"},
		{name: "two-level suffix", input: "www.example.co.uk", want: "example.co.uk"},
		{name: "two-level suffix with trailing dot", input: "api.example.com.cn.", want: "example.com.cn"},
		// 委派子区（账户实际 zone 为 sub.example.com）PSL 不可见——仍按可注册域
		// 解析；委派区需显式配置。
		{name: "delegated subdomain stays PSL", input: "api.sub.example.com", want: "example.com"},
		{name: "single label fallback", input: "localhost", want: "localhost"},
		// DNS 名大小写不敏感：zone 归一必须小写，否则 provider 侧
		// Domain.List 返回的规范形态（小写）无法命中，混合大小写输入会把
		// 「域名合法但大小写不同」误导成「域名不在账户」。
		{name: "mixed case", input: "WWW.Example.COM", want: "example.com"},
		{name: "mixed case with trailing dot", input: "API.Example.Co.UK.", want: "example.co.uk"},
		{name: "mixed case single label", input: "LocalHost", want: "localhost"},
		{name: "unknown tld fallback", input: "host.example.internal", want: "example.internal"},
		{name: "empty", input: "", wantErr: true},
		{name: "dot only", input: ".", wantErr: true},
		{name: "empty label", input: "www..example.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveZone(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ResolveZone(%q)=%q, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveZone(%q): %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("ResolveZone(%q)=%q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// 公共后缀判定（PSL 单源）：多标签公共后缀与单标签 TLD 都必须命中，注册域
// （eTLD+1）与更深子域必须不命中。ACME 权威 NS 上溯用该判据拒绝注册局服务器。
func TestIsPublicSuffix(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"com", true},
		{"co.uk", true},
		{"com.cn", true},
		{"", true},
		{"example.com", false},
		{"foo.co.uk", false},
		{"a.b.example.com.cn", false},
		{"API.Example.CO.UK", false}, // 大小写不敏感：归一后仍是非后缀
		{"Co.UK", true},
	}
	hit := 0
	for _, testCase := range cases {
		if got := IsPublicSuffix(testCase.name); got != testCase.want {
			t.Errorf("IsPublicSuffix(%q)=%v, want %v", testCase.name, got, testCase.want)
		}
		if testCase.want {
			hit++
		}
	}
	if hit == 0 {
		t.Fatal("用例集缺少公共后缀样本——判定退化时本测试不会红")
	}
}
