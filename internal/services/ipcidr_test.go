package services

import (
	"net"
	"reflect"
	"strings"
	"testing"

	"lazy-balancer-v2/wafiplist"
)

func TestNormalizeCIDRsAcceptsBareIPs(t *testing.T) {
	got, err := NormalizeCIDRs([]string{"192.168.1.5", "2001:db8::1", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.1.5/32", "2001:db8::1/128", "10.0.0.0/8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeCIDRs()=%v, want %v", got, want)
	}
}

func TestNormalizeCIDRsRejectsInvalidCIDR(t *testing.T) {
	if _, err := NormalizeCIDRs([]string{"not-an-ip"}); err == nil {
		t.Fatal("NormalizeCIDRs() error=nil, want validation error")
	}
}

func TestNormalizeCIDRs_MappedAndCanonicalForms(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     string
		contains []string
	}{
		{name: "bare IPv4", input: "192.0.2.9", want: "192.0.2.9/32", contains: []string{"192.0.2.9"}},
		{name: "IPv4 CIDR masks host bits", input: "192.0.2.129/24", want: "192.0.2.0/24", contains: []string{"192.0.2.9"}},
		{name: "bare IPv6", input: "2001:db8::1", want: "2001:db8::1/128", contains: []string{"2001:db8::1"}},
		{name: "IPv6 CIDR masks host bits", input: "2001:db8::1/64", want: "2001:db8::/64", contains: []string{"2001:db8::2"}},
		{name: "mapped bare dotted", input: "::ffff:203.0.113.7", want: "203.0.113.7/32", contains: []string{"203.0.113.7"}},
		{name: "mapped bare hexadecimal", input: "::ffff:cb00:7107", want: "203.0.113.7/32", contains: []string{"203.0.113.7"}},
		{name: "mapped CIDR dotted", input: "::ffff:203.0.113.7/120", want: "203.0.113.0/24", contains: []string{"203.0.113.7"}},
		{name: "mapped CIDR hexadecimal", input: "::ffff:cb00:7107/120", want: "203.0.113.0/24", contains: []string{"203.0.113.7"}},
		{name: "mapped host CIDR", input: "::ffff:203.0.113.7/128", want: "203.0.113.7/32", contains: []string{"203.0.113.7"}},
		{name: "mapped whole IPv4 CIDR", input: "::ffff:0.0.0.0/96", want: "0.0.0.0/0", contains: []string{"203.0.113.7"}},
		{name: "non-mapped IPv6 remains IPv6", input: "::1", want: "::1/128", contains: []string{"::1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Given one real net. input shape.
			// When normalizing the whitelist entry.
			got, err := NormalizeCIDRs([]string{tc.input})
			if err != nil {
				t.Fatalf("NormalizeCIDRs(%q): %v", tc.input, err)
			}
			if !reflect.DeepEqual(got, []string{tc.want}) {
				t.Fatalf("NormalizeCIDRs(%q)=%v, want [%s]", tc.input, got, tc.want)
			}
			// Then the persisted value must be accepted by the execution side's
			// actual parser and match the intended client address family.
			_, network, err := net.ParseCIDR(got[0])
			if err != nil {
				t.Fatalf("net.ParseCIDR(normalized %q): %v", got[0], err)
			}
			for _, clientIP := range tc.contains {
				if !network.Contains(net.ParseIP(clientIP)) {
					t.Fatalf("normalized network %q does not contain %s", got[0], clientIP)
				}
			}
		})
	}
}

func TestNormalizeCIDRs_RejectsMalformedMappedPrefixes(t *testing.T) {
	for _, input := range []string{
		"::ffff:192.0.2.1/95",
		"::ffff:192.0.2.1/129",
		"::ffff:192.0.2.1/24",
		"fe80::1%eth0",
		"",
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := NormalizeCIDRs([]string{input}); err == nil {
				t.Fatalf("NormalizeCIDRs(%q) error=nil, want validation error", input)
			}
		})
	}
}

// 重复条目去重：库内条数必须与审计 delta 的「N 条」同源（重复 CIDR 无匹配
// 语义差异，保留重复会让「提交 2 个相同地址 → 审计 2 条 / 库内 2 条」与
// 用户直觉不符，也放大列表噪声）。
func TestNormalizeCIDRs_dedupesEquivalentEntries(t *testing.T) {
	got, err := NormalizeCIDRs([]string{"1.2.3.4", "1.2.3.4/32", " 1.2.3.4 ", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NormalizeCIDRs: %v", err)
	}
	want := []string{"1.2.3.4/32", "10.0.0.0/8"}
	if len(got) != len(want) {
		t.Fatalf("NormalizeCIDRs()=%v, want %v（重复条目去重）", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("NormalizeCIDRs()=%v, want %v（顺序保持）", got, want)
		}
	}
}

// 底层解析原因必须透传：只回「不是有效 CIDR」让用户无法区分「多了个空格/
// 掩码越界/IPv6 写成 v4」等形态——400 文案与日志都要带 %w 链上的原始错误。
func TestNormalizeCIDRs_invalidEntryCarriesUnderlyingReason(t *testing.T) {
	const entry = "not-an-ip"
	_, reasonErr := wafiplist.ParseIPEntry(entry)
	if reasonErr == nil {
		t.Fatal("前置失效：ParseIPEntry 应拒绝该条目")
	}
	_, err := NormalizeCIDRs([]string{entry})
	if err == nil {
		t.Fatal("NormalizeCIDRs() error=nil, want validation error")
	}
	if !strings.Contains(err.Error(), "不是有效 CIDR") {
		t.Fatalf("err=%q, want 保留「不是有效 CIDR」主文案", err)
	}
	if want := reasonErr.Error(); !strings.Contains(err.Error(), want) {
		t.Fatalf("err=%q, want 底层原因 %q 经 %%w 透传", err, want)
	}
}
