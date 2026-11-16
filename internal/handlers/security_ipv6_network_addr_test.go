package handlers

// IPv6 裸网络地址（/64 host 位全零）不得作为名单条目：ACL 按单主机匹配只封
// 网络地址本身，而自动封禁身份键把该值归一为 /64——同键命中后整段自动封禁
// 被永久抑制。整段封禁意图必须显式 CIDR。

import "testing"

func TestValidIPOrCIDR_rejectsBareIPv6NetworkAddress(t *testing.T) {
	for _, tc := range []struct {
		entry string
		want  bool
	}{
		{"2001:db8::", false},           // /64 网络地址（host 位全零）
		{"2001:db8:1234:5678::", false}, // 另一 /64 网络地址
		{"::", false},                   //  unspecified（host 位全零）
		{"2001:db8::1", true},           // 合法主机地址
		{"2001:db8::ffff", true},        // host 位非零
		{"2001:db8::/64", true},         // 显式 CIDR（整段封禁正确形态）
		{"2001:db8::/128", true},        // 单主机 CIDR
		{"fe80::1", true},               // 链路本地主机地址
		{"192.168.1.1", true},           // IPv4 不受影响
		{"10.0.0.0", true},              // IPv4 网络地址形态不拦（v4 身份键不归一）
		{"10.0.0.0/8", true},            // IPv4 CIDR
		{"fe80::1%eth0", false},         // zone 形态既有拒绝
		{"not-an-ip", false},            // 非法值
	} {
		if got := validIPOrCIDR(tc.entry); got != tc.want {
			t.Errorf("validIPOrCIDR(%q)=%v, want %v", tc.entry, got, tc.want)
		}
	}
}
