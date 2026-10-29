package db

import (
	"strings"
	"testing"
)

// CanonicalDomains 是证书域名的唯一规范化入口（写侧校验 + 任务入队 + 索引键），
// 但它此前没有任何直接单测：IDN→punycode、尾点剥离、多值去重、IP 拒绝四条
// 输出从未被钉住，实现漂移只能靠下游（ACME/证书任务）在真实签发时暴露。
func TestCanonicalDomains_normalizesAndDedupes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "大小写与尾点归一", in: "Example.COM.", want: "example.com"},
		{name: "IDN 转 punycode（真实值固化）", in: "中国.cn", want: "xn--fiqs8s.cn"},
		{name: "带变音符的 IDN", in: "bücher.example", want: "xn--bcher-kva.example"},
		{name: "多值去重且保留首次出现顺序", in: "a.com,A.COM,,b.com", want: "a.com,b.com"},
		{name: "各自剥离尾点后去重", in: "example.com.,WWW.Example.com", want: "example.com,www.example.com"},
		{name: "首尾空白与空段", in: "  a.com  ,  , b.com ", want: "a.com,b.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := CanonicalDomains(c.in)
			if err != nil {
				t.Fatalf("CanonicalDomains(%q) err=%v, want nil", c.in, err)
			}
			if got != c.want {
				t.Fatalf("CanonicalDomains(%q)=%q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestCanonicalDomains_rejectsIPAndEmpty(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr string
		// forbid 用于区分「专门的 IP 分支」与「恰好被 idna 拒掉」：后者随 idna
		// 版本/宽容度变化即静默放行（IP 会以 ACME 标识符入队，到签发期才失败）。
		forbid string
	}{
		{name: "IPv4 拒绝", in: "192.168.0.1", wantErr: "invalid domain", forbid: "idna"},
		{name: "混合值里出现 IP 整体拒绝", in: "a.com,10.0.0.1", wantErr: "invalid domain", forbid: "idna"},
		// IPv6 字面量带冒号，会被 idna 先在字符集层拒掉（同样是 fail-closed）；
		// 因此这里只钉拒绝，不钉分支归属。
		{name: "IPv6 拒绝", in: "::1", wantErr: "invalid domain"},
		{name: "空串拒绝", in: "", wantErr: "domain is empty"},
		{name: "只有分隔符与空白拒绝", in: " , , ", wantErr: "domain is empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := CanonicalDomains(c.in)
			if err == nil {
				t.Fatalf("CanonicalDomains(%q)=%q, want error", c.in, got)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("CanonicalDomains(%q) err=%v, want 含 %q", c.in, err, c.wantErr)
			}
			if c.forbid != "" && strings.Contains(err.Error(), c.forbid) {
				t.Fatalf("CanonicalDomains(%q) err=%v 落进了 idna 分支：IP 必须由显式判据拒绝（不得依赖 idna 的宽容度）", c.in, err)
			}
		})
	}
}
