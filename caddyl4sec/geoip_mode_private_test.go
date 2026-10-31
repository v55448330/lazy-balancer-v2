package caddyl4sec

// L4 GeoIP matcher 语义扩展回归测试：
//  1. 私网/回环/链路本地源连接一律不匹配（豁免层，与 HTTP 链首私网豁免对齐；
//     此前这些地址经 xdb Reserved 行归「海外」，allow 模式 not 包裹会断连）。
//  2. Mode 字段：matcher 直接表达「连接应否断连」的阻断谓词——deny 模式
//     归属∈名单命中；allow 模式归属∈名单不命中、名单外命中。查库失败/
//     不可判定恒不匹配（fail-open，放行落回 proxy 路由）——allow 模式不再
//     由渲染侧 not 包裹（not 会把 matcher 失败反转为断连，违反 fail-open）。
import (
	"context"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestGeoIPMatcherPrivateRangesExempt(t *testing.T) {
	xdb := findTestXdb()
	if xdb == "" {
		t.Skip("no ip2region xdb available")
	}
	m := newMatcherForTest(t, xdb, []string{"海外"})
	ips := []string{"192.168.1.1", "10.0.0.5", "172.16.3.4", "127.0.0.1", "169.254.9.9"}
	for _, ip := range ips {
		got, err := m.Match(newTestConn(ip))
		if err != nil {
			t.Fatalf("Match(%s) err = %v, want nil", ip, err)
		}
		if got {
			t.Fatalf("Match(%s) = true, want false（私网豁免）", ip)
		}
	}
}

// newMatcherForTestMode 按 Mode 构造并 Provision（Mode 必须在 Provision 前
// 设置——Provision 期归一为谓词方向）。
func newMatcherForTestMode(t *testing.T, xdb string, countries []string, mode string) *L4GeoIPMatcher {
	t.Helper()
	m := &L4GeoIPMatcher{Countries: countries, XdbPath: xdb, Mode: mode}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("provision matcher: %v", err)
	}
	return m
}

func TestGeoIPMatcherAllowModePredicate(t *testing.T) {
	xdb := findTestXdb()
	if xdb == "" {
		t.Skip("no ip2region xdb available")
	}
	m := newMatcherForTestMode(t, xdb, []string{"海外"}, "allow")
	// 名单内（海外：8.8.8.8）→ 不断连（不匹配）。
	if got, _ := m.Match(newTestConn("8.8.8.8")); got {
		t.Fatal("allow 模式：归属在名单内应放行（Match=false）")
	}
	// 名单外（国内：114.114.114.114）→ 断连（匹配）。
	if got, _ := m.Match(newTestConn("114.114.114.114")); !got {
		t.Fatal("allow 模式：归属在名单外应断连（Match=true）")
	}
}

func TestGeoIPMatcherAllowModeFailsOpenOnLookupError(t *testing.T) {
	xdb := findTestXdb()
	if xdb == "" {
		t.Skip("no ip2region xdb available")
	}
	// 缺库（searcher=nil）+ allow 模式：fail-open 放行，不得断连。
	m := newMatcherForTestMode(t, filepath.Join(t.TempDir(), "missing.xdb"), []string{"中国"}, "allow")
	if got, _ := m.Match(newTestConn("8.8.8.8")); got {
		t.Fatal("allow 模式查库失败应 fail-open（Match=false），不得断连")
	}
	// IPv6 对 v4-only 库：查询失败 → 放行。
	m2 := newMatcherForTestMode(t, xdb, []string{"中国"}, "allow")
	if got, _ := m2.Match(newTestConn("2001:db8::1")); got {
		t.Fatal("allow 模式 IPv6 查库失败应 fail-open（Match=false），不得断连")
	}
}

func TestGeoIPMatcherDenyModePredicateUnchanged(t *testing.T) {
	xdb := findTestXdb()
	if xdb == "" {
		t.Skip("no ip2region xdb available")
	}
	// Mode 缺省=deny：命中名单断连（既有语义，字节不变）。
	m := newMatcherForTest(t, xdb, []string{"海外"})
	if got, _ := m.Match(newTestConn("8.8.8.8")); !got {
		t.Fatal("deny 模式：海外命中应断连（Match=true）")
	}
	if got, _ := m.Match(newTestConn("114.114.114.114")); got {
		t.Fatal("deny 模式：国内不命中应放行（Match=false）")
	}
}
