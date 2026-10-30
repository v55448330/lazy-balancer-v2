package caddyl4sec

import (
	"context"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

// testXdbCandidates 与 caddygeoip 同源：仓库夹具优先，容器路径兜底。
var testXdbCandidates = []string{
	filepath.Join("..", "caddygeoip", "testdata", "ip2region_v4.xdb"),
	"/app/data/ip2region.xdb",
}

func findTestXdb() string {
	for _, p := range testXdbCandidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// addrOnlyConn 只提供 RemoteAddr 的最小 net.Conn：matcher 与 handler 的取值面
// 只消费对端地址（Match/Handle 不读写连接字节——读写在 proxy/close）。
type addrOnlyConn struct {
	net.Conn
	remote net.Addr
}

func (c addrOnlyConn) RemoteAddr() net.Addr { return c.remote }

func tcpAddr(ip string) net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: 53981}
}

func newTestConn(ip string) *layer4.Connection {
	return &layer4.Connection{Conn: addrOnlyConn{remote: tcpAddr(ip)}, Context: context.Background()}
}

func newMatcherForTest(t *testing.T, xdb string, countries []string) *L4GeoIPMatcher {
	t.Helper()
	m := &L4GeoIPMatcher{Countries: countries, XdbPath: xdb}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("provision matcher: %v", err)
	}
	return m
}

// TestGeoIPMatcherModuleID 锁定契约 C2 模块 ID（主审契约：不得改名）。
func TestGeoIPMatcherModuleID(t *testing.T) {
	m := &L4GeoIPMatcher{}
	info := m.CaddyModule()
	if info.ID != "layer4.matchers.lb_geoip" {
		t.Fatalf("matcher module ID = %q, want layer4.matchers.lb_geoip（契约 C2）", info.ID)
	}
	var _ layer4.ConnMatcher = m
}

// TestGeoIPMatcherConfigValidation 畸形 config 显性报错：空名单/空条目在
// Provision 即拒绝，不得静默降级成「永不命中的地域路由」。
func TestGeoIPMatcherConfigValidation(t *testing.T) {
	cases := []struct {
		name      string
		countries []string
		wantErr   bool
	}{
		{"empty countries", nil, true},
		{"blank entry", []string{"  "}, true},
		{"valid mixed", []string{"广东省", "江苏省/南京市", "United States", "海外"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &L4GeoIPMatcher{Countries: tc.countries}
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			err := m.Provision(ctx)
			if tc.wantErr && err == nil {
				t.Fatalf("Provision() = nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Provision() = %v, want nil", err)
			}
		})
	}
}

// TestGeoIPMatcherMatch 命中/未命中矩阵：省条目前缀语义（省/省-市）、
// 「省/市」精确条目、海外国名精确、海外哨兵（已解析海外行 + Reserved 行）。
func TestGeoIPMatcherMatch(t *testing.T) {
	xdb := findTestXdb()
	if xdb == "" {
		t.Skip("no ip2region xdb available")
	}
	cases := []struct {
		name      string
		countries []string
		ip        string
		want      bool
	}{
		{"province entry prefix-hits province/city loc", []string{"江苏省"}, "114.114.114.114", true},
		{"province/city entry exact-hits", []string{"江苏省/南京市"}, "114.114.114.114", true},
		{"province/city entry misses other city", []string{"江苏省/苏州市"}, "114.114.114.114", false},
		{"foreign country name hits", []string{"United States"}, "8.8.8.8", true},
		{"foreign country name misses domestic", []string{"United States"}, "114.114.114.114", false},
		{"overseas sentinel hits resolved foreign", []string{"海外"}, "8.8.8.8", true},
		{"overseas sentinel misses domestic", []string{"海外"}, "114.114.114.114", false},
		{"overseas sentinel hits Reserved row (loc=海外)", []string{"海外"}, "203.0.113.10", true},
		{"domestic country misses foreign", []string{"中国"}, "8.8.8.8", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMatcherForTest(t, xdb, tc.countries)
			got, err := m.Match(newTestConn(tc.ip))
			if err != nil {
				t.Fatalf("Match() err = %v, want nil", err)
			}
			if got != tc.want {
				t.Fatalf("Match(%s, %v) = %v, want %v", tc.ip, tc.countries, got, tc.want)
			}
		})
	}
}

// TestGeoIPMatcherFailOpen 缺库/查库失败 → fail-open（返回不匹配，不返回
// error——用户裁定：地理库不可用时地域路由静默放行，不得 fail-closed 全断）。
func TestGeoIPMatcherFailOpen(t *testing.T) {
	m := newMatcherForTest(t, filepath.Join(t.TempDir(), "missing.xdb"), []string{"江苏省"})
	got, err := m.Match(newTestConn("114.114.114.114"))
	if err != nil {
		t.Fatalf("missing db: Match() err = %v, want nil (fail-open)", err)
	}
	if got {
		t.Fatal("missing db: Match() = true, want false (fail-open)")
	}
}

// TestGeoIPMatcherUnresolvableIP 对端地址不可解析（空/unix socket/IPv6 对
// v4-only 库查询失败）→ fail-open 不匹配、无 error。
func TestGeoIPMatcherUnresolvableIP(t *testing.T) {
	xdb := findTestXdb()
	if xdb == "" {
		t.Skip("no ip2region xdb available")
	}
	m := newMatcherForTest(t, xdb, []string{"海外"})
	cases := []struct {
		name string
		cx   *layer4.Connection
	}{
		{"empty remote", newTestConn("")},
		{"ipv6 on v4-only db", newTestConn("2001:db8::1")},
		{"unix addr", &layer4.Connection{Conn: addrOnlyConn{remote: &net.UnixAddr{Name: "/tmp/s.sock", Net: "unix"}}, Context: context.Background()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := m.Match(tc.cx)
			if err != nil {
				t.Fatalf("Match() err = %v, want nil", err)
			}
			if got {
				t.Fatal("Match() = true, want false")
			}
		})
	}
}

// TestParseRegionLoc 归一 Loc 计算：国内=省 或 省/市（城市列无效时退化省）、
// 海外=归一国名、Reserved/未知=海外哨兵、缺列行解析失败。
func TestParseRegionLoc(t *testing.T) {
	cases := []struct {
		region  string
		ok      bool
		country string
		loc     string
	}{
		// 本仓 xdb 行形态：国家|省|市|区县|国家代码（与 caddygeoip 同夹具实证）。
		{"中国|江苏省|南京市|0|CN", true, "中国", "江苏省/南京市"},
		{"中国|江苏省|0|0|CN", true, "中国", "江苏省"},
		{"United States|California|0|Google LLC|US", true, "United States", "United States"},
		{"Reserved|Reserved|Reserved|0|0", true, "", "海外"},
		{"中国|0|0|0|CN", true, "中国", ""},
		{"short|row", false, "", ""},
	}
	for _, tc := range cases {
		f, ok := parseRegionRow(tc.region)
		if ok != tc.ok {
			t.Fatalf("parseRegionRow(%q) ok = %v, want %v", tc.region, ok, tc.ok)
		}
		if !ok {
			continue
		}
		if f.country != tc.country {
			t.Errorf("parseRegionRow(%q).country = %q, want %q", tc.region, f.country, tc.country)
		}
		if f.loc != tc.loc {
			t.Errorf("parseRegionRow(%q).loc = %q, want %q", tc.region, f.loc, tc.loc)
		}
	}
}

// TestCountryKeyNormalization 统计桶国家键与 HTTP 流量桶同域：「中国」保留、
// Reserved/空/0 归空（不入桶）、海外行发规范英文名。
func TestCountryKeyNormalization(t *testing.T) {
	cases := map[string]string{
		"中国":            "中国",
		"United States": "United States",
		"Reserved":      "",
		"":              "",
		"0":             "",
	}
	for raw, want := range cases {
		if got := normalizeCountryKey(raw); got != want {
			t.Errorf("normalizeCountryKey(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestSharedSearcherSingleton 同路径共享一份 searcher（fd 治理）：两次获取返回
// 同一实例；文件形态变化（touch mtime）触发重建。
func TestSharedSearcherSingleton(t *testing.T) {
	xdb := findTestXdb()
	if xdb == "" {
		t.Skip("no ip2region xdb available")
	}
	s1, err := sharedGeoIPSearcher(xdb)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	s2, err := sharedGeoIPSearcher(xdb)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if s1 != s2 {
		t.Fatal("same path returned different searcher instances (fd leak)")
	}
}

// TestGeoipLocMatches 地域条目匹配语义与 HTTP 侧 geoipLocOperator 同构：
// 含「/」条目精确、其余前缀（条目 或 条目/后缀）、海外哨兵按解析国名判定。
func TestGeoipLocMatches(t *testing.T) {
	type row struct {
		country string
		loc     string
	}
	cases := []struct {
		name      string
		client    row
		countries []string
		want      bool
	}{
		{"prefix hit city suffix", row{"中国", "江苏省/南京市"}, []string{"江苏省"}, true},
		{"exact province hit", row{"中国", "江苏省"}, []string{"江苏省"}, true},
		{"slash entry exact", row{"中国", "江苏省/南京市"}, []string{"江苏省/南京市"}, true},
		{"slash entry miss other city", row{"中国", "江苏省/苏州市"}, []string{"江苏省/南京市"}, false},
		{"foreign exact", row{"United States", "United States"}, []string{"United States"}, true},
		{"overseas hits foreign resolved", row{"United States", "United States"}, []string{"海外"}, true},
		{"overseas misses domestic", row{"中国", "江苏省"}, []string{"海外"}, false},
		{"no hit", row{"中国", "江苏省"}, []string{"广东省", "United States"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := geoipLocMatches(tc.client.country, tc.client.loc, tc.countries); got != tc.want {
				t.Fatalf("geoipLocMatches(%q/%q, %v) = %v, want %v", tc.client.country, tc.client.loc, tc.countries, got, tc.want)
			}
		})
	}
}

// 防呆：模块用到的十六进制编码宽度恒为 8（4 字节 nonce），契约示例逐字依赖。
func TestNonceHexWidth(t *testing.T) {
	var nonce [4]byte = l4EventNonce()
	if got := len(hex.EncodeToString(nonce[:])); got != 8 {
		t.Fatalf("nonce hex width = %d, want 8", got)
	}
}
