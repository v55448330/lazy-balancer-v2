package caddygeoip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// testXdbCandidates lists locations that may hold an ip2region xdb for the
// lookup test; the test skips when none is present.
var testXdbCandidates = []string{
	"testdata/ip2region_v4.xdb",
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

func TestCaddyModule_registers_as_http_handlers_geoip2region(t *testing.T) {
	// When the module metadata is inspected
	info := (GeoIPHandler{}).CaddyModule()

	// Then the module ID and constructor are correct
	if string(info.ID) != "http.handlers.geoip2region" {
		t.Fatalf("module ID = %q, want %q", info.ID, "http.handlers.geoip2region")
	}
	if info.New == nil {
		t.Fatal("module New constructor is nil")
	}
	mod := info.New()
	if _, ok := mod.(caddy.Provisioner); !ok {
		t.Fatal("module does not implement caddy.Provisioner")
	}
	if _, ok := mod.(caddyhttp.MiddlewareHandler); !ok {
		t.Fatal("module does not implement caddyhttp.MiddlewareHandler")
	}
}

func TestProvision_missing_xdb_disables_lookups_and_passes_through(t *testing.T) {
	// Given a handler pointed at a database that does not exist
	h := &GeoIPHandler{XdbPath: filepath.Join(t.TempDir(), "missing.xdb")}

	// When it is provisioned
	if err := h.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision with missing xdb must not fail: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Cleanup(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	// Then lookups stay disabled and requests pass through untouched
	if h.searcher != nil {
		t.Fatal("searcher must stay nil when the xdb is missing")
	}

	repl := caddy.NewReplacer()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
	req.RemoteAddr = "114.114.114.114:53981"
	rec := httptest.NewRecorder()

	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
		return nil
	})

	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if !nextCalled {
		t.Fatal("next handler was not called")
	}
	// F49-P5-6：geoip.country_code 死发射已删除（fields[4]=ISP 列语义错位），
	// 任何路径都不得再产出该变量。
	if _, ok := repl.GetString("geoip.country_code"); ok {
		t.Fatal("geoip.country_code must not be published (dead emission removed)")
	}
}

func TestServeHTTP_sets_geoip_placeholders_for_known_ip(t *testing.T) {
	// Given an ip2region database to look up against
	xdb := findTestXdb()
	if xdb == "" {
		t.Skip("no ip2region xdb available; place one under caddygeoip/testdata/ to run this test")
	}

	h := &GeoIPHandler{XdbPath: xdb}
	if err := h.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Cleanup(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	// When a request from a known IP is served
	repl := caddy.NewReplacer()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
	req.RemoteAddr = "114.114.114.114:53981" // Chinese ISP DNS, present in the v4 xdb
	rec := httptest.NewRecorder()

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusNoContent)
		return nil
	})

	// Then the geoip vars are set (published via caddyhttp.SetVar into the
	// request vars map, readable downstream as {http.vars.geoip.*})
	vars := map[string]any{}
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars))
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if _, ok := vars["geoip.country_code"]; ok {
		t.Fatal("geoip.country_code must not be published (dead emission removed, F49-P5-6)")
	}
	if name, _ := vars["geoip.country_name"].(string); name == "" {
		t.Fatal("geoip.country_name var is empty for a known IP")
	}
}

// geoipTestNext captures the request seen by the downstream handler.
func geoipTestNext(t *testing.T, captured **http.Request) caddyhttp.HandlerFunc {
	t.Helper()
	return caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
		*captured = r
		return nil
	})
}

// TestServeHTTP_stripsSpoofedGeoIPHeaders_evenWithoutXdb：防伪造+fail-closed——客户端
// 伪造的 X-LB-GeoIP-* 头必须在入口剥除（伪造 X-LB-GeoIP-Loc 可绕过 allow 模式地域
// 拦截或制造误拦）；xdb 缺失（searcher nil）时伪造值不得残留，且 X-LB-GeoIP-Loc
// 由「海外」哨兵覆盖——缺失变量会让 coraza 地域规则恒不命中（fail-open），
// 哨兵恢复 deny/allow 两模式的 fail-closed 语义。
func TestServeHTTP_stripsSpoofedGeoIPHeaders_evenWithoutXdb(t *testing.T) {
	h := &GeoIPHandler{XdbPath: filepath.Join(t.TempDir(), "missing.xdb")}
	if err := h.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision with missing xdb must not fail: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Cleanup(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	repl := caddy.NewReplacer()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
	req.RemoteAddr = "114.114.114.114:53981"
	for name, value := range map[string]string{
		"X-LB-GeoIP-Country":      "中国",
		"X-LB-GeoIP-Country-Code": "CN",
		"X-LB-GeoIP-Region":       "中国|0|广东省|深圳市|4403",
		"X-LB-GeoIP-Province":     "广东省",
		"X-LB-GeoIP-City":         "深圳市",
		"X-LB-GeoIP-Loc":          "广东省/深圳市",
	} {
		req.Header.Set(name, value)
	}

	var downstream *http.Request
	if err := h.ServeHTTP(httptest.NewRecorder(), req, geoipTestNext(t, &downstream)); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if got := downstream.Header.Get("X-LB-GeoIP-Loc"); got != "海外" {
		t.Fatalf("X-LB-GeoIP-Loc must be the fail-closed sentinel 海外 (not the spoofed value), got %q", got)
	}
	for _, name := range geoipCorazaHeaders {
		if name == "X-LB-GeoIP-Loc" {
			continue
		}
		if got := downstream.Header.Get(name); got != "" {
			t.Fatalf("spoofed header %s must be stripped without an xdb, got %q", name, got)
		}
	}
}

// TestServeHTTP_setsCorazaHeaders_forKnownIP：xdb 可用时 X-LB-GeoIP-* 头镜像
// geoip.* 变量（国内 IP：Country=中国、Loc=省 或 省/市，与 Province/City 头
// 同源组合）；伪造头先被剥除再以解析值覆盖。
func TestServeHTTP_setsCorazaHeaders_forKnownIP(t *testing.T) {
	xdb := findTestXdb()
	if xdb == "" {
		t.Skip("no ip2region xdb available; place one under caddygeoip/testdata/ to run this test")
	}
	h := &GeoIPHandler{XdbPath: xdb}
	if err := h.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Cleanup(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	repl := caddy.NewReplacer()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
	req.RemoteAddr = "114.114.114.114:53981" // Chinese ISP DNS, present in the v4 xdb
	req.Header.Set("X-LB-GeoIP-Country", "ELBOWLAND")
	req.Header.Set("X-LB-GeoIP-Loc", "海外")

	var downstream *http.Request
	vars := map[string]any{}
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars))
	if err := h.ServeHTTP(httptest.NewRecorder(), req, geoipTestNext(t, &downstream)); err != nil {
		t.Fatalf("serve: %v", err)
	}

	if got := downstream.Header.Get("X-LB-GeoIP-Country"); got != "中国" {
		t.Fatalf("X-LB-GeoIP-Country = %q, want 中国（spoofed value must be overwritten）", got)
	}
	// F49-P5-6：X-LB-GeoIP-Country-Code 头发射已删除（ISP 列语义错位死发射）；
	// 剥离清单保留（防伪造）但模块自身不再产出该头。
	if got := downstream.Header.Get("X-LB-GeoIP-Country-Code"); got != "" {
		t.Fatalf("X-LB-GeoIP-Country-Code = %q, want not emitted", got)
	}
	province := downstream.Header.Get("X-LB-GeoIP-Province")
	if province == "" {
		t.Fatal("X-LB-GeoIP-Province empty for a known Chinese IP")
	}
	city := downstream.Header.Get("X-LB-GeoIP-City")
	loc := downstream.Header.Get("X-LB-GeoIP-Loc")
	wantLoc := province
	if city != "" {
		wantLoc = province + "/" + city
	}
	if loc != wantLoc {
		t.Fatalf("X-LB-GeoIP-Loc = %q, want %q（province[/city] 组合）", loc, wantLoc)
	}
	// 变量与头同源：province 变量与头一致（镜像不变量）
	if pv, _ := vars["geoip.province"].(string); pv != province {
		t.Fatalf("geoip.province var = %q, header = %q（must mirror）", pv, province)
	}
}

// TestServeHTTP_overseasSentinels_forUnresolvableClient：fail-closed 哨兵——
// 不可解析客户端（IPv6 对 v4-only xdb 查询失败）全头发空串、X-LB-GeoIP-Loc 恒
// 「海外」（deny 模式海外策略对其拦截，与 D1 裁决一致）。
func TestServeHTTP_overseasSentinels_forUnresolvableClient(t *testing.T) {
	xdb := findTestXdb()
	if xdb == "" {
		t.Skip("no ip2region xdb available; place one under caddygeoip/testdata/ to run this test")
	}
	h := &GeoIPHandler{XdbPath: xdb}
	if err := h.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Cleanup(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	repl := caddy.NewReplacer()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
	req.RemoteAddr = "[2001:db8::1]:443" // v4-only xdb: lookup fails → sentinels

	var downstream *http.Request
	vars := map[string]any{}
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars))
	if err := h.ServeHTTP(httptest.NewRecorder(), req, geoipTestNext(t, &downstream)); err != nil {
		t.Fatalf("serve: %v", err)
	}

	for _, name := range []string{"X-LB-GeoIP-Country", "X-LB-GeoIP-Region", "X-LB-GeoIP-Province", "X-LB-GeoIP-City"} {
		if got := downstream.Header.Get(name); got != "" {
			t.Fatalf("%s = %q, want empty sentinel", name, got)
		}
	}
	if got := downstream.Header.Get("X-LB-GeoIP-Loc"); got != "海外" {
		t.Fatalf("X-LB-GeoIP-Loc = %q, want 海外 sentinel（fail-closed）", got)
	}
}

// TestServeHTTP_overseasEmitsCountryName（域 G，第 73 轮）：已解析海外行
// X-LB-GeoIP-Loc 发射归一化国名（United States）——非「海外」哨兵；非国家
// 值（Reserved 文档段）形态仍回落「海外」哨兵（fail-closed 兜底不变：
// 解析失败/库缺失/非国家值按海外处理）。
func TestServeHTTP_overseasEmitsCountryName(t *testing.T) {
	xdb := findTestXdb()
	if xdb == "" {
		t.Skip("no ip2region xdb available; place one under caddygeoip/testdata/ to run this test")
	}
	h := &GeoIPHandler{XdbPath: xdb}
	if err := h.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Cleanup(); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	serve := func(t *testing.T, remote string) string {
		t.Helper()
		repl := caddy.NewReplacer()
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
		req.RemoteAddr = remote
		var downstream *http.Request
		vars := map[string]any{}
		req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars))
		if err := h.ServeHTTP(httptest.NewRecorder(), req, geoipTestNext(t, &downstream)); err != nil {
			t.Fatalf("serve: %v", err)
		}
		return downstream.Header.Get("X-LB-GeoIP-Loc")
	}

	// 8.8.8.8 → "United States|California|0|Google LLC|US"：海外行发国名。
	if got := serve(t, "8.8.8.8:12345"); got != "United States" {
		t.Fatalf("X-LB-GeoIP-Loc = %q; want United States（已解析海外行发国名）", got)
	}
	// 203.0.113.10 → "Reserved|Reserved|Reserved|0|0"：非国家值回落哨兵。
	if got := serve(t, "203.0.113.10:12345"); got != "海外" {
		t.Fatalf("X-LB-GeoIP-Loc = %q; want 海外（Reserved 非国家，兜底哨兵）", got)
	}
}

// TestGeoipLocFor_trimsChinaCountryColumn（X4，第 74 轮）：国家列「中国」判定
// TrimSpace 对称——树侧收集判定本就 Trim（ip2region.go），发射侧此前裸比较
// （" 中国" 异形行走海外分支后 NormalizeCountry 折叠出「中国」串发射，匹配
// 键恒不命中）。国内 → 省/省-市；海外 → 归一化国名；不可解析 → 哨兵。
func TestGeoipLocFor_trimsChinaCountryColumn(t *testing.T) {
	cases := []struct{ country, province, city, want string }{
		{"中国", "广东省", "深圳市", "广东省/深圳市"},
		{"中国", "广东省", "", "广东省"},
		{" 中国", "广东省", "", "广东省"},
		{"\t中国 ", "广东省", "深圳市", "广东省/深圳市"},
		{"United States", "", "", "United States"},
		{" 美国", "", "", "United States"},
		{"Reserved", "", "", "海外"},
		{"", "广东省", "", "海外"},
	}
	for _, tc := range cases {
		if got := geoipLocFor(tc.country, tc.province, tc.city); got != tc.want {
			t.Errorf("geoipLocFor(%q,%q,%q)=%q; want %q", tc.country, tc.province, tc.city, got, tc.want)
		}
	}
}

// TestProvision_sharedSearcherSingletonPerXdbPath（审计 M2）：同 XdbPath 的
// 多个 handler 必须共享同一 Ip2Region 实例——每 handler 各建一份会各开 20 个
// searcher fd（50 条 GeoIP 规则≈1000 fd 逼近 soft limit，重载期翻倍），fd 耗尽
// → Provision 降级 pass-through → 全客户端判「海外」误拦。指针同一即证明
// 只开了一份 20-searcher 池。Cleanup 只解除引用不关闭单例（关闭会打断共享方）；
// xdb 文件形态变化（更新流程 rename 换库后重载）→ 重建新实例而非复用旧 inode。
func TestProvision_sharedSearcherSingletonPerXdbPath(t *testing.T) {
	src := findTestXdb()
	if src == "" {
		t.Skip("no ip2region xdb available; place one under caddygeoip/testdata/ to run this test")
	}
	path := filepath.Join(t.TempDir(), "ip2region.xdb")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source xdb: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("seed xdb copy: %v", err)
	}

	// 两个 handler 同路径 → 同一实例（共享一份 20-searcher 池）
	h1 := &GeoIPHandler{XdbPath: path}
	h2 := &GeoIPHandler{XdbPath: path}
	ctx := caddy.Context{Context: context.Background()}
	if err := h1.Provision(ctx); err != nil {
		t.Fatalf("provision h1: %v", err)
	}
	if err := h2.Provision(ctx); err != nil {
		t.Fatalf("provision h2: %v", err)
	}
	if h1.searcher == nil || h1.searcher != h2.searcher {
		t.Fatalf("same-path handlers must share one searcher instance, got %p vs %p", h1.searcher, h2.searcher)
	}
	shared := h1.searcher

	// h1 清理不关单例：h2 引用仍可用（Search 正常返回）
	if err := h1.Cleanup(); err != nil {
		t.Fatalf("cleanup h1: %v", err)
	}
	if h1.searcher != nil {
		t.Fatal("cleanup must drop the handler's own reference")
	}
	if region, err := h2.searcher.Search("114.114.114.114"); err != nil || region == "" {
		t.Fatalf("shared searcher must stay usable after a sibling's cleanup: region=%q err=%v", region, err)
	}

	// xdb 更新（rename 换库后 mtime/size 变化）→ 新 Provision 重建实例
	newMtime := time.Now().Add(2 * time.Minute)
	if err := os.Chtimes(path, newMtime, newMtime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	h3 := &GeoIPHandler{XdbPath: path}
	if err := h3.Provision(ctx); err != nil {
		t.Fatalf("provision h3 after xdb replacement: %v", err)
	}
	if h3.searcher == nil || h3.searcher == shared {
		t.Fatalf("xdb file change must rebuild the shared instance, got %p (old %p)", h3.searcher, shared)
	}
	if err := h3.Cleanup(); err != nil {
		t.Fatalf("cleanup h3: %v", err)
	}
	if err := h2.Cleanup(); err != nil {
		t.Fatalf("cleanup h2: %v", err)
	}
}

// TestProvision_replacedSearcherClosedAfterDelay（F49-5）：换库重建后被替换的
// 旧实例不再「保留至进程退出」——延迟窗口（防重载期在途查询落空误判海外）
// 过后旧实例被 Close（查询报 pool closed），新实例立即可查。
func TestProvision_replacedSearcherClosedAfterDelay(t *testing.T) {
	src := findTestXdb()
	if src == "" {
		t.Skip("no ip2region xdb available; place one under caddygeoip/testdata/ to run this test")
	}
	path := filepath.Join(t.TempDir(), "ip2region.xdb")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source xdb: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("seed xdb copy: %v", err)
	}
	oldDelay := geoipOldInstanceCloseDelay
	geoipOldInstanceCloseDelay = 200 * time.Millisecond
	t.Cleanup(func() { geoipOldInstanceCloseDelay = oldDelay })

	ctx := caddy.Context{Context: context.Background()}
	h1 := &GeoIPHandler{XdbPath: path}
	if err := h1.Provision(ctx); err != nil {
		t.Fatalf("provision h1: %v", err)
	}
	old := h1.searcher
	if old == nil {
		t.Fatal("h1 searcher nil")
	}

	// xdb 形态变化 → 重建新实例
	newMtime := time.Now().Add(2 * time.Minute)
	if err := os.Chtimes(path, newMtime, newMtime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	h2 := &GeoIPHandler{XdbPath: path}
	if err := h2.Provision(ctx); err != nil {
		t.Fatalf("provision h2: %v", err)
	}
	if h2.searcher == nil || h2.searcher == old {
		t.Fatalf("xdb 变化须重建实例, got %p (old %p)", h2.searcher, old)
	}

	// 新实例立即可查
	if region, err := h2.searcher.Search("114.114.114.114"); err != nil || region == "" {
		t.Fatalf("新实例立即可查: region=%q err=%v", region, err)
	}
	// 延迟窗口内旧实例仍在役（重载期在途查询保护）
	if _, err := old.Search("114.114.114.114"); err != nil {
		t.Fatalf("延迟窗口内旧实例不得在役查询失败: %v", err)
	}
	// 窗口过后旧实例被关闭（不再保留至进程退出）
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := old.Search("114.114.114.114"); err != nil {
			break // pool closed
		}
		if time.Now().After(deadline) {
			t.Fatal("旧实例在延迟窗口后仍未被 Close（保留至进程退出的旧行为）")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRealClientIP_ignoresUntrustedProxyHeadersAndStripsPort(t *testing.T) {
	tests := []struct {
		name   string
		remote string
		xff    string
		xri    string
		want   string
	}{
		{"ipv4 with port", "114.114.114.114:53981", "", "", "114.114.114.114"},
		{"ipv6 with port", "[2001:db8::1]:443", "", "", "2001:db8::1"},
		{"bare ipv4", "114.114.114.114", "", "", "114.114.114.114"},
		{"spoofed xff ignored", "10.0.0.1:1234", "8.8.8.8, 10.0.0.1", "", "10.0.0.1"},
		{"spoofed x-real-ip ignored", "10.0.0.1:1234", "", "1.1.1.1", "10.0.0.1"},
		{"invalid remote yields empty", "not-an-addr", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remote
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}
			got := realClientIP(req)
			if got != tt.want {
				t.Fatalf("realClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeCity_pinyinMappedAndPassthrough(t *testing.T) {
	// R72 二十五次：发射侧城市列规范化——拼音段映射为规范中文（策略树侧同款
	// 表，城市级 CEL 规则对拼音段可命中）；中文原样通过；无效值置空。
	cases := map[string]string{
		"Guangzhou Shi": "广州市",
		"Taipei City":   "台北市",
		"Shenzhen":      "深圳市",
		"深圳市":           "深圳市",
		"":              "",
		"0":             "",
	}
	for in, want := range cases {
		if got := normalizeCity(in); got != want {
			t.Fatalf("normalizeCity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeProvince_taiwanCityPromotion(t *testing.T) {
	// 台湾城市误入省列时按台湾省发射（城市变量照常发原值）。
	if got := normalizeProvince("桃园市"); got != "台湾省" {
		t.Fatalf("normalizeProvince(桃园市) = %q, want 台湾省", got)
	}
	if got := normalizeProvince("上海"); got != "上海市" {
		t.Fatalf("normalizeProvince(上海) = %q, want 上海市", got)
	}
	// UEruemqi 乱码省列按新疆发射（与树侧同步，段回收）。
	if got := normalizeProvince("UEruemqi"); got != "新疆维吾尔自治区" {
		t.Fatalf("normalizeProvince(UEruemqi) = %q, want 新疆维吾尔自治区", got)
	}
}

func TestNormalizeCity_autonomousPrefecture(t *testing.T) {
	// R72 二十八次（用户反馈）：少数民族自治州简称 → 全称（与树侧同款表
	// 同步）；「大理市」是另一个县级市，全称必须是「大理白族自治州」。
	cases := map[string]string{
		"大理":   "大理白族自治州",
		"怒江":   "怒江傈僳族自治州",
		"凉山":   "凉山彝族自治州",
		"伊犁":   "伊犁哈萨克自治州",
		"大兴安岭": "大兴安岭地区",
		// 非自治州不受影响
		"呼和浩特市": "呼和浩特市",
		"九龙":    "九龙", // 香港地区名保持原值
	}
	for in, want := range cases {
		if got := normalizeCity(in); got != want {
			t.Fatalf("normalizeCity(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSharedGeoIPSearcher_statFailureEvictsCachedEntry（PLUG-N2，第 72 轮）：
// stat 失败（xdb 更新 rename 窗口/文件被删）且缓存持有该路径条目时，条目
// 必须驱逐——旧实例走既有 AfterFunc 延迟关闭（在途查询保护与换库路径一致）。
// 不驱逐时旧 inode 实例永久占据缓存槽：stat 失败路径原样 return err 不碰
// 缓存，文件以「同 modtime+size」形态恢复（rsync -a/touch -r 保时间戳重铺）
// 时缓存命中判定通过，被删 inode 的旧库被无限期当有效数据服务（更新静默
// 失效——恰是 M2 缓存条目要防的形态）。
func TestSharedGeoIPSearcher_statFailureEvictsCachedEntry(t *testing.T) {
	src := findTestXdb()
	if src == "" {
		t.Skip("no ip2region xdb available; place one under caddygeoip/testdata/ to run this test")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ip2region.xdb")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source xdb: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("seed xdb copy: %v", err)
	}
	oldDelay := geoipOldInstanceCloseDelay
	geoipOldInstanceCloseDelay = 200 * time.Millisecond
	t.Cleanup(func() { geoipOldInstanceCloseDelay = oldDelay })

	// Given 缓存已持有该路径条目
	first, err := sharedGeoIPSearcher(path)
	if err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	// When 文件被移除（stat 失败）后再次解析
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := sharedGeoIPSearcher(path); err == nil {
		t.Fatal("stat failure must surface as error (provision degrades pass-through)")
	}

	// Then 缓存条目已被驱逐（不 panic、不持旧 inode 占位）
	geoipSharedMu.Lock()
	_, stillCached := geoipSharedSearchers[path]
	geoipSharedMu.Unlock()
	if stillCached {
		t.Fatal("stat failure with cached entry must evict it (delayed close), not retain the stale-inode entry")
	}

	// And 旧实例在延迟窗口内仍可查（AfterFunc 在途保护），窗口过后被关闭
	if _, err := first.Search("114.114.114.114"); err != nil {
		t.Fatalf("延迟窗口内旧实例不得在役查询失败: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := first.Search("114.114.114.114"); err != nil {
			break // pool closed
		}
		if time.Now().After(deadline) {
			t.Fatal("被驱逐旧实例在延迟窗口后仍未被 Close")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// And 文件恢复后重建全新实例（不复用被驱逐的旧实例）
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("restore xdb: %v", err)
	}
	second, err := sharedGeoIPSearcher(path)
	if err != nil {
		t.Fatalf("rebuild after restore: %v", err)
	}
	if second == first {
		t.Fatal("evicted entry must not be re-served; expect a freshly built instance")
	}
	if region, err := second.Search("114.114.114.114"); err != nil || region == "" {
		t.Fatalf("rebuilt instance must serve lookups: region=%q err=%v", region, err)
	}
}

// ---- 第 78 轮 U14-01 / U14-05 ----

const googlebotUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

func TestCrawlerVerify_usesClientIPVarOverRemoteAddr(t *testing.T) {
	ResetCrawlerVerifyCacheForTest(&fakeResolver{
		ptr: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
			// socket 对端（CDN 回源）没有官方 PTR：若实现仍用 RemoteAddr 必判伪装
		},
		host: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
		},
	})
	h := &GeoIPHandler{CrawlerExempt: true}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.50:443" // CDN 回源 IP
	req.Header.Set("User-Agent", googlebotUA)
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: "66.249.66.1",
	})
	req = req.WithContext(ctx)

	h.applyCrawlerVerification(req)

	if got := req.Header.Get(crawlerVerifiedHeader); got != "googlebot" {
		t.Fatalf("verified header=%q, want googlebot (client_ip variable must win over socket addr)", got)
	}
	if got := req.Header.Get(crawlerSpoofHeader); got != "" {
		t.Fatalf("spoof header=%q, want empty", got)
	}

	// 变量缺席 → 回退 socket（fail-closed 回归：CDN 回源 IP 不属官方段）。
	ResetCrawlerVerifyCacheForTest(&fakeResolver{})
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "203.0.113.50:443"
	req2.Header.Set("User-Agent", googlebotUA)
	h.applyCrawlerVerification(req2)
	if got := req2.Header.Get(crawlerVerifiedHeader); got != "" {
		t.Fatalf("verified header=%q without client_ip, want empty", got)
	}
	if got := req2.Header.Get(crawlerSpoofHeader); got != "googlebot" {
		t.Fatalf("spoof header=%q, want googlebot (fallback socket IP fails closed)", got)
	}
}

func TestCrawlerVerification_gatedByRenderFlag(t *testing.T) {
	resolver := &fakeResolver{
		ptr:  map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		host: map[string][]string{"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"}},
	}
	ResetCrawlerVerifyCacheForTest(resolver)
	off := &GeoIPHandler{} // crawler_exempt 未配置 = false
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "66.249.66.1:443"
	req.Header.Set("User-Agent", googlebotUA)
	off.applyCrawlerVerification(req)
	if req.Header.Get(crawlerVerifiedHeader) != "" || req.Header.Get(crawlerSpoofHeader) != "" {
		t.Fatal("crawler_exempt=false must not set verification headers")
	}
	// 门控 true 时验证路径不变。
	onReq := httptest.NewRequest(http.MethodGet, "/", nil)
	onReq.RemoteAddr = "66.249.66.1:443"
	onReq.Header.Set("User-Agent", googlebotUA)
	(&GeoIPHandler{CrawlerExempt: true}).applyCrawlerVerification(onReq)
	if onReq.Header.Get(crawlerVerifiedHeader) != "googlebot" {
		t.Fatal("crawler_exempt=true must keep the verification path")
	}
}
