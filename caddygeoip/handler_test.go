package caddygeoip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// testdataXdbSHA256 是仓库测试夹具 testdata/ip2region_v4.xdb 的内容指纹钉：
// 该夹具是地域树/规范化/发射测试的唯一数据源，被替换或与生产库代次分叉时
// 测试会在与生产不同的数据上保持绿色（少量 IP 断言只能部分兜底）——改动
// 夹具必须显式更新本钉。
//
// 来源口径：夹具是**仓库独立代次**，不是 Dockerfile 下载物。生产镜像钉
// ip2region v3.17.0 的 ip2region_v4.xdb（sha256 6307a969…，中国段城市列
// 为拼音的 45 条与本仓 CityPinyinFixes 表一一对应）；本夹具的中国段 ASCII
// 城市列与 v3.18.0 同形（只有「台湾省|Taichung County」一条，见
// CityPinyinFixes 的 Taichung County 条目说明），二者内容不同属设计现状。
const testdataXdbSHA256 = "95e00400137b517ef97ad0f3c808ff8ca397575d8669bec1b7f32948ff13a7f6"

func TestTestdataXDB_fingerprintPinned(t *testing.T) {
	path := filepath.Join("testdata", "ip2region_v4.xdb")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("仓库测试夹具必须随仓提供（不得用 skip 掩盖缺失）: %v", err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != testdataXdbSHA256 {
		t.Fatalf("testdata/ip2region_v4.xdb sha256=%s, want %s（夹具变更须显式更新指纹与来源说明）", got, testdataXdbSHA256)
	}
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
	// geoip.country_code 死发射已删除：v4 xdb 行是 国家|省|市|ISP|国家代码
	// （fields[3]=ISP，fields[4]=国家代码），该变量无任何消费方（纯死发射），
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
		t.Fatal("geoip.country_code must not be published (dead emission removed)")
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
	// caddyhttp.SetVar 只写入上下文里的 vars map（真实 Caddy 链恒有）：
	// 测试需自备一份才能观察 geoip.* 变量形态。
	vars := make(map[string]any)
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)
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
	// 变量形态必须与「查询失败」分支同口径：4 个 geoip.* 变量全部置空串哨兵
	// （只发 Loc 头会让流量统计桶读到未设置变量 → collecting=true 但恒零）。
	for _, key := range []string{"geoip.country_name", "geoip.region", "geoip.province", "geoip.city"} {
		v, ok := caddyhttp.GetVar(downstream.Context(), key).(string)
		if !ok || v != "" {
			t.Fatalf("%s must be set to the empty-string sentinel without an xdb, got %v (set=%v)", key, v, ok)
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
	// X-LB-GeoIP-Country-Code 头发射已删除（ISP 列语义错位死发射）；
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
// 「海外」（deny 模式海外策略对其拦截，与裁决一致）。
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

// TestServeHTTP_overseasEmitsCountryName（域 G）：已解析海外行
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

// TestGeoipLocFor_usesNormalizedCountryColumn：Loc 只消费**已归一**的国家列
// （归一是 normalizeTrafficCountryKey 单源，由 parseGeoIPRegion 前置完成）——
// 本函数不再二次 TrimSpace/NormalizeCountry。历史形态（两处各自归一）在新增
// 国家异体时单侧漏改会让 X-LB-GeoIP-Country 与 X-LB-GeoIP-Loc 口径分裂；
// 本用例按发射侧同口径归一后验证三态（国内 → 省/省-市；海外 → 归一化国名；
// 不可解析 → 哨兵）。
func TestGeoipLocFor_usesNormalizedCountryColumn(t *testing.T) {
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
		if got := geoipLocFor(normalizeTrafficCountryKey(tc.country), tc.province, tc.city); got != tc.want {
			t.Errorf("geoipLocFor(normalize(%q),%q,%q)=%q; want %q", tc.country, tc.province, tc.city, got, tc.want)
		}
	}
}

// 发射侧国家列 TrimSpace + 异体归一——变量/头与 geoipLocFor、统计桶同口径
// （中文异体「美国」折叠为规范名；「中国」保留；Reserved/0/空归空串）。
// 修复前变量/头发射原始列：同一 xdb 行 Loc=United States 而
// country_name=美国，按 Country 头/变量的匹配对异体段恒不命中。
func TestParseGeoIPRegion_trimsCountryForEmission(t *testing.T) {
	cases := []struct {
		region      string
		wantCountry string
		wantLoc     string
	}{
		{"中国|广东省|深圳市|0|ISP", "中国", "广东省/深圳市"},
		{" 中国|广东省|深圳市|0|ISP", "中国", "广东省/深圳市"},
		{"\t中国 |广东省|0|0|ISP", "中国", "广东省"},
		{"United States|0|0|0|ISP", "United States", "United States"},
		{" 美国|0|0|0|ISP", "United States", "United States"},
		{"Reserved|Reserved|Reserved|0|0", "", "海外"},
	}
	for _, tc := range cases {
		got, ok := parseGeoIPRegion(tc.region)
		if !ok {
			t.Fatalf("parseGeoIPRegion(%q) rejected a %d-field row", tc.region, 5)
		}
		if got.Country != tc.wantCountry {
			t.Errorf("parseGeoIPRegion(%q).Country=%q, want %q（发射侧必须 TrimSpace）", tc.region, got.Country, tc.wantCountry)
		}
		if got.Loc != tc.wantLoc {
			t.Errorf("parseGeoIPRegion(%q).Loc=%q, want %q", tc.region, got.Loc, tc.wantLoc)
		}
	}
	if _, ok := parseGeoIPRegion("中国|广东省"); ok {
		t.Fatal("截断行（<5 列）必须拒绝发射")
	}
}

// TestParseGeoIPRegion_noCityWithoutProvince：随包三份
// xdb（caddygeoip/testdata、data/、data-slave/，各 553,954+ 段全量扫描）中
// 「国家=中国 + 省列无效 + 城市列有效」的行数为 0——省列无效的 13 种 region
// 串（如「中国|0|0|阿里|CN」）城市列同为 0/空。但 xdb 可在线更新，
// parseGeoIPRegion 另有代码级守卫（省列归一为空 ⇒ 城市置空），新库即使
// 引入该形态也不会发射树侧不可表达的「/城市」Loc 值：省无效行 Loc 为空
// （省/城市规则均不命中，与树不变式一致），台湾城市误置省列的行由
// ProvinceForEmit 归一为台湾省，仍落「省/城市」形态。
func TestParseGeoIPRegion_noCityWithoutProvince(t *testing.T) {
	cases := []struct {
		region   string
		wantProv string
		wantCity string
		wantLoc  string
	}{
		// 真实形态（xdb 中的 13 种省无效行同族）：ISP 可识别、省市均无效。
		{"中国|0|0|阿里|CN", "", "", ""},
		{"中国|0|0|0|CN", "", "", ""},
		{"中国|0|0|中国移动|CN", "", "", ""},
		// 台湾城市误置省列：省列归一为台湾省（树侧同样挂到台湾省下）。
		{"中国|台中市|0|0|CN", "台湾省", "台中市", "台湾省/台中市"},
		// 假设形态（现有库 0 行，在线更新引入时的守卫对象）：省无效但城市
		// 有效——城市必须随省一起置空，不得发射「/城市」死值。
		{"中国|0|杭州市|阿里|CN", "", "", ""},
		{"中国||深圳市|0|CN", "", "", ""},
	}
	for _, tc := range cases {
		got, ok := parseGeoIPRegion(tc.region)
		if !ok {
			t.Fatalf("parseGeoIPRegion(%q) rejected", tc.region)
		}
		if got.Province != tc.wantProv || got.City != tc.wantCity || got.Loc != tc.wantLoc {
			t.Errorf("parseGeoIPRegion(%q) = {prov:%q city:%q loc:%q}; want {%q %q %q}",
				tc.region, got.Province, got.City, got.Loc, tc.wantProv, tc.wantCity, tc.wantLoc)
		}
		// 树侧不变式（ip2region.go 中 prov=="" → continue）保证省无效行不会
		// 出现在选项树里；发射侧因此不得产生以 "/" 开头的 Loc。
		if strings.HasPrefix(got.Loc, "/") {
			t.Fatalf("parseGeoIPRegion(%q).Loc=%q must not start with '/' (unrepresentable in the policy tree)", tc.region, got.Loc)
		}
	}
}

// TestProvision_sharedSearcherSingletonPerXdbPath：同 XdbPath 的
// 多个 handler 必须共享同一 Ip2Region 实例——每 handler 各建一份会各开 20 个
// searcher fd（50 条 GeoIP 规则≈1000 fd 逼近 soft limit，重载期翻倍），fd 耗尽
// → Provision 降级 pass-through → 全客户端判「海外」误拦。指针同一即证明
// 只开了一份 20-searcher 池。Cleanup 不置空也不关闭单例（旧配置在途请求与
// 其他共享方都可继续查询）；xdb 文件形态变化（更新流程 rename 换库后重载）
// → 重建新实例而非复用旧 inode。
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

	// h1 清理不清空也不关闭共享单例：旧配置的在途请求仍可使用 h1，h2 亦然。
	if err := h1.Cleanup(); err != nil {
		t.Fatalf("cleanup h1: %v", err)
	}
	if h1.searcher != shared {
		t.Fatal("cleanup must retain the handler's shared searcher for in-flight requests")
	}
	if region, err := h1.searcher.Search("114.114.114.114"); err != nil || region == "" {
		t.Fatalf("cleaned-up handler's in-flight searcher must stay usable: region=%q err=%v", region, err)
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

// TestProvision_replacedSearcherClosedAfterDelay：换库重建后被替换的
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
	// 发射侧城市列规范化——拼音段映射为规范中文（策略树侧同款
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
	// （用户反馈）：少数民族自治州简称 → 全称（与树侧同款表
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

// TestSharedGeoIPSearcher_statFailureServesStaleAndForcesRebuild
// stat 失败（xdb 更新 rename 窗口/文件被删）且缓存持有该路径条目时：本次
// 仍返回该实例（fail-stale），并把条目标为「必须重建」。返回 error 会让
// Provision 降级 pass-through，该次 reload 之后 geoip 全量判「海外」，
// allow 模式规则等价全量拦截；而删条目会让同一次 reload 里第二个及之后的
// geoip 规则实例拿不到缓存（同一配置内部行为不一致）。标记保证文件以
// 「同 modtime+size」形态恢复（rsync -a/touch -r 保时间戳重铺）时下一次
// Provision 必然重读重建，旧 inode 不会被无限期当有效数据服务。
func TestSharedGeoIPSearcher_statFailureServesStaleAndForcesRebuild(t *testing.T) {
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
	t.Cleanup(func() {
		geoipOldInstanceCloseDelay = oldDelay
		geoipSharedMu.Lock()
		delete(geoipSharedSearchers, path)
		geoipSharedMu.Unlock()
	})

	// Given 缓存已持有该路径条目
	first, err := sharedGeoIPSearcher(path, "")
	if err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	origStat, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat seed: %v", err)
	}

	// When 文件被移除（stat 失败）后再次解析
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	served, err := sharedGeoIPSearcher(path, "")
	if err != nil {
		t.Fatalf("stat failure with a cached entry must serve it (fail-stale): %v", err)
	}
	if served != first {
		t.Fatal("stat failure must hand back the cached instance for this call")
	}
	if _, err := served.Search("114.114.114.114"); err != nil {
		t.Fatalf("本次 reload 必须能按旧库继续解析（fail-stale）: %v", err)
	}

	// Then 条目保留且标记必须重建
	geoipSharedMu.Lock()
	cached := geoipSharedSearchers[path+"\x00"]
	geoipSharedMu.Unlock()
	if cached == nil || !cached.needsRebuild {
		t.Fatalf("stat 失败必须把条目标为「必须重建」: %#v", cached)
	}

	// And 同一次 reload 里后续 geoip 规则实例（各调一次 Provision）仍拿到
	// 同一 fail-stale 实例——不得只有首个规则免于全量拦截。
	again, err := sharedGeoIPSearcher(path, "")
	if err != nil {
		t.Fatalf("后续 Provision 也必须拿到 fail-stale 实例: %v", err)
	}
	if again != first {
		t.Fatal("后续 Provision 拿到的是另一个实例（同一配置内部行为不一致）")
	}

	// And 文件以「同 modtime+size」形态恢复后必须重建（不复用旧 inode）
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("restore xdb: %v", err)
	}
	if err := os.Chtimes(path, origStat.ModTime(), origStat.ModTime()); err != nil {
		t.Fatalf("restore mtime: %v", err)
	}
	restored, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.ModTime().Equal(origStat.ModTime()) || restored.Size() != origStat.Size() {
		t.Fatalf("夹具形态不一致: %v/%d vs %v/%d", restored.ModTime(), restored.Size(), origStat.ModTime(), origStat.Size())
	}
	second, err := sharedGeoIPSearcher(path, "")
	if err != nil {
		t.Fatalf("rebuild after restore: %v", err)
	}
	if second == first {
		t.Fatal("标记为必须重建的条目不得复用旧实例（同 mtime+size 重铺形态）")
	}
	if region, err := second.Search("114.114.114.114"); err != nil || region == "" {
		t.Fatalf("rebuilt instance must serve lookups: region=%q err=%v", region, err)
	}
	geoipSharedMu.Lock()
	cached = geoipSharedSearchers[path+"\x00"]
	geoipSharedMu.Unlock()
	if cached == nil || cached.needsRebuild {
		t.Fatalf("重建成功后必须清除「必须重建」标记: %#v", cached)
	}

	// And 被替换的旧实例在延迟窗口过后被关闭（换库路径，fd/vIndex 收敛）
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := first.Search("114.114.114.114"); err != nil {
			break // pool closed
		}
		if time.Now().After(deadline) {
			t.Fatal("被替换旧实例在延迟窗口后仍未被 Close")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// xdb 带外损坏（文件形态变化但重建失败）时不得让 Provision 收到
// error 而降级 pass-through（全部客户端判「海外」→ deny 海外全量误拦）；
// 必须 fail-stale 继续服务缓存旧实例（与 wafiplist 的 fail-stale 对称）。
func TestSharedGeoIPSearcher_rebuildFailureServesStale(t *testing.T) {
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
	t.Cleanup(func() {
		geoipOldInstanceCloseDelay = oldDelay
		geoipSharedMu.Lock()
		delete(geoipSharedSearchers, path)
		geoipSharedMu.Unlock()
	})

	first, err := sharedGeoIPSearcher(path, "")
	if err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	// 带外损坏：原子 rename 换入坏文件（文件形态变化 → 触发重建且必失败）。
	// 用 rename 而非原地截断：旧实例持有旧 inode 的 fd，原地改写会连旧实例
	// 一起破坏（生产更新路径本身就是 rename）。
	badPath := filepath.Join(dir, "corrupt.xdb")
	if err := os.WriteFile(badPath, []byte("corrupted-xdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(badPath, path); err != nil {
		t.Fatal(err)
	}
	second, err := sharedGeoIPSearcher(path, "")
	if err != nil {
		t.Fatalf("rebuild failure must fail stale (nil error), got %v", err)
	}
	if second != first {
		t.Fatal("rebuild failure must serve the cached instance, not a replacement")
	}
	if region, err := second.Search("114.114.114.114"); err != nil || region == "" {
		t.Fatalf("stale instance must still serve lookups: region=%q err=%v", region, err)
	}
	// 缓存条目保留（文件修复后下一次 stat 变化仍会触发重建）。
	geoipSharedMu.Lock()
	cached := geoipSharedSearchers[path+"\x00"]
	geoipSharedMu.Unlock()
	if cached == nil || cached.searcher != first {
		t.Fatal("rebuild failure must not evict the cached entry")
	}
}

// ---- 回归钉 ----

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

// 瞬态验证结论（DNS 解析失败/超时/并发饱和）不得置伪装头：真实搜索引擎
// 爬虫在 DNS 抖动时既不被伪装规则阻断，也不产生伪伪装事件。
func TestCrawlerVerification_transientSetsNoSpoofHeader(t *testing.T) {
	ResetCrawlerVerifyCacheForTest(&fakeResolver{
		ptrErr: map[string]error{"66.249.66.1": context.DeadlineExceeded},
	})
	h := &GeoIPHandler{CrawlerExempt: true}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "66.249.66.1:443"
	req.Header.Set("User-Agent", googlebotUA)

	h.applyCrawlerVerification(req)

	if got := req.Header.Get(crawlerSpoofHeader); got != "" {
		t.Fatalf("瞬态验证不得置伪装头，got %q", got)
	}
	if got := req.Header.Get(crawlerVerifiedHeader); got != "" {
		t.Fatalf("瞬态验证不得置已验证头，got %q", got)
	}
}

// 宽品牌标记不构成伪装证据：裸 DeepSeek / ChatGPT-User / Claude-Web 等标记
// 会出现在普通客户端 UA 里，单独命中不得发射伪装头（否则制造伪安全事件）；
// 官方爬虫 token 仍判伪装，官方 PTR 仍判已验证。
func TestCrawlerVerification_weakBrandMarkerIsNotSpoofEvidence(t *testing.T) {
	ResetCrawlerVerifyCacheForTest(&fakeResolver{})
	h := &GeoIPHandler{CrawlerExempt: true}

	wide := []struct {
		ua, engine string
	}{
		{"Mozilla/5.0 (compatible; DeepSeek/1.0)", "deepseekbot"},
		{"Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)", "gptbot"},
		{"Mozilla/5.0 (compatible; Claude-Web/1.0; +claude.ai)", "claudebot"},
		{"Mozilla/5.0 (compatible; anthropic-ai/1.0)", "claudebot"},
	}
	for _, c := range wide {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.7:443" // 无官方 PTR → 确定否定
		req.Header.Set("User-Agent", c.ua)
		h.applyCrawlerVerification(req)
		if got := req.Header.Get(crawlerSpoofHeader); got != "" {
			t.Fatalf("裸 %s 品牌串: 宽品牌标记不得单独判伪装，spoof=%q", c.engine, got)
		}
		if got := req.Header.Get(crawlerVerifiedHeader); got != "" {
			t.Fatalf("%q 不得判已验证，verified=%q", c.ua, got)
		}
	}

	// 官方 token + 无官方 PTR：伪装证据成立。
	for _, c := range []struct{ ua, engine string }{
		{"Mozilla/5.0 (compatible; DeepSeekBot/1.0)", "deepseekbot"},
		{"Mozilla/5.0 (compatible; OAI-SearchBot/1.0)", "gptbot"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.7:443"
		req.Header.Set("User-Agent", c.ua)
		h.applyCrawlerVerification(req)
		if got := req.Header.Get(crawlerSpoofHeader); got != c.engine {
			t.Fatalf("官方 token %q spoof=%q, want %q", c.ua, got, c.engine)
		}
	}

	// 官方 PTR + 宽标记：Verified 路径必须不受证据门影响。
	ResetCrawlerVerifyCacheForTest(&fakeResolver{
		ptr:  map[string][]string{"198.51.100.9": {"crawl.deepseek.com."}},
		host: map[string][]string{"crawl.deepseek.com": {"198.51.100.9"}},
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.9:443"
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; DeepSeek/1.0)")
	h.applyCrawlerVerification(req)
	if got := req.Header.Get(crawlerVerifiedHeader); got != "deepseekbot" {
		t.Fatalf("官方 PTR 应判已验证（宽标记不影响 Verified 路径），verified=%q", got)
	}
	if got := req.Header.Get(crawlerSpoofHeader); got != "" {
		t.Fatalf("已验证路径不得置伪装头，spoof=%q", got)
	}
}
