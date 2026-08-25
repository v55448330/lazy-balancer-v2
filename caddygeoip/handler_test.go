package caddygeoip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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
	if cc, ok := repl.GetString("geoip.country_code"); ok && cc != "" {
		t.Fatalf("country_code = %q, want unset without an xdb", cc)
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
	if cc, _ := vars["geoip.country_code"].(string); cc == "" {
		t.Fatal("geoip.country_code var is empty for a known IP")
	}
	if name, _ := vars["geoip.country_name"].(string); name == "" {
		t.Fatal("geoip.country_name var is empty for a known IP")
	}
}

func TestRealClientIP_honorsHeadersAndStripsPort(t *testing.T) {
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
