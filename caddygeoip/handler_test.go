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

	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("serve: %v", err)
	}

	// Then the country placeholders are set to non-empty values
	cc, ok := repl.GetString("geoip.country_code")
	if !ok {
		t.Fatal("geoip.country_code placeholder was not set")
	}
	if cc == "" {
		t.Fatal("geoip.country_code is empty for a known IP")
	}
	if name, ok := repl.GetString("geoip.country_name"); !ok || name == "" {
		t.Fatalf("geoip.country_name = %q, want non-empty", name)
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
		{"xff first", "10.0.0.1:1234", "8.8.8.8, 10.0.0.1", "", "8.8.8.8"},
		{"x-real-ip", "10.0.0.1:1234", "", "1.1.1.1", "1.1.1.1"},
		{"xff invalid falls back", "114.114.114.114:80", "not-an-ip", "", "114.114.114.114"},
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
