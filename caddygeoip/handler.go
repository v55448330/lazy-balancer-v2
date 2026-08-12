// Package caddygeoip provides a Caddy HTTP handler module that resolves the
// client IP against an ip2region xdb database and publishes the resulting
// country as placeholders for downstream handlers and matchers.
package caddygeoip

import (
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/lionsoul2014/ip2region/binding/golang/service"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(GeoIPHandler{})
}

// GeoIPHandler looks up the client IP in the ip2region database and sets the
// geoip.country_code and geoip.country_name placeholders on the request
// replacer. Blocking decisions belong to downstream matchers; this handler
// always passes the request through.
type GeoIPHandler struct {
	// XdbPath is the path to the ip2region xdb database. When empty it
	// defaults to /app/data/ip2region.xdb.
	XdbPath string `json:"xdb_path,omitempty"`

	searcher *service.Ip2Region
}

// CaddyModule returns the Caddy module information.
func (GeoIPHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.geoip2region",
		New: func() caddy.Module { return new(GeoIPHandler) },
	}
}

// Provision opens the ip2region database. A missing or unreadable database
// disables lookups (the handler degrades to a pass-through) instead of
// failing the Caddy configuration load.
func (h *GeoIPHandler) Provision(ctx caddy.Context) error {
	if h.XdbPath == "" {
		h.XdbPath = "/app/data/ip2region.xdb"
	}
	searcher, err := service.NewIp2RegionWithPath(h.XdbPath, "")
	if err != nil {
		ctx.Logger().Warn("geoip2region: ip2region database unavailable, geoip disabled",
			zap.String("xdb_path", h.XdbPath), zap.Error(err))
		return nil
	}
	h.searcher = searcher
	return nil
}

// ServeHTTP publishes the client country and always delegates to the next
// handler in the chain.
func (h *GeoIPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h.searcher != nil {
		h.setGeoIPPlaceholders(r)
	}
	return next.ServeHTTP(w, r)
}

// Cleanup releases the ip2region database handle.
func (h *GeoIPHandler) Cleanup() error {
	if h.searcher != nil {
		h.searcher.Close()
		h.searcher = nil
	}
	return nil
}

// setGeoIPPlaceholders resolves the client IP against the database and
// publishes the country fields on the request replacer.
func (h *GeoIPHandler) setGeoIPPlaceholders(r *http.Request) {
	ip := realClientIP(r)
	if ip == "" {
		return
	}
	region, err := h.searcher.Search(ip)
	if err != nil || region == "" {
		return
	}
	fields := strings.Split(region, "|")
	if len(fields) < 5 {
		return
	}
	ctx := r.Context()
	caddyhttp.SetVar(ctx, "geoip.country_code", fields[4])
	caddyhttp.SetVar(ctx, "geoip.country_name", fields[0])
	caddyhttp.SetVar(ctx, "geoip.region", region)
	if len(fields) >= 3 {
		caddyhttp.SetVar(ctx, "geoip.province", fields[2])
	}
	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if ok && repl != nil {
		repl.Set("geoip.country_code", fields[4])
		repl.Set("geoip.country_name", fields[0])
		repl.Set("geoip.region", region)
		if len(fields) >= 3 {
			repl.Set("geoip.province", fields[2])
		}
	}
}

// realClientIP extracts the true client IP: honors X-Forwarded-For / X-Real-IP
// when present (trusted proxy scenario), falling back to RemoteAddr.
func realClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for _, part := range strings.Split(xff, ",") {
			part = strings.TrimSpace(part)
			if part != "" && net.ParseIP(part) != nil {
				return part
			}
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		xri = strings.TrimSpace(xri)
		if net.ParseIP(xri) != nil {
			return xri
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if net.ParseIP(r.RemoteAddr) != nil {
			return r.RemoteAddr
		}
		return ""
	}
	return host
}
