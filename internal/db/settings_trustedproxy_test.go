package db

import (
	"database/sql"
	"reflect"
	"testing"
)

// 受信代理四列（trusted_proxy_enabled/ranges/headers/strict）读写往返：
// CDN 部署下渲染层与 caddygeoip 均依赖这四值（v2.3.x 真实 IP 支持）。
func TestTrustedProxySettings_roundtrip(t *testing.T) {
	database, err := sql.Open("sqlite", t.TempDir()+"/settings.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	oldDB := DB
	DB = database
	defer func() { DB = oldDB }()
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY,
		trusted_proxy_enabled INTEGER NOT NULL DEFAULT 0,
		trusted_proxy_ranges TEXT NOT NULL DEFAULT '[]',
		trusted_proxy_headers TEXT NOT NULL DEFAULT '[]',
		trusted_proxy_strict INTEGER NOT NULL DEFAULT 1,
		updated_at DATETIME)`); err != nil {
		t.Fatalf("create global_config: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id) VALUES (1)"); err != nil {
		t.Fatalf("seed global_config: %v", err)
	}

	// Given 默认值
	enabled, ranges, headers, strict, err := GetTrustedProxySettings()
	if err != nil {
		t.Fatalf("get defaults: %v", err)
	}
	if enabled || strict != true || len(ranges) != 0 || len(headers) != 0 {
		t.Fatalf("defaults=(%v,%v,%v,%v), want (false,[],[],true)", enabled, ranges, headers, strict)
	}

	// When 写入
	wantRanges := []string{"203.0.113.0/24", "2001:db8::/32"}
	wantHeaders := []string{"CF-Connecting-IP", "X-Forwarded-For"}
	if err := SetTrustedProxySettings(true, false, wantRanges, wantHeaders); err != nil {
		t.Fatalf("set: %v", err)
	}

	// Then 读回一致（头序保持）
	enabled, ranges, headers, strict, err = GetTrustedProxySettings()
	if err != nil {
		t.Fatalf("get after set: %v", err)
	}
	if !enabled || strict || !reflect.DeepEqual(ranges, wantRanges) || !reflect.DeepEqual(headers, wantHeaders) {
		t.Fatalf("got=(%v,%v,%v,%v), want (true,%v,%v,false)", enabled, ranges, headers, strict, wantRanges, wantHeaders)
	}
}

// 读侧失败时返回错误（调用方 fail-closed）而非静默零值。
func TestTrustedProxySettings_getPropagatesError(t *testing.T) {
	database, err := sql.Open("sqlite", t.TempDir()+"/settings.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	oldDB := DB
	DB = database
	defer func() { DB = oldDB }()
	// Given：表缺 trusted_proxy 列（查询必失败）
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id) VALUES (1)"); err != nil {
		t.Fatal(err)
	}

	// When/Then
	if _, _, _, _, err := GetTrustedProxySettings(); err == nil {
		t.Fatal("want error when columns missing")
	}
}
