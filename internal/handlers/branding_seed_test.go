package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// EnsureBrandingFile(2026-09-11 裁定):服务启动时(Caddy 载入前)确保
// branding.json 字段齐备——缺失建全空模板;缺字段补空值且保留已有值与
// 未知键;齐全合法不动(零写入);畸形 JSON 不动(保守,不破坏用户数据,
// 运行时按字段级回退)。
func TestEnsureBrandingFile_createsTemplateWhenMissing(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "branding.json")

	if err := EnsureBrandingFile(dataDir); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	var raw map[string]json.RawMessage
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, field := range []string{"app_name", "footer_text", "landing_text", "version"} {
		var v string
		val, ok := raw[field]
		if !ok {
			t.Errorf("template missing field %q", field)
			continue
		}
		if err := json.Unmarshal(val, &v); err != nil || v != "" {
			t.Errorf("template field %q = %s, want empty string", field, val)
		}
	}
}

func TestEnsureBrandingFile_backfillsMissingFieldsPreservesExisting(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "branding.json")
	if err := os.WriteFile(path, []byte(`{"app_name":"Custom","future_key":123}`), 0644); err != nil {
		t.Fatal(err)
	}

	if err := EnsureBrandingFile(dataDir); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	var raw map[string]json.RawMessage
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse: %v", err)
	}
	// 已有值保留
	var name string
	if err := json.Unmarshal(raw["app_name"], &name); err != nil || name != "Custom" {
		t.Errorf("app_name = %q err=%v, want preserved Custom", name, err)
	}
	// 未知键保留(前向兼容)
	if _, ok := raw["future_key"]; !ok {
		t.Error("unknown key future_key dropped by backfill")
	}
	// 缺失字段补空值
	for _, field := range []string{"footer_text", "landing_text", "version"} {
		var v string
		val, ok := raw[field]
		if !ok {
			t.Errorf("field %q not backfilled", field)
			continue
		}
		if err := json.Unmarshal(val, &v); err != nil || v != "" {
			t.Errorf("backfilled field %q = %s, want empty", field, val)
		}
	}
}

func TestEnsureBrandingFile_completeFileUntouched(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "branding.json")
	original := []byte("{\n  \"app_name\": \"X\",\n  \"footer_text\": \"F\",\n  \"landing_text\": \"L\",\n  \"version\": \"\",\n  \"extra\": true\n}")
	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatal(err)
	}
	stBefore, _ := os.Stat(path)

	if err := EnsureBrandingFile(dataDir); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Errorf("complete file rewritten:\nbefore=%s\nafter=%s", original, after)
	}
	stAfter, _ := os.Stat(path)
	if !stAfter.ModTime().Equal(stBefore.ModTime()) {
		t.Error("complete file mtime churned (zero-write contract broken)")
	}
}

func TestEnsureBrandingFile_corruptJSONLeftUntouched(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "branding.json")
	corrupt := []byte(`{"app_name": broken`)
	if err := os.WriteFile(path, corrupt, 0644); err != nil {
		t.Fatal(err)
	}

	if err := EnsureBrandingFile(dataDir); err != nil {
		t.Fatalf("ensure must not error on corrupt json: %v", err)
	}

	after, _ := os.ReadFile(path)
	if string(after) != string(corrupt) {
		t.Errorf("corrupt file modified (data-loss risk):\nafter=%s", after)
	}
}

func TestEnsureBrandingFile_idempotent(t *testing.T) {
	dataDir := t.TempDir()
	if err := EnsureBrandingFile(dataDir); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(filepath.Join(dataDir, "branding.json"))
	if err := EnsureBrandingFile(dataDir); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(filepath.Join(dataDir, "branding.json"))
	if string(first) != string(second) {
		t.Errorf("second ensure rewrote file:\nfirst=%s\nsecond=%s", first, second)
	}
}

func TestLoadBrandingConfig_emptyTemplateKeepsDefaults(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "branding.json"), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := loadBrandingConfig(dataDir)

	if cfg.AppName != "Lazy Balancer" {
		t.Fatalf("app_name = %q, want default Lazy Balancer", cfg.AppName)
	}
	if cfg.FooterText != "" {
		t.Fatalf("footer_text = %q, want empty (default-footer signal)", cfg.FooterText)
	}
}

// 等待文件系统 mtime 精度(粗粒度 FS 下同秒写入视为未变)。
func waitForDistinctMtime(t *testing.T, path string, prev time.Time) {
	t.Helper()
	for i := 0; i < 20; i++ {
		st, err := os.Stat(path)
		if err == nil && st.ModTime().After(prev) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}
