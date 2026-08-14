package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeedBrandingTemplate_createsEmptyTemplateOnce(t *testing.T) {
	// Given a data dir without branding.json
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "branding.json")

	// When seeded twice
	if err := SeedBrandingTemplate(dataDir); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := SeedBrandingTemplate(dataDir); err != nil {
		t.Fatalf("second seed: %v", err)
	}

	// Then the file holds an all-empty template (empty values keep defaults)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(data), "Lazy Balancer") || strings.Contains(string(data), "Copyright") {
		t.Fatalf("template must contain empty values only, got: %s", data)
	}
}

func TestSeedBrandingTemplate_preservesExistingFile(t *testing.T) {
	// Given an existing configured file
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "branding.json")
	if err := os.WriteFile(path, []byte(`{"app_name":"Custom"}`), 0644); err != nil {
		t.Fatal(err)
	}

	// When seeded
	if err := SeedBrandingTemplate(dataDir); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Then the existing content is preserved verbatim
	preserved, err := os.ReadFile(path)
	if err != nil || string(preserved) != `{"app_name":"Custom"}` {
		t.Fatalf("existing file overwritten: %q err=%v", preserved, err)
	}
}

func TestLoadBrandingConfig_emptyTemplateKeepsDefaults(t *testing.T) {
	// Given an all-empty template file
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "branding.json"), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	// When loaded
	cfg := loadBrandingConfig(dataDir)

	// Then fields fall back to defaults
	if cfg.AppName != "Lazy Balancer" {
		t.Fatalf("app_name = %q, want default Lazy Balancer", cfg.AppName)
	}
	if cfg.FooterText != "" {
		t.Fatalf("footer_text = %q, want empty (default-footer signal)", cfg.FooterText)
	}
}
