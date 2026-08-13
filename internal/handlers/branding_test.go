package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func initBrandingTestDB(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
}

func defaultBlockPageRow(t *testing.T) (content, updatedAt string) {
	t.Helper()
	err := db.DB.QueryRow("SELECT content, updated_at FROM security_block_pages WHERE is_default=1").Scan(&content, &updatedAt)
	if err != nil {
		t.Fatalf("read default block page row: %v", err)
	}
	return content, updatedAt
}

func TestRenderDefaultBlockPage_substitutes_app_name_and_footer_text(t *testing.T) {
	// Given
	cfg := brandingConfig{AppName: "Acme 均衡器", FooterText: "© 2026 Acme"}

	// When
	html := renderDefaultBlockPage(cfg)

	// Then
	if !strings.Contains(html, "<title>Access Denied — Acme 均衡器</title>") {
		t.Errorf("rendered page missing app name in title:\n%s", html)
	}
	if !strings.Contains(html, `Powered by <span class="name">Acme 均衡器</span>`) {
		t.Errorf("rendered page missing app name in footer:\n%s", html)
	}
	if !strings.Contains(html, "© 2026 Acme") {
		t.Errorf("rendered page missing footer text:\n%s", html)
	}
}

func TestRenderDefaultBlockPage_omits_footer_text_line_when_empty(t *testing.T) {
	// Given
	cfg := brandingConfig{AppName: "Acme"}

	// When
	html := renderDefaultBlockPage(cfg)

	// Then
	if !strings.Contains(html, `Powered by <span class="name">Acme</span>`) {
		t.Errorf("rendered page missing powered-by line:\n%s", html)
	}
	if strings.Contains(html, "<br>") {
		t.Errorf("rendered page should not contain a footer line break when footer text is empty:\n%s", html)
	}
}

func TestGetDefaultBlockPage_serves_branded_html(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "branding.json"), []byte(`{"app_name":"测试品牌","footer_text":"测试页脚"}`), 0644); err != nil {
		t.Fatalf("write branding file: %v", err)
	}
	h := &Handlers{cfg: &config.Config{DataDir: dataDir}}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/default-block-page", h.GetDefaultBlockPage)

	// When
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/security/default-block-page", nil)
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if ct := response.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type=%q, want text/html", ct)
	}
	body := response.Body.String()
	if !strings.Contains(body, "测试品牌") || !strings.Contains(body, "测试页脚") {
		t.Errorf("response body missing branding:\n%s", body)
	}
}

func TestSeedDefaultBlockPage_renders_custom_branding_into_default_row(t *testing.T) {
	// Given
	initBrandingTestDB(t)
	before, _ := defaultBlockPageRow(t)
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "branding.json"), []byte(`{"app_name":"定制品牌","footer_text":"定制页脚文案"}`), 0644); err != nil {
		t.Fatalf("write branding file: %v", err)
	}

	// When
	if _, err := SeedDefaultBlockPage(dataDir); err != nil {
		t.Fatalf("SeedDefaultBlockPage: %v", err)
	}

	// Then
	content, _ := defaultBlockPageRow(t)
	if !strings.Contains(content, "定制品牌") {
		t.Errorf("default block page missing custom app name:\n%s", content)
	}
	if !strings.Contains(content, "定制页脚文案") {
		t.Errorf("default block page missing custom footer text:\n%s", content)
	}
	if content == before {
		t.Error("default block page content was not updated")
	}
	var statusCode int
	if err := db.DB.QueryRow("SELECT status_code FROM security_block_pages WHERE is_default=1").Scan(&statusCode); err != nil {
		t.Fatalf("read status_code: %v", err)
	}
	if statusCode != 403 {
		t.Errorf("status_code=%d, want 403 (seeder must not touch it)", statusCode)
	}
}

func TestSeedDefaultBlockPage_uses_default_branding_when_file_missing(t *testing.T) {
	// Given
	initBrandingTestDB(t)
	before, _ := defaultBlockPageRow(t)
	dataDir := t.TempDir()

	// When
	if _, err := SeedDefaultBlockPage(dataDir); err != nil {
		t.Fatalf("SeedDefaultBlockPage: %v", err)
	}

	// Then
	content, _ := defaultBlockPageRow(t)
	if !strings.Contains(content, defaultBranding.AppName) || !strings.Contains(content, defaultBranding.FooterText) {
		t.Errorf("default block page missing default branding:\n%s", content)
	}
	if content == before {
		t.Error("default block page content was not updated")
	}
}

func TestSeedDefaultBlockPage_falls_back_to_defaults_on_invalid_json(t *testing.T) {
	// Given
	initBrandingTestDB(t)
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "branding.json"), []byte(`{invalid`), 0644); err != nil {
		t.Fatalf("write branding file: %v", err)
	}

	// When
	if _, err := SeedDefaultBlockPage(dataDir); err != nil {
		t.Fatalf("SeedDefaultBlockPage: %v", err)
	}

	// Then
	content, _ := defaultBlockPageRow(t)
	if !strings.Contains(content, defaultBranding.AppName) || !strings.Contains(content, defaultBranding.FooterText) {
		t.Errorf("default block page missing default branding fallback:\n%s", content)
	}
}

func TestSeedDefaultBlockPage_keeps_updated_at_when_content_unchanged(t *testing.T) {
	// Given: default row already holds the freshly rendered content with a sentinel timestamp
	initBrandingTestDB(t)
	dataDir := t.TempDir()
	rendered := renderDefaultBlockPage(loadBrandingConfig(dataDir))
	if _, err := db.DB.Exec("UPDATE security_block_pages SET content=?, updated_at='2020-01-01 00:00:00' WHERE is_default=1", rendered); err != nil {
		t.Fatalf("arrange default row: %v", err)
	}

	// When
	if _, err := SeedDefaultBlockPage(dataDir); err != nil {
		t.Fatalf("SeedDefaultBlockPage: %v", err)
	}

	// Then
	content, updatedAt := defaultBlockPageRow(t)
	if content != rendered {
		t.Errorf("content changed unexpectedly")
	}
	if !strings.HasPrefix(updatedAt, "2020-01-01") {
		t.Errorf("updated_at=%q, want the 2020-01-01 sentinel preserved (no churn when unchanged)", updatedAt)
	}
}

func TestSeedDefaultBlockPage_leaves_custom_pages_untouched(t *testing.T) {
	// Given
	initBrandingTestDB(t)
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "branding.json"), []byte(`{"app_name":"定制品牌","footer_text":"定制页脚"}`), 0644); err != nil {
		t.Fatalf("write branding file: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_block_pages (name, description, content, status_code, is_default, created_by, updated_by)
		VALUES ('自定义页面', '', 'SENTINEL-CONTENT', 451, 0, 0, 0)`); err != nil {
		t.Fatalf("insert custom block page: %v", err)
	}

	// When
	if _, err := SeedDefaultBlockPage(dataDir); err != nil {
		t.Fatalf("SeedDefaultBlockPage: %v", err)
	}

	// Then
	var content string
	var statusCode int
	err := db.DB.QueryRow("SELECT content, status_code FROM security_block_pages WHERE is_default=0 AND name='自定义页面'").Scan(&content, &statusCode)
	if err != nil {
		t.Fatalf("read custom block page: %v", err)
	}
	if content != "SENTINEL-CONTENT" {
		t.Errorf("custom block page content=%q, want SENTINEL-CONTENT", content)
	}
	if statusCode != 451 {
		t.Errorf("custom block page status_code=%d, want 451", statusCode)
	}
}
