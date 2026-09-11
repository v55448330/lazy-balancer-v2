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
	"lazy-balancer-v2/internal/services"
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

// D5 KNOWN-GAP-1（用户预期 2026-08-10）：默认拦截页卡片应占满页面宽度，
// 旧模板 max-width:640px 的居中卡片只占约 60% 宽。锁定新模板的全宽卡片
// CSS（浏览器布局引擎消费的结构化 token），防止回退到居中卡片布局。
func TestRenderDefaultBlockPage_card_spans_full_width(t *testing.T) {
	// Given
	cfg := brandingConfig{AppName: "Acme"}

	// When
	html := renderDefaultBlockPage(cfg)

	// Then
	if !strings.Contains(html, "max-width: none; width: auto; margin: 0 4%") {
		t.Errorf("rendered default block page card must span full width:\n%s", html)
	}
	if strings.Contains(html, "max-width: 640px") {
		t.Errorf("rendered default block page card still uses centered 640px layout:\n%s", html)
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
	if strings.Count(html, "<br>") != 1 || !strings.Contains(html, `href="https://github.com/v55448330/lazy-balancer-v2"`) {
		t.Errorf("rendered page should contain exactly one line break (repo link only) when footer text is empty:\n%s", html)
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
	if !strings.Contains(content, defaultBranding.AppName) || !strings.Contains(content, strings.Split(defaultBranding.FooterText, " · ")[0]) {
		t.Errorf("default block page missing default branding:\n%s", content)
	}
	if !strings.Contains(content, `href="https://github.com/v55448330/lazy-balancer-v2"`) {
		t.Errorf("default block page footer missing repo link:\n%s", content)
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
	if !strings.Contains(content, defaultBranding.AppName) || !strings.Contains(content, strings.Split(defaultBranding.FooterText, " · ")[0]) {
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
	if _, err := db.DB.Exec(`INSERT INTO security_block_pages (name, description, content, is_default, created_by, updated_by)
		VALUES ('自定义页面', '', 'SENTINEL-CONTENT', 0, 0, 0)`); err != nil {
		t.Fatalf("insert custom block page: %v", err)
	}

	// When
	if _, err := SeedDefaultBlockPage(dataDir); err != nil {
		t.Fatalf("SeedDefaultBlockPage: %v", err)
	}

	// Then
	var content string
	err := db.DB.QueryRow("SELECT content FROM security_block_pages WHERE is_default=0 AND name='自定义页面'").Scan(&content)
	if err != nil {
		t.Fatalf("read custom block page: %v", err)
	}
	if content != "SENTINEL-CONTENT" {
		t.Errorf("custom block page content=%q, want SENTINEL-CONTENT", content)
	}
}

// LandingText(2026-09-11):空域名命中的「Lazy Balancer V2 is running!」提示
// 文案迁入 branding.json(landing_text 字段);未定义时回退当前默认文案。
// SyncDefaultLandingText 把 branding.json 的 landing_text 注入 services 的
// 默认站点渲染;Caddy 配置的 http_80 catch-all body 必须随之变化。
func TestSyncDefaultLandingText_custom(t *testing.T) {
	// Given:自定义文案
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "branding.json"), []byte(`{"landing_text":"欢迎使用 XX 网关"}`), 0644); err != nil {
		t.Fatalf("write branding file: %v", err)
	}
	defer services.SetDefaultLandingBody("Lazy Balancer V2 is running!") // 还原

	// When
	changed, err := SyncDefaultLandingText(dataDir)
	if err != nil {
		t.Fatalf("SyncDefaultLandingText: %v", err)
	}

	// Then:报告变更,且 services 渲染注入自定义文案
	if !changed {
		t.Fatal("changed=false, want true (custom differs from default)")
	}
	cfg := services.DefaultLandingBody()
	if cfg != "欢迎使用 XX 网关" {
		t.Errorf("default site body=%q, want custom text", cfg)
	}
}

func TestSyncDefaultLandingText_default_fallback(t *testing.T) {
	// Given:branding.json 无 landing_text(空对象)
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "branding.json"), []byte(`{}`), 0644); err != nil {
		t.Fatalf("write branding file: %v", err)
	}
	services.SetDefaultLandingBody("自定义占位") // 模拟此前被改过
	defer services.SetDefaultLandingBody("Lazy Balancer V2 is running!")

	// When
	changed, err := SyncDefaultLandingText(dataDir)
	if err != nil {
		t.Fatalf("SyncDefaultLandingText: %v", err)
	}

	// Then:恢复默认文案
	if !changed {
		t.Fatal("changed=false, want true (reverts placeholder to default)")
	}
	if got := services.DefaultLandingBody(); got != "Lazy Balancer V2 is running!" {
		t.Errorf("default site body=%q, want default text", got)
	}
}

func TestSyncDefaultLandingText_invalid_json_falls_back(t *testing.T) {
	// Given:畸形 JSON 文件(loadBrandingConfig 重置为零配置)
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "branding.json"), []byte(`{"landing_text": broken`), 0644); err != nil {
		t.Fatalf("write branding file: %v", err)
	}
	services.SetDefaultLandingBody("被污染的占位")
	defer services.SetDefaultLandingBody(services.DefaultLandingText)

	// When
	if _, err := SyncDefaultLandingText(dataDir); err != nil {
		t.Fatalf("SyncDefaultLandingText: %v", err)
	}

	// Then:回退默认
	if got := services.DefaultLandingBody(); got != services.DefaultLandingText {
		t.Errorf("landing body=%q, want default on invalid json", got)
	}
}

// 内存快照契约(2026-09-11 重实现):loadBrandingConfig 从进程内快照读取,
// 文件 mtime/size 变化时透明重载;文件删除回退默认;跨 dataDir 不共享缓存。
func TestLoadBrandingConfig_memorySnapshotDetectsFileChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "branding.json")

	os.WriteFile(path, []byte(`{"app_name":"AlphaBranding"}`), 0644)
	if cfg := loadBrandingConfig(dir); cfg.AppName != "AlphaBranding" {
		t.Fatalf("first load: app_name=%q, want AlphaBranding", cfg.AppName)
	}

	st, _ := os.Stat(path)
	os.WriteFile(path, []byte(`{"app_name":"Beta"}`), 0644)
	waitForDistinctMtime(t, path, st.ModTime())
	if cfg := loadBrandingConfig(dir); cfg.AppName != "Beta" {
		t.Fatalf("after rewrite: app_name=%q, want Beta (change detection broken)", cfg.AppName)
	}

	os.Remove(path)
	if cfg := loadBrandingConfig(dir); cfg.AppName != defaultBranding.AppName {
		t.Fatalf("after remove: app_name=%q, want default %q", cfg.AppName, defaultBranding.AppName)
	}

	dir2 := t.TempDir()
	os.WriteFile(filepath.Join(dir2, "branding.json"), []byte(`{"app_name":"Other"}`), 0644)
	if cfg := loadBrandingConfig(dir2); cfg.AppName != "Other" {
		t.Fatalf("dir2: app_name=%q, want Other (cross-dir cache leak)", cfg.AppName)
	}
	if cfg := loadBrandingConfig(dir2); cfg.AppName != "Other" {
		t.Fatalf("dir2 second: app_name=%q, want Other", cfg.AppName)
	}
}

// 字段级类型回退:单字段类型错仅该字段回退,其余字段正常生效。
func TestLoadBrandingConfig_fieldTypeFallback(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "branding.json"), []byte(`{"app_name":123,"footer_text":"有效页脚","landing_text":"有效落地页"}`), 0644)

	cfg := loadBrandingConfig(dir)

	if cfg.AppName != defaultBranding.AppName {
		t.Errorf("app_name = %q, want default (int is invalid for string field)", cfg.AppName)
	}
	if cfg.FooterText != "有效页脚" {
		t.Errorf("footer_text = %q, want preserved (other fields must survive)", cfg.FooterText)
	}
	if cfg.LandingText != "有效落地页" {
		t.Errorf("landing_text = %q, want preserved", cfg.LandingText)
	}
}

// null 值按空处理(回退默认)。
func TestLoadBrandingConfig_nullFieldTreatedAsEmpty(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "branding.json"), []byte(`{"app_name":null,"landing_text":"自定义落地"}`), 0644)

	cfg := loadBrandingConfig(dir)

	if cfg.AppName != defaultBranding.AppName {
		t.Errorf("app_name = %q, want default (null→empty)", cfg.AppName)
	}
	if cfg.LandingText != "自定义落地" {
		t.Errorf("landing_text = %q, want preserved", cfg.LandingText)
	}
}

// 启动品牌载入日志(2026-09-11 裁定):boot 后操作日志记录「载入/品牌配置」,
// detail 标注各字段自定义/默认;系统日志同步 info。主从同路径。
func TestStartupBrandingLog_recordsAuditWithFieldStatus(t *testing.T) {
	oldAudit := db.AuditDB
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatalf("init audit: %v", err)
	}
	t.Cleanup(func() { db.AuditDB = oldAudit })

	dataDir := t.TempDir()
	os.WriteFile(filepath.Join(dataDir, "branding.json"), []byte(`{"app_name":"我的网关","landing_text":"欢迎"}`), 0644)

	StartupBrandingLog(dataDir)

	var action, resource, detail string
	if err := db.AuditDB.QueryRow(`SELECT action, resource, detail FROM audit_log WHERE resource='品牌配置' ORDER BY id DESC LIMIT 1`).Scan(&action, &resource, &detail); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if action != "载入" {
		t.Errorf("action=%q, want 载入", action)
	}
	if !strings.Contains(detail, "我的网关") {
		t.Errorf("detail missing custom app_name: %q", detail)
	}
	if !strings.Contains(detail, "欢迎") {
		t.Errorf("detail missing custom landing: %q", detail)
	}
	// 未自定义字段标注默认
	if !strings.Contains(detail, "页脚") {
		t.Errorf("detail missing footer status: %q", detail)
	}
}
