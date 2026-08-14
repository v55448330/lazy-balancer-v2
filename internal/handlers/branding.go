package handlers

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

type brandingConfig struct {
	AppName    string `json:"app_name"`
	FooterText string `json:"footer_text"`
	Version    string `json:"version,omitempty"`
}

// defaultFooterText is the product footer rendered when branding.json is
// absent or its footer_text is empty; the GitHub link is appended only in
// this default rendering — a configured footer_text is rendered verbatim.
const defaultFooterText = "Lazy Balancer V2 · Copyright © 2026 XiaoBao"

var defaultBranding = brandingConfig{
	AppName:    "Lazy Balancer",
	FooterText: defaultFooterText,
}

// SeedBrandingTemplate writes an all-empty branding.json on first boot so the
// file exists as an editable template; empty values keep default rendering.
func SeedBrandingTemplate(dataDir string) error {
	path := filepath.Join(dataDir, "branding.json")
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("检查品牌配置文件: %w", err)
	}
	template := brandingConfig{}
	data, err := json.MarshalIndent(template, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化品牌配置模板: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("写入品牌配置模板: %w", err)
	}
	return nil
}

// loadBrandingConfig reads branding.json onto a zero config: absent file or
// empty fields mean "use the default for that field"; non-empty fields are
// rendered verbatim (never merged with defaults).
func loadBrandingConfig(dataDir string) brandingConfig {
	var cfg brandingConfig
	path := filepath.Join(dataDir, "branding.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("loadBrandingConfig: failed to read branding file %s, using defaults: %v", path, err)
		}
		cfg.AppName = defaultBranding.AppName
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("loadBrandingConfig: invalid branding file %s, using defaults: %v", path, err)
		cfg = brandingConfig{AppName: defaultBranding.AppName}
		return cfg
	}
	if cfg.AppName == "" {
		cfg.AppName = defaultBranding.AppName
	}
	return cfg
}

type brandingResponse struct {
	AppName           string `json:"app_name"`
	FooterText        string `json:"footer_text"`
	Version           string `json:"version"`
	FooterUsesDefault bool   `json:"footer_uses_default"`
}

func (h *Handlers) GetBranding(c *gin.Context) {
	cfg := loadBrandingConfig(h.cfg.DataDir)
	resp := brandingResponse{
		AppName:           cfg.AppName,
		FooterText:        cfg.FooterText,
		FooterUsesDefault: cfg.FooterText == "",
	}
	if cfg.Version == "" {
		cfg.Version = h.cfg.Version
	}
	resp.Version = cfg.Version
	if resp.FooterUsesDefault {
		resp.FooterText = defaultFooterText
	}
	if changed, _ := SeedDefaultBlockPage(h.cfg.DataDir); changed {
		go func() {
			if err := h.applyCaddyConfigE(); err != nil {
				log.Printf("branding 触发的 Caddy 配置应用失败: %v", err)
			}
		}()
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: resp})
}

// renderDefaultBlockPage is the single renderer shared by GetDefaultBlockPage
// and SeedDefaultBlockPage so both produce the identical branded page.
func renderDefaultBlockPage(cfg brandingConfig) string {
	appName := html.EscapeString(cfg.AppName)
	footer := fmt.Sprintf(`Powered by <span class="name">%s</span>`, appName)
	if cfg.FooterText != "" {
		footer += "<br>" + blockPageFooterHTML(cfg.FooterText)
	} else {
		footer += "<br>" + html.EscapeString(defaultFooterText) + ` · <a href="https://github.com/v55448330/lazy-balancer-v2" target="_blank" rel="noopener noreferrer">GitHub</a>`
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access Denied — %s</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f9fafb; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
.card { background: #fff; border-radius: 12px; padding: 48px 40px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,.08); max-width: 640px; width: 95%%; }
.icon { font-size: 48px; margin-bottom: 16px; }
h1 { font-size: 24px; color: #1f2937; margin-bottom: 12px; }
p { font-size: 14px; color: #6b7280; line-height: 1.6; margin-bottom: 8px; }
.footer { margin-top: 24px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #9ca3af; }
.footer .name { font-weight: 600; color: #4b5563; }
.footer a { color: inherit; text-decoration: underline; text-decoration-color: #d1d5db; }
.footer a:hover { color: #4b5563; }
</style>
</head>
<body>
<div class="card">
<div class="icon">🚫</div>
<h1>Access Denied</h1>
<p>Your request has been blocked by the security policy.</p>
<p>If you believe this is an error, please contact the administrator.</p>
<div class="footer">%s</div>
</div>
</body>
</html>`, appName, footer)
}

// blockPageFooterHTML escapes the footer text and linkifies bare http(s) URLs,
// keeping user-controlled branding content inert in the block page.
func blockPageFooterHTML(text string) string {
	esc := strings.ReplaceAll(text, "&", "&amp;")
	esc = strings.ReplaceAll(esc, "<", "&lt;")
	esc = strings.ReplaceAll(esc, ">", "&gt;")
	esc = strings.ReplaceAll(esc, "\"", "&#34;")
	return urlLinkRe.ReplaceAllString(esc, `<a href="$0" target="_blank" rel="noopener noreferrer">$0</a>`)
}

var urlLinkRe = regexp.MustCompile(`https?://(?:[^\s"'&]|&amp;)+`)

// SeedDefaultBlockPage re-renders the default block page row (is_default=1) from
// branding.json. Idempotent: an unchanged render writes nothing (updated_at is
// not churned); custom pages are never touched.
func SeedDefaultBlockPage(dataDir string) (bool, error) {
	if db.DB == nil {
		return false, nil
	}
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err == nil && !isMaster {
		// The default block page content is owned by the master and arrives on
		// slaves via cluster sync; branding.json is node-local, so re-rendering
		// here would overwrite the synced content with local defaults.
		return false, nil
	}
	content := renderDefaultBlockPage(loadBrandingConfig(dataDir))
	result, err := db.DB.Exec(`UPDATE security_block_pages SET content=?, updated_at=datetime('now') WHERE is_default=1 AND content != ?`, content, content)
	if err != nil {
		return false, fmt.Errorf("更新默认拦截页面内容: %w", err)
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

func (h *Handlers) GetDefaultBlockPage(c *gin.Context) {
	cfg := loadBrandingConfig(h.cfg.DataDir)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(renderDefaultBlockPage(cfg)))
}
