package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

type brandingConfig struct {
	AppName    string `json:"app_name"`
	FooterText string `json:"footer_text"`
	Version    string `json:"version,omitempty"`
}

var defaultBranding = brandingConfig{
	AppName:    "Lazy Balancer",
	FooterText: "Copyright © 2026 XiaoBao. All rights reserved.",
}

func SeedDefaultBranding(dataDir string) error {
	path := filepath.Join(dataDir, "branding.json")
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("检查品牌配置文件: %w", err)
	}
	data, err := json.MarshalIndent(defaultBranding, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化默认品牌配置: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("写入默认品牌配置: %w", err)
	}
	return nil
}

func loadBrandingConfig(dataDir string) brandingConfig {
	cfg := defaultBranding
	path := filepath.Join(dataDir, "branding.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("loadBrandingConfig: failed to read branding file %s, using defaults: %v", path, err)
		}
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("loadBrandingConfig: invalid branding file %s, using defaults: %v", path, err)
		return defaultBranding
	}
	return cfg
}

func (h *Handlers) GetBranding(c *gin.Context) {
	cfg := loadBrandingConfig(h.cfg.DataDir)
	if cfg.Version == "" {
		cfg.Version = h.cfg.Version
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: cfg})
}

// renderDefaultBlockPage is the single renderer shared by GetDefaultBlockPage
// and SeedDefaultBlockPage so both produce the identical branded page.
func renderDefaultBlockPage(cfg brandingConfig) string {
	footer := fmt.Sprintf(`Powered by <span class="name">%s</span>`, cfg.AppName)
	if cfg.FooterText != "" {
		footer += "<br>" + cfg.FooterText
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
</html>`, cfg.AppName, footer)
}

// SeedDefaultBlockPage re-renders the default block page row (is_default=1) from
// branding.json. Idempotent: an unchanged render writes nothing (updated_at is
// not churned); custom pages are never touched.
func SeedDefaultBlockPage(dataDir string) error {
	if db.DB == nil {
		return nil
	}
	content := renderDefaultBlockPage(loadBrandingConfig(dataDir))
	if _, err := db.DB.Exec(`UPDATE security_block_pages SET content=?, updated_at=datetime('now') WHERE is_default=1 AND content != ?`, content, content); err != nil {
		return fmt.Errorf("更新默认拦截页面内容: %w", err)
	}
	return nil
}

func (h *Handlers) GetDefaultBlockPage(c *gin.Context) {
	cfg := defaultBranding
	path := filepath.Join(h.cfg.DataDir, "branding.json")
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &cfg)
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(renderDefaultBlockPage(cfg)))
}
