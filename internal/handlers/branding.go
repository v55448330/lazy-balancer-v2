package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"

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

func (h *Handlers) GetBranding(c *gin.Context) {
	cfg := defaultBranding
	path := filepath.Join(h.cfg.DataDir, "branding.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("GetBranding: failed to read branding file %s, using defaults: %v", path, err)
		}
		cfg.Version = h.cfg.Version
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: cfg})
		return
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("GetBranding: invalid branding file %s, using defaults: %v", path, err)
		cfg = defaultBranding
	}
	if cfg.Version == "" {
		cfg.Version = h.cfg.Version
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: cfg})
}
