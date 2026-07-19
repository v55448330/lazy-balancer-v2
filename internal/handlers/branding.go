package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

type brandingConfig struct {
	AppName    string `json:"app_name"`
	FooterText string `json:"footer_text"`
	Version    string `json:"version"`
}

var defaultBranding = brandingConfig{
	AppName:    "Lazy Balancer",
	FooterText: "Copyright © 2026 XiaoBao. All rights reserved.",
}

func (h *Handlers) GetBranding(c *gin.Context) {
	cfg := defaultBranding
	path := filepath.Join(h.cfg.DataDir, "branding.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if defaults, merr := json.MarshalIndent(cfg, "", "  "); merr == nil {
				_ = os.WriteFile(path, defaults, 0644)
			}
		}
		cfg.Version = h.cfg.Version
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: cfg})
		return
	}
	_ = json.Unmarshal(data, &cfg)
	cfg.Version = h.cfg.Version
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: cfg})
}
