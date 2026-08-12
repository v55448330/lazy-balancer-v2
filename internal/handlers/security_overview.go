package handlers

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// GetSecurityRateLimitBlocks 返回各站点被限流（HTTP 429, handler=rate_limit）拦截的
// 累计次数，数据来自 Caddy admin /metrics。注意口径：计数自 Caddy 进程启动以来
// 累计，重启即归零（前端按"累计拦截"标注）。采集失败时降级为空列表返回 200，
// 不影响安全总览页其余区块。
func (h *Handlers) GetSecurityRateLimitBlocks(c *gin.Context) {
	blocks, err := services.ScrapeRateLimitBlocks(h.cfg.CaddyMetricsURL)
	if err != nil {
		log.Printf("Scrape rate-limit blocks failed: %v", err)
		blocks = []services.RateLimitHostBlocks{}
	}
	var total float64
	for _, block := range blocks {
		total += block.Count
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"total": total,
		"hosts": blocks,
	}})
}
