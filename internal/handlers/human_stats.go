package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"lazy-balancer-v2/internal/models"

	"github.com/gin-gonic/gin"
)

// GetHumanVerifyStats GET /security/human/stats：人机验证挑战统计（Caddy admin
// /lb/human/stats 拉取；端点缺失=旧二进制，返回全零不报错——与 l4-conn-stats
// 同容错口径）。2s 超时，不阻塞总览加载。
func (h *Handlers) GetHumanVerifyStats(c *gin.Context) {
	type stats struct {
		Challenges int64 `json:"challenges"`
		Passes     int64 `json:"passes"`
		Fails      int64 `json:"fails"`
		Bans       int64 `json:"bans"`
	}
	out := stats{}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(h.cfg.CaddyAdminURL + "/lb/human/stats")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: out})
}
