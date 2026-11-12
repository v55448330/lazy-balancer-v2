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
// 计数为进程累计（重启归零）：挑战成功不落安全事件（2026-11-13 用户裁定），
// 通过数/通过率以本端点为权威源；CC「封禁」响应退役后不再有 bans。
func (h *Handlers) GetHumanVerifyStats(c *gin.Context) {
	type stats struct {
		Challenges int64 `json:"challenges"`
		Passes     int64 `json:"passes"`
		Fails      int64 `json:"fails"`
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
