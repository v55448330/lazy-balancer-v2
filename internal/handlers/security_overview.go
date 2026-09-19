package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// GetSecurityRateLimitBlocks 返回各站点被限流（HTTP 429）拦截的累计次数，数据
// 来自 Caddy admin /metrics。注意口径：仅按 code=429 过滤、含上游自返 429；
// 计数自最近一次 Caddy 配置重载以来累计（SECLB34-ACL-1 第 34 轮实证：/load
// 重建 metrics registry 即归零；进程重启同），非进程启动口径（前端按"累计拦截"标注）。
// 抓取失败返回 500：降级为空列表会让「Caddy 指标不可达」与「暂无限流拦截」
// 不可区分，面板错误态需可达（R38 三-4）。
func (h *Handlers) GetSecurityRateLimitBlocks(c *gin.Context) {
	blocks, err := services.ScrapeRateLimitBlocks(h.cfg.CaddyMetricsURL)
	if err != nil {
		services.Logf("error", "Scrape rate-limit blocks failed: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "限流拦截数据不可用"})
		return
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

// GetRuleStageStats 返回单规则的三阶段计数（流程抽屉计数 chip）：
//   - stage1_blocked_24h / stage3_blocked_24h：近 24h 该规则 blocked 安全事件
//     按 rule_triggered id 形状分桶——阶段 1（IP 访问控制+地域拦截预检）=
//     {2,4,7,8} ∪ [800000,900000)，其余（CRS 9xxxxx/自定义/合成 id）归阶段 3；
//   - ratelimit_blocks_reload：Caddy /metrics 429 计数（重载口径，自最近一次
//     配置重载以来累计）按规则 domain 映射回规则求和——规则域名与 host 标签
//     不匹配的部署（泛域名/CNAME）显示 0 而非报错（已声明口径，不新造时序）。
//
// 429 抓取失败返回 500（与 GetSecurityRateLimitBlocks 同口径：指标不可达与
// 暂无限流拦截必须可区分，前端 chip 显示「暂无计数」）。
func (h *Handlers) GetRuleStageStats(c *gin.Context) {
	ruleCaddyID := c.Param("caddy_id")
	rows, err := db.MetricsDB.Query(`SELECT rule_triggered, COUNT(*) FROM security_events WHERE rule_caddy_id=? AND action='blocked' AND event_time >= datetime('now','-1 day') GROUP BY rule_triggered`, ruleCaddyID)
	if err != nil {
		services.Logf("error", "stage-stats query failed for %s: %v", ruleCaddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "阶段统计查询失败"})
		return
	}
	stage1, stage3 := 0, 0
	for rows.Next() {
		var triggered string
		var count int
		if err := rows.Scan(&triggered, &count); err != nil {
			rows.Close()
			services.Logf("error", "stage-stats scan failed for %s: %v", ruleCaddyID, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "阶段统计查询失败"})
			return
		}
		n, convErr := strconv.Atoi(triggered)
		if convErr == nil && (n == 2 || n == 4 || n == 7 || n == 8 || (n >= 800000 && n < 900000)) {
			stage1 += count
		} else {
			stage3 += count
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		services.Logf("error", "stage-stats rows iteration failed for %s: %v", ruleCaddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "阶段统计查询失败"})
		return
	}
	rows.Close()

	var domain string
	if err := db.DB.QueryRow(`SELECT COALESCE(domain,'') FROM lb_rules WHERE caddy_id=?`, ruleCaddyID).Scan(&domain); err != nil {
		services.Logf("error", "stage-stats read rule domain failed for %s: %v", ruleCaddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "规则不存在"})
		return
	}
	var ratelimit float64
	if domain != "" {
		blocks, err := services.ScrapeRateLimitBlocks(h.cfg.CaddyMetricsURL)
		if err != nil {
			services.Logf("error", "stage-stats scrape rate-limit blocks failed: %v", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "限流拦截数据不可用"})
			return
		}
		ruleHosts := make(map[string]struct{})
		for _, host := range strings.Split(domain, ",") {
			if trimmed := strings.ToLower(strings.TrimSpace(host)); trimmed != "" {
				ruleHosts[trimmed] = struct{}{}
			}
		}
		for _, block := range blocks {
			if _, ok := ruleHosts[strings.ToLower(block.Host)]; ok {
				ratelimit += block.Count
			}
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"stage1_blocked_24h":      stage1,
		"stage3_blocked_24h":      stage3,
		"ratelimit_blocks_reload": ratelimit,
	}})
}
