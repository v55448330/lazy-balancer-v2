package handlers

import (
	"database/sql"
	"errors"
	"fmt"
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
//     按 rule_triggered id 形状分桶——阶段 1（IP 访问控制+威胁情报库+地域拦截预检）=
//     {2,4,7,8,14} ∪ [800000,900000)，其余（CRS 9xxxxx/自定义/合成 id）归阶段 3；
//   - ratelimit_blocks_reload：Caddy /metrics 429 计数（重载口径，自最近一次
//     配置重载以来累计）按规则 domain 映射回规则求和——规则域名与 host 标签
//     不匹配的部署（泛域名/CNAME）显示 0 而非报错（已声明口径，不新造时序）。
//
// 429 抓取失败返回 500（与 GetSecurityRateLimitBlocks 同口径：指标不可达与
// 暂无限流拦截必须可区分，前端 chip 显示「暂无计数」）。
func (h *Handlers) GetRuleStageStats(c *gin.Context) {
	if db.MetricsDB == nil {
		// MetricsDB 未装配：返回空统计而非 panic（第 57 轮 P5-4）
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]any{}})
		return
	}
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
		if convErr == nil && services.IsStage1PrecheckID(n) { // 第 59 轮收敛：五元组单一事实源
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
		// APIMCP45-3：ErrNoRows（规则不存在）与真实 DB 故障分判——前者归 404
		// not_found，后者保持 500 且 message 归位查询失败（不再借「规则不存在」
		// 文案）。前端对非 200 一律 stats=null，404 化不改变前端表现。
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
			return
		}
		services.Logf("error", "stage-stats read rule domain failed for %s: %v", ruleCaddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "阶段统计查询失败"})
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
			if trimmed := services.NormalizeMetricsHost(host); trimmed != "" {
				ruleHosts[trimmed] = struct{}{}
			}
		}
		for _, block := range blocks {
			if _, ok := ruleHosts[services.NormalizeMetricsHost(block.Host)]; ok {
				ratelimit += block.Count
			}
		}
	}
	// 分段平均处理耗时（2026-09-27 用户裁定）：security_events.duration_us 按
	// 预检/WAF 段分桶平均（摄取管道已按规则归属选段值——预检事件=纯预检耗时,
	// WAF 事件=隔离预检后的 WAF 耗时）。24h 窗口对齐计数口径;duration_us>0 过滤
	// 历史行/未命中行;高并发下 GROUP BY 走 idx_security_events_rule+time 索引。
	preAvg, preCnt, wafAvg, wafCnt := 0.0, 0, 0.0, 0
	// 预检平均用 precheck_us 全样本(含 WAF 事件的预检快照,样本更大更准);
	// WAF 平均只用 WAF 段事件的 duration_us(已隔离预检开销)。
	stageTimingSQL := fmt.Sprintf(`SELECT rule_triggered, AVG(CASE WHEN %s THEN precheck_us ELSE duration_us END), COUNT(*) FROM security_events WHERE rule_caddy_id=? AND event_time >= datetime('now','-1 day') AND duration_us > 0 GROUP BY rule_triggered`, services.Stage1PrecheckSegmentSQL)
	if trows, terr := db.MetricsDB.Query(stageTimingSQL, ruleCaddyID); terr == nil {
		for trows.Next() {
			var triggered string
			var avg float64
			var cnt int
			if serr := trows.Scan(&triggered, &avg, &cnt); serr != nil {
				break
			}
			if n, cerr := strconv.Atoi(triggered); cerr == nil && services.IsStage1PrecheckID(n) {
				preAvg = (preAvg*float64(preCnt) + avg*float64(cnt)) / float64(preCnt+cnt)
				preCnt += cnt
			} else {
				wafAvg = (wafAvg*float64(wafCnt) + avg*float64(cnt)) / float64(wafCnt+cnt)
				wafCnt += cnt
			}
		}
		// SEC-B-2（第 70 轮）：分段耗时迭代失败不再静默——与 F62-21 查询失败
		// 同待遇记 warn（耗时为增强信息，响应仍 200，已收样本保留）。
		if err := trows.Err(); err != nil {
			services.Logf("warn", "stage-stats timing rows iteration failed for %s: %v", ruleCaddyID, err)
		}
		trows.Close()
	} else {
		// 第 62 轮 F62-21:查询失败不再静默——留 warn 便于排查(响应仍 200,
		// 耗时为增强信息,与计数/429 的 500 纪律不同——已声明口径)
		services.Logf("warn", "stage-stats timing query failed for %s: %v", ruleCaddyID, terr)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"stage1_blocked_24h":      stage1,
		"stage3_blocked_24h":      stage3,
		"ratelimit_blocks_reload": ratelimit,
		"precheck_avg_us":         preAvg,
		"precheck_samples":        preCnt,
		"waf_avg_us":              wafAvg,
		"waf_samples":             wafCnt,
	}})
}
