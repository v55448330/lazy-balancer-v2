package handlers

// 日报配置/预览/手动触发 REST（方案：日报从订阅矩阵拆出为独立
// 区块——启用/时间/项目定制/投递格式/预览；定时与管理员触发共用
// notify.DeliverDailyForAll 单源）。

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

// GetNotificationDaily GET /notification/daily——当前用户配置（无行=默认）。
func (h *Handlers) GetNotificationDaily(c *gin.Context) {
	uid := contextUserID(c)
	cfg, err := notify.GetDailyConfig(uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.dailyConfigReadFailed", err))
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"config": cfg,
		"items":  notify.DailyItemIDs,
		"labels": notify.DailyItemLabels,
		// 大模块分组（2026-11-21 裁定：配置按模块选择）
		"modules": notify.DailyModules(),
	}})
}

// validateDailySendTime 校验日报投递时间（HH:MM）。独立日报端点与聚合规则
// 端点共用同一实现——两处各写一份会让其中一侧静默接受非法时间。
func validateDailySendTime(c *gin.Context, sendTime string) bool {
	if _, err := time.Parse("15:04", sendTime); err != nil {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(400, "notify.dailySendTimeInvalid"))
		return false
	}
	return true
}

// validateDailyItems 校验日报项目白名单（空切片合法=不改）。
func validateDailyItems(c *gin.Context, items []string) bool {
	validItems := map[string]bool{}
	for _, it := range notify.DailyItemIDs {
		validItems[it] = true
	}
	for _, it := range items {
		if !validItems[it] {
			c.JSON(http.StatusBadRequest, apimsg.Envelope(400, "notify.dailyItemUnknown", it))
			return false
		}
	}
	return true
}

// PutNotificationDaily PUT /notification/daily——保存配置（items 白名单校验、
// send_time HH:MM 校验、format 白名单校验）。审计留痕。
func (h *Handlers) PutNotificationDaily(c *gin.Context) {
	uid := contextUserID(c)
	var req struct {
		Enabled  *bool             `json:"enabled"` // nil=缺省键，不得改动既有启用态
		SendTime string            `json:"send_time"`
		Items    []string          `json:"items"`
		Formats  map[string]string `json:"formats"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(400, "notify.invalidRequest", apimsg.ErrMsg(err)))
		return
	}
	if !validateDailySendTime(c, req.SendTime) {
		return
	}
	if !validateDailyItems(c, req.Items) {
		return
	}
	// 部分更新：以既有配置为基线，缺省键沿用现值——此前以零值构造整份
	// 配置，任何只改 send_time/items 的请求都会把日报静默停用。
	cfg, err := notify.GetDailyConfig(uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.dailyConfigReadFailed", err))
		return
	}
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}
	// send_time 在入口已强制校验（空值恒 400），此处必非空。
	cfg.SendTime = req.SendTime
	if len(req.Items) > 0 {
		cfg.Items = req.Items
	}
	if req.Formats != nil {
		cfg.Formats = req.Formats
	}
	if err := notify.SaveDailyConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.dailyConfigSaveFailed", err))
		return
	}
	recordAudit(c, "修改", "通知日报", services.FormatAuditDetail(
		services.AuditTextPart("audit.autoUpdateSettings", cfg.Enabled, cfg.SendTime, len(cfg.Items)), services.AuditRawPart(""), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0})
}

// PreviewNotificationDaily POST /notification/daily/preview——按请求体配置
// 渲染昨日真实数据的预览（format 指定输出格式；不落库）。
func (h *Handlers) PreviewNotificationDaily(c *gin.Context) {
	var req struct {
		Items  []string `json:"items"`
		Format string   `json:"format"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(400, "notify.invalidRequest", apimsg.ErrMsg(err)))
		return
	}
	switch req.Format {
	case "text", "markdown", "html", "json":
	default:
		req.Format = "markdown"
	}
	if len(req.Items) == 0 {
		req.Items = append([]string{}, notify.DailyItemIDs...)
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	data, err := notify.CollectDailyData(ctx, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.dailyDataCollectFailed", err))
		return
	}
	content := notify.RenderDaily(data, req.Items, req.Format)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"format":  req.Format,
		"content": content,
		"date":    data.Date,
	}})
}

// TriggerNotificationDaily POST /notification/daily/trigger——管理员手动触发
// 全员日报（复用 DeliverDailyForAll：与 Scheduled 任务体单源同路径）。审计留痕。
func (h *Handlers) TriggerNotificationDaily(c *gin.Context) {
	// 与 TestNotificationRule/TestNotificationDaily 同族主节点门：从节点没有
	// pending 消费方（投递 Daemon 只在主节点），放行=200 假成功 + 投递行堆积。
	if !requireNotifyMaster(c) {
		return
	}
	if !isAdminRequest(c) {
		c.JSON(http.StatusForbidden, apimsg.Envelope(403, "notify.dailyTriggerForbidden"))
		return
	}
	rendered, err := notify.DeliverDailyForAll(c.Request.Context(), time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.dailyTriggerAllFailed", err))
		return
	}
	recordAudit(c, "触发", "通知日报", services.FormatAuditDetail(
		services.AuditTextPart("audit.dailyReportManualTrigger", rendered), services.AuditRawPart(""), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"rendered": rendered}})
}

// GetDailyTargets GET /notification/daily/targets——日报投递目标透明化：
// 启用日报的用户 → 各自的启用通道（管理员全量，普通用户仅自己）。
func (h *Handlers) GetDailyTargets(c *gin.Context) {
	admin := isAdminRequest(c)

	type target struct {
		Username string `json:"username"`
		Channels []struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"channels"`
	}

	// LEFT JOIN：无 notification_daily 行=默认启用（与 GetDailyConfig 同口径），
	// JOIN 会把从未保存过日报配置的用户整行排除，投递目标页与实际调度分叉。
	query := `SELECT DISTINCT u.id, u.username
		FROM users u
		LEFT JOIN notification_daily nd ON nd.user_id = u.id
		WHERE COALESCE(json_extract(nd.config,'$.enabled'),1)=1`
	args := []any{}
	if !admin {
		// 非管理员只看自己：此前拼了 WHERE 却没传参——Query 缺参恒报错，
		// 普通用户调用直接 500（「查询日报投递目标失败」）。
		query += ` AND u.id=?`
		args = append(args, contextUserID(c))
	}
	query += ` ORDER BY u.id`

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.dailyTargetsQueryFailed", err))
		return
	}
	var userIDs []int64
	var usernames []string
	skipped := 0
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			skipped++
			continue
		}
		userIDs = append(userIDs, id)
		usernames = append(usernames, name)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.dailyTargetsQueryFailed", err))
		return
	}
	rows.Close()

	targets := make([]target, 0, len(userIDs))
	for i, id := range userIDs {
		t := target{Username: usernames[i], Channels: []struct {
			Type string `json:"type"`
			Name string `json:"name"`
		}{}}
		chRows, err := db.DB.Query(`SELECT type, name FROM notification_channels
			WHERE user_id=? AND enabled=1 ORDER BY id`, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.dailyTargetsQueryFailed", err))
			return
		}
		for chRows.Next() {
			var ct, cn string
			if err := chRows.Scan(&ct, &cn); err != nil {
				// 跳过坏行但计数披露（data.partial），不静默吞掉目标通道。
				skipped++
				continue
			}
			t.Channels = append(t.Channels, struct {
				Type string `json:"type"`
				Name string `json:"name"`
			}{Type: ct, Name: cn})
		}
		if err := chRows.Err(); err != nil {
			chRows.Close()
			c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.dailyTargetsQueryFailed", err))
			return
		}
		chRows.Close()
		targets = append(targets, t)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"targets": targets, "skipped": skipped, "partial": skipped > 0}})
}
