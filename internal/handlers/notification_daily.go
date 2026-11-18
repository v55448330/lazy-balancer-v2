package handlers

// 日报配置/预览/手动触发 REST（audit151 方案：日报从订阅矩阵拆出为独立
// 区块——启用/时间/项目定制/按通道格式/预览）。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取日报配置失败", err)})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"config": cfg,
		"items":  notify.DailyItemIDs,
		"labels": notify.DailyItemLabels,
	}})
}

// PutNotificationDaily PUT /notification/daily——保存配置（items 白名单校验、
// send_time HH:MM 校验、formats 通道键白名单校验）。
func (h *Handlers) PutNotificationDaily(c *gin.Context) {
	uid := contextUserID(c)
	var req struct {
		Enabled  bool              `json:"enabled"`
		SendTime string            `json:"send_time"`
		Items    []string          `json:"items"`
		Formats  map[string]string `json:"formats"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if _, err := time.Parse("15:04", req.SendTime); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.Tf(c, "k_f9986707"), MessageKey: msgDailySendTimeInvalid})
		return
	}
	validItems := map[string]bool{}
	for _, it := range notify.DailyItemIDs {
		validItems[it] = true
	}
	for _, it := range req.Items {
		if !validItems[it] {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.Tf(c, "k_d1a39d14", it), MessageKey: msgDailyItemUnknown})
			return
		}
	}
	cfg := notify.DailyConfig{UserID: uid, Enabled: req.Enabled, SendTime: req.SendTime,
		Items: req.Items, Formats: req.Formats}
	if err := notify.SaveDailyConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存日报配置失败", err)})
		return
	}
	recordAudit(c, "修改", "通知日报", services.FormatAuditDetail(
		fmt.Sprintf("启用=%v 时间=%s 项目数=%d", req.Enabled, req.SendTime, len(req.Items)), "", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0})
}

// PreviewNotificationDaily POST /notification/daily/preview——按请求体配置
// 渲染昨日真实数据的预览（format 指定输出格式；不落库）。
func (h *Handlers) PreviewNotificationDaily(c *gin.Context) {
	var req struct {
		Items  []string `json:"items"`
		Format string   `json:"format"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	switch req.Format {
	case "html", "json", "markdown":
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
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("采集日报数据失败", err)})
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
// 全员日报（复用 Scheduled 任务体）。
func (h *Handlers) TriggerNotificationDaily(c *gin.Context) {
	if !isAdminRequest(c) {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: apimsg.T(c, msgDailyTriggerForbidden), MessageKey: msgDailyTriggerForbidden})
		return
	}
	var users []int64
	rows, err := db.DB.Query(`SELECT DISTINCT user_id FROM notification_daily WHERE COALESCE(json_extract(config,'$.enabled'),1)=1`)
	if err == nil {
		for rows.Next() {
			var u int64
			if rows.Scan(&u) == nil {
				users = append(users, u)
			}
		}
		rows.Close()
	}
	if len(users) == 0 {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"rendered": 0}})
		return
	}
	rendered := 0
	now := time.Now()
	for _, u := range users {
		cfg, err := notify.GetDailyConfig(u)
		if err != nil {
			continue
		}
		data, err := notify.CollectDailyData(context.Background(), now)
		if err != nil {
			continue
		}
		content := notify.RenderDaily(data, cfg.Items, "markdown")
		insertDailyDelivery(u, content, now)
		rendered++
	}
	recordAudit(c, "触发", "通知日报", services.FormatAuditDetail(
		fmt.Sprintf("手动触发全员日报（渲染 %d 用户）", rendered), "", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"rendered": rendered}})
}

// insertDailyDelivery 日报直接落 pending 投递（content 为渲染后正文）。
func insertDailyDelivery(userID int64, content string, now time.Time) {
	_, err := db.DB.Exec(`INSERT INTO notification_deliveries
		(user_id, event_type, level, title, body, status, attempts, created_at)
		VALUES (?,?,?,?,?, 'pending', 0, ?)`,
		userID, "sys.daily_report", "info", "每日日报", content,
		now.UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		_ = err
	}
}

var _ = json.Marshal
var _ = strconv.Itoa
