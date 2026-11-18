package handlers

// 通知中心订阅矩阵 REST：事件目录导出 + 用户订阅读写。
// 订阅语义与 notify.subscribersFor 同口径：显式订阅行按 min_level 过滤；
// 无显式行按目录 DefaultSub 兜底（critical+warn 默认开）。PUT 的 min_level
// 空串=删除显式行回默认态。

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

// ListNotificationCatalog GET /notification/catalog——事件目录全量（含分组）。
func (h *Handlers) ListNotificationCatalog(c *gin.Context) {
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"events": notify.CatalogExport()}})
}

// ListNotificationSubscriptions GET /notification/subscriptions——当前用户
// 订阅矩阵：目录全量行（含未订阅行的默认态）合并本人显式订阅。
func (h *Handlers) ListNotificationSubscriptions(c *gin.Context) {
	uid := contextUserID(c)
	rows, err := db.DB.Query(`SELECT event_type, min_level, COALESCE(body_template,'') FROM notification_subscriptions WHERE user_id=?`, uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取通知订阅失败", err)})
		return
	}
	defer rows.Close()
	explicit := map[string]string{}
	explicitTpl := map[string]string{}
	for rows.Next() {
		var eventType, minLevel, bodyTemplate string
		if err := rows.Scan(&eventType, &minLevel, &bodyTemplate); err != nil {
			continue
		}
		explicit[eventType] = minLevel
		explicitTpl[eventType] = bodyTemplate
	}

	catalog := notify.CatalogExport()
	subs := make([]gin.H, 0, len(catalog))
	for _, e := range catalog {
		minLevel := ""
		subscribed := false
		bodyTemplate := ""
		if lvl, ok := explicit[e.ID]; ok {
			subscribed = true
			minLevel = lvl
			bodyTemplate = explicitTpl[e.ID]
		}
		subs = append(subs, gin.H{
			"event_type":         e.ID,
			"level":              e.Level,
			"default_subscribed": e.DefaultSubscribed,
			"subscribed":         subscribed,
			"min_level":          minLevel,
			"body_template":      bodyTemplate,
		})
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"subscriptions": subs}})
}

// validSubLevel 订阅下限白名单（与 notify.Level 三档同口径）。
func validSubLevel(l string) bool {
	switch l {
	case string(notify.LevelInfo), string(notify.LevelWarn), string(notify.LevelCritical):
		return true
	}
	return false
}

// UpdateNotificationSubscriptions PUT /notification/subscriptions——批量
// 设置当前用户订阅（user×event_type→min_level UPSERT；min_level 空=删行）。
func (h *Handlers) UpdateNotificationSubscriptions(c *gin.Context) {
	uid := contextUserID(c)
	var req struct {
		Items []struct {
			EventType    string `json:"event_type"`
			MinLevel     string `json:"min_level"`
			BodyTemplate string `json:"body_template"`
		} `json:"items"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Items) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_76de02a0"), MessageKey: "k_76de02a0"})
		return
	}
	catalogByID := map[string]struct{}{}
	for _, e := range notify.CatalogExport() {
		catalogByID[e.ID] = struct{}{}
	}
	type subOp struct {
		eventType    string
		minLevel     string
		bodyTemplate string // 空=删除
	}
	ops := make([]subOp, 0, len(req.Items))
	for _, item := range req.Items {
		if _, ok := catalogByID[item.EventType]; !ok {
			msg := apimsg.Tf(c, "k_74125a73", item.EventType)
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg, MessageKey: "k_74125a73"})
			return
		}
		if item.MinLevel != "" && !validSubLevel(item.MinLevel) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_3ae60346"), MessageKey: "k_3ae60346"})
			return
		}
		ops = append(ops, subOp{eventType: item.EventType, minLevel: item.MinLevel, bodyTemplate: item.BodyTemplate})
	}

	tx, err := db.DB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存通知订阅失败", err)})
		return
	}
	defer tx.Rollback()
	for _, op := range ops {
		if op.minLevel == "" {
			if _, err := tx.Exec(`DELETE FROM notification_subscriptions WHERE user_id=? AND event_type=?`, uid, op.eventType); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存通知订阅失败", err)})
				return
			}
			continue
		}
		if _, err := tx.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, body_template) VALUES (?,?,?,?)
			ON CONFLICT(user_id, event_type) DO UPDATE SET min_level=excluded.min_level, body_template=excluded.body_template`, uid, op.eventType, op.minLevel, op.bodyTemplate); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存通知订阅失败", err)})
			return
		}
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存通知订阅失败", err)})
		return
	}
	recordAudit(c, "修改", "通知订阅", services.FormatAuditDetail(fmt.Sprintf("订阅更新×%d", len(ops)), "", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0})
}
