package handlers

// 通知中心订阅矩阵 REST：事件目录导出 + 用户订阅读写。
// 订阅语义与 notify.subscribersFor 同口径：显式订阅行按 min_level 过滤；
// 无显式行按目录 DefaultSub 兜底（critical+warn 默认开）。PUT 的 min_level
// 空串=停用显式行（enabled=0，作为用户意志 opt-out 默认兜底），不删行——
// 停用行保留更新者/时间，GET 以 enabled/disabled 披露该三态。

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

// subscriptionExecer 抽象停用写的执行面（事务 *sql.Tx 或全局 *sql.DB）。
type subscriptionExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// disableSubscriptionRow 停用 user×event 订阅（opt-out 显式行）。
// 无行时 UPDATE 影响 0 行——不建行等于静默无操作：目录 DefaultSub=true 的
// 事件仍按默认兜底投递，用户「关掉默认订阅组」在投递侧毫无效果
// 。因此 0 行时补建 enabled=0 的显式行，让用户
// 意志（opt-out）在 subscribersFor 的停用分支生效；min_level 留空串（停用
// 态级别对投递无意义）。actor=操作者（管理员代管时与 user_id 不同）。
func disableSubscriptionRow(execer subscriptionExecer, uid int64, eventType string, actor int64) error {
	res, err := execer.Exec(`UPDATE notification_subscriptions SET enabled=0, updated_at=datetime('now'), updated_by=? WHERE user_id=? AND event_type=?`, actor, uid, eventType)
	if err != nil {
		return err
	}
	if affected, err := res.RowsAffected(); err != nil {
		return err
	} else if affected > 0 {
		return nil
	}
	// 探测与插入之间的并发建行由 UPSERT 兜住（只置停用，不清既有级别/模板）。
	_, err = execer.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, body_template, enabled, updated_at, updated_by)
		VALUES (?,?,'','',0,datetime('now'),?)
		ON CONFLICT(user_id, event_type) DO UPDATE SET enabled=0, updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
		uid, eventType, actor)
	return err
}

// ListNotificationCatalog GET /notification/catalog——事件目录全量（含分组）。
func (h *Handlers) ListNotificationCatalog(c *gin.Context) {
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"events": notify.CatalogExport()}})
}

// ListNotificationSubscriptions GET /notification/subscriptions——当前用户
// 订阅矩阵：目录全量行（含未订阅行的默认态）合并本人显式订阅。
// 三态单源（与 notify.subscribersFor 同口径）：启用行=subscribed；停用行
// （enabled=0，opt-out 默认兜底）=disabled 且 subscribed=false；无行=默认态。
// 停用行不回显 min_level/body_template——停用态的级别对投递无意义，回显会
// 让消费端把「已停用」读成「按该级别订阅」。
func (h *Handlers) ListNotificationSubscriptions(c *gin.Context) {
	uid := contextUserID(c)
	rows, err := db.DB.Query(`SELECT event_type, COALESCE(min_level,''), COALESCE(body_template,''), COALESCE(enabled,1) FROM notification_subscriptions WHERE user_id=?`, uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取通知订阅失败", err)})
		return
	}
	defer rows.Close()
	type subRow struct {
		minLevel, bodyTemplate string
		enabled                bool
	}
	explicit := map[string]subRow{}
	for rows.Next() {
		var eventType string
		var row subRow
		var enabled int
		if err := rows.Scan(&eventType, &row.minLevel, &row.bodyTemplate, &enabled); err != nil {
			// 行读取失败必须 fail-visible：静默跳行会让停用行回退成「默认态」，
			// 用户看到的订阅矩阵与真实投递口径分叉（同族）。
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取通知订阅失败", err)})
			return
		}
		row.enabled = enabled != 0
		explicit[eventType] = row
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取通知订阅失败", err)})
		return
	}

	catalog := notify.CatalogExport()
	subs := make([]gin.H, 0, len(catalog))
	for _, e := range catalog {
		row, hasRow := explicit[e.ID]
		enabled := hasRow && row.enabled
		minLevel := ""
		bodyTemplate := ""
		if enabled {
			minLevel = row.minLevel
			bodyTemplate = row.bodyTemplate
		}
		subs = append(subs, gin.H{
			"event_type":         e.ID,
			"level":              e.Level,
			"default_subscribed": e.DefaultSubscribed,
			"subscribed":         enabled,
			"enabled":            enabled,
			"disabled":           hasRow && !row.enabled,
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
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Items) == 0 {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "common.malformedRequest"))
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
			msg := apimsg.Tf(c, "notify.subscriptionEventNotInCatalog", item.EventType)
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg, MessageKey: "notify.subscriptionEventNotInCatalog"})
			return
		}
		if item.MinLevel != "" && !validSubLevel(item.MinLevel) {
			c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "notify.invalidSubscriptionLevel"))
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
			// 取消订阅=停用行（保留更新者/时间；无行时补建 opt-out 行，否则
			// 默认订阅兜底会让「关闭」静默失效）。
			if err := disableSubscriptionRow(tx, uid, op.eventType, uid); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存通知订阅失败", err)})
				return
			}
			continue
		}
		if _, err := tx.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, min_level, body_template, enabled, updated_at, updated_by) VALUES (?,?,?,?,1,datetime('now'),?)
			ON CONFLICT(user_id, event_type) DO UPDATE SET min_level=excluded.min_level, body_template=excluded.body_template, enabled=1,
			updated_at=excluded.updated_at, updated_by=excluded.updated_by`, uid, op.eventType, op.minLevel, op.bodyTemplate, uid); err != nil {
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
