package handlers

// 通知中心投递流水 REST：本人投递列表（管理员 ?all=1 全平台）+ 失败重发。
// 跨属主可见性：管理员排障视角，正文截断脱敏；重发为属主或管理员，全部
// 留审计。

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

type notificationDeliveryDTO struct {
	ID        int64  `json:"id"`
	UserID    int64  `json:"user_id"`
	EventType string `json:"event_type"`
	Level     string `json:"level"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Status    string `json:"status"`
	Attempts  int    `json:"attempts"`
	Error     string `json:"error"`
	CreatedAt string `json:"created_at"`
	SentAt    string `json:"sent_at"`
}

// maskDeliveryBody 跨属主正文脱敏：rune 截断到 200 字符（保留边界完整字符）。
func maskDeliveryBody(body string) string {
	runes := []rune(body)
	if len(runes) <= 200 {
		return body
	}
	return string(runes[:200]) + "…（截断）"
}

// ListNotificationDeliveries GET /notification/deliveries——默认只看自己；
// 管理员 ?all=1 全平台（含 user_id，跨属主行正文截断脱敏）。
// ?limit= 默认 50 上限 200；?status= ∈ pending/sent/failed/dead。
func (h *Handlers) ListNotificationDeliveries(c *gin.Context) {
	uid := contextUserID(c)
	admin := isAdminRequest(c)
	all := admin && c.Query("all") == "1"

	limit := 50
	if raw := c.Query("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_76de02a0"), MessageKey: "k_76de02a0"})
			return
		}
		if n > 200 {
			n = 200
		}
		limit = n
	}
	status := c.Query("status")
	if status != "" {
		switch status {
		case "pending", "sent", "failed", "dead":
		default:
			msg := apimsg.Tf(c, "k_0d569dd0", status)
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg, MessageKey: "k_0d569dd0"})
			return
		}
	}

	query := `SELECT id, user_id, event_type, level, title, body, status, attempts, COALESCE(error,''), created_at, COALESCE(sent_at,'')
		FROM notification_deliveries WHERE 1=1`
	args := []any{}
	if !all {
		query += ` AND user_id=?`
		args = append(args, uid)
	}
	if status != "" {
		query += ` AND status=?`
		args = append(args, status)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取通知投递失败", err)})
		return
	}
	defer rows.Close()
	out := make([]notificationDeliveryDTO, 0, limit)
	for rows.Next() {
		var d notificationDeliveryDTO
		var attempts int
		if err := rows.Scan(&d.ID, &d.UserID, &d.EventType, &d.Level, &d.Title, &d.Body, &d.Status, &attempts, &d.Error, &d.CreatedAt, &d.SentAt); err != nil {
			continue
		}
		d.Attempts = attempts
		if d.UserID != uid {
			d.Body = maskDeliveryBody(d.Body)
		}
		out = append(out, d)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"deliveries": out}})
}

// ResendNotificationDelivery POST /notification/deliveries/:id/resend——
// 属主或管理员把非 pending 投递重置回 pending 并唤醒投递循环。
func (h *Handlers) ResendNotificationDelivery(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_76de02a0"), MessageKey: "k_76de02a0"})
		return
	}
	uid := contextUserID(c)
	admin := isAdminRequest(c)
	var owner int64
	var status string
	if err := db.DB.QueryRow(`SELECT user_id, status FROM notification_deliveries WHERE id=?`, id).Scan(&owner, &status); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: apimsg.T(c, "k_e742ee3f"), MessageKey: "k_e742ee3f"})
		return
	}
	if owner != uid && !admin {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: apimsg.T(c, "k_e18b003b"), MessageKey: "k_e18b003b"})
		return
	}
	if status == "pending" {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: apimsg.T(c, "k_c16c1667"), MessageKey: "k_c16c1667"})
		return
	}
	found, reset, err := notify.ResendDelivery(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("重发通知失败", err)})
		return
	}
	if !found || !reset {
		// 预检后状态被并发改变（已 pending 或已删除）。
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: apimsg.T(c, "k_c16c1667"), MessageKey: "k_c16c1667"})
		return
	}
	if owner != uid {
		recordAudit(c, "重发", "通知投递", "管理员重发用户投递 #"+strconv.FormatInt(id, 10))
	} else {
		recordAudit(c, "重发", "通知投递", services.FormatAuditDetail("投递 #"+strconv.FormatInt(id, 10), "", services.AuditResultPart("success")))
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_07b47533"), MessageKey: "k_07b47533"})
}
