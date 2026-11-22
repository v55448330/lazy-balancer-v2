package handlers

// 通知中心投递流水 REST：本人投递列表（管理员 ?all=1 全平台）+ 失败重发。
// 跨属主可见性：管理员排障视角，正文截断脱敏；重发为属主或管理员，全部
// 留审计。

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

type notificationDeliveryDTO struct {
	ID         int64                `json:"id"`
	UserID     int64                `json:"user_id"`
	Username   string               `json:"username"`
	EventType  string               `json:"event_type"`
	EventTitle string               `json:"event_title"`
	Level      string               `json:"level"`
	Title      string               `json:"title"`
	Body       string               `json:"body"`
	Status     string               `json:"status"`
	IsTest     bool                 `json:"is_test"`
	Attempts   int                  `json:"attempts"`
	Error      string               `json:"error"`
	CreatedAt  string               `json:"created_at"`
	SentAt     string               `json:"sent_at"`
	Channels   []deliveryChannelDTO `json:"channels"`
}

// deliveryChannelDTO 每通道投递结果（notification_delivery_channels JOIN）。
type deliveryChannelDTO struct {
	ChannelID   int64  `json:"channel_id"`
	ChannelName string `json:"channel_name"`
	ChannelType string `json:"channel_type"`
	Status      string `json:"status"`
	Error       string `json:"error"`
	DurationMs  int64  `json:"duration_ms"` // 通道处理耗时（毫秒）
}

// maskDeliveryBody 跨属主正文脱敏：rune 截断到 200 字符（保留边界完整字符）。
func maskDeliveryBody(body string) string {
	runes := []rune(body)
	if len(runes) <= 200 {
		return body
	}
	return string(runes[:200]) + "…（截断）"
}

// ListNotificationDeliveries GET /notification/deliveries——投递流水恒全量
// （投递记录不区分用户视角；用户/通道维度经行内 username+channels 呈现）。
// 跨属主正文截断脱敏；?status= ∈ pending/sent/partial/failed/dead；分页 ?page/&page_size
// （默认 50 上限 200）+ total（底部统计，审计页同口径）。
func (h *Handlers) ListNotificationDeliveries(c *gin.Context) {
	uid := contextUserID(c)

	pageSize := 50
	if raw := c.Query("page_size"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_76de02a0"), MessageKey: "k_76de02a0"})
			return
		}
		if n > 200 {
			n = 200
		}
		pageSize = n
	}
	page := 1
	if raw := c.Query("page"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			page = n
		}
	}
	status := c.Query("status")
	if status != "" {
		switch status {
		case "pending", "sent", "partial", "failed", "dead":
		default:
			msg := apimsg.Tf(c, "k_0d569dd0", status)
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: msg, MessageKey: "k_0d569dd0"})
			return
		}
	}

	where := " WHERE 1=1"
	args := []any{}
	if status != "" {
		where += ` AND d.status=?`
		args = append(args, status)
	}
	// total（底部统计）：与列表同过滤口径
	var total int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries d`+where, args...).Scan(&total); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取通知投递失败", err)})
		return
	}
	// 用户列：显示名优先（无显示名回退用户名）
	query := `SELECT d.id, d.user_id, COALESCE(NULLIF(u.display_name,''), u.username, ''), d.event_type, d.level, d.title, d.body, d.status, d.attempts, COALESCE(d.error,''), d.created_at, COALESCE(d.sent_at,''), d.is_test
		FROM notification_deliveries d LEFT JOIN users u ON u.id = d.user_id` + where + ` ORDER BY d.id DESC LIMIT ? OFFSET ?`
	args = append(args, pageSize, (page-1)*pageSize)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("读取通知投递失败", err)})
		return
	}
	defer rows.Close()
	// 事件可读标题（目录单源；日报等目录外事件显式映射，不回退裸键）
	titles := map[string]string{}
	for _, e := range notify.CatalogExport() {
		titles[e.ID] = e.Title
	}
	titles[notify.EvtDailyReport] = "每日日报"
	out := make([]notificationDeliveryDTO, 0, pageSize)
	ids := make([]int64, 0, pageSize)
	for rows.Next() {
		var d notificationDeliveryDTO
		var attempts, isTest int
		if err := rows.Scan(&d.ID, &d.UserID, &d.Username, &d.EventType, &d.Level, &d.Title, &d.Body, &d.Status, &attempts, &d.Error, &d.CreatedAt, &d.SentAt, &isTest); err != nil {
			continue
		}
		d.Attempts = attempts
		d.IsTest = isTest != 0
		d.EventTitle = d.EventType
		if t, ok := titles[d.EventType]; ok {
			d.EventTitle = t
		}
		if d.UserID != uid {
			d.Body = maskDeliveryBody(d.Body)
		}
		d.Channels = []deliveryChannelDTO{}
		out = append(out, d)
		ids = append(ids, d.ID)
	}
	// 每通道结果批量 JOIN（一次查询，按 delivery_id 归组）。通道名优先现表名，
	// 通道已删回退结果行快照名，再回退「通道 #id」。
	if len(ids) > 0 {
		placeholders := make([]byte, 0, len(ids)*2)
		chArgs := make([]any, 0, len(ids))
		for i, id := range ids {
			if i > 0 {
				placeholders = append(placeholders, ',')
			}
			placeholders = append(placeholders, '?')
			chArgs = append(chArgs, id)
		}
		chRows, err := db.DB.Query(`SELECT nc.delivery_id, nc.channel_id, COALESCE(NULLIF(c.name,''), NULLIF(nc.channel_name,''), ''), nc.channel_type, nc.status, COALESCE(nc.error,''), COALESCE(nc.duration_ms,0)
			FROM notification_delivery_channels nc LEFT JOIN notification_channels c ON c.id = nc.channel_id
			WHERE nc.delivery_id IN (`+string(placeholders)+`)
			  AND nc.id=(SELECT MAX(id) FROM notification_delivery_channels
			             WHERE delivery_id=nc.delivery_id AND channel_id=nc.channel_id)
			ORDER BY nc.id`, chArgs...)
		if err == nil {
			byDelivery := map[int64]int{}
			for i, id := range ids {
				byDelivery[id] = i
			}
			for chRows.Next() {
				var deliveryID int64
				var ch deliveryChannelDTO
				if chRows.Scan(&deliveryID, &ch.ChannelID, &ch.ChannelName, &ch.ChannelType, &ch.Status, &ch.Error, &ch.DurationMs) == nil {
					if ch.ChannelName == "" {
						ch.ChannelName = "通道 #" + strconv.FormatInt(ch.ChannelID, 10)
					}
					if idx, ok := byDelivery[deliveryID]; ok {
						out[idx].Channels = append(out[idx].Channels, ch)
					}
				}
			}
			chRows.Close()
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"deliveries": out, "total": total}})
}

// ResendNotificationDelivery POST /notification/deliveries/:id/resend——
// 属主或管理员把非 pending 投递重置回 pending 并唤醒投递循环。
// body {"failed_only": bool}：failed_only 且 partial 时只重发失败通道
// （retry_channel_ids 过滤，派发消费后清空）；否则重发全部通道。空 body=全量。
// 审计详情=投递标题+通道名（禁「投递 #id」形态）。
func (h *Handlers) ResendNotificationDelivery(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_76de02a0"), MessageKey: "k_76de02a0"})
		return
	}
	var req struct {
		FailedOnly bool `json:"failed_only"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	// 空 body 兼容（旧客户端无 body 全量重发）：EOF 视同缺省，坏 JSON 仍 400。
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_76de02a0"), MessageKey: "k_76de02a0"})
		return
	}
	uid := contextUserID(c)
	admin := isAdminRequest(c)
	var owner int64
	var status, title string
	if err := db.DB.QueryRow(`SELECT user_id, status, title FROM notification_deliveries WHERE id=?`, id).Scan(&owner, &status, &title); err != nil {
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
	// 审计通道名在重置前取快照（重置唤醒投递后结果行可能追加）。
	names := resendAuditChannelNames(id, req.FailedOnly && status == "partial")
	found, reset, err := notify.ResendDelivery(id, req.FailedOnly)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("重发通知失败", err)})
		return
	}
	if !found || !reset {
		// 预检后状态被并发改变（已 pending 或已删除）。
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: apimsg.T(c, "k_c16c1667"), MessageKey: "k_c16c1667"})
		return
	}
	subject := "重发投递「" + title + "」"
	if len(names) > 0 {
		subject += "（通道：" + strings.Join(names, "、") + "）"
	}
	if owner != uid {
		subject = "管理员" + subject
	}
	recordAudit(c, "重发", "通知投递", services.FormatAuditDetail(subject, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_07b47533"), MessageKey: "k_07b47533"})
}

// resendAuditChannelNames 重发审计通道名：每通道取最新结果行（重发追加行，
// 历史行不计）；failedOnly 仅取最新仍失败的通道。名优先现表名 > 结果行快照名 >
// 通道类型（审计详情禁「通道 #id」形态）。
func resendAuditChannelNames(id int64, failedOnly bool) []string {
	rows, err := db.DB.Query(`SELECT COALESCE(NULLIF(c.name,''), NULLIF(nc.channel_name,''), nc.channel_type), nc.status
		FROM notification_delivery_channels nc LEFT JOIN notification_channels c ON c.id=nc.channel_id
		WHERE nc.delivery_id=? AND nc.id IN (SELECT MAX(id) FROM notification_delivery_channels WHERE delivery_id=? GROUP BY channel_id)
		ORDER BY nc.channel_id`, id, id)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name, status string
		if rows.Scan(&name, &status) != nil {
			continue
		}
		if failedOnly && status != "failed" {
			continue
		}
		names = append(names, name)
	}
	return names
}
