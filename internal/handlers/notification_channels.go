package handlers

// 通知中心 REST（audit151 方案）：通道 CRUD/测试、订阅矩阵、投递流水/重发、
// 管理员凭据与全平台概览、MCP 会话列表。
// 权限：登录用户=自己的资源；管理员=全平台元数据（通道目标对非属主脱敏），
// 跨属主管理动作审计留痕（边界见审计151 报告「管理可见性纪律」）。
// 角色判定与 API Key 同口径：c.GetString("role") == "admin"（apiKeyAuth 链注入）。

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

const (
	channelTypeWebhook = "webhook"
	channelTypeEmail   = "email"
	channelTypeQQ      = "qq"
	channelTypeWx      = "wx_clawbot"
)

type notificationChannelDTO struct {
	ID         int64  `json:"id"`
	UserID     int64  `json:"user_id"`
	Type       string `json:"type"`
	Name       string `json:"name"`
	Target     string `json:"target"`
	Enabled    bool   `json:"enabled"`
	LastTestAt string `json:"last_test_at"`
	LastTestOK bool   `json:"last_test_ok"`
}

// isAdminRequest 角色门（与 API Key 管理同口径：apiKeyAuth 注入 role）。
func isAdminRequest(c *gin.Context) bool { return c.GetString("role") == "admin" }

func scanNotificationChannel(scan func(...any) error) (notificationChannelDTO, string, error) {
	var r notificationChannelDTO
	var enabled, testOK int
	var lastTest string
	err := scan(&r.ID, &r.UserID, &r.Type, &r.Name, &r.Target, &enabled, &lastTest, &testOK)
	r.Enabled = enabled != 0
	r.LastTestAt = lastTest
	r.LastTestOK = testOK != 0
	return r, r.Target, err
}

// ListNotificationChannels GET /notification/channels——管理员全平台（目标对
// 非属主脱敏），普通用户仅自己的。
func (h *Handlers) ListNotificationChannels(c *gin.Context) {
	admin := isAdminRequest(c)
	uid := contextUserID(c)
	query := `SELECT id, user_id, type, name, target, enabled, COALESCE(last_test_at,''), COALESCE(last_test_ok,0)
		FROM notification_channels`
	args := []any{}
	if !admin {
		query += ` WHERE user_id=?`
		args = append(args, uid)
	}
	query += ` ORDER BY id`
	rows, err := db.DB.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("查询通知通道失败", err)})
		return
	}
	defer rows.Close()
	out := make([]notificationChannelDTO, 0, 4)
	for rows.Next() {
		r, _, err := scanNotificationChannel(rows.Scan)
		if err != nil {
			continue
		}
		if r.UserID != uid {
			r.Target = maskChannelTarget(r.Type, r.Target)
		}
		out = append(out, r)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"channels": out}})
}

// maskChannelTarget 通道目标脱敏（管理员排障视角）。
func maskChannelTarget(typ, target string) string {
	switch typ {
	case channelTypeEmail:
		at := strings.Index(target, "@")
		if at <= 0 {
			return "***"
		}
		return target[:1] + "***" + target[at:]
	default:
		if len(target) > 6 {
			return target[:3] + "***" + target[len(target)-3:]
		}
		return "***"
	}
}

// validateChannelTarget 通道目标 JSON 校验（按类型的最小契约）。
func validateChannelTarget(typ, raw string) error {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return err
	}
	switch typ {
	case channelTypeWebhook:
		if u, _ := m["url"].(string); !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return errors.New("webhook 通道需要 http(s) URL")
		}
	case channelTypeEmail:
		if e, _ := m["email"].(string); !strings.Contains(e, "@") {
			return errors.New("邮件通道需要收件邮箱")
		}
	case channelTypeQQ:
		if o, _ := m["openid"].(string); o == "" {
			return errors.New("QQ 通道需先完成扫码绑定（生成绑定码并在 QQ 中发送）")
		}
	case channelTypeWx:
		if r, _ := m["receiver"].(string); r == "" {
			return errors.New("微信通道需要接收者（wxid/群 id）")
		}
	}
	return nil
}

// CreateNotificationChannel POST /notification/channels。
func (h *Handlers) CreateNotificationChannel(c *gin.Context) {
	uid := contextUserID(c)
	var req struct {
		Type   string `json:"type"`
		Name   string `json:"name"`
		Target string `json:"target"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_76de02a0")})
		return
	}
	switch req.Type {
	case channelTypeWebhook, channelTypeEmail, channelTypeQQ, channelTypeWx:
	default:
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "不支持的通知通道类型"})
		return
	}
	if err := validateChannelTarget(req.Type, req.Target); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	res, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, enabled, created_at, updated_at)
		VALUES (?,?,?,?,1,datetime('now'),datetime('now'))`, uid, req.Type, req.Name, req.Target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("创建通知通道失败", err)})
		return
	}
	id, _ := res.LastInsertId()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"id": id}})
}

// UpdateNotificationChannel PUT /notification/channels/:id——属主或管理员。
func (h *Handlers) UpdateNotificationChannel(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	uid := contextUserID(c)
	admin := isAdminRequest(c)
	var owner int64
	var typ string
	if err := db.DB.QueryRow(`SELECT user_id, type FROM notification_channels WHERE id=?`, id).Scan(&owner, &typ); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: apimsg.T(c, "k_45c84896")})
		return
	}
	if owner != uid && !admin {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅可管理自己的通知通道"})
		return
	}
	var req struct {
		Name    string `json:"name"`
		Target  string `json:"target"`
		Enabled *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if req.Target != "" {
		if err := validateChannelTarget(typ, req.Target); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}
	if req.Name != "" {
		if _, err := db.DB.Exec(`UPDATE notification_channels SET name=?, updated_at=datetime('now') WHERE id=?`, req.Name, id); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("更新通知通道失败", err)})
			return
		}
	}
	if req.Target != "" {
		if _, err := db.DB.Exec(`UPDATE notification_channels SET target=?, updated_at=datetime('now') WHERE id=?`, req.Target, id); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("更新通知通道失败", err)})
			return
		}
	}
	if req.Enabled != nil {
		if _, err := db.DB.Exec(`UPDATE notification_channels SET enabled=?, updated_at=datetime('now') WHERE id=?`, boolToInt(*req.Enabled), id); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("更新通知通道失败", err)})
			return
		}
	}
	recordAudit(c, "修改", "通知通道", services.FormatAuditDetail("通道 #"+strconv.FormatInt(id, 10), "", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0})
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// DeleteNotificationChannel DELETE /notification/channels/:id——属主或管理员，
// 跨属主删除审计留痕。
func (h *Handlers) DeleteNotificationChannel(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	uid := contextUserID(c)
	admin := isAdminRequest(c)
	var owner int64
	if err := db.DB.QueryRow(`SELECT user_id FROM notification_channels WHERE id=?`, id).Scan(&owner); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: apimsg.T(c, "k_45c84896")})
		return
	}
	if owner != uid && !admin {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅可管理自己的通知通道"})
		return
	}
	if _, err := db.DB.Exec(`DELETE FROM notification_channels WHERE id=?`, id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("删除通知通道失败", err)})
		return
	}
	if owner != uid {
		recordAudit(c, "删除", "通知通道", "管理员删除用户通道 #"+strconv.FormatInt(id, 10))
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0})
}

// TestNotificationChannel POST /notification/channels/:id/test——发送测试消息。
func (h *Handlers) TestNotificationChannel(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	uid := contextUserID(c)
	admin := isAdminRequest(c)
	var typ, target string
	var owner int64
	if err := db.DB.QueryRow(`SELECT user_id, type, target FROM notification_channels WHERE id=?`, id).Scan(&owner, &typ, &target); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: apimsg.T(c, "k_45c84896")})
		return
	}
	if owner != uid && !admin {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅可测试自己的通知通道"})
		return
	}
	msg := notify.Message{
		EventType: "test", Level: string(notify.LevelInfo),
		Title: "通知测试", Body: "这是一条测试通知（" + typ + "）——收到即代表通道可用。",
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	err := notify.TestChannel(ctx, typ, target)
	ok := err == nil
	_, _ = db.DB.Exec(`UPDATE notification_channels SET last_test_at=datetime('now'), last_test_ok=? WHERE id=?`, boolToInt(ok), id)
	if err != nil {
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: "测试消息发送失败: " + err.Error()})
		return
	}
	_ = msg
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "测试消息已发送"})
}
