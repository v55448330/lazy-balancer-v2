package handlers

// 通知中心 REST：通道 CRUD/测试、订阅矩阵、投递流水/重发、
// 管理员凭据与全平台概览、MCP 会话列表。
// 权限：登录用户=自己的资源；管理员=全平台元数据（通道目标对非属主脱敏），
// 跨属主管理动作审计留痕（管理可见性纪律：元数据+聚合计数可见，内容与联系方式脱敏）。
// 角色判定与 API Key 同口径：c.GetString("role") == "admin"（apiKeyAuth 链注入）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/accesslog"
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
	ID            int64  `json:"id"`
	UserID        int64  `json:"user_id"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Target        string `json:"target"`
	Enabled       bool   `json:"enabled"`
	LastTestAt    string `json:"last_test_at"`
	LastTestOK    bool   `json:"last_test_ok"`
	StyleConfig   string `json:"style_config"`
	LinkConnected bool   `json:"link_connected"` // qq/wx 实时入站在线态
	LinkState     string `json:"link_state"`     // online/offline/none
	SessionReady  bool   `json:"session_ready"`  // wx 接收者会话上下文就绪=可主动发送（在线≠就绪）
}

// isAdminRequest 角色门（与 API Key 管理同口径：apiKeyAuth 注入 role）。
func isAdminRequest(c *gin.Context) bool { return c.GetString("role") == "admin" }

func scanNotificationChannel(scan func(...any) error) (notificationChannelDTO, string, error) {
	var r notificationChannelDTO
	var enabled, testOK int
	var lastTest string
	err := scan(&r.ID, &r.UserID, &r.Type, &r.Name, &r.Target, &r.StyleConfig, &enabled, &lastTest, &testOK)
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
	query := `SELECT id, user_id, type, name, target, COALESCE(style_config,'{}'), enabled, COALESCE(last_test_at,''), COALESCE(last_test_ok,0)
		FROM notification_channels`
	args := []any{}
	if !admin {
		query += ` WHERE user_id=?`
		args = append(args, uid)
	} else if q := c.Query("user_id"); q != "" {
		if v, err := strconv.ParseInt(q, 10, 64); err == nil && v > 0 {
			query += ` WHERE user_id=?`
			args = append(args, v)
		}
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
		if r.Type == "qq" || r.Type == "wx_clawbot" {
			r.LinkConnected, r.LinkState = notify.ChannelLinkStatus(r.Type, r.Target)
			if r.Type == "wx_clawbot" {
				r.SessionReady = notify.WxSessionReady(r.Target)
			}
		} else {
			r.LinkState = "none"
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

// pinBotChannelTarget 通道 target 钉住 bot 凭据（多机器人出站鉴权源：各用
// 所属 bot 凭据，互不覆盖）。target 已带凭据→原样；qq 优先本用户最近扫码
// 绑定下发的凭据（openid 匹配防误钉），回退全局；wx 经 notify 侧待钉新凭据
// →全局登录态。
func pinBotChannelTarget(uid int64, typ, target string) string {
	switch typ {
	case channelTypeQQ:
		return pinQQChannelTarget(uid, target)
	case channelTypeWx:
		return notify.WxPinChannelTarget(target)
	}
	return target
}

// pinQQChannelTarget QQ target 钉住 appid/secret（缺凭据才钉；无凭据源
// 原样返回——发送侧回退全局/fail-loud，行为不变）。
func pinQQChannelTarget(uid int64, target string) string {
	var m map[string]any
	if json.Unmarshal([]byte(target), &m) != nil {
		return target
	}
	if a, _ := m["appid"].(string); a != "" {
		if s, _ := m["secret"].(string); s != "" {
			return target
		}
	}
	appid, secret := "", ""
	openid, _ := m["openid"].(string)
	qqTaskMu.Lock()
	bound, ok := qqBoundByUser[uid]
	qqTaskMu.Unlock()
	if ok && bound.OpenID == openid {
		appid, secret = bound.AppID, bound.Secret
	} else {
		appid, secret, _ = notify.QQBotCredentialsPair()
	}
	if appid == "" || secret == "" {
		return target
	}
	m["appid"], m["secret"] = appid, secret
	b, err := json.Marshal(m)
	if err != nil {
		return target
	}
	return string(b)
}

// findExistingNotificationChannel 幂等复用查找：钉住 target 优先，亦匹配
// 无凭据的存量 target（存量行保持全局回退行为，不重复建行）。
func findExistingNotificationChannel(uid int64, typ, pinned, raw string) (int64, bool) {
	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM notification_channels
		WHERE user_id=? AND type=? AND target=?`, uid, typ, pinned).Scan(&id); err == nil {
		return id, true
	}
	if pinned != raw {
		if err := db.DB.QueryRow(`SELECT id FROM notification_channels
			WHERE user_id=? AND type=? AND target=?`, uid, typ, raw).Scan(&id); err == nil {
			return id, true
		}
	}
	return 0, false
}

// CreateNotificationChannel POST /notification/channels。
func (h *Handlers) CreateNotificationChannel(c *gin.Context) {
	uid := contextUserID(c)
	var req struct {
		Type        string          `json:"type"`
		Name        string          `json:"name"`
		Target      string          `json:"target"`
		StyleConfig json.RawMessage `json:"style_config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_76de02a0")})
		return
	}
	switch req.Type {
	case channelTypeWebhook, channelTypeEmail, channelTypeQQ, channelTypeWx:
	default:
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_0b1f0aee"), MessageKey: "k_0b1f0aee"})
		return
	}
	if err := validateChannelTarget(req.Type, req.Target); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	styleConfig := "{}"
	if len(req.StyleConfig) > 0 {
		normalized, err := validateChannelStyle(req.Type, req.StyleConfig)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		styleConfig = normalized
	}
	// 多机器人：target 钉住 bot 凭据（出站按 target 凭据鉴权）。
	target := pinBotChannelTarget(uid, req.Type, req.Target)
	// 同 user+type+target 唯一约束：先查既有行幂等复用（扫码绑定后重复保存
	// 是正常路径——openid 不变，二次提交不是错误），并发窗口 INSERT 仍撞
	// 约束时同口径处理。
	if id, ok := findExistingNotificationChannel(uid, req.Type, target, req.Target); ok {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"id": id, "reused": true}})
		return
	}
	res, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, style_config, enabled, created_at, updated_at)
		VALUES (?,?,?,?,?,1,datetime('now'),datetime('now'))`, uid, req.Type, req.Name, target, styleConfig)
	if err != nil {
		if isUniqueConstraintErr(err) {
			if id, ok := findExistingNotificationChannel(uid, req.Type, target, req.Target); ok {
				c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"id": id, "reused": true}})
				return
			}
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("创建通知通道失败", err)})
		return
	}
	id, _ := res.LastInsertId()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"id": id}})
}

// isUniqueConstraintErr SQLite 唯一约束冲突（CONSTRAINT 2067）。
func isUniqueConstraintErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// UpdateNotificationChannel PUT /notification/channels/:id——属主或管理员。
func (h *Handlers) UpdateNotificationChannel(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	uid := contextUserID(c)
	admin := isAdminRequest(c)
	var owner int64
	var typ, name string
	if err := db.DB.QueryRow(`SELECT user_id, type, name FROM notification_channels WHERE id=?`, id).Scan(&owner, &typ, &name); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: apimsg.T(c, "k_45c84896")})
		return
	}
	if owner != uid && !admin {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: apimsg.T(c, "k_6928b5b0"), MessageKey: "k_6928b5b0"})
		return
	}
	var req struct {
		Name        string          `json:"name"`
		Target      string          `json:"target"`
		Enabled     *bool           `json:"enabled"`
		StyleConfig json.RawMessage `json:"style_config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if len(req.StyleConfig) > 0 {
		normalized, err := validateChannelStyle(typ, req.StyleConfig)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		if _, err := db.DB.Exec(`UPDATE notification_channels SET style_config=?, updated_at=datetime('now') WHERE id=?`, normalized, id); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("更新通知通道失败", err)})
			return
		}
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
		target := pinBotChannelTarget(owner, typ, req.Target)
		if _, err := db.DB.Exec(`UPDATE notification_channels SET target=?, updated_at=datetime('now') WHERE id=?`, target, id); err != nil {
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
	// 审计详情=通道名+结果（禁「通道 #id」形态）；改名以新名为准。
	auditName := req.Name
	if auditName == "" {
		auditName = name
	}
	if auditName == "" {
		auditName = typ
	}
	subject := "通道「" + auditName + "」"
	if owner != uid {
		subject = "管理员修改用户" + subject
	}
	recordAudit(c, "修改", "通知通道", services.FormatAuditDetail(subject, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0})
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// DeleteNotificationChannel DELETE /notification/channels/:id——属主或管理员，
// 删除审计留痕（跨属主注明管理员代删；Explicit 分类=中间件不复记）。
func (h *Handlers) DeleteNotificationChannel(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	uid := contextUserID(c)
	admin := isAdminRequest(c)
	var owner int64
	var typ, name string
	if err := db.DB.QueryRow(`SELECT user_id, type, name FROM notification_channels WHERE id=?`, id).Scan(&owner, &typ, &name); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: apimsg.T(c, "k_45c84896")})
		return
	}
	if owner != uid && !admin {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: apimsg.T(c, "k_6928b5b0"), MessageKey: "k_6928b5b0"})
		return
	}
	if _, err := db.DB.Exec(`DELETE FROM notification_channels WHERE id=?`, id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("删除通知通道失败", err)})
		return
	}
	auditName := name
	if auditName == "" {
		auditName = typ
	}
	subject := "通道「" + auditName + "」"
	if owner != uid {
		subject = "管理员删除用户" + subject
	}
	recordAudit(c, "删除", "通知通道", services.FormatAuditDetail(subject, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0})
}

// TestNotificationChannel POST /notification/channels/:id/test——发送测试消息。
// 审计留痕（Explicit：通道名+结果，成功/失败均记录；详情不含目标 URL）。
func (h *Handlers) TestNotificationChannel(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	uid := contextUserID(c)
	admin := isAdminRequest(c)
	var typ, target, name string
	var owner int64
	if err := db.DB.QueryRow(`SELECT user_id, type, target, name FROM notification_channels WHERE id=?`, id).Scan(&owner, &typ, &target, &name); err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: apimsg.T(c, "k_45c84896")})
		return
	}
	if owner != uid && !admin {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: apimsg.T(c, "k_435eb4ab"), MessageKey: "k_435eb4ab"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	err := notify.TestChannel(ctx, typ, target)
	ok := err == nil
	_, _ = db.DB.Exec(`UPDATE notification_channels SET last_test_at=datetime('now'), last_test_ok=? WHERE id=?`, boolToInt(ok), id)
	// 通道测试留痕投递记录（用户裁定：所有外发消息含测试均可见）。
	testErr := ""
	if err != nil {
		testErr = err.Error()
	}
	_ = notify.RecordChannelTestDelivery(owner, id, typ, name, ok, testErr)
	auditName := name
	if auditName == "" {
		auditName = typ
	}
	subject := "通道「" + auditName + "」"
	if owner != uid {
		subject = "管理员测试用户" + subject
	}
	if ok {
		recordAudit(c, "测试", "通知通道", services.FormatAuditDetail(subject, services.AuditResultPart("success")))
	} else {
		recordAudit(c, "测试", "通知通道", services.FormatAuditDetail(subject, services.AuditResultPart("failed")))
	}
	if err != nil {
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: apimsg.Tf(c, "k_8e353bc9", err.Error()), MessageKey: "k_8e353bc9"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_4bde3724"), MessageKey: "k_4bde3724"})
}

// validateChannelStyle 通道消息样式校验+归一（返回规范化 JSON）：
//
//	键白名单 payload_template/subject_template/body_template/content_template/
//	msg_type/daily_format/body_format/method/headers
//	webhook.payload_template：{{占位符}}替换后必须可解析 JSON
//	webhook.method ∈ GET/POST；headers 键白名单（认证/内容类型类，禁 Host/Cookie 等）
//	qq.msg_type ∈ text/markdown；*.daily_format ∈ 格式白名单；email 键值白名单
func validateChannelStyle(typ string, raw json.RawMessage) (string, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("消息样式解析失败: %w", err)
	}
	out := map[string]any{}
	validFormats := map[string]bool{"text": true, "markdown": true, "html": true, "json": true}
	for k, v := range m {
		sv, _ := v.(string)
		switch k {
		case "payload_template":
			if typ != "webhook" {
				return "", errors.New("payload_template 仅 webhook 通道支持")
			}
			if sv == "" {
				continue
			}
			// 占位符替换后必须可解析（保存即拦截，投递期才不踩坏模板）
			probe := regexp.MustCompile(`\{\{[^}]*}}`).ReplaceAllString(sv, `"probe"`)
			if !json.Valid([]byte(probe)) {
				return "", errors.New("payload_template 不是合法 JSON 模板（占位符替换后仍需可解析）")
			}
			out[k] = sv
		case "subject_template":
			if typ != "email" {
				return "", errors.New("subject_template 仅邮件通道支持")
			}
			if len(sv) > 300 {
				return "", errors.New("subject_template 过长（≤300）")
			}
			out[k] = sv
		case "body_template":
			if typ != "email" {
				return "", errors.New("body_template 仅邮件通道支持")
			}
			if len(sv) > 4000 {
				return "", errors.New("body_template 过长（≤4000）")
			}
			out[k] = sv
		case "content_template":
			if typ != "qq" && typ != "wx_clawbot" {
				return "", errors.New("content_template 仅 QQ/微信通道支持")
			}
			if len(sv) > 2000 {
				return "", errors.New("content_template 过长（≤2000）")
			}
			out[k] = sv
		case "body_format":
			if typ != "email" {
				return "", errors.New("body_format 仅邮件通道支持")
			}
			if sv != "html" && sv != "text" {
				return "", errors.New("body_format 仅支持 html/text")
			}
			out[k] = sv
		case "msg_type":
			if typ != "qq" {
				return "", errors.New("msg_type 仅 QQ 通道支持")
			}
			if sv != "text" && sv != "markdown" {
				return "", errors.New("msg_type 仅支持 text/markdown")
			}
			out[k] = sv
		case "daily_format":
			if !validFormats[sv] {
				return "", errors.New("daily_format 仅支持 text/markdown/html/json")
			}
			out[k] = sv
		case "method":
			if typ != "webhook" {
				return "", errors.New("method 仅 webhook 通道支持")
			}
			if sv != "" && sv != "GET" && sv != "POST" {
				return "", errors.New("method 仅支持 GET/POST")
			}
			if sv != "" {
				out[k] = sv
			}
		case "headers":
			if typ != "webhook" {
				return "", errors.New("headers 仅 webhook 通道支持")
			}
			hm, ok := v.(map[string]any)
			if !ok {
				return "", errors.New("headers 必须是键值对象")
			}
			if len(hm) > 8 {
				return "", errors.New("headers 最多 8 个")
			}
			clean := map[string]string{}
			for hk, hv := range hm {
				if !webhookHeaderAllowed(hk) {
					return "", fmt.Errorf("header 不在允许列表: %s（支持 Authorization/%s/Content-Type/Accept/User-Agent/X-* 自定义）", hk, accesslog.APIKeyHeaderName)
				}
				hvStr, _ := hv.(string)
				if len(hvStr) > 500 {
					return "", fmt.Errorf("header %s 值过长（≤500）", hk)
				}
				if strings.ContainsAny(hvStr, "\r\n") {
					return "", fmt.Errorf("header %s 值含非法换行", hk)
				}
				if hvStr != "" {
					clean[hk] = hvStr
				}
			}
			if len(clean) > 0 {
				out[k] = clean
			}
		default:
			return "", fmt.Errorf("未知消息样式键: %s", k)
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// webhookHeaderAllowed 自定义头白名单：认证/内容协商类 + X- 前缀自定义。
// 禁 Host/Cookie/Set-Cookie/Transfer-Encoding 等可致请求走私或会话泄漏的头。
func webhookHeaderAllowed(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "authorization", "x-api-key", "content-type", "accept", "user-agent", "cache-control":
		return true
	}
	return strings.HasPrefix(lower, "x-") && len(name) <= 64
}
