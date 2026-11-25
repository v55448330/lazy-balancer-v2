package handlers

// 通知中心 REST：通道 CRUD/测试、订阅矩阵、投递流水/重发、
// 管理员凭据与全平台概览、MCP 会话列表。
// 权限：登录用户=自己的资源；管理员=全平台元数据（通道目标对非属主脱敏），
// 跨属主管理动作审计留痕（管理可见性纪律：元数据+聚合计数可见，内容与联系方式脱敏）。
// 角色判定与 API Key 同口径：c.GetString("role") == "admin"（apiKeyAuth 链注入）。

import (
	"context"
	"database/sql"
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
	ID     int64  `json:"id"`
	UserID int64  `json:"user_id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Target string `json:"target"`
	// TargetMasked=true 表示 target 已脱敏（非属主视角）：调用方（前端编辑
	// 抽屉）不得把该展示值回写 target，否则会把掩码串写进真实目标。
	TargetMasked  bool   `json:"target_masked"`
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
		c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.channelListQueryFailed", err))
		return
	}
	defer rows.Close()
	out := make([]notificationChannelDTO, 0, 4)
	for rows.Next() {
		r, _, err := scanNotificationChannel(rows.Scan)
		if err != nil {
			c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.channelListQueryFailed", err))
			return
		}
		if r.Type == "qq" || r.Type == "wx_clawbot" {
			r.LinkConnected, r.LinkState = notify.ChannelLinkStatus(r.Type, r.Target)
			if r.Type == "wx_clawbot" {
				r.SessionReady = notify.WxSessionReady(r.Target)
			}
		} else {
			r.LinkState = "none"
		}
		// 模板作用域读面归一：存量行（日报模板仍在事件键上）直接按新布局输出。
		r.StyleConfig = notify.CanonicalChannelStyleJSON(r.StyleConfig)
		if r.UserID != uid {
			r.Target = maskChannelTarget(r.Type, r.Target)
			r.TargetMasked = true
			// headers 里的 Authorization/X-Api-Key 同样是凭据：只掩码 target
			// 会让管理员排障视图直接读出他人 webhook token。
			r.StyleConfig = maskChannelStyleHeaders(r.StyleConfig)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.channelListQueryFailed", err))
		return
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

// styleSensitiveHeaders 需要跨属主掩码的请求头：认证/密钥类（含 X-* 自定义）
// 全部视为凭据；内容协商类保留原值供排障识别请求形态。
func styleHeaderSensitive(name string) bool {
	switch strings.ToLower(name) {
	case "content-type", "accept", "user-agent", "cache-control":
		return false // 内容协商类：无凭据，保留供排障识别
	}
	return true // Authorization/X-Api-Key/X-* 自定义头均可能携带 token
}

// maskChannelStyleHeaders 非属主视角的 style_config 脱敏：仅掩码 headers
// 值（Authorization/X-Api-Key 等凭据原样返回=管理员排障读走 token）。
func maskChannelStyleHeaders(styleJSON string) string {
	var m map[string]any
	if json.Unmarshal([]byte(styleJSON), &m) != nil {
		return styleJSON
	}
	headers, ok := m["headers"].(map[string]any)
	if !ok || len(headers) == 0 {
		return styleJSON
	}
	for k, v := range headers {
		if !styleHeaderSensitive(k) {
			continue
		}
		if s, ok := v.(string); ok && s != "" {
			headers[k] = "***"
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return styleJSON
	}
	return string(b)
}

// restoreMaskedStyleHeaders 旧前端把列表里的掩码值当真实值回写时，用既有
// style_config 还原被掩码的头值（与服务端 target 回写兜底同纪律：前端版本
// 不得决定数据安全/完整性）。
func restoreMaskedStyleHeaders(raw json.RawMessage, current string) json.RawMessage {
	var sub, cur map[string]any
	if json.Unmarshal(raw, &sub) != nil || json.Unmarshal([]byte(current), &cur) != nil {
		return raw
	}
	subHeaders, ok := sub["headers"].(map[string]any)
	if !ok {
		return raw
	}
	curHeaders, ok := cur["headers"].(map[string]any)
	if !ok {
		return raw
	}
	restored := false
	for k, v := range subHeaders {
		if s, ok := v.(string); ok && s == "***" {
			if prev, ok := curHeaders[k].(string); ok && prev != "" {
				subHeaders[k] = prev
				restored = true
			}
		}
	}
	if !restored {
		return raw
	}
	b, err := json.Marshal(sub)
	if err != nil {
		return raw
	}
	return b
}

// targetContainsMaskedValue 提交的 target JSON 中是否有字符串值等于脱敏串
// （旧前端把列表展示值当真实值回写的形态）。仅精确相等才豁免，用户名/URL
// 里正常出现 *** 不受影响。
func targetContainsMaskedValue(raw, masked string) bool {
	if masked == "" || raw == "" {
		return false
	}
	var m map[string]any
	if json.Unmarshal([]byte(raw), &m) != nil {
		return false
	}
	for _, v := range m {
		if s, ok := v.(string); ok && s == masked {
			return true
		}
	}
	return false
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
			return errors.New("QQ 通道需先完成扫码绑定（扫码后在 QQ 中发送「绑定测试」）")
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
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "common.malformedRequest"))
		return
	}
	switch req.Type {
	case channelTypeWebhook, channelTypeEmail, channelTypeQQ, channelTypeWx:
	default:
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "notify.unsupportedChannelType"))
		return
	}
	if err := validateChannelTarget(req.Type, req.Target); err != nil {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "notify.channelTargetValidationFailed", apimsg.ErrMsg(c, err)))
		return
	}
	styleConfig := "{}"
	if len(req.StyleConfig) > 0 {
		normalized, err := validateChannelStyle(req.Type, req.StyleConfig)
		if err != nil {
			c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "notify.channelStyleValidationFailed", apimsg.ErrMsg(c, err)))
			return
		}
		styleConfig = notify.CanonicalTemplateScope(normalized, "")
	}
	// 多机器人：target 钉住 bot 凭据（出站按 target 凭据鉴权）。
	target := pinBotChannelTarget(uid, req.Type, req.Target)
	// 同 user+type+target 唯一约束：先查既有行幂等复用（扫码绑定后重复保存
	// 是正常路径——openid 不变，二次提交不是错误），并发窗口 INSERT 仍撞
	// 约束时同口径处理。
	if id, ok := findExistingNotificationChannel(uid, req.Type, target, req.Target); ok {
		notify.ClearBindSessionsByUser(uid)
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"id": id, "reused": true}})
		return
	}
	res, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, style_config, enabled, created_at, updated_at)
		VALUES (?,?,?,?,?,1,datetime('now'),datetime('now'))`, uid, req.Type, req.Name, target, styleConfig)
	if err != nil {
		if isUniqueConstraintErr(err) {
			if id, ok := findExistingNotificationChannel(uid, req.Type, target, req.Target); ok {
				notify.ClearBindSessionsByUser(uid)
				c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"id": id, "reused": true}})
				return
			}
		}
		c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.channelCreateFailed", err))
		return
	}
	id, _ := res.LastInsertId()
	notify.ClearBindSessionsByUser(uid)
	notify.Publish(notify.Event{Type: notify.EvtNotifyChannelChanged, Fields: map[string]string{"1": c.GetString("username"), "2": "创建", "3": req.Name}})
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
	var typ, name, currentTarget, currentStyle string
	if err := db.DB.QueryRow(`SELECT user_id, type, name, COALESCE(target,''), COALESCE(style_config,'{}') FROM notification_channels WHERE id=?`, id).Scan(&owner, &typ, &name, &currentTarget, &currentStyle); err != nil {
		c.JSON(http.StatusNotFound, apimsg.Envelope(c, 404, "security.policyNotFound"))
		return
	}
	if owner != uid && !admin {
		c.JSON(http.StatusForbidden, apimsg.Envelope(c, 403, "notify.canOnlyManageOwnChannel"))
		return
	}
	var req struct {
		Name        string          `json:"name"`
		Target      string          `json:"target"`
		Enabled     *bool           `json:"enabled"`
		StyleConfig json.RawMessage `json:"style_config"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "notify.invalidRequest", apimsg.ErrMsg(c, err)))
		return
	}
	// 校验先行（无副作用），写库统一进单事务——四条 UPDATE 曾各自独立提交：
	// 中途失败（DB 忙/约束）会留下「名称已改、目标/启用态未改」的半更新行。
	normalizedStyle := ""
	hasStyle := false
	if len(req.StyleConfig) > 0 {
		// 列表对非属主掩码 headers 值：旧前端原样回写时还原既有真实值，
		// 避免把 "***" 写进 Authorization 破坏投递。
		req.StyleConfig = restoreMaskedStyleHeaders(req.StyleConfig, currentStyle)
		normalized, err := validateChannelStyle(typ, req.StyleConfig)
		if err != nil {
			c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "notify.channelStyleValidationFailed", apimsg.ErrMsg(c, err)))
			return
		}
		normalizedStyle, hasStyle = notify.CanonicalTemplateScope(normalized, currentStyle), true
	}
	if req.Target != "" {
		if err := validateChannelTarget(typ, req.Target); err != nil {
			c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "notify.channelTargetValidationFailed", apimsg.ErrMsg(c, err)))
			return
		}
		// 旧前端兜底：列表对非属主 target 整体脱敏，旧版编辑把掩码串当新目标
		// 回写（形如 {"openid":"{\"o***6\"}"}）。服务端识别「内层值等于当前目标
		// 的脱敏串」→ 视为未变更，跳过 target 更新——不能让前端版本决定数据安全。
		if req.Target == maskChannelTarget(typ, currentTarget) || targetContainsMaskedValue(req.Target, maskChannelTarget(typ, currentTarget)) {
			services.Logf("warn", "通知通道 %d 的 target 提交为脱敏串（旧前端回写），按未变更处理", id)
			req.Target = ""
		}
	}
	tx, err := db.DB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.channelUpdateFailed", err))
		return
	}
	defer tx.Rollback()
	failTx := func(err error) {
		c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.channelUpdateFailed", err))
	}
	if hasStyle {
		if _, err := tx.Exec(`UPDATE notification_channels SET style_config=?, updated_at=datetime('now') WHERE id=?`, normalizedStyle, id); err != nil {
			failTx(err)
			return
		}
	}
	if req.Name != "" {
		if _, err := tx.Exec(`UPDATE notification_channels SET name=?, updated_at=datetime('now') WHERE id=?`, req.Name, id); err != nil {
			failTx(err)
			return
		}
	}
	if req.Target != "" {
		target := pinBotChannelTarget(owner, typ, req.Target)
		if target != currentTarget {
			// 目标已变=旧验证结论失效：不能把重绑前的“验证失败”继续显示在
			// 新 bot 上（用户可见“绑定成功但验证失败”根因）。落为未验证，
			// 重绑/保存后的自动测试再写真实结果。
			if _, err := tx.Exec(`UPDATE notification_channels SET target=?, last_test_ok=NULL, last_test_at=NULL, updated_at=datetime('now') WHERE id=?`, target, id); err != nil {
				failTx(err)
				return
			}
		} else if _, err := tx.Exec(`UPDATE notification_channels SET target=?, updated_at=datetime('now') WHERE id=?`, target, id); err != nil {
			failTx(err)
			return
		}
	}
	if req.Enabled != nil {
		if _, err := tx.Exec(`UPDATE notification_channels SET enabled=?, updated_at=datetime('now') WHERE id=?`, boolToInt(*req.Enabled), id); err != nil {
			failTx(err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		failTx(err)
		return
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
	recordAudit(c, "修改", "通知通道", services.FormatAuditDetail(services.AuditRawPart(subject) /* audit-detail raw */, services.AuditResultPart("success")))
	notify.Publish(notify.Event{Type: notify.EvtNotifyChannelChanged, Fields: map[string]string{"1": c.GetString("username"), "2": "更新", "3": auditName}})
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
	var typ, name, currentTarget string
	if err := db.DB.QueryRow(`SELECT user_id, type, name, COALESCE(target,'') FROM notification_channels WHERE id=?`, id).Scan(&owner, &typ, &name, &currentTarget); err != nil {
		c.JSON(http.StatusNotFound, apimsg.Envelope(c, 404, "security.policyNotFound"))
		return
	}
	if owner != uid && !admin {
		c.JSON(http.StatusForbidden, apimsg.Envelope(c, 403, "notify.canOnlyManageOwnChannel"))
		return
	}
	if _, err := db.DB.Exec(`DELETE FROM notification_channels WHERE id=?`, id); err != nil {
		c.JSON(http.StatusInternalServerError, securityErrKeyed(http.StatusInternalServerError, "notify.channelDeleteFailed", err))
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
	recordAudit(c, "删除", "通知通道", services.FormatAuditDetail(services.AuditRawPart(subject) /* audit-detail raw */, services.AuditResultPart("success")))
	notify.Publish(notify.Event{Type: notify.EvtNotifyChannelChanged, Fields: map[string]string{"1": c.GetString("username"), "2": "删除", "3": auditName}})
	c.JSON(http.StatusOK, models.APIResponse{Code: 0})
}

// TestNotificationChannel POST /notification/channels/:id/test——发送测试消息。
// 审计留痕（Explicit：通道名+结果，成功/失败均记录；详情不含目标 URL）。
func (h *Handlers) TestNotificationChannel(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	uid := contextUserID(c)
	admin := isAdminRequest(c)
	var typ, target, name, style string
	var owner int64
	if err := db.DB.QueryRow(`SELECT user_id, type, target, name, COALESCE(style_config,'') FROM notification_channels WHERE id=?`, id).Scan(&owner, &typ, &target, &name, &style); err != nil {
		c.JSON(http.StatusNotFound, apimsg.Envelope(c, 404, "security.policyNotFound"))
		return
	}
	if owner != uid && !admin {
		c.JSON(http.StatusForbidden, apimsg.Envelope(c, 403, "notify.canOnlyTestOwnChannel"))
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	// 测试与真实投递同口径：样式（method/headers/模板）合并进 target，否则 GET/自定义头不生效。
	err := notify.TestChannel(ctx, typ, notify.MergeStyleIntoTarget(target, style))
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
		recordAudit(c, "测试", "通知通道", services.FormatAuditDetail(services.AuditRawPart(subject) /* audit-detail raw */, services.AuditResultPart("success")))
	} else {
		recordAudit(c, "测试", "通知通道", services.FormatAuditDetail(services.AuditRawPart(subject) /* audit-detail raw */, services.AuditResultPart("failed")))
	}
	if err != nil {
		c.JSON(http.StatusBadGateway, apimsg.Envelope(c, 502, "notify.testMessageSendFailed", err.Error()))
		return
	}
	c.JSON(http.StatusOK, apimsg.Envelope(c, 0, "notify.testMessageSent"))
}

// validateChannelStyle 通道消息样式校验+归一（返回规范化 JSON）：
//
//	键白名单 payload_template/subject_template/body_template/content_template/
//	daily_payload_template/daily_body_template/daily_content_template/
//	daily_mode/msg_type/daily_format/body_format/method/headers
//	正文模板两套作用域：事件键只用于事件、daily_* 键只用于日报（同门校验）
//	webhook.payload_template：{{占位符}}替换后必须可解析 JSON
//	webhook.method ∈ GET/POST；headers 键白名单（认证/内容类型类，禁 Host/Cookie 等）
//	qq.msg_type ∈ text/markdown；*.daily_format ∈ 格式白名单；email 键值白名单
//	daily_mode ∈ modules/template；作用域归一（CanonicalTemplateScope）由调用方
//	在本函数之后执行。
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
		case "payload_template", "daily_payload_template":
			// 事件载荷模板与日报载荷模板（日报卡写入口）同门校验。
			if typ != "webhook" {
				return "", errors.New("payload_template 仅 webhook 通道支持")
			}
			if sv == "" {
				continue
			}
			if err := probeWebhookPayloadTemplate(sv); err != nil {
				return "", err
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
		case "body_template", "daily_body_template":
			// 事件正文模板与日报正文模板（日报卡写入口）同门校验。
			if typ != "email" {
				return "", errors.New("body_template 仅邮件通道支持")
			}
			if len(sv) > 4000 {
				return "", errors.New("body_template 过长（≤4000）")
			}
			out[k] = sv
		case "content_template", "daily_content_template":
			// 事件正文模板与日报正文模板（日报卡写入口）同门校验。
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
		case "daily_mode":
			// 日报渲染模式（前端保存无条件携带）：白名单外一律 400——此前该
			// 键不在校验表，保存日报模板恒 400（后端半边）。
			if sv != "modules" && sv != "template" {
				return "", errors.New("daily_mode 仅支持 modules/template")
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

// probeWebhookPayloadTemplate 占位符替换后必须可解析 JSON（保存即拦截，
// 投递期才不踩坏模板）。两种占位符约定都接受：裸占位符（保存侧 probe 口径）
// 与裹引号占位符（规则弹框旧预置的写法）——后者连引号一起替换，避免误判成
// `""probe""` 非法 JSON。
func probeWebhookPayloadTemplate(sv string) error {
	quoted := regexp.MustCompile(`"\{\{[^}]*}}"`).ReplaceAllString(sv, `"probe"`)
	probe := regexp.MustCompile(`\{\{[^}]*}}`).ReplaceAllString(quoted, `"probe"`)
	if !json.Valid([]byte(probe)) {
		return errors.New("payload_template 不是合法 JSON 模板（占位符替换后仍需可解析）")
	}
	return nil
}

// ruleTemplateValidationError 规则模板校验的业务错误（handler 按语义键提示）。
type ruleTemplateValidationError struct{ key string }

func (e *ruleTemplateValidationError) Error() string { return e.key }

// validateRuleChannelTemplates 规则级「事件×通道模板」保存门（与派发渲染同门）：
// webhook → JSON 载荷模板（占位符替换后可解析，兼容裹引号写法）；机器人
// ≤2000 字节；邮件 ≤4000 字节。通道行不存在（已删除）跳过——不因历史模板
// 阻止规则保存。database 读取失败按基础设施错误返回（调用方映射 500）。
func validateRuleChannelTemplates(database *sql.DB, userID int64, tpls map[string]string) error {
	if len(tpls) == 0 {
		return nil
	}
	// 键按数值归一后再查（与派发侧 strconv.ParseInt 同口径）：SQLite 对 INTEGER
	// 列做数值亲和，"05"/"+5" 这类写法在 IN 里同样命中该通道——拿原始字符串
	// 键回查类型会落空，等于借写法绕过保存门。无法解析的键派发侧永不命中，
	// 不拦。
	byChannel := make(map[int64]string, len(tpls))
	idArgs := make([]any, 0, len(tpls))
	for id, tpl := range tpls {
		chID, err := strconv.ParseInt(id, 10, 64)
		if err != nil || chID <= 0 {
			continue
		}
		byChannel[chID] = tpl
		idArgs = append(idArgs, chID)
	}
	if len(idArgs) == 0 {
		return nil
	}
	args := make([]any, 0, len(idArgs)+1)
	args = append(args, userID)
	args = append(args, idArgs...)
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(idArgs)), ",")
	rows, err := database.Query(`SELECT id, type FROM notification_channels WHERE user_id=? AND id IN (`+placeholders+`)`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	types := make(map[int64]string, len(idArgs))
	for rows.Next() {
		var id int64
		var typ string
		if err := rows.Scan(&id, &typ); err != nil {
			return err
		}
		types[id] = typ
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for chID, tpl := range byChannel {
		switch types[chID] {
		case "webhook":
			if err := probeWebhookPayloadTemplate(tpl); err != nil {
				return &ruleTemplateValidationError{key: "notify.ruleTemplateInvalidJson"}
			}
		case "email":
			if len(tpl) > 4000 {
				return &ruleTemplateValidationError{key: "notify.ruleTemplateTooLong"}
			}
		case "qq", "wx_clawbot":
			if len(tpl) > 2000 {
				return &ruleTemplateValidationError{key: "notify.ruleTemplateTooLong"}
			}
		}
	}
	return nil
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
