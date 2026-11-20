package handlers

// 通知中心管理设置 REST（管理员）：凭据（SMTP/QQ/微信）、MCP 推送开关、
// 拦截聚合阈值、每日日报手动触发。secret 类写后不回显（GET 只回「已配置」
// 布尔）；PUT 部分更新（只更新提供的键）。

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/models"
	"time"

	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

// GetNotificationSettings GET /notification/settings——聚合 notify_settings
// 键值；secret 类只回布尔。
func (h *Handlers) GetNotificationSettings(c *gin.Context) {
	if !isAdminRequest(c) {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: apimsg.T(c, "k_20b2245c"), MessageKey: "k_20b2245c"})
		return
	}
	m := notify.GetSettings(
		notify.KeySMTPHost, notify.KeySMTPPort, notify.KeySMTPUser, notify.KeySMTPPass, notify.KeySMTPFrom,
		notify.KeySMTPTLS, notify.KeySMTPInsecure,
		notify.KeyQQAppID, notify.KeyQQSecret,
		notify.KeyWxBotCred,
	)
	warnAt, criticalAt := notify.BlockedThresholds()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"smtp": gin.H{
			"host":            m[notify.KeySMTPHost],
			"port":            m[notify.KeySMTPPort],
			"user":            m[notify.KeySMTPUser],
			"from":            m[notify.KeySMTPFrom],
			"pass_configured": m[notify.KeySMTPPass] != "",
			"tls":             m[notify.KeySMTPTLS] != "0",
			"insecure":        m[notify.KeySMTPInsecure] == "1",
		},
		// QQ/微信凭据不回显（单源=扫码绑定自动落库；bot 登录态经
		// /notification/wx/bind-state 供通道向导查询）
		"mcp_enabled":        notify.MCPEnabled(),
		"api_enabled":        notify.APIEnabled(),
		"attack_warn_at":     warnAt,
		"attack_critical_at": criticalAt,
	}})
}

// UpdateNotificationSettings PUT /notification/settings——部分更新：仅出现
// 在请求体中的键生效；secret 类传空串=清除。阈值整体校验 0<warn<critical。
func (h *Handlers) UpdateNotificationSettings(c *gin.Context) {
	if !isAdminRequest(c) {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: apimsg.T(c, "k_20b2245c"), MessageKey: "k_20b2245c"})
		return
	}
	var req struct {
		SMTP *struct {
			Host     *string `json:"host"`
			Port     *string `json:"port"`
			User     *string `json:"user"`
			Pass     *string `json:"pass"`
			From     *string `json:"from"`
			TLS      *bool   `json:"tls"`
			Insecure *bool   `json:"insecure"`
		} `json:"smtp"`
		// QQ 凭据不走本端点：扫码绑定完成时自动落库（凭据单源，手工覆盖
		// 入口已删——避免与扫码态互相踩踏）。
		MCPEnabled       *bool `json:"mcp_enabled"`
		APIEnabled       *bool `json:"api_enabled"`
		AttackWarnAt     *int  `json:"attack_warn_at"`
		AttackCriticalAt *int  `json:"attack_critical_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_76de02a0"), MessageKey: "k_76de02a0"})
		return
	}

	updates := map[string]string{}
	changed := []string{}
	put := func(key string, v *string) {
		if v != nil {
			updates[key] = *v
			changed = append(changed, key)
		}
	}
	if req.SMTP != nil {
		if req.SMTP.Port != nil && *req.SMTP.Port != "" {
			if p, err := strconv.Atoi(*req.SMTP.Port); err != nil || p < 1 || p > 65535 {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_d37587be"), MessageKey: "k_d37587be"})
				return
			}
		}
		put(notify.KeySMTPHost, req.SMTP.Host)
		put(notify.KeySMTPPort, req.SMTP.Port)
		put(notify.KeySMTPUser, req.SMTP.User)
		put(notify.KeySMTPPass, req.SMTP.Pass)
		put(notify.KeySMTPFrom, req.SMTP.From)
		if req.SMTP.TLS != nil {
			v := "1"
			if !*req.SMTP.TLS {
				v = "0"
			}
			updates[notify.KeySMTPTLS] = v
			changed = append(changed, notify.KeySMTPTLS)
		}
		if req.SMTP.Insecure != nil {
			v := "0"
			if *req.SMTP.Insecure {
				v = "1"
			}
			updates[notify.KeySMTPInsecure] = v
			changed = append(changed, notify.KeySMTPInsecure)
		}
	}
	if req.MCPEnabled != nil {
		v := "0"
		if *req.MCPEnabled {
			v = "1"
		}
		updates[notify.KeyMCPEnabled] = v
		changed = append(changed, notify.KeyMCPEnabled)
	}
	if req.APIEnabled != nil {
		v := "0"
		if *req.APIEnabled {
			v = "1"
		}
		updates[notify.KeyAPIEnabled] = v
		changed = append(changed, notify.KeyAPIEnabled)
	}
	// 阈值：以生效值合并请求值后整体校验（0<warn<critical）。
	warnAt, criticalAt := notify.BlockedThresholds()
	if req.AttackWarnAt != nil {
		warnAt = *req.AttackWarnAt
		changed = append(changed, notify.KeyAttackWarnAt)
	}
	if req.AttackCriticalAt != nil {
		criticalAt = *req.AttackCriticalAt
		changed = append(changed, notify.KeyAttackCriticalAt)
	}
	if warnAt <= 0 || criticalAt <= warnAt {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_04f0eea4"), MessageKey: "k_04f0eea4"})
		return
	}
	if req.AttackWarnAt != nil {
		updates[notify.KeyAttackWarnAt] = strconv.Itoa(warnAt)
	}
	if req.AttackCriticalAt != nil {
		updates[notify.KeyAttackCriticalAt] = strconv.Itoa(criticalAt)
	}

	if len(changed) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: apimsg.T(c, "k_76de02a0"), MessageKey: "k_76de02a0"})
		return
	}
	if err := notify.SetSettings(updates); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存通知设置失败", err)})
		return
	}
	recordAudit(c, "修改", "通知设置", services.FormatAuditDetail("变更键: "+strings.Join(changed, ","), "", services.AuditResultPart("success")))
	notify.Publish(notify.Event{Type: notify.EvtNotificationCfgChanged, Fields: map[string]string{"1": c.GetString("username")}})
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_ce6e6687"), MessageKey: "k_ce6e6687"})
}

// TestSMTPSettings POST /notification/settings/smtp-test——SMTP 连通性测试
// （管理员）：test_to 非空时发标记邮件到指定收件人，空=仅握手+AUTH。
func (h *Handlers) TestSMTPSettings(c *gin.Context) {
	if !isAdminRequest(c) {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: apimsg.T(c, "k_20b2245c"), MessageKey: "k_20b2245c"})
		return
	}
	var req struct {
		TestTo string `json:"test_to"`
		// 草稿（测试先于保存）：host 非空时用未保存配置测试，pass 空沿用已存。
		Host     string `json:"host"`
		Port     string `json:"port"`
		User     string `json:"user"`
		Pass     string `json:"pass"`
		From     string `json:"from"`
		TLS      bool   `json:"tls"`
		Insecure bool   `json:"insecure"`
	}
	_ = c.ShouldBindJSON(&req)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	var draft *notify.SMTPDraft
	if req.Host != "" {
		draft = &notify.SMTPDraft{Host: req.Host, Port: req.Port, User: req.User, Pass: req.Pass, From: req.From, TLS: req.TLS, Insecure: req.Insecure}
	}
	if err := notify.SmtpConnectivityTest(ctx, req.TestTo, draft); err != nil {
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: apimsg.Tf(c, "k_8e353bc9", err.Error()), MessageKey: "k_8e353bc9"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_4bde3724"), MessageKey: "k_4bde3724"})
}
