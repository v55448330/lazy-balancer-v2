package handlers

// SMTP OAuth2 设备码授权 REST（管理员，Outlook/Office365 公共客户端）：
// POST 发起设备码（落 client_id/tenant/scope，返回 user_code+验证网址）→
// 前端轮询 GET（completed 时 refresh_token 静态加密落库）→ DELETE 解绑。
// 全程出站契合免公网。审计走 Generic（auditpolicy + FormatAuditAction 映射，
// 中间件单次记录，handler 不显式 recordAudit，镜像 smtp-test）。

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
)

// smtpOAuthSession 每用户进行中的设备码会话（内存态，重启作废重新发起）。
type smtpOAuthSession struct {
	DeviceCode string
	ClientID   string
	Tenant     string
	Scope      string
	Interval   int
	ExpiresAt  time.Time
}

var (
	smtpOAuthMu     sync.Mutex
	smtpOAuthByUser = map[int64]*smtpOAuthSession{}
)

// PostSMTPOAuthDeviceCode POST /notification/settings/smtp-oauth——发起设备码。
func (h *Handlers) PostSMTPOAuthDeviceCode(c *gin.Context) {
	if !isAdminRequest(c) {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: apimsg.T(c, "k_20b2245c"), MessageKey: "k_20b2245c"})
		return
	}
	var req struct {
		Tenant   string `json:"tenant"`
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
	}
	_ = c.ShouldBindJSON(&req)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	dc, err := notify.DeviceCodeStart(ctx, req.ClientID, req.Tenant, req.Scope)
	if err != nil {
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: apimsg.Tf(c, "k_8e353bc9", err.Error()), MessageKey: "k_8e353bc9"})
		return
	}
	// client_id/tenant/scope 非密落库（refresh_token 待 poll completed）。
	if err := notify.SetSettings(map[string]string{
		notify.KeySMTPOAuthTenant:   req.Tenant,
		notify.KeySMTPOAuthClientID: req.ClientID,
		notify.KeySMTPOAuthScope:    req.Scope,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存 OAuth 配置失败", err)})
		return
	}
	uid := contextUserID(c)
	smtpOAuthMu.Lock()
	smtpOAuthByUser[uid] = &smtpOAuthSession{
		DeviceCode: dc.DeviceCode, ClientID: req.ClientID, Tenant: req.Tenant, Scope: req.Scope,
		Interval: dc.Interval, ExpiresAt: time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second),
	}
	smtpOAuthMu.Unlock()
	recordAudit(c, "授权", "SMTP OAuth", "发起设备码授权（client_id "+req.ClientID+"，tenant "+req.Tenant+"）")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"user_code": dc.UserCode, "verification_uri": dc.VerificationURI,
		"expires_in": dc.ExpiresIn, "interval": dc.Interval,
	}})
}

// GetSMTPOAuthDeviceCode GET /notification/settings/smtp-oauth——轮询设备码。
func (h *Handlers) GetSMTPOAuthDeviceCode(c *gin.Context) {
	if !isAdminRequest(c) {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: apimsg.T(c, "k_20b2245c"), MessageKey: "k_20b2245c"})
		return
	}
	uid := contextUserID(c)
	smtpOAuthMu.Lock()
	sess := smtpOAuthByUser[uid]
	smtpOAuthMu.Unlock()
	if sess == nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "idle"}})
		return
	}
	if time.Now().After(sess.ExpiresAt) {
		smtpOAuthMu.Lock()
		delete(smtpOAuthByUser, uid)
		smtpOAuthMu.Unlock()
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "expired"}})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	res, err := notify.DeviceCodePoll(ctx, sess.ClientID, sess.Tenant, sess.DeviceCode)
	if err != nil {
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: apimsg.Tf(c, "k_8e353bc9", err.Error()), MessageKey: "k_8e353bc9"})
		return
	}
	if res.Status == "completed" {
		// refresh_token 静态加密落库 + 清令牌缓存 + 消费会话。
		if err := notify.SetSettings(map[string]string{notify.KeySMTPOAuthRefreshToken: res.RefreshToken}); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("保存 OAuth 凭据失败", err)})
			return
		}
		notify.InvalidateOAuthToken()
		smtpOAuthMu.Lock()
		delete(smtpOAuthByUser, uid)
		smtpOAuthMu.Unlock()
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"status": res.Status, "interval": sess.Interval, "error": res.Error,
	}})
}

// DeleteSMTPOAuth DELETE /notification/settings/smtp-oauth——解绑（清除配置）。
func (h *Handlers) DeleteSMTPOAuth(c *gin.Context) {
	if !isAdminRequest(c) {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: apimsg.T(c, "k_20b2245c"), MessageKey: "k_20b2245c"})
		return
	}
	if err := notify.SetSettings(map[string]string{
		notify.KeySMTPOAuthTenant: "", notify.KeySMTPOAuthClientID: "",
		notify.KeySMTPOAuthRefreshToken: "", notify.KeySMTPOAuthScope: "",
	}); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: serverErrMsg("解绑 OAuth 失败", err)})
		return
	}
	notify.InvalidateOAuthToken()
	uid := contextUserID(c)
	smtpOAuthMu.Lock()
	delete(smtpOAuthByUser, uid)
	smtpOAuthMu.Unlock()
	recordAudit(c, "解绑", "SMTP OAuth", "清除 SMTP OAuth 配置（client_id/tenant/refresh_token/scope）")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: apimsg.T(c, "k_ce6e6687"), MessageKey: "k_ce6e6687"})
}
