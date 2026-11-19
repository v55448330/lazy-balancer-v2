package handlers

// 微信 iLink 扫码登录 REST：二维码获取/状态轮询（管理员，凭据管理页）。
// 协议实现见 internal/notify/wxbot.go（WxQRLoginStart/Poll——confirmed 时
// 首登凭证落 notify_settings 并重置会话态；全局已配置则不覆盖，新凭据
// 待通道保存钉住，入站长轮询仍首 bot）。

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
)

// PostWxQRStart GET/POST /notification/wx/qr/start——发起扫码登录，返回
// qrcode_img_content（可直接渲染为二维码图）。
func (h *Handlers) StartWxQRLogin(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	qrImg, err := notify.WxQRLoginStart(ctx)
	if err != nil {
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: apimsg.Tf(c, "k_94d8f73b", err.Error()), MessageKey: msgWxQRStartFailed})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"qr_content": qrImg}})
}

// GetWxQRStatus GET /notification/wx/qr/status——轮询扫码状态
// （wait/scaned/confirmed/expired；confirmed 时首登凭证已落库，二登凭据待通道钉住）。
func (h *Handlers) GetWxQRStatus(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()
	status, confirmed, err := notify.WxQRLoginPoll(ctx)
	if err != nil {
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: apimsg.Tf(c, "k_403c12fe", err.Error()), MessageKey: msgWxQRPollFailed})
		return
	}
	if confirmed {
		// 登录确认即凭据就绪（首登落全局/二登待通道钉住）——产码 start 不记
		// （一次登录一次审计）。
		recordAudit(c, "绑定", "通知设置", "微信机器人扫码登录成功")
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": status, "confirmed": confirmed}})
}

// GetWxBindState GET /notification/wx/bind-state——通道向导微信分支判据：
// bot 登录态 + 领取最近入站接收者（向导内「发送任意消息自动回填」闭环；
// 领取即清，3 分钟内有效）。
func (h *Handlers) GetWxBindState(c *gin.Context) {
	const captureWindow = 3 * time.Minute
	receiver := notify.WxTakePendingReceiver(captureWindow)
	if receiver == "" && notify.WxBotLoggedIn() {
		// 扫码确认后默认接收者=扫码者，无需再发消息即可保存（入站捕获优先）。
		receiver = notify.WxDefaultReceiver()
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"bot_ready": notify.WxBotLoggedIn(),
		"receiver":  receiver,
	}})
}
