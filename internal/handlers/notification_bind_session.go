package handlers

// 绑定会话 REST（弹框统一绑定流程：扫码→连接测试→发送「绑定测试」→确认→保存）：
// POST 注册会话（扫码确认后），GET 轮询 phase/连接态。per-user（business 组鉴权）。
// 入站「绑定测试」由 notify 入站处理挂钩标记 confirmed+品牌回复；保存门控由弹框
// 据 phase 决定。审计：注册/确认属绑定动作，handler 显式留痕（Explicit）。

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
)

// PostBindSession POST /notification/bind-session——扫码确认+连接测试后注册会话。
func (h *Handlers) PostBindSession(c *gin.Context) {
	var req struct {
		Type      string `json:"type"`
		ScannerID string `json:"scanner_id"`
		BotKey    string `json:"bot_key"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil || (req.Type != "qq" && req.Type != "wx_clawbot") || req.ScannerID == "" {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "common.malformedRequest"))
		return
	}
	uid := contextUserID(c)
	// QQ 待绑定 secret（qqBoundByUser）随会话携带，supervisor 提前建连破死锁；
	// wx 凭据经 wxConfirmedPin 枚举，secret 留空。
	secret := ""
	if req.Type == "qq" {
		qqTaskMu.Lock()
		if b, ok := qqBoundByUser[uid]; ok && b.AppID == req.BotKey {
			secret = b.Secret
		}
		qqTaskMu.Unlock()
	}
	notify.StartBindSessionWithCred(uid, req.Type, req.ScannerID, req.BotKey, secret)
	recordAudit(c, "绑定", "通知通道", "发起绑定会话（"+req.Type+"，待发送绑定测试）")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"phase":     "awaiting_message",
		"connected": notify.BindSessionConnected(req.Type, req.BotKey),
	}})
}

// GetBindSession GET /notification/bind-session——轮询会话 phase/接收者/连接态。
func (h *Handlers) GetBindSession(c *gin.Context) {
	typ := c.Query("type")
	scannerID := c.Query("scanner_id")
	botKey := c.Query("bot_key")
	phase, receiver := notify.PollBindSession(contextUserID(c), typ, scannerID, botKey)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"phase":     phase,
		"receiver":  receiver,
		"connected": notify.BindSessionConnected(typ, botKey),
	}})
}

// DeleteBindSession DELETE /notification/bind-session——弹框取消清理绑定会话+
// 待绑定凭据（防幽灵入站连接）。qq 同步清 qqBoundByUser 匹配项。
func (h *Handlers) DeleteBindSession(c *gin.Context) {
	typ := c.Query("type")
	scannerID := c.Query("scanner_id")
	botKey := c.Query("bot_key")
	uid := contextUserID(c)
	if typ == "qq" {
		qqTaskMu.Lock()
		if b, ok := qqBoundByUser[uid]; ok && b.AppID == botKey {
			delete(qqBoundByUser, uid)
		}
		qqTaskMu.Unlock()
	}
	notify.AbortBindSession(uid, typ, scannerID, botKey)
	recordAudit(c, "绑定", "通知通道", "取消绑定会话（"+typ+"）")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0})
}
