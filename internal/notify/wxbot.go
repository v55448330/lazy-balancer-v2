package notify

// 微信个人 Bot（iLink 协议）连接 Daemon：与 QQ 连接器同构（出站长连+扫码
// 登录态+绑定指令+文本发送）。协议编解码细节以微信官方 Bot 开放文档为准；
// 登录二维码/登录态由协议流程下发，通知中心页透传展示。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

var wxLink botLinkState

// WxBotConfigured 微信 Bot 登录态凭据已配置。
func WxBotConfigured() bool {
	appid, secret, ok := wxBotCredentials()
	return ok && appid != "" && secret != ""
}

// wxBotCredentials 全局凭据（notify.wx_appid/notify.wx_secret）。
func wxBotCredentials() (appid, secret string, ok bool) {
	if db.DB == nil {
		return "", "", false
	}
	_ = db.DB.QueryRow(`SELECT COALESCE((SELECT value FROM global_config WHERE key='notify.wx_appid'),''),
		COALESCE((SELECT value FROM global_config WHERE key='notify.wx_secret'),'')`).Scan(&appid, &secret)
	return appid, secret, appid != "" && secret != ""
}

// WxLinkStatus 连接状态（REST 只读）。
func WxLinkStatus() (bool, string, time.Time) {
	wxLink.mu.Lock()
	defer wxLink.mu.Unlock()
	return wxLink.connected, wxLink.lastErr, wxLink.lastChange
}

var (
	wxMu       sync.Mutex
	wxEndpoint string // 用户 clawbot/官方发送端点配置（通道 target 持有亦可）
)

// SendWxText 经 iLink 长连发微信文本（投递通道适配器调用）。
// receiver 为通道 target JSON 的 {"receiver":"wxid/群 id"}。
func SendWxText(ctx context.Context, targetJSON, text string) error {
	var cfg struct{ Receiver string `json:"receiver"` }
	if err := json.Unmarshal([]byte(targetJSON), &cfg); err != nil || cfg.Receiver == "" {
		return fmt.Errorf("微信通道目标缺少 receiver: %w", err)
	}
	appid, secret, ok := wxBotCredentials()
	if !ok {
		return errors.New("微信 Bot 凭据未配置（连接器离线）")
	}
	// iLink 发送：REST 形态（长连负责收事件；发送按官方 API 调用）。
	_ = appid
	_ = secret
	return errors.New("微信 iLink 发送通道：协议适配待官方文档参数校准（通道配置与订阅链路已就绪）")
}

// RunWxBotConnection 连接主循环（对称 RunQQBotConnection；退避重连）。
func RunWxBotConnection(ctx context.Context) error {
	appid, secret, ok := wxBotCredentials()
	if !ok {
		return fmt.Errorf("微信 Bot 凭据未配置")
	}
	attempt := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := wxBotSession(ctx, appid, secret)
		if ctx.Err() != nil {
			return nil
		}
		wxLink.set(false, fmt.Sprintf("连接断开: %v", err))
		attempt++
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(botBackoff(attempt)):
		}
	}
}

// wxBotSession iLink 会话（收事件+心跳）。协议编解码以官方文档为准的适配点：
// 鉴权握手/事件帧结构在本函数内集中实现，其余系统面（绑定/掉线告警/状态点）
// 均已就绪。
func wxBotSession(ctx context.Context, appid, secret string) error {
	// TODO(wx-iLink)：官方协议编解码落地（鉴权帧/事件帧/心跳）。
	return errors.New("微信 iLink 协议适配待官方文档参数校准")
}
