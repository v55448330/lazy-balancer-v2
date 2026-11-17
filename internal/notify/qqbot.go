package notify

// QQ 官方机器人连接 Daemon（WebSocket 出站，免公网）：
//   AppID+Secret → getAppAccessToken → wss 事件网关（op:2 Identify/op:1 心跳/
//   op:6 Resume）→ C2C_MESSAGE_CREATE 处理「绑定 XXXXXXX」指令。
// 发消息走官方 REST（/v2/users/{openid}/messages，被动回复带 msg_id 免额度；
// 主动消息受官方额度频控——QQ 通道默认只订 critical）。
//
// 协议细节以 QQ 机器人开放平台文档为准；本文件为连接生命周期+发送通道。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// QQBotConfigured 全局凭据（AppID+Secret）已配置。
func QQBotConfigured() bool {
	appid, secret, ok := qqBotCredentials()
	return ok && appid != "" && secret != ""
}

// qqBotCredentials 读全局凭据（global_config 键 notify.qq_appid/notify.qq_secret）。
func qqBotCredentials() (appid, secret string, ok bool) {
	if db.DB == nil {
		return "", "", false
	}
	_ = db.DB.QueryRow(`SELECT COALESCE((SELECT value FROM global_config WHERE key='notify.qq_appid'),''),
		COALESCE((SELECT value FROM global_config WHERE key='notify.qq_secret'),'')`).Scan(&appid, &secret)
	return appid, secret, appid != "" && secret != ""
}

// qqLink 连接状态单例（通知中心页状态点）。
var qqLink botLinkState

// QQLinkStatus 通道连接状态（REST 只读）。
func QQLinkStatus() (bool, string, time.Time) {
	qqLink.mu.Lock()
	defer qqLink.mu.Unlock()
	return qqLink.connected, qqLink.lastErr, qqLink.lastChange
}

// SendQQC2C 经长连/REST 发 QQ 单聊文本（投递 Daemon 通道适配器调用）。
// 若 ChannelTarget JSON 形如 {"openid":"..."}，发送到该 openid。
func SendQQC2C(ctx context.Context, targetJSON, text string) error {
	var cfg struct{ OpenID string `json:"openid"` }
	if err := json.Unmarshal([]byte(targetJSON), &cfg); err != nil || cfg.OpenID == "" {
		return fmt.Errorf("QQ 通道目标缺少 openid: %w", err)
	}
	// 发送走官方 REST（token 由连接管理器持有）；连接离线=明确错误（投递留痕）。
	return sendQQRESTMessage(ctx, cfg.OpenID, text)
}

// RunQQBotConnection 连接主循环：鉴权→ws→收发→断线退避重连（rc.Ctx 取消退出）。
func RunQQBotConnection(ctx context.Context) error {
	appid, secret, ok := qqBotCredentials()
	if !ok {
		return fmt.Errorf("QQ 机器人凭据未配置")
	}
	attempt := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := qqBotSession(ctx, appid, secret)
		if ctx.Err() != nil {
			return nil
		}
		qqLink.set(false, fmt.Sprintf("连接断开: %v", err))
		attempt++
		log.Printf("WARN: QQ 机器人连接断开（第 %d 次，%v 后重连）: %v", attempt, botBackoff(attempt), err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(botBackoff(attempt)):
		}
	}
}

var _ sync.Mutex // 骨架引用占位（连接器实现使用）
var _ = errors.New
