package notify

// QQ 官方机器人连接 Daemon（WebSocket 出站，免公网）：
//   AppID+Secret → getAppAccessToken → wss 事件网关（op:2 Identify/op:1 心跳/
//   op:6 Resume）→ C2C_MESSAGE_CREATE 处理「绑定 XXXXXXX」指令。
// 发消息走官方 REST（/v2/users/{openid}/messages，被动回复带 msg_id 免额度；
// 主动消息受官方额度频控——QQ 通道默认只订 critical）。
// access_token 经包级单例 qqTokens 复用（连接会话与发送共用，过期自动刷新
// 并重读全局凭据——支持凭据轮换）。
//
// 协议细节以 QQ 机器人开放平台文档为准（q.qq.com）；本文件为连接生命周期+
// 通道适配器，协议帧编解码在 qqbot_session.go。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// QQBotConfigured 全局凭据（AppID+Secret）已配置。
func QQBotConfigured() bool {
	appid, secret, ok := qqBotCredentials()
	return ok && appid != "" && secret != ""
}

// qqBotCredentials 读全局凭据（notify_settings KV：notify.qq_appid/
// notify.qq_secret，单源 settings.go 键常量）。
func qqBotCredentials() (appid, secret string, ok bool) {
	kv := GetSettings(KeyQQAppID, KeyQQSecret)
	appid, secret = kv[KeyQQAppID], kv[KeyQQSecret]
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

// qqSender QQ 通道适配器：发送/测试均走官方 REST（token 经单例复用）。
type qqSender struct{}

func (qqSender) Send(ctx context.Context, targetJSON string, msg Message) error {
	// 停止语义（用户裁定）：连接任务未运行=机器人服务不在位，出站投递直接
	// 失败（落 failed+原因），不静默滞留 pending。连接在线态由连接 Daemon 维护。
	if connected, lastErr, _ := QQLinkStatus(); !connected {
		if lastErr != "" {
			return fmt.Errorf("QQ 机器人服务未运行: %s", lastErr)
		}
		return errors.New("QQ 机器人服务未运行（连接任务已停止或凭据未配置）")
	}
	var styled struct {
		MsgType         string `json:"msg_type"`
		ContentTemplate string `json:"content_template"`
	}
	_ = json.Unmarshal([]byte(targetJSON), &styled) // 样式键缺失/坏 JSON=文本默认
	text := formatBotTextWithTemplate(styled.ContentTemplate, msg, time.Now())
	if styled.MsgType == "markdown" {
		return SendQQC2CMarkdown(ctx, targetJSON, text)
	}
	return SendQQC2C(ctx, targetJSON, text)
}

// Test 连接离线时返回明确错误（面板「测试」按钮的语义：连接不在位即不可发）。
func (qqSender) Test(ctx context.Context, targetJSON string) error {
	connected, lastErr, _ := QQLinkStatus()
	if !connected {
		if lastErr != "" {
			return fmt.Errorf("QQ 机器人连接离线: %s", lastErr)
		}
		return errors.New("QQ 机器人连接离线（连接任务未运行或凭据未配置）")
	}
	return SendQQC2C(ctx, targetJSON, formatBotText(testNotificationMessage()))
}

// SendQQC2C 发 QQ 单聊文本（投递 Daemon 通道适配器调用）。
// ChannelTarget JSON 形如 {"openid":"..."}；错误全部返回（投递留痕）。
func SendQQC2C(ctx context.Context, targetJSON, text string) error {
	var cfg struct {
		OpenID string `json:"openid"`
	}
	if err := json.Unmarshal([]byte(targetJSON), &cfg); err != nil {
		return fmt.Errorf("QQ 通道目标解析失败: %w", err)
	}
	if cfg.OpenID == "" {
		return errors.New("QQ 通道目标缺少 openid（请先在 QQ 内发送绑定指令完成绑定）")
	}
	return sendQQRESTMessage(ctx, cfg.OpenID, text)
}

// SendQQC2CMarkdown 发 QQ 单聊 markdown 富文本（msg_type=2；机器人需具备
// markdown 权限，失败留痕）。
func SendQQC2CMarkdown(ctx context.Context, targetJSON, md string) error {
	var cfg struct {
		OpenID string `json:"openid"`
	}
	if err := json.Unmarshal([]byte(targetJSON), &cfg); err != nil {
		return fmt.Errorf("QQ 通道目标解析失败: %w", err)
	}
	if cfg.OpenID == "" {
		return errors.New("QQ 通道目标缺少 openid（请先在 QQ 内发送绑定指令完成绑定）")
	}
	return sendQQRESTMarkdown(ctx, cfg.OpenID, md)
}

// qqWakeCh 凭据变更唤醒信号（SaveQQBotCredentials 落库后投递；非阻塞，
// 循环未运行时弃置——下轮启动自然读新凭据）。
var qqWakeCh = make(chan struct{}, 1)

// RunQQBotConnection 连接主循环：鉴权→ws→收发→断线退避重连（ctx 取消退出）。
// Resume 断线续传：会话态（sessionID/seq）跨重连持有，服务端请求重连
// （op:7）或闪断时优先 Resume 补拉遗漏事件；会话失效（op:9）回退重新
// Identify。长时间在线后重连退避计数归零（长期运行不受历史断连拖累）。
// 凭据变更（qqWakeCh）立即重置会话态重连，不等退避。
func RunQQBotConnection(ctx context.Context) error { //scope-exempt: daemon-run-body-loop
	ctx = withTaskID(ctx, "qq-bot-connection")
	// 清洁停止必须置离线：否则 qqLink 残留 connected=true，Send/Test 门被
	// 污染成假在线（停止后仍放行的实测根因）。任何退出路径统一收尾。
	defer qqLink.set(false, "连接任务已停止")
	// 出站长连：ws 事件网关（qqBotSession 内心跳/Resume），断线退避重连。
	if !QQBotConfigured() {
		return fmt.Errorf("QQ 机器人凭据未配置")
	}
	taskLogf(ctx, "connect", "QQ 机器人连接任务启动（凭据已配置，开始鉴权建连）")
	resume := &qqResumeState{}
	attempt := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		started := time.Now()
		err := qqBotSession(ctx, resume)
		if ctx.Err() != nil {
			return nil
		}
		qqLink.set(false, fmt.Sprintf("连接断开: %v", err))
		if time.Since(started) > 5*time.Minute {
			attempt = 0
		}
		attempt++
		taskLogWarn(ctx, "connect", "QQ 机器人连接断开（第 %d 次，%v 后重连）: %v", attempt, botBackoff(attempt), err)
		select {
		case <-ctx.Done():
			return nil
		case <-qqWakeCh:
			// 凭据已轮换：旧会话态作废，立即以新凭据重新 Identify。
			resume.reset()
			attempt = 0
			taskLogf(ctx, "connect", "QQ 凭据已轮换，重置会话态立即重连")
		case <-time.After(botBackoff(attempt)):
		}
	}
}

func init() { RegisterSender("qq", qqSender{}) }
