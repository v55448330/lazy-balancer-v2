package notify

// QQ 官方机器人协议实现：WebSocket 事件网关 + REST 发送。
// 文档：QQ 机器人开放平台（q.qq.com）。鉴权=AppID+Secret→access_token；
// 事件=op 帧（10 Hello/2 Identify/0 Dispatch/1 心跳请求/11 心跳 ACK/
// 7 服务端请求重连/9 会话失效/6 Resume）；发送=POST /v2/users/{openid}/
// messages（被动回复带 msg_id 免主动额度）。
// 生命周期：Identify（或持 sessionID 时 Resume 续传）→ 心跳（带最新 seq，
// ACK 超时判死）→ dispatch 分发；任何错误交由 RunQQBotConnection 退避重连。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	qqAPIBase   = "https://api.sgroup.qq.com"
	qqWSGateway = "wss://api.sgroup.qq.com/websocket"
	qqTokenURL  = "https://bots.qq.com/app/getAppAccessToken"
	qqIntentC2C = 1 << 25 // C2C_MESSAGE_CREATE

	qqHTTPTimeout  = 10 * time.Second
	qqDialTimeout  = 15 * time.Second
	qqBeatGrace    = 10 * time.Second // 心跳判死宽限（2 个周期 + 宽限）
	qqReadDeadline = 15 * time.Second // 首帧/拨号读时限基数
)

// qqTokenManager access_token 持有与刷新（包级单例 qqTokens：ws 会话与
// REST 发送共用一把 token，避免每调用重新鉴权）。token 按 appid 持有：
// 重新绑定（新 bot 凭据）后旧 token 立即作废——此前缓存不认 appid，
// 换绑后旧 token 持续 Identify → op:9 Invalid Session 死循环（实测根因）。
type qqTokenManager struct {
	mu        sync.Mutex
	token     string
	appid     string // token 所属 appid（凭据轮换判据）
	expiresAt time.Time
}

// qqTokens 包级单例（连接会话与通道发送共用）。
var qqTokens qqTokenManager

// invalidate 作废缓存 token（op:9 会话失效/凭据变更时调用，下轮强制重鉴权）。
func (m *qqTokenManager) invalidate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.token = ""
	m.appid = ""
}

func (m *qqTokenManager) ensure(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	appid, secret, ok := qqBotCredentials()
	if !ok {
		return "", errors.New("QQ 机器人凭据未配置（全局设置→通知凭据）")
	}
	if m.token != "" && m.appid == appid && time.Now().Before(m.expiresAt.Add(-2*time.Minute)) {
		return m.token, nil
	}
	body, err := json.Marshal(map[string]string{"appId": appid, "clientSecret": secret})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, qqTokenURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: qqHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("QQ 鉴权请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("QQ 鉴权 status=%d body=%s", resp.StatusCode, string(raw))
	}
	var tr struct {
		Token     string `json:"access_token"`
		ExpiresIn string `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &tr); err != nil {
		return "", fmt.Errorf("QQ 鉴权响应解析失败: %w", err)
	}
	if tr.Token == "" {
		return "", fmt.Errorf("QQ 鉴权响应缺 access_token: %s", string(raw))
	}
	secs, _ := time.ParseDuration(tr.ExpiresIn + "s")
	if secs <= 0 {
		secs = 2 * time.Hour
	}
	m.token = tr.Token
	m.appid = appid
	m.expiresAt = time.Now().Add(secs)
	return m.token, nil
}

// qqResumeState 断线续传会话态（跨重连持有；仅连接 goroutine 串行访问）。
type qqResumeState struct {
	sessionID string // READY 下发的会话 ID（空=尚未建立，走 Identify）
	lastS     atomic.Int64
}

func (rs *qqResumeState) reset() {
	rs.sessionID = ""
	rs.lastS.Store(0)
}

// qqBotSession 单次连接生命周期：Hello→Resume(或 Identify)→心跳→分发。
// 心跳带最新 seq；超过两个周期无 ACK 即判死断开；读侧逐帧刷新超时兜底
// 半开连接。服务端请求重连（op:7）与会话失效（op:9）返回错误由外层重连
// （前者保留会话态走 Resume，后者重置后重新 Identify）。
func qqBotSession(ctx context.Context, rs *qqResumeState) error {
	token, err := qqTokens.ensure(ctx)
	if err != nil {
		return err
	}
	dialer := websocket.Dialer{HandshakeTimeout: qqDialTimeout}
	conn, _, err := dialer.DialContext(ctx, qqWSGateway, nil)
	if err != nil {
		return fmt.Errorf("ws 拨号: %w", err)
	}
	defer conn.Close()

	var writeMu sync.Mutex
	send := func(payload map[string]any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(qqHTTPTimeout))
		return conn.WriteJSON(payload)
	}
	// op:10 Hello → 心跳间隔。
	var hello struct {
		OP int `json:"op"`
		D  struct {
			HeartbeatInterval int64 `json:"heartbeat_interval"`
		} `json:"d"`
	}
	_ = conn.SetReadDeadline(time.Now().Add(qqReadDeadline))
	if err := conn.ReadJSON(&hello); err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	if hello.OP != 10 {
		return fmt.Errorf("hello 帧异常 op=%d", hello.OP)
	}
	beat := time.Duration(hello.D.HeartbeatInterval) * time.Millisecond //scope-exempt: daemon-run-body-loop
	if beat <= 0 {
		beat = 30 * time.Second
	}

	// Resume 优先（有会话态），否则重新 Identify。
	if rs.sessionID != "" {
		err = send(map[string]any{"op": 6, "d": map[string]any{
			"token": "QQBot " + token, "session_id": rs.sessionID, "seq": rs.lastS.Load(),
		}})
		if err == nil {
			taskLogf(ctx, "connect", "QQ 机器人尝试断线续传（seq=%d）", rs.lastS.Load())
		}
	} else {
		err = send(map[string]any{"op": 2, "d": map[string]any{
			"token": "QQBot " + token, "intents": qqIntentC2C,
		}})
	}
	if err != nil {
		return fmt.Errorf("identify/resume 发送: %w", err)
	}

	lastAck := atomic.Int64{}
	lastAck.Store(time.Now().UnixMilli())
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(beat)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				_ = conn.Close() // 唤醒阻塞的读侧
				return
			case <-t.C:
				if err := send(map[string]any{"op": 1, "d": rs.lastS.Load()}); err != nil {
					_ = conn.Close()
					return
				}
				if time.Since(time.UnixMilli(lastAck.Load())) > 2*beat+qqBeatGrace {
					taskLogWarn(ctx, "connect", "QQ 心跳 ACK 超时，判定连接死亡")
					_ = conn.Close()
					return
				}
			}
		}
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(2*beat + qqBeatGrace))
		var frame struct {
			OP int             `json:"op"`
			S  int64           `json:"s"`
			D  json.RawMessage `json:"d"`
			T  string          `json:"t"`
		}
		if err := conn.ReadJSON(&frame); err != nil {
			return err
		}
		if frame.S > 0 {
			rs.lastS.Store(frame.S)
		}
		switch frame.OP {
		case 11: // 心跳 ACK
			lastAck.Store(time.Now().UnixMilli())
		case 1: // 服务端心跳请求 → 立即回带最新 seq
			if err := send(map[string]any{"op": 1, "d": rs.lastS.Load()}); err != nil {
				return fmt.Errorf("心跳应答发送: %w", err)
			}
		case 7: // 服务端请求重连：保留会话态，外层立即重连走 Resume
			return errors.New("服务端请求重连")
		case 9: // 会话失效：重置会话态+作废 token（旧凭据 token 也会 op:9），外层重新鉴权 Identify
			rs.reset()
			qqTokens.invalidate()
			return errors.New("会话失效（Invalid Session）")
		case 0: // dispatch
			switch frame.T {
			case "READY":
				var d struct {
					SessionID string `json:"session_id"`
				}
				if json.Unmarshal(frame.D, &d) == nil && d.SessionID != "" {
					rs.sessionID = d.SessionID
				}
				qqLink.set(true, "")
				taskLogf(ctx, "connect", "QQ 机器人连接建立（READY，session 已就绪）")
			case "RESUMED":
				taskLogf(ctx, "connect", "QQ 机器人断线续传成功（seq=%d）", rs.lastS.Load())
				qqLink.set(true, "")
			case "C2C_MESSAGE_CREATE":
				handleQQC2CMessage(ctx, frame.D)
			}
		}
	}
}

// handleQQC2CMessage 处理单聊消息：绑定指令「绑定 XXXXXX」→ openid↔user；
// 回复为被动消息（带 msg_id，免主动额度）。
func handleQQC2CMessage(ctx context.Context, raw json.RawMessage) {
	var msg struct {
		Content string `json:"content"`
		Author  struct {
			UserOpenID string `json:"user_openid"`
		} `json:"author"`
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &msg) != nil || msg.Author.UserOpenID == "" {
		return
	}
	code := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(msg.Content), "绑定"))
	bindBotChannel(code, msg.Author.UserOpenID, "qq", "QQ 机器人", `{"openid":`+quoteJSON(msg.Author.UserOpenID)+`}`,
		func(reply string) {
			if err := qqSendText(ctx, msg.Author.UserOpenID, reply, msg.ID); err != nil {
				taskLogWarn(ctx, "bind", "QQ 绑定回复发送失败: %v", err)
			}
		})
}

// sendQQRESTMessage 主动发 QQ 单聊文本（投递通道适配器调用；token 单例复用）。
func sendQQRESTMessage(ctx context.Context, openid, text string) error {
	return qqSendText(ctx, openid, text, "")
}

// sendQQRESTMarkdown 主动发 QQ 单聊 markdown 富文本（msg_type=2；需机器人
// 具备 markdown 权限——失败原样留痕，通道「测试」可预检）。
func sendQQRESTMarkdown(ctx context.Context, openid, md string) error {
	// 官方载荷（bot.q.qq.com 消息类型·Markdown）：msg_type=2 且内容置于
	// markdown.content 对象——顶层 content 是文本字段形态，markdown 不生效。
	// 换行规范：QQ markdown 单换行不渲染，需空行分段（单 \n → 双 \n）。
	content := strings.ReplaceAll(md, "\n", "\n\n")
	for strings.Contains(content, "\n\n\n\n") {
		content = strings.ReplaceAll(content, "\n\n\n\n", "\n\n")
	}
	return qqSendRaw(ctx, openid, map[string]any{"msg_type": 2, "markdown": map[string]any{"content": content}}, "")
}

// qqSendText REST 发送文本：msgID 非空=被动回复（免主动消息额度）。
// 非 2xx 与业务错误码均原样返回（含响应体片段，投递留痕可读）。
func qqSendText(ctx context.Context, openid, text, msgID string) error {
	return qqSendRaw(ctx, openid, map[string]any{"content": text, "msg_type": 0}, msgID)
}

// qqSendRaw REST 发送（payload 由调用方组装：msg_type 0=文本 2=markdown）。
func qqSendRaw(ctx context.Context, openid string, payload map[string]any, msgID string) error {
	token, err := qqTokens.ensure(ctx)
	if err != nil {
		return err
	}
	if msgID != "" {
		payload["msg_id"] = msgID
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/v2/users/%s/messages", qqAPIBase, openid), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "QQBot "+token)
	resp, err := (&http.Client{Timeout: qqHTTPTimeout}).Do(req)
	if err != nil {
		return fmt.Errorf("QQ 发送请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("QQ 发送 status=%d body=%s", resp.StatusCode, string(raw))
	}
	// 业务错误形态：HTTP 200 + {"code":非0,"message":...}。
	var br struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &br) == nil && br.Code != 0 {
		return fmt.Errorf("QQ 发送业务错误 code=%d message=%s", br.Code, br.Message)
	}
	return nil
}
