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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	qqIntentC2C = 1 << 25 // C2C_MESSAGE_CREATE

	qqHTTPTimeout  = 10 * time.Second
	qqDialTimeout  = 15 * time.Second
	qqBeatGrace    = 10 * time.Second // 心跳判死宽限（2 个周期 + 宽限）
	qqReadDeadline = 15 * time.Second // 首帧/拨号读时限基数
)

// 端点 var（测试 mock 覆写；生产=官方开放平台端点，同 qqbind.go 口径）。
var (
	qqAPIBase   = "https://api.sgroup.qq.com"
	qqTokenURL  = "https://bots.qq.com/app/getAppAccessToken"
	qqWSGateway = "wss://api.sgroup.qq.com/websocket"
)

// qqTokenManager access_token 持有与刷新（包级单例 qqTokens）。token 按
// appid 隔离缓存：多机器人场景各 bot 凭据独立鉴权互不顶掉；per-bot 入站 ws
// 会话与 REST 发送（target 钉住凭据）共用同一缓存。
type qqTokenManager struct {
	mu     sync.Mutex
	tokens map[string]qqTokenEntry // appid → token
}

type qqTokenEntry struct {
	token     string
	expiresAt time.Time
}

// qqTokens 包级单例（连接会话与通道发送共用）。
var qqTokens qqTokenManager

// invalidate 作废全部缓存 token（全局凭据落库时调用，下轮强制重鉴权）。
func (m *qqTokenManager) invalidate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens = nil
}

// invalidateAppID 作废单个 bot 的缓存 token（op:9 会话失效——只影响该 bot
// 入站会话，不波及其它 bot 的出站 token）。
func (m *qqTokenManager) invalidateAppID(appid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, appid)
}

// ensureCred 按给定凭据取 token（缓存命中免鉴权；过期前 2 分钟刷新）。
// 凭据由调用方解析：出站=target 钉住凭据（缺省回退全局），入站=会话所属 bot。
func (m *qqTokenManager) ensureCred(ctx context.Context, appid, secret string) (string, error) {
	if appid == "" || secret == "" {
		return "", errors.New("QQ 机器人凭据未配置（全局设置→通知凭据）")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.tokens[appid]; ok && e.token != "" && time.Now().Before(e.expiresAt.Add(-2*time.Minute)) {
		return e.token, nil
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
	if m.tokens == nil {
		m.tokens = map[string]qqTokenEntry{}
	}
	m.tokens[appid] = qqTokenEntry{token: tr.Token, expiresAt: time.Now().Add(secs)}
	return tr.Token, nil
}

// qqResumeState 断线续传会话态（跨重连持有；仅所属 bot 会话 goroutine 串行访问）。
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
// cred/link=会话所属 bot 的凭据与连接态（per-bot 隔离，互不顶掉）。
func qqBotSession(ctx context.Context, cred qqBotCred, link *botLinkState, rs *qqResumeState) error {
	appid, secret := cred.AppID, cred.Secret
	token, err := qqTokens.ensureCred(ctx, appid, secret)
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
			taskLogf(ctx, "connect", "QQ 机器人尝试断线续传（bot=%s seq=%d）", cred.AppID, rs.lastS.Load())
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
					taskLogWarn(ctx, "connect", "QQ 心跳 ACK 超时（bot=%s），判定连接死亡", cred.AppID)
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
		case 9: // 会话失效：重置会话态+作废本 bot token（旧凭据 token 也会 op:9），外层重新鉴权 Identify
			rs.reset()
			qqTokens.invalidateAppID(appid)
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
				link.set(true, "")
				taskLogf(ctx, "connect", "QQ 机器人连接建立（bot=%s READY，session 已就绪）", cred.AppID)
			case "RESUMED":
				taskLogf(ctx, "connect", "QQ 机器人断线续传成功（bot=%s seq=%d）", cred.AppID, rs.lastS.Load())
				link.set(true, "")
			case "C2C_MESSAGE_CREATE":
				handleQQC2CMessage(ctx, cred, frame.D)
			}
		}
	}
}

// handleQQC2CMessage 处理单聊消息：绑定指令「绑定 XXXXXX」→ openid↔user；
// 回复为被动消息（带 msg_id，免主动额度）。入站 ws 属会话所属 bot——通道
// target 钉住该 bot 凭据（多机器人出站鉴权源），回执亦用其 token。
func handleQQC2CMessage(ctx context.Context, cred qqBotCred, raw json.RawMessage) {
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
	appid, secret := cred.AppID, cred.Secret
	// 弹框绑定会话：「绑定测试」匹配活跃会话→confirmed+品牌确认回复（被动消息
	// 带 msg_id 免额度）。无活跃会话落回旧「绑定 <验证码>」指令。
	if IsBindTestMessage(msg.Content) {
		if ConfirmBindSessionByInbound("qq", msg.Author.UserOpenID, appid, msg.Author.UserOpenID, "") {
			if err := qqSendText(ctx, msg.Author.UserOpenID, BindConfirmReply(), msg.ID, appid, secret); err != nil {
				taskLogWarn(ctx, "bind", "QQ 绑定确认回复发送失败（bot=%s）: %v", appid, err)
			}
			return
		}
	}
	target := map[string]any{"openid": msg.Author.UserOpenID}
	if appid != "" && secret != "" {
		target["appid"], target["secret"] = appid, secret
	}
	targetJSON, _ := json.Marshal(target)
	code := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(msg.Content), "绑定"))
	bindBotChannel(code, msg.Author.UserOpenID, "qq", "QQ 机器人", string(targetJSON),
		func(reply string) {
			if err := qqSendText(ctx, msg.Author.UserOpenID, reply, msg.ID, appid, secret); err != nil {
				taskLogWarn(ctx, "bind", "QQ 绑定回复发送失败（bot=%s）: %v", appid, err)
			}
		})
}

// sendQQRESTMessage 主动发 QQ 单聊文本（投递通道适配器调用；appid/secret
// 为 target 钉住凭据，空=调用方已回退全局）。
func sendQQRESTMessage(ctx context.Context, openid, text, appid, secret string) error {
	return qqSendText(ctx, openid, text, "", appid, secret)
}

// sendQQRESTMarkdown 主动发 QQ 单聊 markdown 富文本（msg_type=2；需机器人
// 具备 markdown 权限——失败原样留痕，通道「测试」可预检）。
func sendQQRESTMarkdown(ctx context.Context, openid, md, appid, secret string) error {
	// 官方载荷（bot.q.qq.com 消息类型·Markdown）：msg_type=2 且内容置于
	// markdown.content 对象——顶层 content 是文本字段形态，markdown 不生效。
	content := normalizeQQMarkdown(md)
	return qqSendRaw(ctx, openid, map[string]any{"msg_type": 2, "markdown": map[string]any{"content": content}}, "", appid, secret)
}

// normalizeQQMarkdown QQ markdown 换行规范：段落间空行分隔（单换行不渲染分段），
// 但表格/列表/代码块行须保持连续单换行——空行会断表（用户实测表格不渲染根因：
// 旧实现把全部 \n 翻倍，表格行间插空行致 markdown 表格语法失效）。
func normalizeQQMarkdown(md string) string {
	lines := strings.Split(md, "\n")
	// 结构化行（表格/列表/代码围栏）内部保持单换行，其余段落空行分隔。
	structural := func(s string) bool {
		t := strings.TrimSpace(s)
		if strings.HasPrefix(t, "|") || strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "* ") || strings.HasPrefix(t, "```") {
			return true
		}
		// 有序列表 "1. "
		if i := strings.Index(t, ". "); i > 0 && i <= 3 {
			if _, err := strconv.Atoi(t[:i]); err == nil {
				return true
			}
		}
		return false
	}
	var b strings.Builder
	for i, ln := range lines {
		if i > 0 {
			if structural(ln) && structural(lines[i-1]) {
				b.WriteString("\n")
			} else {
				b.WriteString("\n\n")
			}
		}
		b.WriteString(ln)
	}
	out := b.String()
	for strings.Contains(out, "\n\n\n") {
		out = strings.ReplaceAll(out, "\n\n\n", "\n\n")
	}
	return out
}

// qqSendText REST 发送文本：msgID 非空=被动回复（免主动消息额度）。
// 非 2xx 与业务错误码均原样返回（含响应体片段，投递留痕可读）。
func qqSendText(ctx context.Context, openid, text, msgID, appid, secret string) error {
	return qqSendRaw(ctx, openid, map[string]any{"content": text, "msg_type": 0}, msgID, appid, secret)
}

// qqSendRaw REST 发送（payload 由调用方组装：msg_type 0=文本 2=markdown）。
func qqSendRaw(ctx context.Context, openid string, payload map[string]any, msgID, appid, secret string) error {
	token, err := qqTokens.ensureCred(ctx, appid, secret)
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
