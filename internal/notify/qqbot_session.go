package notify

// QQ 官方机器人协议实现：WebSocket 事件网关 + REST 发送。
// 文档：QQ 机器人开放平台（q.qq.com）。鉴权=AppID+Secret→access_token；
// 事件=op 帧（10 Hello/2 Identify/0 Dispatch/1 心跳请求/11 心跳 ACK/6 Resume）；
// 发送=POST /v2/users/{openid}/messages（被动回复带 msg_id 免主动额度）。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"lazy-balancer-v2/internal/db"
)

const (
	qqAPIBase    = "https://api.sgroup.qq.com"
	qqWSGateway  = "wss://api.sgroup.qq.com/websocket"
	qqTokenURL   = "https://bots.qq.com/app/getAppAccessToken"
	qqIntentC2C  = 1 << 25 // C2C_MESSAGE_CREATE
)

type qqTokenManager struct {
	mu       sync.Mutex
	token    string
	expiresAt time.Time
	appid    string
	secret   string
}

func (m *qqTokenManager) ensure(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.token != "" && time.Now().Before(m.expiresAt.Add(-2*time.Minute)) {
		return m.token, nil
	}
	body, _ := json.Marshal(map[string]string{"appId": m.appid, "clientSecret": m.secret})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, qqTokenURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	var resp struct {
		Token       string `json:"access_token"`
		ExpiresIn   string `json:"expires_in"`
	}
	if err := json.NewDecoder(resp_ensure(client, req)).Decode(&resp); err != nil {
		return "", err
	}
	if resp.Token == "" {
		return "", errors.New("QQ 鉴权响应缺 access_token")
	}
	secs, _ := time.ParseDuration(resp.ExpiresIn + "s")
	if secs <= 0 {
		secs = 2 * time.Hour
	}
	m.token = resp.Token
	m.expiresAt = time.Now().Add(secs)
	return m.token, nil
}

func resp_ensure(client *http.Client, req *http.Request) interface{ Read([]byte) (int, error) } {
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("WARN: QQ token 请求失败: %v", err)
		return strings.NewReader("{}")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("WARN: QQ token 请求 status=%d", resp.StatusCode)
	}
	return resp.Body
}

// qqBotSession 单次连接生命周期：鉴权→Identify→心跳→dispatch 分发。
// 断线（任何错误）返回——由 RunQQBotConnection 退避重连（Resume 形态见
// sessionID/seq 持有，简化为重新 Identify：事件为触发型，遗漏事件不产生
// 数据丢失——绑定指令可重复发送）。
func qqBotSession(ctx context.Context, appid, secret string) error {
	tm := &qqTokenManager{appid: appid, secret: secret}
	token, err := tm.ensure(ctx)
	if err != nil {
		return err
	}
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, qqWSGateway, nil)
	if err != nil {
		return fmt.Errorf("ws 拨号: %w", err)
	}
	defer conn.Close()

	send := func(payload map[string]any) error {
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return conn.WriteJSON(payload)
	}
	// op:10 Hello → 心跳间隔
	var hello struct {
		OP int `json:"op"`
		D  struct {
			HeartbeatInterval int64 `json:"heartbeat_interval"`
		} `json:"d"`
	}
	if err := conn.ReadJSON(&hello); err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	beat := time.Duration(hello.D.HeartbeatInterval) * time.Millisecond
	if beat <= 0 {
		beat = 30 * time.Second
	}
	// op:2 Identify
	if err := send(map[string]any{
		"op": 2,
		"d": map[string]any{
			"token":   "QQBot " + token,
			"intents": qqIntentC2C,
		},
	}); err != nil {
		return fmt.Errorf("identify: %w", err)
	}

	ackCh := make(chan struct{}, 8)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(beat):
				_ = send(map[string]any{"op": 1, "d": nil})
			case <-ackCh:
			}
		}
	}()

	for {
		var frame struct {
			OP int             `json:"op"`
			S  int64           `json:"s"`
			D  json.RawMessage `json:"d"`
			T  string          `json:"t"`
		}
		if err := conn.ReadJSON(&frame); err != nil {
			return err
		}
		switch frame.OP {
		case 11: // 心跳 ACK
			select {
			case ackCh <- struct{}{}:
			default:
			}
		case 0: // dispatch
			if frame.T == "C2C_MESSAGE_CREATE" {
				handleQQC2CMessage(ctx, tm, frame.D)
			}
		}
	}
}

// handleQQC2CMessage 处理单聊消息：绑定指令「绑定 XXXXXX」→ openid↔user。
func handleQQC2CMessage(ctx context.Context, tm *qqTokenManager, raw json.RawMessage) {
	var msg struct {
		Content    string `json:"content"`
		Author     struct{ UserOpenID string `json:"user_openid"` } `json:"author"`
		ID         string `json:"id"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}
	code := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(msg.Content), "绑定"))
	bindQQOpenID(code, msg.Author.UserOpenID, func(reply string) {
		// 被动回复（带 msg_id）免主动额度。
		token, err := tm.ensure(ctx)
		if err != nil {
			return
		}
		body, _ := json.Marshal(map[string]any{
			"content": reply, "msg_type": 0, "msg_id": msg.ID,
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			fmt.Sprintf("%s/v2/users/%s/messages", qqAPIBase, msg.Author.UserOpenID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "QQBot "+token)
		client := &http.Client{Timeout: 10 * time.Second}
		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	})
}

// bindQQOpenID 绑定码换 openid 落库到 QQ 通道 target，并投递确认回复文本。
func bindQQOpenID(code, openid string, reply func(string)) {
	if code == "" || openid == "" {
		return
	}
	var userID int64
	err := db.DB.QueryRow(`SELECT user_id FROM qq_bind_codes WHERE code=? AND expires_at>datetime('now')`, code).Scan(&userID)
	if err != nil {
		reply("绑定码无效或已过期，请在面板重新生成")
		return
	}
	var channelID int64
	err = db.DB.QueryRow(`SELECT id FROM notification_channels WHERE user_id=? AND type='qq'`, userID).Scan(&channelID)
	if err != nil {
		_, err = db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, enabled, created_at, updated_at)
			VALUES (?, 'qq', 'QQ 机器人', ?, 1, datetime('now'), datetime('now'))`, userID, fmt.Sprintf(`{"openid":%q}`, openid))
		channelID, _ = resInt(err)
	} else {
		_, _ = db.DB.Exec(`UPDATE notification_channels SET target=?, updated_at=datetime('now') WHERE id=?`,
			fmt.Sprintf(`{"openid":%q}`, openid), channelID)
	}
	_, _ = db.DB.Exec(`DELETE FROM qq_bind_codes WHERE code=?`, code)
	reply("绑定成功")
	_ = channelID
}

func resInt(err error) (int64, error) { return 0, err }

// sendQQRESTMessage 主动/被动发 QQ 单聊文本（投递通道适配器调用）。
func sendQQRESTMessage(ctx context.Context, openid, text string) error {
	appid, secret, ok := qqBotCredentials()
	if !ok {
		return errors.New("QQ 机器人凭据未配置（连接器离线）")
	}
	tm := &qqTokenManager{appid: appid, secret: secret}
	token, err := tm.ensure(ctx)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"content": text, "msg_type": 0})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/v2/users/%s/messages", qqAPIBase, openid), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "QQBot "+token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("QQ 发送 status=%d", resp.StatusCode)
	}
	return nil
}
