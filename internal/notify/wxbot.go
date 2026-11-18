package notify

// 微信个人 Bot（iLink 协议）连接 Daemon：与 QQ 连接器同构（出站+绑定指令+
// 文本发送）。协议形态已按官方实现（腾讯 @tencent-weixin/openclaw-weixin）
// 公开整理文档确认：iLink 为 HTTP 长轮询收（getupdates，服务端挂起 ~35s）
// + REST 发（sendmessage），**无 WebSocket**。登录=二维码扫码确认→bot_token
// 凭证（JSON 落库 notify_wx_bot_cred），通知中心页经 WxLinkStatus 透传状态。
//
// 会话路由锚点 context_token：sendmessage 必须回传对方最近一条入站消息携带
// 的 token（协议无「打开会话」API——主动通知要求接收方先给机器人发过消息，
// 缺失时 fail-loud 报错并留痕，绝不静默丢弃）。

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TODO(协议-校准): 以下端点/参数整理自官方 openclaw-weixin v1.0.2 源码的
// 公开协议文档（github.com/the-yex/wechat-ilink-sdk docs/protocol.md）。
// 上线前以微信官方 Bot 开放文档核对一次：①基址与四个业务路径；②
// bot_type=3；③channel_version 取值；④凭证字段名（bot_token/ilink_bot_id/
// ilink_user_id/baseurl）；⑤扫码状态枚举（wait/scaned/confirmed/expired）。
const (
	wxAPIBaseDefault  = "https://ilinkai.weixin.qq.com"
	wxChannelVersion  = "1.0.0"
	wxQRBotType       = 3
	wxLongPollTimeout = 40 * time.Second // 服务端挂起约 35s，客户端留余量
	wxSendTimeout     = 10 * time.Second
	wxTextChunkLimit  = 2000 // 社区兼容口径的文本上限（协议未显式下发）
)

// wxBotCred 扫码确认后下发的登录态凭证（原样落库 notify_wx_bot_cred）。
type wxBotCred struct {
	Token     string `json:"token"`
	BaseURL   string `json:"baseUrl"`
	AccountID string `json:"accountId"`
	UserID    string `json:"userId"`
}

var wxLink botLinkState

// WxBotConfigured 微信 Bot 登录态凭证已配置。
func WxBotConfigured() bool {
	_, ok := loadWxBotCred()
	return ok
}

// loadWxBotCred 读全局凭证（notify_settings KV：notify.wx_bot_cred JSON，
// 键常量 KeyWxBotCred 单源 settings.go；token 空=未配置）。
func loadWxBotCred() (wxBotCred, bool) {
	var cred wxBotCred
	raw := GetSetting(KeyWxBotCred)
	if raw == "" || json.Unmarshal([]byte(raw), &cred) != nil || cred.Token == "" {
		return cred, false
	}
	return cred, true
}

// saveWxBotCred 凭证落库（扫码确认后调用；经 SetSettings 事务 UPSERT）。
func saveWxBotCred(cred wxBotCred) error {
	raw, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	return SetSettings(map[string]string{KeyWxBotCred: string(raw)})
}

// WxLinkStatus 连接状态（REST 只读）。
func WxLinkStatus() (bool, string, time.Time) {
	wxLink.mu.Lock()
	defer wxLink.mu.Unlock()
	return wxLink.connected, wxLink.lastErr, wxLink.lastChange
}

// 会话路由态（进程内存）：getupdates 游标 + 各会话最近一次 context_token。
// 进程重启后游标清零（错过期间的私聊不补拉——绑定指令可重发）；
// context_token 缓存清零后需对方再发一条消息恢复主动发送。
var (
	wxCtxMu         sync.Mutex
	wxContextTokens = map[string]string{}
	wxUpdatesBuf    string
	wxPendingQR     string // 进行中的扫码登录二维码令牌
	// wxPendingInbound 最近一条入站私聊（通道向导「发送任意消息捕获
	// receiver」闭环的领取槽）：单 bot 场景全局单槽，领取即清；时间窗外
	// 视为过期不交付。
	wxPendingInbound wxInboundCapture
)

type wxInboundCapture struct {
	Receiver string
	At       time.Time
}

// noteWxInboundCapture 记录最近入站（向导轮询领取用；任意文本均捕获——
// 「绑定 XXX」指令路径同时保留，两形态并存）。
func noteWxInboundCapture(receiver string) {
	wxCtxMu.Lock()
	wxPendingInbound = wxInboundCapture{Receiver: receiver, At: time.Now()}
	wxCtxMu.Unlock()
}

// WxTakePendingReceiver 领取最近入站接收者（maxAge 内有效；领取即清，
// 防重复回填）。无有效捕获返回空串。
func WxTakePendingReceiver(maxAge time.Duration) string {
	wxCtxMu.Lock()
	defer wxCtxMu.Unlock()
	if wxPendingInbound.Receiver == "" || time.Since(wxPendingInbound.At) > maxAge {
		return ""
	}
	r := wxPendingInbound.Receiver
	wxPendingInbound = wxInboundCapture{}
	return r
}

// WxBotLoggedIn 机器人登录态（通道向导分支判据：未登录时管理员需先在
// 凭据页/向导内完成扫码登录）。
func WxBotLoggedIn() bool {
	raw := GetSetting(KeyWxBotCred)
	return raw != ""
}

func cacheWxContextToken(from, token string) {
	wxCtxMu.Lock()
	wxContextTokens[from] = token
	wxCtxMu.Unlock()
}

func wxContextTokenFor(to string) string {
	wxCtxMu.Lock()
	defer wxCtxMu.Unlock()
	return wxContextTokens[to]
}

func wxUIN() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return base64.StdEncoding.EncodeToString([]byte(strconv.FormatUint(uint64(binary.BigEndian.Uint32(b[:])), 10)))
}

// applyWxHeaders 业务 POST 公共头（AuthorizationType/Bearer/X-WECHAT-UIN）。
func applyWxHeaders(req *http.Request, token string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("AuthorizationType", "ilink_bot_token")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-WECHAT-UIN", wxUIN())
}

// wxSender 微信通道适配器。
type wxSender struct{}

func (wxSender) Send(ctx context.Context, targetJSON string, msg Message) error {
	var styled struct {
		ContentTemplate string `json:"content_template"`
	}
	_ = json.Unmarshal([]byte(targetJSON), &styled)
	return SendWxText(ctx, targetJSON, formatBotTextWithTemplate(styled.ContentTemplate, msg, time.Now()))
}

// Test 连接离线时返回明确错误；在线则发测试文本。
func (wxSender) Test(ctx context.Context, targetJSON string) error {
	connected, lastErr, _ := WxLinkStatus()
	if !connected {
		if lastErr != "" {
			return fmt.Errorf("微信机器人连接离线: %s", lastErr)
		}
		return errors.New("微信机器人连接离线（连接任务未运行或登录态未配置）")
	}
	return SendWxText(ctx, targetJSON, formatBotText(testNotificationMessage()))
}

// SendWxText 发微信文本（投递通道适配器调用）。
// target JSON 形如 {"receiver":"wxid/群 id"}；错误全部返回（投递留痕）。
func SendWxText(ctx context.Context, targetJSON, text string) error {
	var cfg struct {
		Receiver string `json:"receiver"`
	}
	if err := json.Unmarshal([]byte(targetJSON), &cfg); err != nil {
		return fmt.Errorf("微信通道目标解析失败: %w", err)
	}
	if cfg.Receiver == "" {
		return errors.New("微信通道目标缺少 receiver（请先在微信内向机器人发送绑定指令完成绑定）")
	}
	cred, ok := loadWxBotCred()
	if !ok {
		return errors.New("微信 Bot 登录态未配置（请先扫码登录）")
	}
	return sendWxMessage(ctx, cred, cfg.Receiver, text, "")
}

// sendWxMessage REST 发送（contextToken 空=查缓存；缺失即 fail-loud——
// iLink 协议要求回传对方入站消息的会话令牌，绝不臆造）。文本超 2000 字符
// 分片发送（每片新 client_id，复用同一 context_token）。
func sendWxMessage(ctx context.Context, cred wxBotCred, toUserID, text, contextToken string) error {
	if contextToken == "" {
		contextToken = wxContextTokenFor(toUserID)
	}
	if contextToken == "" {
		return fmt.Errorf("微信接收方 %s 缺少会话上下文（请先在微信内向机器人发送任意消息以建立会话）", toUserID)
	}
	base := cred.BaseURL
	if base == "" {
		base = wxAPIBaseDefault
	}
	for _, chunk := range splitWxText(text, wxTextChunkLimit) {
		payload, err := json.Marshal(map[string]any{
			"msg": map[string]any{
				"from_user_id":  "",
				"to_user_id":    toUserID,
				"client_id":     wxClientID(),
				"message_type":  2, // BOT
				"message_state": 2, // FINISH（稳定投递形态）
				"context_token": contextToken,
				"item_list": []map[string]any{{
					"type":      1, // TEXT
					"text_item": map[string]any{"text": chunk},
				}},
			},
			"base_info": map[string]any{"channel_version": wxChannelVersion},
		})
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/ilink/bot/sendmessage", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		applyWxHeaders(req, cred.Token)
		resp, err := (&http.Client{Timeout: wxSendTimeout}).Do(req)
		if err != nil {
			return fmt.Errorf("微信发送请求失败: %w", err)
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("微信发送 status=%d body=%s", resp.StatusCode, string(raw))
		}
	}
	return nil
}

// wxClientID 出站消息幂等 ID（时间戳+随机 4 字节 hex，协议未约束格式）。
func wxClientID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("lb-notify-%d-%s", time.Now().UnixMilli(), hexEncode(b[:]))
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0f]
	}
	return string(out)
}

// splitWxText 按上限分片：优先段落/换行/空格边界，均无则硬切。
// 分片不改动原文（不 trim）——通知文本逐字符保全，丢字符=静默截断。
func splitWxText(text string, limit int) []string {
	runes := []rune(text)
	if len(runes) <= limit {
		return []string{text}
	}
	var chunks []string
	for len(runes) > 0 {
		end := limit
		if end > len(runes) {
			end = len(runes)
		}
		if end < len(runes) {
			// 在窗口内回退寻找软边界。
			window := string(runes[:end])
			cut := strings.LastIndex(window, "\n\n")
			if cut < 0 {
				cut = strings.LastIndex(window, "\n")
			}
			if cut < 0 {
				cut = strings.LastIndex(window, " ")
			}
			if cut > 0 {
				end = len([]rune(window[:cut]))
			}
		}
		chunks = append(chunks, string(runes[:end]))
		runes = runes[end:]
	}
	return chunks
}

// RunWxBotConnection 连接主循环（对称 RunQQBotConnection；退避重连）。
// 登录态过期（-14）fail-loud 终止：轮询再无意义，需重新扫码后由任务门重新拉起。
func RunWxBotConnection(ctx context.Context) error { //scope-exempt: daemon-run-body-loop
	// iLink 长轮询出站：wxBotSession（getupdates 挂起 ~35s），断线退避重连。
	if !WxBotConfigured() {
		return fmt.Errorf("微信 Bot 登录态未配置（请先扫码登录）")
	}
	attempt := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		cred, ok := loadWxBotCred()
		if !ok {
			return fmt.Errorf("微信 Bot 登录态未配置（请先扫码登录）")
		}
		started := time.Now()
		err := wxBotSession(ctx, cred)
		if ctx.Err() != nil {
			return nil
		}
		wxLink.set(false, fmt.Sprintf("连接断开: %v", err))
		if strings.Contains(err.Error(), "-14") {
			return fmt.Errorf("微信登录态已过期，需重新扫码: %w", err)
		}
		if time.Since(started) > 5*time.Minute {
			attempt = 0
		}
		attempt++
		log.Printf("WARN: 微信机器人连接断开（第 %d 次，%v 后重连）: %v", attempt, botBackoff(attempt), err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(botBackoff(attempt)):
		}
	}
}

// wxInMsg 入站消息（文本项拼接取绑定指令；context_token 回传缓存）。
type wxInMsg struct {
	FromUserID   string `json:"from_user_id"`
	ContextToken string `json:"context_token"`
	ItemList     []struct {
		Type     int `json:"type"`
		TextItem struct {
			Text string `json:"text"`
		} `json:"text_item"`
	} `json:"item_list"`
}

// wxBotSession 长轮询会话：getupdates 循环（游标进程内存态）→逐条分发。
// ret/errcode 非 0 视为失败；-14=登录态过期（fail-loud 上抛）。
func wxBotSession(ctx context.Context, cred wxBotCred) error {
	base := cred.BaseURL
	if base == "" {
		base = wxAPIBaseDefault
	}
	first := true
	for { //scope-exempt: daemon-run-body-loop（getupdates 长轮询挂起 ~35s，无 ticker）
		if ctx.Err() != nil {
			return nil
		}
		wxCtxMu.Lock()
		buf := wxUpdatesBuf
		wxCtxMu.Unlock()
		payload, err := json.Marshal(map[string]any{
			"get_updates_buf": buf,
			"base_info":       map[string]any{"channel_version": wxChannelVersion},
		})
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/ilink/bot/getupdates", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		applyWxHeaders(req, cred.Token)
		resp, err := (&http.Client{Timeout: wxLongPollTimeout}).Do(req)
		if err != nil {
			return fmt.Errorf("getupdates: %w", err)
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("getupdates status=%d body=%s", resp.StatusCode, string(raw))
		}
		var ur struct {
			Ret           int       `json:"ret"`
			Errcode       int       `json:"errcode"`
			Errmsg        string    `json:"errmsg"`
			Msgs          []wxInMsg `json:"msgs"`
			GetUpdatesBuf string    `json:"get_updates_buf"`
		}
		if json.Unmarshal(raw, &ur) != nil {
			return fmt.Errorf("getupdates 响应解析失败: %.256s", string(raw))
		}
		if ur.Ret != 0 || ur.Errcode != 0 {
			code := ur.Ret
			if code == 0 {
				code = ur.Errcode
			}
			if code == -14 {
				return fmt.Errorf("会话过期（ret=%d errmsg=%s）", ur.Ret, ur.Errmsg)
			}
			return fmt.Errorf("getupdates 业务错误 ret=%d errcode=%d errmsg=%s", ur.Ret, ur.Errcode, ur.Errmsg)
		}
		if ur.GetUpdatesBuf != "" {
			wxCtxMu.Lock()
			wxUpdatesBuf = ur.GetUpdatesBuf
			wxCtxMu.Unlock()
		}
		if first {
			first = false
			wxLink.set(true, "")
		}
		for _, m := range ur.Msgs {
			handleWxInbound(ctx, cred, m)
		}
	}
}

// handleWxInbound 单条入站：缓存 context_token →「绑定 XXX」指令处理
// （回执走被动形态=回传本条 context_token）。
func handleWxInbound(ctx context.Context, cred wxBotCred, m wxInMsg) {
	if m.FromUserID == "" || strings.HasSuffix(m.FromUserID, "@im.bot") {
		return
	}
	if m.ContextToken != "" {
		cacheWxContextToken(m.FromUserID, m.ContextToken)
	}
	// 任意私聊均登记捕获槽（通道向导「发送任意消息自动回填 receiver」；
	// 领取即清——「绑定 XXX」指令形态并存不受影响）。
	noteWxInboundCapture(m.FromUserID)
	var text strings.Builder
	for _, it := range m.ItemList {
		if it.Type == 1 {
			text.WriteString(it.TextItem.Text)
		}
	}
	code := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(text.String()), "绑定"))
	bindBotChannel(code, m.FromUserID, "wx_clawbot", "微信机器人",
		`{"receiver":`+quoteJSON(m.FromUserID)+`}`,
		func(reply string) {
			if err := sendWxMessage(ctx, cred, m.FromUserID, reply, m.ContextToken); err != nil {
				log.Printf("WARN: 微信绑定回复发送失败: %v", err)
			}
		})
}

// WxQRLoginStart 发起扫码登录：返回可直接渲染为二维码的 URL（qrcode_img_content）。
// REST 端点由凭据管理侧包装暴露（本函数只管协议与凭证落库）。
func WxQRLoginStart(ctx context.Context) (qrURL string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/ilink/bot/get_bot_qrcode?bot_type=%d", wxAPIBaseDefault, wxQRBotType), nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Timeout: wxSendTimeout}).Do(req)
	if err != nil {
		return "", fmt.Errorf("获取登录二维码失败: %w", err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("获取登录二维码 status=%d body=%s", resp.StatusCode, string(raw))
	}
	var qr struct {
		Qrcode       string `json:"qrcode"`
		QRImgContent string `json:"qrcode_img_content"`
	}
	if json.Unmarshal(raw, &qr) != nil || qr.Qrcode == "" {
		return "", fmt.Errorf("登录二维码响应解析失败: %.256s", string(raw))
	}
	wxCtxMu.Lock()
	wxPendingQR = qr.Qrcode
	wxCtxMu.Unlock()
	return qr.QRImgContent, nil
}

// WxQRLoginPoll 轮询扫码状态：wait/scaned/confirmed/expired（confirmed 时
// 凭证落库并重置会话态，返回 confirmed=true）。
func WxQRLoginPoll(ctx context.Context) (status string, confirmed bool, err error) {
	wxCtxMu.Lock()
	qr := wxPendingQR
	wxCtxMu.Unlock()
	if qr == "" {
		// 无进行中的扫码（confirmed 后会话态已重置，前端在途轮询会打到
		// 此分支）——返回 idle 而非错误，避免轮询期报错刷屏。
		return "idle", false, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		wxAPIBaseDefault+"/ilink/bot/get_qrcode_status?qrcode="+qr, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("iLink-App-ClientVersion", "1")
	resp, err := (&http.Client{Timeout: wxSendTimeout}).Do(req)
	if err != nil {
		return "", false, fmt.Errorf("扫码状态轮询失败: %w", err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", false, fmt.Errorf("扫码状态轮询 status=%d body=%s", resp.StatusCode, string(raw))
	}
	var pr struct {
		Status   string `json:"status"`
		BotToken string `json:"bot_token"`
		BotID    string `json:"ilink_bot_id"`
		UserID   string `json:"ilink_user_id"`
		BaseURL  string `json:"baseurl"`
	}
	if json.Unmarshal(raw, &pr) != nil || pr.Status == "" {
		return "", false, fmt.Errorf("扫码状态响应解析失败: %.256s", string(raw))
	}
	if pr.Status == "confirmed" {
		if pr.BotToken == "" {
			return pr.Status, false, fmt.Errorf("扫码确认响应缺 bot_token: %.256s", string(raw))
		}
		if err := saveWxBotCred(wxBotCred{Token: pr.BotToken, BaseURL: pr.BaseURL, AccountID: pr.BotID, UserID: pr.UserID}); err != nil {
			return pr.Status, false, err
		}
		wxCtxMu.Lock()
		wxUpdatesBuf = ""
		wxContextTokens = map[string]string{}
		wxPendingQR = ""
		wxCtxMu.Unlock()
		log.Printf("INFO: 微信机器人扫码登录成功（bot=%s）", pr.BotID)
	}
	return pr.Status, pr.Status == "confirmed", nil
}

func init() { RegisterSender("wx_clawbot", wxSender{}) }
