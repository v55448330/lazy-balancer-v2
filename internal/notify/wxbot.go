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
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
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

// 扫码端点 var（测试 mock 覆写；生产=官方 iLink 基址，同 qqbind.go 口径）。
var (
	wxQRCodeURL   = wxAPIBaseDefault + "/ilink/bot/get_bot_qrcode"
	wxQRStatusURL = wxAPIBaseDefault + "/ilink/bot/get_qrcode_status"
)

// wxBotCred 扫码确认后下发的登录态凭证（原样落库 notify_wx_bot_cred）。
type wxBotCred struct {
	Token     string `json:"token"`
	BaseURL   string `json:"baseUrl"`
	AccountID string `json:"accountId"`
	UserID    string `json:"userId"`
}

// wxLinks per-bot 连接态登记表（通知中心页状态点数据源）。
var wxLinks botLinkRegistry

// WxBotConfigured 微信 Bot 登录态凭证已配置。
func WxBotConfigured() bool {
	_, ok := loadWxBotCred()
	return ok
}

// WxAnyBotConfigured 任一 bot 凭据可枚举（全局或通道钉住）——daemon Run 包装
// 门判据：pinned-only 形态（全局未配置、仅通道带凭据）入站亦可启动。
func WxAnyBotConfigured() bool {
	return len(wxEnumerateBots()) > 0
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

// wxCredKey bot 唯一键（account_id 优先，缺省 token）：在线态登记/游标/
// context_token 命名空间/枚举去重均用此键。
func wxCredKey(cred wxBotCred) string {
	if cred.AccountID != "" {
		return cred.AccountID
	}
	return cred.Token
}

// wxEnumerateBots 枚举 distinct bots：全局首 bot + 各通道钉住凭据，按
// account_id/token 去重（全局优先）。序=全局在前、通道按 id 升序（首元素=
// 首 bot，无参在线态兼容锚点）。缺 token/坏 JSON 的 target 跳过。
func wxEnumerateBots() []wxBotCred {
	var bots []wxBotCred
	seen := map[string]bool{}
	add := func(cred wxBotCred) {
		if cred.Token == "" {
			return
		}
		key := wxCredKey(cred)
		if seen[key] {
			return
		}
		seen[key] = true
		bots = append(bots, cred)
	}
	if cred, ok := loadWxBotCred(); ok {
		add(cred)
	}
	// 二登待钉住凭据（wxConfirmedPin）：提前建连破「连接测试↔保存门控」死锁
	// （否则扫码后 supervisor 不建连，微信客户端报网络错误）。
	wxCtxMu.Lock()
	pin := wxConfirmedPin
	wxCtxMu.Unlock()
	if pin != nil {
		add(*pin)
	}
	if db.DB != nil {
		rows, err := db.DB.Query(`SELECT target FROM notification_channels WHERE type='wx_clawbot' ORDER BY id`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var target string
				if rows.Scan(&target) != nil {
					continue
				}
				var cfg struct {
					Token     string `json:"token"`
					BaseURL   string `json:"baseurl"`
					AccountID string `json:"account_id"`
					UserID    string `json:"user_id"`
				}
				if json.Unmarshal([]byte(target), &cfg) == nil {
					add(wxBotCred{Token: cfg.Token, BaseURL: cfg.BaseURL, AccountID: cfg.AccountID, UserID: cfg.UserID})
				}
			}
		}
	}
	return bots
}

// wxWakeCh 凭据/钉住变更唤醒信号（WxPinChannelTarget 钉住成功/
// WxQRLoginPoll 扫码确认后投递；非阻塞，循环未运行时弃置——下轮对账自然读新凭据）。
var wxWakeCh = make(chan struct{}, 1)

func wakeWxBotConnection() {
	select {
	case wxWakeCh <- struct{}{}:
	default:
	}
}

// WxPinChannelTarget 通道 target 钉住登录凭据（多机器人出站鉴权源，对称
// QQ）：已带 token 原样返回；否则优先最近一次扫码确认的新凭据（全局已配
// 时二登不落全局，凭据在此待钉），回退全局登录态；均无原样返回（发送侧
// fail-loud）。target 键：token/baseurl/account_id/user_id。
func WxPinChannelTarget(targetJSON string) string {
	var m map[string]any
	if json.Unmarshal([]byte(targetJSON), &m) != nil {
		return targetJSON
	}
	if t, _ := m["token"].(string); t != "" {
		return targetJSON
	}
	wxCtxMu.Lock()
	var pending *wxBotCred
	if wxConfirmedPin != nil {
		c := *wxConfirmedPin
		pending = &c
		// 钉住即消费：清除本次扫码凭据，防止下一个新通道弹框再自动回填
		// 上一次扫码者的旧 id（用户实测"多次填旧 id"脏状态根因）。
		wxConfirmedPin = nil
	}
	wxCtxMu.Unlock()
	cred, ok := loadWxBotCred()
	if pending != nil {
		cred, ok = *pending, true
	}
	if !ok {
		return targetJSON
	}
	m["token"], m["baseurl"], m["account_id"], m["user_id"] = cred.Token, cred.BaseURL, cred.AccountID, cred.UserID
	b, err := json.Marshal(m)
	if err != nil {
		return targetJSON
	}
	wakeWxBotConnection() // 钉住成功唤醒连接任务：新 bot 入站会话不等对账周期上线
	return string(b)
}

// WxLinkStatus 连接状态（REST 只读）=首 bot（全局凭据 bot，单 bot 时代兼容
// 口径）；多机器人按 bot 查询用 WxLinkStatusFor。
func WxLinkStatus() (bool, string, time.Time) {
	return wxLinks.status("")
}

// WxLinkStatusFor 查指定 bot（account_id/token 键）入站会话在线态；空=首 bot；
// 未登记 bot=离线。
func WxLinkStatusFor(botID string) (bool, string, time.Time) {
	return wxLinks.status(botID)
}

// wxTargetBotKey 解析 target 所属 bot 键（钉住优先/全局回退；空=首 bot）。
// Send/Test 闸门按 target 查对应 bot 的入站在线态（各 bot 会话独立）。
func wxTargetBotKey(targetJSON string) string {
	var cfg struct {
		Token     string `json:"token"`
		AccountID string `json:"account_id"`
		UserID    string `json:"user_id"`
	}
	_ = json.Unmarshal([]byte(targetJSON), &cfg)
	if cfg.Token == "" {
		cred, ok := loadWxBotCred()
		if !ok {
			return ""
		}
		return wxCredKey(cred)
	}
	return wxCredKey(wxBotCred{Token: cfg.Token, AccountID: cfg.AccountID, UserID: cfg.UserID})
}

// 会话路由态（进程内存，per-bot 隔离）：getupdates 游标 + 各会话最近一次 context_token。
// 进程重启后游标清零（错过期间的私聊不补拉——绑定指令可重发）；
// context_token 缓存清零后需对方再发一条消息恢复主动发送。
var (
	wxCtxMu sync.Mutex
	// wxContextTokens botKey → from → context_token；wxUpdatesBufs botKey → getupdates 游标。
	// 多 bot 入站会话互不共用游标/会话令牌（二登不重置首 bot）。
	wxContextTokens = map[string]map[string]string{}
	wxUpdatesBufs   = map[string]string{}
	wxPendingQR     string // 进行中的扫码登录二维码令牌
	// wxConfirmedPin 最近一次扫码确认的新凭据（全局已配置时二登不落全局，
	// 凭据在此待通道保存钉住；首登落全局时清空）。wxCtxMu 守护。
	wxConfirmedPin *wxBotCred
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

// WxQRLoginActive 是否有进行中的扫码会话（wxPendingQR 非空）。bind-state 据此
// 把入站捕获回填限定在"无进行中扫码"（已登录 bot 追加通道），防扫码期间旧 bot
// 入站消息泄漏旧 wxid。
func WxQRLoginActive() bool {
	wxCtxMu.Lock()
	defer wxCtxMu.Unlock()
	return wxPendingQR != ""
}

// WxDefaultReceiver 仅取「本次扫码确认」凭据的扫码者 wxid（wxConfirmedPin）。
// 未扫码/无本次确认返回空——不得回退全局首 bot，否则新建通道未扫码即被填旧
// bot 接收者，保存后凭据/接收者错配致测试失败（用户实测根因）。入站捕获仍可覆盖。
func WxDefaultReceiver() string {
	wxCtxMu.Lock()
	pin := wxConfirmedPin
	wxCtxMu.Unlock()
	if pin != nil && pin.UserID != "" {
		return pin.UserID
	}
	return ""
}

// wxContextKeyPrefix 会话上下文持久化键前缀（复用 notify_settings KV，与
// wx_bot_cred 同表，无新表）；命名空间 per-bot per-receiver 隔离（多通道共存）。
const wxContextKeyPrefix = "notify.wx_ctx:"

func wxContextKey(botKey, receiver string) string {
	return wxContextKeyPrefix + botKey + ":" + receiver
}

func cacheWxContextToken(botKey, from, token string) {
	wxCtxMu.Lock()
	m := wxContextTokens[botKey]
	if m == nil {
		m = map[string]string{}
		wxContextTokens[botKey] = m
	}
	m[from] = token
	wxCtxMu.Unlock()
	// 持久化复用 notify_settings KV（值经 SetSettings 静态加密），扛面板重启。
	// 微信侧会话本身仍可能过期，过期须对方再发消息刷新（协议约束）。
	_ = SetSettings(map[string]string{wxContextKey(botKey, from): token + wxContextSep + strconv.FormatInt(time.Now().Unix(), 10)})
}

func wxContextTokenFor(botKey, to string) string {
	wxCtxMu.Lock()
	tok := wxContextTokens[botKey][to]
	wxCtxMu.Unlock()
	if tok != "" {
		return tok
	}
	// 内存未命中（如重启后）→ 读持久化 KV（GetSetting 自动解密）回填内存。
	persisted := GetSetting(wxContextKey(botKey, to))
	token := wxContextDecodeToken(persisted)
	if token == "" {
		return ""
	}
	wxCtxMu.Lock()
	m := wxContextTokens[botKey]
	if m == nil {
		m = map[string]string{}
		wxContextTokens[botKey] = m
	}
	m[to] = token
	wxCtxMu.Unlock()
	return token
}

// wxContextSep 持久化值分隔符：token\x1f<unixsec>（嵌入更新时间供 TTL 清理；
// KV 无 per-row 时间戳，复用 notify_settings 的代价以此弥补）。
const wxContextSep = "\x1f"

func wxContextDecodeToken(stored string) string {
	if stored == "" {
		return ""
	}
	return strings.SplitN(stored, wxContextSep, 2)[0]
}

func wxContextDecodeTime(stored string) int64 {
	parts := strings.SplitN(stored, wxContextSep, 2)
	if len(parts) < 2 {
		return 0 // 遗留无时间戳值视为最旧（清理后对方再发消息即重建）
	}
	ts, _ := strconv.ParseInt(parts[1], 10, 64)
	return ts
}

// PruneWxContextTokens 清理超过 maxAge 未刷新的会话上下文 KV（防 notify_settings
// 无界增长）。context_token 服务端早已过期，清掉仅意味着对方需再发一条消息重建
// （协议本就要求周期性互动）。挂投递保留任务周期执行。
func PruneWxContextTokens(maxAge time.Duration) (int, error) {
	if db.DB == nil {
		return 0, nil
	}
	rows, err := db.DB.Query(`SELECT key FROM notify_settings WHERE key LIKE ?`, wxContextKeyPrefix+"%")
	if err != nil {
		return 0, err
	}
	var keys []string
	for rows.Next() {
		var k string
		if rows.Scan(&k) == nil {
			keys = append(keys, k)
		}
	}
	rows.Close()
	cutoff := time.Now().Add(-maxAge).Unix()
	deleted := 0
	for _, k := range keys {
		if wxContextDecodeTime(GetSetting(k)) < cutoff {
			if _, err := db.DB.Exec(`DELETE FROM notify_settings WHERE key=?`, k); err == nil {
				deleted++
			}
		}
	}
	return deleted, nil
}

// WxSessionReady 微信通道接收者是否已有会话上下文（context_token）=可主动发送。
// 供通道卡「会话就绪/待建立」指示与保存/测试前预警（连接在线≠会话就绪）。
func WxSessionReady(targetJSON string) bool {
	var cfg struct {
		Receiver string `json:"receiver"`
	}
	_ = json.Unmarshal([]byte(targetJSON), &cfg)
	if cfg.Receiver == "" {
		return false
	}
	key := wxTargetBotKey(targetJSON)
	if key == "" {
		return false
	}
	return wxContextTokenFor(key, cfg.Receiver) != ""
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
	// 任务即服务（用户裁定，同 QQ）：出站闸门=引擎真实运行态（IsRunning），
	// 停止常驻任务=无法处理发送。iLink 仅文本，无 markdown 形态。
	connected, lastErr, _ := WxLinkStatusFor(wxTargetBotKey(targetJSON))
	if !botServiceRunning("wx-bot-connection", connected) {
		if lastErr != "" {
			return fmt.Errorf("微信机器人服务未运行: %s", lastErr)
		}
		return errors.New("微信机器人服务未运行（连接任务已停止或登录态未配置）")
	}
	var styled struct {
		ContentTemplate string `json:"content_template"`
	}
	_ = json.Unmarshal([]byte(targetJSON), &styled)
	return SendWxText(ctx, targetJSON, formatBotTextWithTemplate(styled.ContentTemplate, msg, time.Now()))
}

// Test 所属 bot 连接离线时返回明确错误；在线则发测试文本。
func (wxSender) Test(ctx context.Context, targetJSON string) error {
	connected, lastErr, _ := WxLinkStatusFor(wxTargetBotKey(targetJSON))
	if !botServiceRunning("wx-bot-connection", connected) {
		if lastErr != "" {
			return fmt.Errorf("微信机器人连接离线: %s", lastErr)
		}
		return errors.New("微信机器人连接离线（连接任务未运行或登录态未配置）")
	}
	return SendWxText(ctx, targetJSON, formatBotText(testNotificationMessage()))
}

// SendWxText 发微信文本（投递通道适配器调用）。
// target JSON 形如 {"receiver":"wxid/群 id","token":"...","baseurl":"...",
// "account_id":"...","user_id":"..."}（凭据为绑定/保存时钉住的 bot 登录态，
// 缺省回退全局）；错误全部返回（投递留痕）。
func SendWxText(ctx context.Context, targetJSON, text string) error {
	var cfg struct {
		Receiver  string `json:"receiver"`
		Token     string `json:"token"`
		BaseURL   string `json:"baseurl"`
		AccountID string `json:"account_id"`
		UserID    string `json:"user_id"`
	}
	if err := json.Unmarshal([]byte(targetJSON), &cfg); err != nil {
		return fmt.Errorf("微信通道目标解析失败: %w", err)
	}
	if cfg.Receiver == "" {
		return errors.New("微信通道目标缺少 receiver（请先在微信内向机器人发送绑定指令完成绑定）")
	}
	cred := wxBotCred{Token: cfg.Token, BaseURL: cfg.BaseURL, AccountID: cfg.AccountID, UserID: cfg.UserID}
	if cred.Token == "" {
		var ok bool
		cred, ok = loadWxBotCred()
		if !ok {
			return errors.New("微信 Bot 登录态未配置（请先扫码登录）")
		}
	}
	return sendWxMessage(ctx, cred, cfg.Receiver, text, "")
}

// sendWxMessage REST 发送（contextToken 空=查缓存；缺失即 fail-loud——
// iLink 协议要求回传对方入站消息的会话令牌，绝不臆造）。文本超 2000 字符
// 分片发送（每片新 client_id，复用同一 context_token）。
func sendWxMessage(ctx context.Context, cred wxBotCred, toUserID, text, contextToken string) error {
	if contextToken == "" {
		contextToken = wxContextTokenFor(wxCredKey(cred), toUserID)
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
		// 解析业务错误码：HTTP 200 仍可能 ret/errcode 非 0（如 context_token
		// 过期/会话失效）。只查 HTTP 状态会误报成功（用户实测"提示成功但未收到"
		// 根因），与 getupdates 同口径 fail-loud。
		var sr struct {
			Ret     int    `json:"ret"`
			Errcode int    `json:"errcode"`
			Errmsg  string `json:"errmsg"`
		}
		if json.Unmarshal(raw, &sr) != nil {
			return fmt.Errorf("微信发送响应解析失败: %.256s", string(raw))
		}
		if sr.Ret != 0 || sr.Errcode != 0 {
			code := sr.Ret
			if code == 0 {
				code = sr.Errcode
			}
			if code == -14 {
				return fmt.Errorf("%w（发送 ret=%d errmsg=%s，请对方再发一条消息刷新会话）", errWxSessionExpired, sr.Ret, sr.Errmsg)
			}
			return fmt.Errorf("微信发送业务错误 ret=%d errcode=%d errmsg=%s", sr.Ret, sr.Errcode, sr.Errmsg)
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

// errWxSessionExpired 登录态过期（-14）哨兵错误：worker 据此终止该 bot 长轮询
// （fail-loud 留痕），其它 bot 不受影响；重新扫码凭据变更后由 supervisor 重建。
var errWxSessionExpired = errors.New("微信登录态已过期")

// wxBotWorker 单 bot 入站会话句柄（supervisor 独占 cancel/done；fatal=登录
// 过期终止标记，仅 worker 退出前写、done 收口后读）。
type wxBotWorker struct {
	cred   wxBotCred
	cancel context.CancelFunc
	done   chan struct{}
	fatal  bool
}

// RunWxBotConnection 连接 supervisor（对称 RunQQBotConnection）：枚举 distinct
// bots（全局+通道钉住），每 bot 一个独立长轮询会话 goroutine（WaitGroup 同步
// 收口，ctx 取消全停），per-bot 游标/在线态/日志（bot=account）与退避重连。
// 登录态过期（-14）仅终止该 bot（fail-loud 留痕），其它 bot 不受影响；
// 凭据/钉住变更（wxWakeCh）立即对账，新 bot 上线不等周期。
func RunWxBotConnection(ctx context.Context) error { //scope-exempt: daemon-run-body-loop
	ctx = withTaskID(ctx, "wx-bot-connection")
	// 清洁停止置离线（同 QQ 根因）：防 per-bot 态残留假在线污染 Send/Test 门。
	defer wxLinks.stopAll("连接任务已停止")
	bots := wxEnumerateBots()
	if len(bots) == 0 {
		return fmt.Errorf("微信 Bot 登录态未配置（请先扫码登录）")
	}
	var wg sync.WaitGroup
	defer wg.Wait() // Run 同步等待全部 bot 会话 goroutine 收口（引擎形态②子协程）
	workers := map[string]*wxBotWorker{}
	reconcile := func() {
		bots := wxEnumerateBots()
		desired := map[string]wxBotCred{}
		for _, b := range bots {
			desired[wxCredKey(b)] = b
		}
		// 回收：不再枚举到的 bot / 凭据变更（取消+等待收口+注销登记）。
		for key, w := range workers {
			b, ok := desired[key]
			if ok && b == w.cred {
				select {
				case <-w.done:
					if w.fatal {
						continue // 登录过期：不自动重建，等重新扫码凭据变更
					}
				default:
					continue // 运行中
				}
			}
			w.cancel()
			<-w.done
			wxLinks.unregister(key)
			delete(workers, key)
			if ok {
				taskLogf(ctx, "connect", "微信机器人凭据更新（bot=%s），重建入站会话", key)
			} else {
				taskLogf(ctx, "connect", "微信机器人移除（bot=%s），关闭入站会话", key)
			}
		}
		// 新增 bot：独立长轮询会话 goroutine（游标/在线态 per-bot 隔离）。
		for _, b := range bots {
			key := wxCredKey(b)
			if _, ok := workers[key]; ok {
				continue
			}
			wctx, cancel := context.WithCancel(ctx)
			w := &wxBotWorker{cred: b, cancel: cancel, done: make(chan struct{})}
			workers[key] = w
			link := wxLinks.register(key)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer close(w.done)
				w.fatal = wxBotWorkerRun(wctx, b, link)
			}()
			taskLogf(ctx, "connect", "微信机器人入站会话启动（bot=%s，开始长轮询）", key)
		}
		if len(bots) > 0 {
			wxLinks.setFirst(wxCredKey(bots[0]))
		}
	}
	reconcile()
	ids := make([]string, 0, len(bots))
	for _, b := range bots {
		ids = append(ids, wxCredKey(b))
	}
	taskLogf(ctx, "connect", "微信机器人连接任务启动（%d 个 bot：%s）", len(bots), strings.Join(ids, ", "))
	for {
		select {
		case <-ctx.Done():
			for _, w := range workers {
				w.cancel()
			}
			return nil
		case <-wxWakeCh:
			reconcile()
		case <-time.After(botReconcileInterval):
			reconcile()
		}
	}
}

// wxBotWorkerRun 单 bot 长轮询会话循环：getupdates（挂起 ~35s）→断线退避重连。
// 登录态过期（-14）返回 fatal=true 终止该 bot（其它 bot 不受影响），supervisor
// 待重新扫码凭据变更重建；其它错误 per-bot 隔离退避重连。
func wxBotWorkerRun(ctx context.Context, cred wxBotCred, link *botLinkState) (fatal bool) {
	// 退出不置离线：计划内回收由 supervisor unregister 收口（无虚假掉线告警），
	// 清洁停止由 stopAll 统一置离线；fatal 分支自行置离线并保留「登录态过期」原因。
	key := wxCredKey(cred)
	attempt := 0
	for {
		if ctx.Err() != nil {
			return false
		}
		started := time.Now()
		err := wxBotSession(ctx, cred, link)
		if ctx.Err() != nil {
			return false
		}
		if errors.Is(err, errWxSessionExpired) {
			link.set(false, fmt.Sprintf("bot=%s 登录态过期，需重新扫码", key))
			taskLogWarn(ctx, "connect", "微信机器人登录态过期（bot=%s），停止该 bot 长轮询（其它 bot 不受影响），需重新扫码: %v", key, err)
			return true
		}
		link.set(false, fmt.Sprintf("bot=%s 连接断开: %v", key, err))
		if time.Since(started) > 5*time.Minute {
			attempt = 0
		}
		attempt++
		taskLogWarn(ctx, "connect", "微信机器人连接断开（bot=%s 第 %d 次，%v 后重连）: %v", key, attempt, botBackoff(attempt), err)
		select {
		case <-ctx.Done():
			return false
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

// wxBotSession 长轮询会话：getupdates 循环（游标 per-bot 进程内存态）→逐条分发。
// ret/errcode 非 0 视为失败；-14=登录态过期（errWxSessionExpired fail-loud 上抛）。
// cred/link=会话所属 bot 的凭据与连接态（per-bot 隔离）。
func wxBotSession(ctx context.Context, cred wxBotCred, link *botLinkState) error {
	key := wxCredKey(cred)
	base := cred.BaseURL
	if base == "" {
		base = wxAPIBaseDefault
	}
	// 扫码已验证凭据，会话启动即视为在线（连接测试快速通过，不等首批 getupdates
	// 长轮询 ~35s 才置在线——QQ WebSocket READY 即时而 wx 慢的根因）；若首批
	// getupdates 返回 -14/错误再由 worker 置离线。
	link.set(true, "")
	first := true
	for { //scope-exempt: daemon-run-body-loop（getupdates 长轮询挂起 ~35s，无 ticker）
		if ctx.Err() != nil {
			return nil
		}
		wxCtxMu.Lock()
		buf := wxUpdatesBufs[key]
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
				return fmt.Errorf("%w（ret=%d errmsg=%s）", errWxSessionExpired, ur.Ret, ur.Errmsg)
			}
			return fmt.Errorf("getupdates 业务错误 ret=%d errcode=%d errmsg=%s", ur.Ret, ur.Errcode, ur.Errmsg)
		}
		if ur.GetUpdatesBuf != "" {
			wxCtxMu.Lock()
			wxUpdatesBufs[key] = ur.GetUpdatesBuf
			wxCtxMu.Unlock()
		}
		if first {
			first = false
			link.set(true, "")
			taskLogf(ctx, "connect", "微信机器人长轮询建立（bot=%s 首批 getupdates 成功，在线）", key)
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
		cacheWxContextToken(wxCredKey(cred), m.FromUserID, m.ContextToken)
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
	// 弹框绑定会话：「绑定测试」匹配活跃会话→confirmed+品牌确认回复（不自动建
	// 通道，建通道交弹框保存）。无活跃会话则落回旧「绑定 <验证码>」指令。
	if IsBindTestMessage(text.String()) {
		if ConfirmBindSessionByInbound("wx_clawbot", m.FromUserID, cred.AccountID, m.FromUserID, m.ContextToken) {
			if err := sendWxMessage(ctx, cred, m.FromUserID, BindConfirmReply(), m.ContextToken); err != nil {
				taskLogWarn(ctx, "bind", "微信绑定确认回复发送失败（bot=%s）: %v", wxCredKey(cred), err)
			}
			return
		}
	}
	code := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(text.String()), "绑定"))
	// 入站长轮询属会话所属 bot——通道 target 钉住该 bot 凭据（多机器人出站鉴权源）。
	target, _ := json.Marshal(map[string]any{
		"receiver": m.FromUserID, "token": cred.Token, "baseurl": cred.BaseURL,
		"account_id": cred.AccountID, "user_id": cred.UserID,
	})
	bindBotChannel(code, m.FromUserID, "wx_clawbot", "微信机器人", string(target),
		func(reply string) {
			if err := sendWxMessage(ctx, cred, m.FromUserID, reply, m.ContextToken); err != nil {
				taskLogWarn(ctx, "bind", "微信绑定回复发送失败（bot=%s）: %v", wxCredKey(cred), err)
			}
		})
}

// WxQRLoginStart 发起扫码登录：返回可直接渲染为二维码的 URL（qrcode_img_content）。
// REST 端点由凭据管理侧包装暴露（本函数只管协议与凭证落库）。
func WxQRLoginStart(ctx context.Context) (qrURL string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s?bot_type=%d", wxQRCodeURL, wxQRBotType), nil)
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
	// 新扫码会话丢弃旧凭据 pin 与旧入站捕获：防新通道未扫码即回填上一个
	// 会话/旧 bot 的接收者（用户实测"未扫码跳 wxid"根因）。
	wxConfirmedPin = nil
	wxPendingInbound = wxInboundCapture{}
	wxCtxMu.Unlock()
	return qr.QRImgContent, nil
}

// WxQRLoginPoll 轮询扫码状态：wait/scaned/confirmed/expired。confirmed 时
// 首登凭证落全局并重置会话态；全局已配置（二登）不覆盖——首 bot 入站会话
// 不受影响，新凭据待通道保存钉住（WxPinChannelTarget 钉住成功唤醒连接任务，
// 第二 bot 入站自动上线）。返回 confirmed=true。
func WxQRLoginPoll(ctx context.Context) (status string, confirmed bool, err error) {
	wxCtxMu.Lock()
	qr := wxPendingQR
	wxCtxMu.Unlock()
	if qr == "" {
		// 无进行中的扫码（confirmed 后 wxPendingQR 已清，前端在途轮询会打到
		// 此分支）——返回 idle 而非错误，避免轮询期报错刷屏。
		return "idle", false, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		wxQRStatusURL+"?qrcode="+qr, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("iLink-App-ClientVersion", "1")
	resp, err := (&http.Client{Timeout: wxLongPollTimeout}).Do(req)
	if err != nil {
		// get_qrcode_status 为长轮询（服务端挂起 ~35s）。客户端本地超时按协议
		// 等价 wait 继续轮询，而非错误——旧 10s 短超时必超时→502 刷屏、扫码
		// 确认无法检出（用户实测客户端网络错误/弹框久卡根因）。
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return "wait", false, nil
		}
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
		cred := wxBotCred{Token: pr.BotToken, BaseURL: pr.BaseURL, AccountID: pr.BotID, UserID: pr.UserID}
		if _, ok := loadWxBotCred(); !ok {
			// 首登：落全局（首 bot 入站鉴权源）并重置会话态。
			if err := saveWxBotCred(cred); err != nil {
				return pr.Status, false, err
			}
			wxCtxMu.Lock()
			wxUpdatesBufs = map[string]string{}
			wxContextTokens = map[string]map[string]string{}
			wxConfirmedPin = &cred // 首登亦置 pin：本次扫码者 wxid 供自动回填（保存时消费）
			wxPendingQR = ""
			wxCtxMu.Unlock()
		} else {
			// 二登：不覆盖全局（覆盖=首 bot 长轮询掉线根因），不清首 bot
			// 会话态；新凭据待通道保存钉住。
			wxCtxMu.Lock()
			wxConfirmedPin = &cred
			wxPendingQR = ""
			wxCtxMu.Unlock()
		}
		wakeWxBotConnection()
		taskLogf(ctx, "bind", "微信机器人扫码登录成功（bot=%s）", pr.BotID)
	}
	return pr.Status, pr.Status == "confirmed", nil
}

func init() { RegisterSender("wx_clawbot", wxSender{}) }
