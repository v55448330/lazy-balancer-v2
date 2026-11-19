package notify

// 绑定会话状态机（弹框引导统一流程：扫码→连接测试→待发送「绑定测试」→已确认
// →允许保存）。per-user 内存态，重启作废重新扫码。入站「绑定测试」匹配扫码者
// →confirmed+品牌确认回复；保存门控由弹框据 phase 决定（confirmed 前禁保存）。
// 与旧「绑定 <验证码>」自动建通道指令并存（无活跃会话时旧指令仍生效）。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// BindTestKeyword 绑定确认指令（用户在微信/QQ 内向机器人发送此文本完成绑定）。
const BindTestKeyword = "绑定测试"

// BindSession 一次弹框绑定会话。
type BindSession struct {
	UserID       int64
	Type         string // qq / wx_clawbot
	ScannerID    string // openid / wxid（扫码者）
	BotKey       string // appid / wx account_id
	Phase        string // awaiting_message / confirmed
	Receiver     string // 确认后捕获的接收者
	ContextToken string // wx 会话上下文
	UpdatedAt    time.Time
}

var (
	bindSessionMu sync.Mutex
	bindSessions  = map[string]*BindSession{} // key = type|scannerID|botKey
)

func bindSessionKey(typ, scannerID, botKey string) string {
	return typ + "|" + scannerID + "|" + botKey
}

// StartBindSession 弹框扫码确认后注册会话（待发送「绑定测试」）。
func StartBindSession(userID int64, typ, scannerID, botKey string) {
	if scannerID == "" {
		return
	}
	bindSessionMu.Lock()
	defer bindSessionMu.Unlock()
	bindSessions[bindSessionKey(typ, scannerID, botKey)] = &BindSession{
		UserID: userID, Type: typ, ScannerID: scannerID, BotKey: botKey,
		Phase: "awaiting_message", UpdatedAt: time.Now(),
	}
}

// PollBindSession 弹框轮询会话 phase（无会话=idle）。
func PollBindSession(typ, scannerID, botKey string) (phase, receiver string) {
	bindSessionMu.Lock()
	defer bindSessionMu.Unlock()
	s := bindSessions[bindSessionKey(typ, scannerID, botKey)]
	if s == nil {
		return "idle", ""
	}
	return s.Phase, s.Receiver
}

// BindSessionConnected 绑定会话对应 bot 的入站连接态（连接测试判据：API 正确、
// 系统能连上机器人）。
func BindSessionConnected(typ, botKey string) bool {
	switch typ {
	case "qq":
		c, _, _ := QQLinkStatusFor(botKey)
		return c
	case "wx_clawbot":
		c, _, _ := WxLinkStatusFor(botKey)
		return c
	}
	return false
}

// ConfirmBindSessionByInbound 入站「绑定测试」匹配活跃会话→confirmed（捕获
// receiver/context）。返回是否匹配——匹配则调用方回品牌确认文案。已确认会话
// 不重复回复（幂等）。
func ConfirmBindSessionByInbound(typ, scannerID, botKey, receiver, contextToken string) bool {
	bindSessionMu.Lock()
	defer bindSessionMu.Unlock()
	s := bindSessions[bindSessionKey(typ, scannerID, botKey)]
	if s == nil || s.Phase == "confirmed" {
		return false
	}
	s.Phase = "confirmed"
	s.Receiver = receiver
	s.ContextToken = contextToken
	s.UpdatedAt = time.Now()
	return true
}

// IsBindTestMessage 入站文本是否为绑定确认指令（去空白后精确匹配）。
func IsBindTestMessage(text string) bool {
	return strings.TrimSpace(text) == BindTestKeyword
}

// BindConfirmReply 品牌绑定成功文案（app_name 取自 branding.json，缺省 Lazy Balancer）。
func BindConfirmReply() string {
	return "【" + brandAppName() + "】绑定成功！已绑定通知机器人，将为您推送相关通知。"
}

// brandAppName 读 branding.json app_name（notify 不依赖 handlers/services，避免
// 循环；自读 data 目录品牌文件，字段缺失/坏 JSON 回退默认）。
func brandAppName() string {
	const fallback = "Lazy Balancer"
	d := db.DataDir()
	if d == "" {
		return fallback
	}
	raw, err := os.ReadFile(filepath.Join(d, "branding.json"))
	if err != nil {
		return fallback
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return fallback
	}
	if v, ok := m["app_name"]; ok {
		var s string
		if json.Unmarshal(v, &s) == nil && s != "" {
			return s
		}
	}
	return fallback
}

// WxScanIdentity 最近扫码确认凭据的扫码者 wxid 与 bot account_id（弹框注册会话
// 用）。首登/二登均置 pin（见 WxQRLoginPoll），无 pin 回退全局首 bot。
func WxScanIdentity() (scannerID, botKey string) {
	wxCtxMu.Lock()
	pin := wxConfirmedPin
	wxCtxMu.Unlock()
	if pin != nil {
		return pin.UserID, pin.AccountID
	}
	if cred, ok := loadWxBotCred(); ok {
		return cred.UserID, cred.AccountID
	}
	return "", ""
}
