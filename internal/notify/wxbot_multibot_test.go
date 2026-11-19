package notify

// 微信多机器人凭据回归（对称 QQ 根因）：①第二次扫码登录不覆盖全局登录态
// （入站长轮询仍首 bot），新凭据经通道 target 钉住；②出站用 target 的
// token/baseurl，存量 target 无凭据回退全局；③「绑定」指令建通道钉住会话凭据。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// wxMockILink mock iLink sendmessage（记录出站 Authorization）。
type wxMockILink struct {
	mu     sync.Mutex
	auths  []string
	server *httptest.Server
}

func setupWxSendMock(t *testing.T) *wxMockILink {
	t.Helper()
	m := &wxMockILink{}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ilink/bot/sendmessage" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		m.mu.Lock()
		m.auths = append(m.auths, r.Header.Get("Authorization"))
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ret":0}`))
	}))
	t.Cleanup(m.server.Close)
	return m
}

func seedWxGlobalCred(t *testing.T, token, baseURL string) {
	t.Helper()
	raw, _ := json.Marshal(wxBotCred{Token: token, BaseURL: baseURL, AccountID: "AG", UserID: "UG"})
	if err := SetSettings(map[string]string{KeyWxBotCred: string(raw)}); err != nil {
		t.Fatalf("写入全局登录态失败: %v", err)
	}
	t.Cleanup(func() { _ = SetSettings(map[string]string{KeyWxBotCred: ""}) })
}

// 出站凭据钉住：target 带 token/baseurl 用第二 bot；存量无凭据回退全局。
func TestWxSendUsesTargetPinnedCredentials(t *testing.T) {
	newNotifyConnectorDB(t)
	m := setupWxSendMock(t)
	seedWxGlobalCred(t, "T_GLOBAL", m.server.URL)
	cacheWxContextToken("B2", "r1", "ctx-1")
	cacheWxContextToken("AG", "r2", "ctx-2")
	ctx := context.Background()
	// When 第二 bot target 出站
	if err := SendWxText(ctx, `{"receiver":"r1","token":"T_B","baseurl":"`+m.server.URL+`","account_id":"B2","user_id":"U2"}`, "hi"); err != nil {
		t.Fatalf("target 凭据出站失败: %v", err)
	}
	// When 存量 target（无凭据）出站
	if err := SendWxText(ctx, `{"receiver":"r2"}`, "hi"); err != nil {
		t.Fatalf("存量回退出站失败: %v", err)
	}
	// Then 依次用第二 bot / 全局 bot 的 token
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.auths) != 2 || m.auths[0] != "Bearer T_B" || m.auths[1] != "Bearer T_GLOBAL" {
		t.Errorf("出站 Authorization=%v, want [Bearer T_B Bearer T_GLOBAL]", m.auths)
	}
}

// 第二次扫码登录：全局登录态不被覆盖、首 bot 会话态（游标/context_token）
// 不被清空；新凭据经 WxPinChannelTarget 钉入通道 target。
func TestWxQRSecondLoginKeepsGlobal(t *testing.T) {
	newNotifyConnectorDB(t)
	var qrN int
	qrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ilink/bot/get_bot_qrcode":
			qrN++
			fmt.Fprintf(w, `{"qrcode":"QR%d","qrcode_img_content":"img"}`, qrN)
		case "/ilink/bot/get_qrcode_status":
			switch r.URL.Query().Get("qrcode") {
			case "QR1":
				_, _ = w.Write([]byte(`{"status":"confirmed","bot_token":"T1","ilink_bot_id":"B1","ilink_user_id":"U1","baseurl":"http://first"}`))
			case "QR2":
				_, _ = w.Write([]byte(`{"status":"confirmed","bot_token":"T2","ilink_bot_id":"B2","ilink_user_id":"U2","baseurl":"http://second"}`))
			default:
				_, _ = w.Write([]byte(`{"status":"wait"}`))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	oldCode, oldStatus := wxQRCodeURL, wxQRStatusURL
	wxQRCodeURL, wxQRStatusURL = qrSrv.URL+"/ilink/bot/get_bot_qrcode", qrSrv.URL+"/ilink/bot/get_qrcode_status"
	t.Cleanup(func() {
		wxQRCodeURL, wxQRStatusURL = oldCode, oldStatus
		qrSrv.Close()
		wxCtxMu.Lock()
		wxPendingQR = ""
		wxConfirmedPin = nil
		wxContextTokens = map[string]map[string]string{}
		wxUpdatesBufs = map[string]string{}
		wxPendingInbound = wxInboundCapture{}
		wxCtxMu.Unlock()
	})
	ctx := context.Background()

	// Given 首 bot 扫码登录 → 落全局
	if _, err := WxQRLoginStart(ctx); err != nil {
		t.Fatalf("首次产码失败: %v", err)
	}
	if _, confirmed, err := WxQRLoginPoll(ctx); err != nil || !confirmed {
		t.Fatalf("首次登录未确认: confirmed=%v err=%v", confirmed, err)
	}
	if cred, ok := loadWxBotCred(); !ok || cred.Token != "T1" {
		t.Fatalf("首登全局=%+v ok=%v, want T1", cred, ok)
	}
	// 首 bot 已建立的会话态
	cacheWxContextToken("B1", "r1", "ctx-1")
	wxCtxMu.Lock()
	wxUpdatesBufs["B1"] = "cursor"
	wxCtxMu.Unlock()

	// When 第二 bot 扫码登录
	if _, err := WxQRLoginStart(ctx); err != nil {
		t.Fatalf("二次产码失败: %v", err)
	}
	if _, confirmed, err := WxQRLoginPoll(ctx); err != nil || !confirmed {
		t.Fatalf("二次登录未确认: confirmed=%v err=%v", confirmed, err)
	}
	// Then 全局仍是首 bot（长轮询不掉线），会话态不被清空
	if cred, ok := loadWxBotCred(); !ok || cred.Token != "T1" {
		t.Errorf("二登覆盖全局: %+v ok=%v, want T1", cred, ok)
	}
	if wxContextTokenFor("B1", "r1") != "ctx-1" {
		t.Error("二登清空了首 bot 的 context_token 缓存")
	}
	wxCtxMu.Lock()
	buf := wxUpdatesBufs["B1"]
	wxCtxMu.Unlock()
	if buf != "cursor" {
		t.Error("二登清空了首 bot 的 getupdates 游标")
	}
	// Then 新凭据经通道 target 钉住
	pinned := WxPinChannelTarget(`{"receiver":"r9"}`)
	var tm map[string]any
	if err := json.Unmarshal([]byte(pinned), &tm); err != nil {
		t.Fatalf("钉住 target 非 JSON: %v", err)
	}
	if tm["receiver"] != "r9" || tm["token"] != "T2" || tm["baseurl"] != "http://second" || tm["account_id"] != "B2" || tm["user_id"] != "U2" {
		t.Errorf("钉住 target=%s, want 第二 bot 凭据", pinned)
	}
	// 已带凭据的 target 原样保留
	if got := WxPinChannelTarget(`{"receiver":"r9","token":"TX"}`); got != `{"receiver":"r9","token":"TX"}` {
		t.Errorf("已钉住 target 被改写: %s", got)
	}
	// 无待钉新凭据时回退全局
	wxCtxMu.Lock()
	wxConfirmedPin = nil
	wxCtxMu.Unlock()
	pinned = WxPinChannelTarget(`{"receiver":"r8"}`)
	tm = nil
	_ = json.Unmarshal([]byte(pinned), &tm)
	if tm["token"] != "T1" {
		t.Errorf("回退全局钉住=%s, want token T1", pinned)
	}
	// 全局亦无 → 原样返回（发送侧 fail-loud）
	_ = SetSettings(map[string]string{KeyWxBotCred: ""})
	if got := WxPinChannelTarget(`{"receiver":"r7"}`); got != `{"receiver":"r7"}` {
		t.Errorf("无凭据时 target 被改写: %s", got)
	}
}

// 微信「绑定」指令：通道 target 钉住入站会话（首 bot）凭据。
func TestWxBindCommandPinsSessionCredentials(t *testing.T) {
	newNotifyConnectorDB(t)
	m := setupWxSendMock(t)
	if _, err := db.DB.Exec(`INSERT INTO qq_bind_codes (code, user_id, expires_at) VALUES ('CODE8', 7, datetime('now', '+1 hour'))`); err != nil {
		t.Fatalf("播种绑定码失败: %v", err)
	}
	cred := wxBotCred{Token: "T_S", BaseURL: m.server.URL, AccountID: "B_S", UserID: "U_S"}
	var in wxInMsg
	if err := json.Unmarshal([]byte(`{"from_user_id":"wx9","context_token":"ctx-9","item_list":[{"type":1,"text_item":{"text":"绑定 CODE8"}}]}`), &in); err != nil {
		t.Fatal(err)
	}
	// When 入站绑定指令
	handleWxInbound(context.Background(), cred, in)
	// Then 通道 target 含 receiver+token/baseurl/account_id/user_id
	var target string
	if err := db.DB.QueryRow(`SELECT target FROM notification_channels WHERE type='wx_clawbot'`).Scan(&target); err != nil {
		t.Fatalf("通道行未落库: %v", err)
	}
	var tm map[string]any
	if err := json.Unmarshal([]byte(target), &tm); err != nil {
		t.Fatalf("target 非 JSON: %v", err)
	}
	if tm["receiver"] != "wx9" || tm["token"] != "T_S" || tm["baseurl"] != m.server.URL || tm["account_id"] != "B_S" || tm["user_id"] != "U_S" {
		t.Errorf("绑定 target=%s, want 会话凭据钉住", target)
	}
	// Then 被动回执用会话 token
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.auths) != 1 || m.auths[0] != "Bearer T_S" {
		t.Errorf("绑定回执 Authorization=%v, want [Bearer T_S]", m.auths)
	}
}
