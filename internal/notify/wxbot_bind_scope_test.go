package notify

// 微信扫码绑定作用域回归（用户实测"未扫码跳 wxid + 保存后发送失败"）：
// 新扫码会话清除旧 pin/旧入站捕获；扫码期间旧 bot 入站消息不得泄漏旧 wxid；
// 本次扫码确认后 receiver=本次扫码者 wxid（与钉住凭据一致，防错配发送失败）。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWxBindScope_NoLeakBeforeScan(t *testing.T) {
	newNotifyConnectorDB(t)
	// 全局首 bot 已登录（WxBotLoggedIn=true）
	if err := saveWxBotCred(wxBotCred{Token: "TG", BaseURL: "http://g", AccountID: "BG", UserID: "UG"}); err != nil {
		t.Fatalf("播种全局凭据: %v", err)
	}
	var confirmed atomic.Bool
	qrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ilink/bot/get_bot_qrcode":
			_, _ = w.Write([]byte(`{"qrcode":"QRNEW","qrcode_img_content":"img"}`))
		case "/ilink/bot/get_qrcode_status":
			if confirmed.Load() {
				_, _ = w.Write([]byte(`{"status":"confirmed","bot_token":"TNEW","ilink_bot_id":"BNEW","ilink_user_id":"U_NEW","baseurl":"http://new"}`))
			} else {
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
		wxPendingQR, wxConfirmedPin, wxPendingInbound = "", nil, wxInboundCapture{}
		wxCtxMu.Unlock()
	})
	ctx := context.Background()

	// Given 残留旧会话态（上一次扫码 pin + 旧入站捕获）
	wxCtxMu.Lock()
	wxConfirmedPin = &wxBotCred{UserID: "OLD_SCANNER"}
	wxPendingInbound = wxInboundCapture{Receiver: "OLD_INBOUND", At: time.Now()}
	wxCtxMu.Unlock()

	// When 发起新扫码会话
	if _, err := WxQRLoginStart(ctx); err != nil {
		t.Fatalf("产码失败: %v", err)
	}
	// Then 旧 pin/旧入站捕获被清，未扫码不回填
	if !WxQRLoginActive() {
		t.Errorf("新扫码会话应 active")
	}
	if WxDefaultReceiver() != "" {
		t.Errorf("未扫码不应回填旧扫码者, got %q", WxDefaultReceiver())
	}
	if WxTakePendingReceiver(3*time.Minute) != "" {
		t.Errorf("新会话应清除旧入站捕获")
	}

	// When 扫码期间旧 bot 入站消息到达（重新污染捕获）
	noteWxInboundCapture("OLD_INBOUND")
	// Then 本次扫码未确认 → pin 仍空（bind-state 据 WxQRLoginActive 屏蔽入站捕获）
	if _, conf, err := WxQRLoginPoll(ctx); err != nil || conf {
		t.Fatalf("未扫码应 wait, conf=%v err=%v", conf, err)
	}
	if WxDefaultReceiver() != "" {
		t.Errorf("扫码期间旧入站消息不得泄漏为 receiver, got %q", WxDefaultReceiver())
	}
	if !WxQRLoginActive() {
		t.Errorf("未确认前应仍 active（屏蔽入站回填）")
	}

	// When 本次扫码确认（二登，全局已存在）
	confirmed.Store(true)
	if _, conf, err := WxQRLoginPoll(ctx); err != nil || !conf {
		t.Fatalf("本次扫码应确认, conf=%v err=%v", conf, err)
	}
	// Then receiver=本次扫码者 wxid（与钉住凭据一致）
	if got := WxDefaultReceiver(); got != "U_NEW" {
		t.Errorf("确认后 receiver 应=本次扫码者 U_NEW, got %q", got)
	}
	// 钉住消费 pin，target 凭据/接收者一致
	pinned := WxPinChannelTarget(`{"receiver":"U_NEW"}`)
	if !strings.Contains(pinned, "TNEW") || !strings.Contains(pinned, "U_NEW") {
		t.Errorf("钉住 target 应含本次凭据 TNEW+U_NEW, got %s", pinned)
	}
	if WxDefaultReceiver() != "" {
		t.Errorf("钉住应消费 pin, got %q", WxDefaultReceiver())
	}
}
