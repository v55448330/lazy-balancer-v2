package notify

// QQ 多机器人凭据回归（覆盖根因：绑第二个 bot 覆盖全局凭据→老 bot 掉线）：
// ①SaveQQBotCredentialsIfAbsent 仅全局未配置时写入；②token 缓存按 appid 隔离；
// ③出站用 target 钉住的 appid/secret 鉴权，存量 target 无凭据回退全局；
// ④QQ 内「绑定测试」确认弹框会话（被动回执用会话 bot token；建通道交保存路径）。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// qqMockPlatform mock QQ 开放平台：getAppAccessToken（按 appid 发 token）+
// /v2/users/{openid}/messages（记录出站 Authorization）。
type qqMockPlatform struct {
	mu       sync.Mutex
	authReqs []string // 鉴权请求的 appId 序列
	sentAuth []string // 出站消息的 Authorization 序列
	server   *httptest.Server
}

func setupQQPlatformMock(t *testing.T) *qqMockPlatform {
	t.Helper()
	m := &qqMockPlatform{}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app/getAppAccessToken":
			var body struct {
				AppID string `json:"appId"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.mu.Lock()
			m.authReqs = append(m.authReqs, body.AppID)
			m.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"access_token":"token-%s","expires_in":"7200"}`, body.AppID)
		case strings.HasPrefix(r.URL.Path, "/v2/users/"):
			m.mu.Lock()
			m.sentAuth = append(m.sentAuth, r.Header.Get("Authorization"))
			m.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	oldToken, oldAPI := qqTokenURL, qqAPIBase
	qqTokenURL, qqAPIBase = m.server.URL+"/app/getAppAccessToken", m.server.URL
	t.Cleanup(func() {
		qqTokenURL, qqAPIBase = oldToken, oldAPI
		qqTokens.invalidate()
		m.server.Close()
	})
	return m
}

func seedQQGlobalCred(t *testing.T, appid, secret string) {
	t.Helper()
	if err := SetSettings(map[string]string{KeyQQAppID: appid, KeyQQSecret: secret}); err != nil {
		t.Fatalf("写入全局凭据失败: %v", err)
	}
	t.Cleanup(func() { _ = SetSettings(map[string]string{KeyQQAppID: "", KeyQQSecret: ""}) })
}

// 双 bot 绑定不互覆全局：首个 bot 供入站 WS，后续绑定只钉通道 target。
func TestQQSaveCredentialsIfAbsent(t *testing.T) {
	newNotifyConnectorDB(t)
	// Given 全局未配置
	// When 首个 bot 凭据落库
	written, err := SaveQQBotCredentialsIfAbsent("APP_A", "SEC_A")
	if err != nil || !written {
		t.Fatalf("首绑应写入全局: written=%v err=%v", written, err)
	}
	// When 第二个 bot 绑定完成
	written, err = SaveQQBotCredentialsIfAbsent("APP_B", "SEC_B")
	if err != nil || written {
		t.Fatalf("二绑不应写入全局: written=%v err=%v", written, err)
	}
	// Then 全局仍是首个 bot（连接 Daemon 不掉线）
	appid, secret, ok := QQBotCredentialsPair()
	if !ok || appid != "APP_A" || secret != "SEC_A" {
		t.Errorf("全局凭据被覆盖: appid=%q secret=%q ok=%v, want APP_A/SEC_A", appid, secret, ok)
	}
}

// token 缓存按 appid 隔离：两 bot 各持 token，同 appid 命中缓存不重复鉴权。
func TestQQTokenCachePerAppID(t *testing.T) {
	newNotifyConnectorDB(t)
	m := setupQQPlatformMock(t)
	ctx := context.Background()
	// Given/When 交替取两 bot 的 token
	tokA1, err := qqTokens.ensureCred(ctx, "APP_A", "SEC_A")
	if err != nil {
		t.Fatalf("ensureCred A: %v", err)
	}
	tokB, err := qqTokens.ensureCred(ctx, "APP_B", "SEC_B")
	if err != nil {
		t.Fatalf("ensureCred B: %v", err)
	}
	tokA2, err := qqTokens.ensureCred(ctx, "APP_A", "SEC_A")
	if err != nil {
		t.Fatalf("ensureCred A 复用: %v", err)
	}
	// Then token 按 appid 隔离且缓存命中
	if tokA1 != "token-APP_A" || tokB != "token-APP_B" || tokA2 != tokA1 {
		t.Errorf("token 隔离失败: A1=%q B=%q A2=%q", tokA1, tokB, tokA2)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.authReqs) != 2 {
		t.Errorf("鉴权请求数=%d（%v）, want 2（A 缓存命中）", len(m.authReqs), m.authReqs)
	}
}

// 出站凭据钉住：target 带 appid/secret 用第二 bot 鉴权；存量无凭据回退全局。
func TestQQSendUsesTargetPinnedCredentials(t *testing.T) {
	newNotifyConnectorDB(t)
	m := setupQQPlatformMock(t)
	seedQQGlobalCred(t, "APP_GLOBAL", "SEC_GLOBAL")
	ctx := context.Background()
	// When 第二 bot target 出站（文本）
	if err := SendQQC2C(ctx, `{"openid":"o1","appid":"APP_B","secret":"SEC_B"}`, "hi"); err != nil {
		t.Fatalf("target 凭据出站失败: %v", err)
	}
	// When 存量 target（无凭据）出站
	if err := SendQQC2C(ctx, `{"openid":"o2"}`, "hi"); err != nil {
		t.Fatalf("存量回退出站失败: %v", err)
	}
	// When 第二 bot target 出站（markdown）
	if err := SendQQC2CMarkdown(ctx, `{"openid":"o3","appid":"APP_B","secret":"SEC_B"}`, "**hi**"); err != nil {
		t.Fatalf("markdown target 凭据出站失败: %v", err)
	}
	// Then 出站依次用 B/全局/B 的 token（markdown 复用 B 缓存）
	m.mu.Lock()
	defer m.mu.Unlock()
	want := []string{"QQBot token-APP_B", "QQBot token-APP_GLOBAL", "QQBot token-APP_B"}
	if len(m.sentAuth) != len(want) {
		t.Fatalf("出站数=%d, want %d", len(m.sentAuth), len(want))
	}
	for i, w := range want {
		if m.sentAuth[i] != w {
			t.Errorf("出站[%d] Authorization=%q, want %q", i, m.sentAuth[i], w)
		}
	}
	if len(m.authReqs) != 2 || m.authReqs[0] != "APP_B" || m.authReqs[1] != "APP_GLOBAL" {
		t.Errorf("鉴权序列=%v, want [APP_B APP_GLOBAL]（target 凭据优先）", m.authReqs)
	}
}

// QQ 内「绑定测试」：确认弹框注册的会话（首 bot=全局凭据），被动回执用其
// token；入站不建通道（旧「绑定 <验证码>」自动建通道已移除，不向后兼容）。
func TestQQBindTestMessageConfirmsSession(t *testing.T) {
	newNotifyConnectorDB(t)
	m := setupQQPlatformMock(t)
	seedQQGlobalCred(t, "APP_G", "SEC_G")
	clearBindSessions()
	t.Cleanup(clearBindSessions)
	StartBindSessionWithCred(7, "qq", "o9", "APP_G", "SEC_G")
	// When 入站「绑定测试」（首 bot 会话：凭据=全局）
	handleQQC2CMessage(context.Background(), qqBotCred{AppID: "APP_G", Secret: "SEC_G"}, json.RawMessage(`{"content":"绑定测试","author":{"user_openid":"o9"},"id":"MSG9"}`))
	// Then 会话 confirmed + receiver 捕获
	phase, receiver := PollBindSession(7, "qq", "o9", "APP_G")
	if phase != "confirmed" || receiver != "o9" {
		t.Fatalf("确认后 phase=%q receiver=%q, want confirmed/o9", phase, receiver)
	}
	// Then 入站不建通道（建通道交弹框保存路径）
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_channels`).Scan(&n); err != nil || n != 0 {
		t.Errorf("入站绑定测试不应建通道: n=%d err=%v", n, err)
	}
	// Then 被动回执用全局 bot token
	m.mu.Lock()
	if len(m.sentAuth) != 1 || m.sentAuth[0] != "QQBot token-APP_G" {
		t.Errorf("绑定回执 Authorization=%v, want [QQBot token-APP_G]", m.sentAuth)
	}
	m.mu.Unlock()
	// When 重复「绑定测试」→幂等不重复回执
	handleQQC2CMessage(context.Background(), qqBotCred{AppID: "APP_G", Secret: "SEC_G"}, json.RawMessage(`{"content":"绑定测试","author":{"user_openid":"o9"},"id":"MSG9R"}`))
	// When 旧「绑定 <验证码>」形态→不建通道/不回执（不向后兼容）
	handleQQC2CMessage(context.Background(), qqBotCred{AppID: "APP_G", Secret: "SEC_G"}, json.RawMessage(`{"content":"绑定 CODE9","author":{"user_openid":"o9"},"id":"MSG9O"}`))
	m.mu.Lock()
	nReply := len(m.sentAuth)
	m.mu.Unlock()
	if nReply != 1 {
		t.Errorf("重复/旧形态指令回执数=%d, want 1（幂等+旧指令已移除）", nReply)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_channels`).Scan(&n); err != nil || n != 0 {
		t.Errorf("旧绑定指令不应建通道: n=%d err=%v", n, err)
	}
}
