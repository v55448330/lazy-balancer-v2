package handlers

// QQ 扫码绑定协议钉测（对齐 @tencent-connect/qqbot-connector 1.2.0 行为）。
// mock q.qq.com 两端点 + 固定 AES 密钥向量，覆盖全形状：
//   ①生成二维码（connect.html URL 含 task_id）
//   ②poll completed：AES-GCM 解密 → 凭据落 notify_settings + openid 绑定通道
//   ③EXPIRED：重生成提示形态

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

// encryptForTest 加密（IV 12B‖ct‖tag 16B 的 base64）——与官方
// connector decryptSecret 互逆的测试向量构造器。
func encryptForTest(key []byte, plain string) string {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	iv := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(iv)
	ct := gcm.Seal(nil, iv, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(append(iv, ct...))
}

// newQQBindRouter 带「登录用户」身份注入的测试路由（user_id/role 对齐中间件注入）。
func newQQBindRouter(t *testing.T, userID int64) *gin.Engine {
	t.Helper()
	h := newFakeCaddyHandlers(t)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", float64(userID))
		c.Set("role", "admin")
		c.Next()
	})
	router.POST("/notification/qq/bind-code", h.PostQQBindCode)
	router.GET("/notification/qq/bind-code", h.GetQQBindCode)
	return router
}

// qqBindMockEnv mock q.qq.com 环境（端点覆写自动还原）。
type qqBindMockEnv struct {
	mu      sync.Mutex
	lastKey []byte
	server  *httptest.Server
	// poll completed 下发的凭据（多机器人用例覆写；默认 APP_MOCK 向量）。
	appID  string
	secret string
	openid string
}

func (e *qqBindMockEnv) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lite/create_bind_task":
			var body struct {
				Key string `json:"key"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if raw, err := base64.StdEncoding.DecodeString(body.Key); err == nil && len(raw) == 32 {
				e.mu.Lock()
				e.lastKey = raw
				e.mu.Unlock()
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"retcode":0,"data":{"task_id":"TASK_MOCK"}}`))
		case "/lite/poll_bind_result":
			e.mu.Lock()
			key := e.lastKey
			appID, secret, openid := e.appID, e.secret, e.openid
			e.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if len(key) != 32 {
				_, _ = w.Write([]byte(`{"retcode":0,"data":{"status":1}}`))
				return
			}
			_, _ = w.Write([]byte(fmt.Sprintf(
				`{"retcode":0,"data":{"status":2,"bot_appid":%q,"bot_encrypt_secret":%q,"user_openid":%q}}`,
				appID, encryptForTest(key, secret), openid)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// setupQQBindMock 起 mock q.qq.com 并把包级端点指向它；返回还原函数。
func setupQQBindMock(t *testing.T) *qqBindMockEnv {
	t.Helper()
	env := &qqBindMockEnv{appID: "APP_MOCK", secret: "SECRET_MOCK", openid: "OPENID_MOCK"}
	env.server = httptest.NewServer(env.handler())
	oldTask, oldPoll := notify.BindTaskURL, notify.BindPollURL
	notify.BindTaskURL = env.server.URL + "/lite/create_bind_task"
	notify.BindPollURL = env.server.URL + "/lite/poll_bind_result"
	t.Cleanup(func() {
		notify.BindTaskURL, notify.BindPollURL = oldTask, oldPoll
		env.server.Close()
		qqTaskMu.Lock()
		qqBoundByUser = map[int64]qqBoundCred{}
		qqTaskMu.Unlock()
	})
	return env
}

// TestQQBindScan_e2e 主形状：生成二维码 → mock poll completed（AES 向量）→
// GET 轮询 bound=true + 凭据落 notify_settings + openid 绑定通道。
func TestQQBindScan_e2e(t *testing.T) {
	env := setupQQBindMock(t)
	setupSecurityPolicyTestDB(t)
	const uid = int64(42)
	router := newQQBindRouter(t, uid)

	// ① 生成二维码（connect.html URL 含 task_id）
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/notification/qq/bind-code", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("qr status=%d body=%s", w.Code, w.Body.String())
	}
	var qr struct {
		Data struct {
			QrContent string `json:"qr_content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &qr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(qr.Data.QrContent, "task_id=TASK_MOCK") {
		t.Fatalf("qr_content=%q, want connect.html URL", qr.Data.QrContent)
	}
	env.mu.Lock()
	keySeen := len(env.lastKey) == 32
	env.mu.Unlock()
	if !keySeen {
		t.Fatal("mock create_bind_task 未收到 32B 密钥（协议形状漂移）")
	}

	// ② 轮询（mock poll completed + AES 向量）
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/notification/qq/bind-code", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("poll status=%d", w2.Code)
	}
	var poll struct {
		Data struct {
			Bound  bool   `json:"bound"`
			AppID  string `json:"appid"`
			OpenID string `json:"openid"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &poll); err != nil {
		t.Fatal(err)
	}
	if !poll.Data.Bound || poll.Data.AppID != "APP_MOCK" || poll.Data.OpenID != "OPENID_MOCK" {
		t.Fatalf("poll=%+v, want bound+APP_MOCK+OPENID_MOCK", poll.Data)
	}

	// ③ 凭据落 notify_settings（连接 Daemon 鉴权单源）
	var appID, appSecret string
	if err := db.DB.QueryRow(`SELECT value FROM notify_settings WHERE key='notify.qq_appid'`).Scan(&appID); err != nil || appID != "APP_MOCK" {
		t.Fatalf("notify.qq_appid=%q (err=%v), want APP_MOCK", appID, err)
	}
	// qq_secret 静态加密落库（unify_all）：密文带前缀且不含明文；读路径还原。
	if err := db.DB.QueryRow(`SELECT value FROM notify_settings WHERE key='notify.qq_secret'`).Scan(&appSecret); err != nil {
		t.Fatalf("notify.qq_secret 读取 err=%v", err)
	}
	if !strings.HasPrefix(appSecret, "enc:v1:") || strings.Contains(appSecret, "SECRET_MOCK") {
		t.Fatalf("notify.qq_secret 应密文落库, got %q", appSecret)
	}
	if _, sec, ok := notify.QQBotCredentialsPair(); !ok || sec != "SECRET_MOCK" {
		t.Fatalf("QQBotCredentialsPair secret=%q ok=%v, want SECRET_MOCK", sec, ok)
	}

	// ④ 绑定动作不再自动建通道（「保存」是唯一创建入口；删除通道后重新
	// 绑定→保存=新建，不再误判已存在）
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_channels WHERE user_id=? AND type='qq'`, uid).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("绑定后通道行数=%d err=%v, want 0（通道由保存动作创建）", rows, err)
	}
}

// TestQQBindScan_expired EXPIRED 形态：poll status=3 → 重生成提示数据形态。
func TestQQBindScan_expired(t *testing.T) {
	env := setupQQBindMock(t)
	_ = env
	oldTask, oldPoll := notify.BindTaskURL, notify.BindPollURL
	defer func() { notify.BindTaskURL, notify.BindPollURL = oldTask, oldPoll }()
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"retcode":0,"data":{"status":3}}`))
	}))
	defer mock.Close()
	notify.BindTaskURL, notify.BindPollURL = mock.URL+"/lite/create_bind_task", mock.URL+"/lite/poll_bind_result"

	task := &notify.BindTask{Key: make([]byte, 32), TaskID: "TASK_MOCK"}
	result, err := notify.PollBindResult(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != notify.BindExpired {
		t.Fatalf("status=%d, want expired(3)", result.Status)
	}
}

// TestChannelCreate_idempotentReuse 同 user+type+target 唯一约束的幂等复用：
// 首建 200 新建；同 target 二次提交（QQ 扫码绑定后重复保存的正常路径）200
// reused=true 复用既有行，不再 500 撞约束。
func TestChannelCreate_idempotentReuse(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	const uid = int64(42)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", float64(uid))
		c.Set("role", "admin")
		c.Next()
	})
	h := &Handlers{}
	router.POST("/notification/channels", h.CreateNotificationChannel)

	body := `{"type":"qq","name":"QQ 机器人","target":"{\"openid\":\"OPENID_MOCK\"}"}`
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/notification/channels", strings.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("首建 status=%d body=%s", w.Code, w.Body.String())
	}
	var first struct {
		Data struct {
			ID     int64 `json:"id"`
			Reused bool  `json:"reused"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.Data.Reused {
		t.Fatal("首建 reused=true，want false")
	}

	// 同 target 二次提交：幂等复用（200 reused=true，行数不增）
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, httptest.NewRequest(http.MethodPost, "/notification/channels", strings.NewReader(body)))
	if w2.Code != http.StatusOK {
		t.Fatalf("复用 status=%d body=%s", w2.Code, w2.Body.String())
	}
	var second struct {
		Data struct {
			ID     int64 `json:"id"`
			Reused bool  `json:"reused"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if !second.Data.Reused || second.Data.ID != first.Data.ID {
		t.Fatalf("复用 reused=%v id=%d, want true/%d", second.Data.Reused, second.Data.ID, first.Data.ID)
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_channels WHERE user_id=? AND type='qq'`, uid).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("行数=%d err=%v, want 1（无重复行）", rows, err)
	}
}
