package handlers

// 多机器人通道凭据回归（REST 层）：①双 QQ bot 扫码绑定不互覆全局凭据；
// ②创建/更新通道时 target 缺凭据则钉住（qq 优先本用户最近绑定下发的凭据，
// openid 匹配；wx 全局登录态）；③钉住后重复保存幂等复用、存量无凭据行不重复建。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

// newMultiBotChannelRouter 绑定+通道 CRUD 测试路由（登录用户 uid，admin 角色）。
func newMultiBotChannelRouter(t *testing.T, uid int64) *gin.Engine {
	t.Helper()
	h := newFakeCaddyHandlers(t)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", float64(uid))
		c.Set("role", "admin")
		c.Next()
	})
	router.POST("/notification/qq/bind-code", h.PostQQBindCode)
	router.GET("/notification/qq/bind-code", h.GetQQBindCode)
	router.POST("/notification/channels", h.CreateNotificationChannel)
	router.PUT("/notification/channels/:id", h.UpdateNotificationChannel)
	return router
}

// bindQQBot 走完整扫码绑定流程（产码→poll completed），返回 poll 响应数据。
func bindQQBot(t *testing.T, router *gin.Engine, env *qqBindMockEnv, appid, secret, openid string) {
	t.Helper()
	env.mu.Lock()
	env.appID, env.secret, env.openid = appid, secret, openid
	env.mu.Unlock()
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/notification/qq/bind-code", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("产码 status=%d body=%s", w.Code, w.Body.String())
	}
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/notification/qq/bind-code", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("poll status=%d body=%s", w2.Code, w2.Body.String())
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
	if !poll.Data.Bound || poll.Data.AppID != appid || poll.Data.OpenID != openid {
		t.Fatalf("poll=%+v, want bound+%s+%s", poll.Data, appid, openid)
	}
}

func globalQQCred(t *testing.T) (appid, secret string) {
	t.Helper()
	// 经读路径取全局凭据（qq_secret 静态加密落库，QQBotCredentialsPair 解密还原）。
	a, s, ok := notify.QQBotCredentialsPair()
	if !ok {
		t.Fatalf("全局 QQ 凭据未配置")
	}
	return a, s
}

func channelTarget(t *testing.T, id int64) map[string]any {
	t.Helper()
	var target string
	if err := db.DB.QueryRow(`SELECT target FROM notification_channels WHERE id=?`, id).Scan(&target); err != nil {
		t.Fatalf("读通道 target: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(target), &m); err != nil {
		t.Fatalf("target 非 JSON: %v", err)
	}
	return m
}

func createChannel(t *testing.T, router *gin.Engine, typ, target string) (id int64, reused bool) {
	t.Helper()
	body := `{"type":"` + typ + `","name":"多机器人测试","target":` + quoteJSONForTest(target) + `}`
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/notification/channels", strings.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("创建通道 status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			ID     int64 `json:"id"`
			Reused bool  `json:"reused"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Data.ID, resp.Data.Reused
}

func quoteJSONForTest(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// 双 QQ bot 绑定不互覆全局：首 bot 落全局（入站 WS），二 bot 凭据只供通道钉住。
func TestQQBindSecondBotDoesNotOverwriteGlobal(t *testing.T) {
	env := setupQQBindMock(t)
	setupSecurityPolicyTestDB(t)
	router := newMultiBotChannelRouter(t, 42)

	bindQQBot(t, router, env, "APP_A", "SEC_A", "OPENID_A")
	if appid, secret := globalQQCred(t); appid != "APP_A" || secret != "SEC_A" {
		t.Fatalf("首绑全局=%s/%s, want APP_A/SEC_A", appid, secret)
	}
	bindQQBot(t, router, env, "APP_B", "SEC_B", "OPENID_B")
	if appid, secret := globalQQCred(t); appid != "APP_A" || secret != "SEC_A" {
		t.Errorf("二绑覆盖全局=%s/%s, want APP_A/SEC_A（老 bot 掉线根因）", appid, secret)
	}
}

// 创建 QQ 通道钉住凭据：最近绑定（openid 匹配）优先→全局回退→显式凭据原样；
// 钉住后重复保存幂等复用；存量无凭据行按原 target 复用不重复建。
func TestChannelCreatePinsQQCredentials(t *testing.T) {
	env := setupQQBindMock(t)
	setupSecurityPolicyTestDB(t)
	router := newMultiBotChannelRouter(t, 42)
	bindQQBot(t, router, env, "APP_A", "SEC_A", "OPENID_A")
	bindQQBot(t, router, env, "APP_B", "SEC_B", "OPENID_B")

	// 最近绑定（二 bot）的 openid → 钉住二 bot 凭据
	id, reused := createChannel(t, router, "qq", `{"openid":"OPENID_B"}`)
	if reused {
		t.Fatal("首建不应 reused")
	}
	tm := channelTarget(t, id)
	if tm["appid"] != "APP_B" || tm["secret"] != "SEC_B" {
		t.Errorf("二 bot 通道钉住=%v, want APP_B/SEC_B", tm)
	}
	// 重复保存 → 幂等复用（钉住形态确定性）
	id2, reused := createChannel(t, router, "qq", `{"openid":"OPENID_B"}`)
	if !reused || id2 != id {
		t.Errorf("重复保存 reused=%v id=%d, want true/%d", reused, id2, id)
	}
	// openid 不匹配最近绑定 → 回退全局（首 bot）
	id3, _ := createChannel(t, router, "qq", `{"openid":"OPENID_A"}`)
	tm = channelTarget(t, id3)
	if tm["appid"] != "APP_A" || tm["secret"] != "SEC_A" {
		t.Errorf("全局回退钉住=%v, want APP_A/SEC_A", tm)
	}
	// target 显式带凭据 → 原样保留
	id4, _ := createChannel(t, router, "qq", `{"openid":"OX","appid":"APP_X","secret":"SEC_X"}`)
	tm = channelTarget(t, id4)
	if tm["appid"] != "APP_X" || tm["secret"] != "SEC_X" {
		t.Errorf("显式凭据被改写=%v", tm)
	}
	// 存量无凭据行 → 按原 target 幂等复用（不新建钉住行）
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, enabled, created_at, updated_at)
		VALUES (42, 'qq', '存量', '{"openid":"LEGACY"}', 1, datetime('now'), datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	id5, reused := createChannel(t, router, "qq", `{"openid":"LEGACY"}`)
	if !reused {
		t.Error("存量无凭据行应幂等复用")
	}
	if tm := channelTarget(t, id5); tm["appid"] != nil {
		t.Errorf("存量行被改写=%v（存量回退全局行为应不变）", tm)
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_channels WHERE user_id=42 AND type='qq' AND target LIKE '%LEGACY%'`).Scan(&rows); err != nil || rows != 1 {
		t.Errorf("LEGACY 行数=%d err=%v, want 1", rows, err)
	}
}

// 创建微信通道钉住全局登录态凭据（token/baseurl/account_id/user_id）。
func TestChannelCreatePinsWxCredentials(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiBotChannelRouter(t, 42)
	if err := notify.SetSettings(map[string]string{
		notify.KeyWxBotCred: `{"token":"TW","baseUrl":"http://wx","accountId":"AW","userId":"UW"}`,
	}); err != nil {
		t.Fatal(err)
	}
	id, reused := createChannel(t, router, "wx_clawbot", `{"receiver":"r1"}`)
	if reused {
		t.Fatal("首建不应 reused")
	}
	tm := channelTarget(t, id)
	if tm["token"] != "TW" || tm["baseurl"] != "http://wx" || tm["account_id"] != "AW" || tm["user_id"] != "UW" {
		t.Errorf("微信通道钉住=%v, want 全局登录态凭据", tm)
	}
	id2, reused := createChannel(t, router, "wx_clawbot", `{"receiver":"r1"}`)
	if !reused || id2 != id {
		t.Errorf("重复保存 reused=%v id=%d, want true/%d", reused, id2, id)
	}
}

// 更新通道 target 缺凭据 → 钉住当前全局凭据（qq/wx 同口径）。
func TestChannelUpdatePinsCredentials(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newMultiBotChannelRouter(t, 42)
	if err := notify.SetSettings(map[string]string{
		notify.KeyQQAppID:   "APP_A",
		notify.KeyQQSecret:  "SEC_A",
		notify.KeyWxBotCred: `{"token":"TW","baseUrl":"http://wx","accountId":"AW","userId":"UW"}`,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, enabled, created_at, updated_at)
		VALUES (42, 'qq', '存量QQ', '{"openid":"OU"}', 1, datetime('now'), datetime('now')),
		       (42, 'wx_clawbot', '存量微信', '{"receiver":"RU"}', 1, datetime('now'), datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	var qqID, wxID int64
	if err := db.DB.QueryRow(`SELECT id FROM notification_channels WHERE type='qq'`).Scan(&qqID); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT id FROM notification_channels WHERE type='wx_clawbot'`).Scan(&wxID); err != nil {
		t.Fatal(err)
	}
	put := func(id int64, target string) {
		t.Helper()
		body := `{"target":` + quoteJSONForTest(target) + `}`
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/notification/channels/"+itoa64(id), strings.NewReader(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("更新通道 status=%d body=%s", w.Code, w.Body.String())
		}
	}
	put(qqID, `{"openid":"OU"}`)
	if tm := channelTarget(t, qqID); tm["appid"] != "APP_A" || tm["secret"] != "SEC_A" {
		t.Errorf("更新后 QQ 钉住=%v, want APP_A/SEC_A", tm)
	}
	put(wxID, `{"receiver":"RU"}`)
	if tm := channelTarget(t, wxID); tm["token"] != "TW" || tm["baseurl"] != "http://wx" {
		t.Errorf("更新后微信钉住=%v, want TW/http://wx", tm)
	}
}
