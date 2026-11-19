package handlers

// SMTP OAuth2 设备码 REST 流程回归：POST 发起（落 client_id/tenant）→ GET
// 轮询 completed（refresh_token 静态加密落库 + 会话消费）→ GET idle → DELETE
// 解绑（清配置）。端点经 notify.SetOAuthEndpointsForTest 覆写为 httptest。

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

func newSMTPOAuthRouter(t *testing.T, uid int64) *gin.Engine {
	t.Helper()
	h := newFakeCaddyHandlers(t)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", float64(uid))
		c.Set("role", "admin")
		c.Next()
	})
	router.POST("/notification/settings/smtp-oauth", h.PostSMTPOAuthDeviceCode)
	router.GET("/notification/settings/smtp-oauth", h.GetSMTPOAuthDeviceCode)
	router.DELETE("/notification/settings/smtp-oauth", h.DeleteSMTPOAuth)
	return router
}

func TestSMTPOAuthDeviceCodeFlow(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	deviceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_code":"DC","user_code":"ABCD-EFGH","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5}`))
	}))
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT","refresh_token":"RT_SECRET","expires_in":3600}`))
	}))
	restore := notify.SetOAuthEndpointsForTest(func(string) string { return deviceSrv.URL }, func(string) string { return tokenSrv.URL })
	t.Cleanup(func() { restore(); deviceSrv.Close(); tokenSrv.Close() })

	const uid = int64(42)
	router := newSMTPOAuthRouter(t, uid)

	// ① POST 发起设备码
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/notification/settings/smtp-oauth",
		strings.NewReader(`{"tenant":"common","client_id":"cid-test"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("发起 status=%d body=%s", w.Code, w.Body.String())
	}
	var start struct {
		Data struct {
			UserCode        string `json:"user_code"`
			VerificationURI string `json:"verification_uri"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &start)
	if start.Data.UserCode != "ABCD-EFGH" || start.Data.VerificationURI == "" {
		t.Fatalf("发起响应不符: %+v", start.Data)
	}
	// client_id 落库
	if notify.GetSetting(notify.KeySMTPOAuthClientID) != "cid-test" {
		t.Errorf("client_id 应落库")
	}

	// ② GET 轮询 completed → refresh_token 静态加密落库
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/notification/settings/smtp-oauth", nil))
	var poll struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &poll)
	if poll.Data.Status != "completed" {
		t.Fatalf("轮询 status=%q, want completed (body=%s)", poll.Data.Status, w2.Body.String())
	}
	var rawRT string
	_ = db.DB.QueryRow(`SELECT value FROM notify_settings WHERE key=?`, notify.KeySMTPOAuthRefreshToken).Scan(&rawRT)
	if !strings.HasPrefix(rawRT, "enc:v1:") || strings.Contains(rawRT, "RT_SECRET") {
		t.Errorf("refresh_token 应密文落库, got %q", rawRT)
	}
	if !notify.OAuthConfigured() {
		t.Errorf("completed 后 OAuthConfigured 应为 true")
	}

	// ③ 会话已消费 → GET idle
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, httptest.NewRequest(http.MethodGet, "/notification/settings/smtp-oauth", nil))
	var idle struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w3.Body.Bytes(), &idle)
	if idle.Data.Status != "idle" {
		t.Errorf("会话消费后应 idle, got %q", idle.Data.Status)
	}

	// ④ DELETE 解绑 → 清配置
	w4 := httptest.NewRecorder()
	router.ServeHTTP(w4, httptest.NewRequest(http.MethodDelete, "/notification/settings/smtp-oauth", nil))
	if w4.Code != http.StatusOK {
		t.Fatalf("解绑 status=%d body=%s", w4.Code, w4.Body.String())
	}
	if notify.OAuthConfigured() {
		t.Errorf("解绑后 OAuthConfigured 应为 false")
	}
	if notify.GetSetting(notify.KeySMTPOAuthRefreshToken) != "" {
		t.Errorf("解绑后 refresh_token 应清除")
	}
}

func TestSMTPOAuthDeviceCodeStartMissingClientID(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSMTPOAuthRouter(t, 42)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/notification/settings/smtp-oauth",
		strings.NewReader(`{"tenant":"common","client_id":""}`)))
	if w.Code != http.StatusBadGateway {
		t.Errorf("缺 client_id 应 502, got %d", w.Code)
	}
}
