package handlers

// 后端半边：日报渲染模式开关（style_config.daily_mode）必须在
// validateChannelStyle 白名单内，否则前端保存日报模板恒 400（E1 已复现）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestUpdateNotificationChannel_targetChangeClearsStaleTestStatus(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", int64(7))
		c.Set("username", "tester")
		c.Set("role", "user")
		c.Next()
	})
	r.PUT("/notification/channels/:id", h.UpdateNotificationChannel)

	res, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, style_config, enabled, last_test_ok, last_test_at, created_at, updated_at)
		VALUES (7, 'qq', 'bot', '{"openid":"o1","appid":"a","secret":"s"}', '{}', 1, 0, datetime('now'), datetime('now'), datetime('now'))`)
	if err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	id, _ := res.LastInsertId()
	path := "/notification/channels/" + strconv.FormatInt(id, 10)

	// 目标变更：旧失败结论清空为未验证。
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(`{"target":"{\"openid\":\"o2\",\"appid\":\"a\",\"secret\":\"s\"}"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("target change status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var testOK *int
	var testAt *string
	if err := db.DB.QueryRow(`SELECT last_test_ok, last_test_at FROM notification_channels WHERE id=?`, id).Scan(&testOK, &testAt); err != nil {
		t.Fatal(err)
	}
	if testOK != nil || testAt != nil {
		t.Fatalf("target change testOK=%v testAt=%v, want NULL/NULL（旧验证结论失效）", testOK, testAt)
	}

	// 非目标编辑（改名）不得清空既有验证结论。
	if _, err := db.DB.Exec(`UPDATE notification_channels SET last_test_ok=1, last_test_at=datetime('now') WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, path, strings.NewReader(`{"name":"renamed"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var ok int
	if err := db.DB.QueryRow(`SELECT last_test_ok FROM notification_channels WHERE id=?`, id).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	if ok != 1 {
		t.Fatalf("rename last_test_ok=%d, want 1（未改目标不得清空）", ok)
	}
}

func TestUpdateNotificationChannel_acceptsDailyModeStyle(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", int64(7))
		c.Set("username", "tester")
		c.Set("role", "user")
		c.Next()
	})
	r.POST("/notification/channels", h.CreateNotificationChannel)
	r.PUT("/notification/channels/:id", h.UpdateNotificationChannel)

	res, err := db.DB.Exec(`INSERT INTO notification_channels (user_id, type, name, target, style_config, enabled, created_at, updated_at)
		VALUES (7, 'qq', 'bot', '{"openid":"o"}', '{}', 1, datetime('now'), datetime('now'))`)
	if err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	id, _ := res.LastInsertId()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/notification/channels/"+strconv.FormatInt(id, 10),
		strings.NewReader(`{"style_config":{"daily_mode":"modules","content_template":"x"}}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("daily_mode=modules status=%d body=%s，want 200", rec.Code, rec.Body.String())
	}
	var raw string
	if err := db.DB.QueryRow(`SELECT style_config FROM notification_channels WHERE id=?`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		t.Fatalf("style_config 非 JSON: %v (%s)", err, raw)
	}
	if stored["daily_mode"] != "modules" || stored["content_template"] != "x" {
		t.Fatalf("回读 style_config=%s，want daily_mode=modules + content_template=x", raw)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/notification/channels/"+strconv.FormatInt(id, 10),
		strings.NewReader(`{"style_config":{"daily_mode":"bogus"}}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("daily_mode=bogus status=%d body=%s，want 400", rec.Code, rec.Body.String())
	}
}
