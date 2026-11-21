package handlers

// FE154-P1-01 后端半边：日报渲染模式开关（style_config.daily_mode）必须在
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
