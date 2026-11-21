package handlers

// audit154 通知规则聚合端点修复钉测：
//   - HDL154-P3-02：概览/趋势/分布读失败必须 500（不得静默展示全零）；
//   - HDL154-P3-03：聚合规则写端点复用兄弟端点的 min_level/send_time/items
//     白名单校验；
//   - HDL154-P3-04：组写单事务（失败零部分写入）+ 读错误区分 ErrNoRows。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

func TestUpdateNotificationRule_rejectsInvalidDailyFields(t *testing.T) {
	h := newBackupTestHandlers(t)
	r := newRulesTestRouter(h, 7, "user")

	status, out := doNotifyRequest(t, r, http.MethodPost, "/notification/rules/daily", `{"send_time":"25:99"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("非法 send_time status=%d body=%v，want 400", status, out)
	}
	status, out = doNotifyRequest(t, r, http.MethodPost, "/notification/rules/daily", `{"items":["not-a-daily-item"]}`)
	if status != http.StatusBadRequest {
		t.Fatalf("未知日报项目 status=%d body=%v，want 400", status, out)
	}
	// 拒绝不得落库（配置仍是默认值）。
	cfg, err := notify.GetDailyConfig(7)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SendTime == "25:99" {
		t.Fatalf("非法 send_time 已落库: %+v", cfg)
	}
}

func TestUpdateNotificationRule_rejectsInvalidMinLevel(t *testing.T) {
	h := newBackupTestHandlers(t)
	r := newRulesTestRouter(h, 7, "user")
	gid := certGroupID(t)

	status, out := doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+gid, `{"enabled":true,"min_level":"urgent"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("非法 min_level status=%d body=%v，want 400", status, out)
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_subscriptions WHERE user_id=7 AND min_level='urgent'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("非法 min_level 落库 %d 行", count)
	}
}

func TestUpdateNotificationRule_groupWriteIsAtomic(t *testing.T) {
	h := newBackupTestHandlers(t)
	gid := certGroupID(t)
	group := strings.TrimPrefix(gid, "group:")
	var eventIDs []string
	for _, e := range notify.CatalogExport() {
		if e.Group == group {
			eventIDs = append(eventIDs, e.ID)
		}
	}
	if len(eventIDs) < 2 {
		t.Fatalf("证书组事件数=%d，需要 ≥2 才能验证事务原子性", len(eventIDs))
	}
	last := eventIDs[len(eventIDs)-1]
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_last_group_event BEFORE INSERT ON notification_subscriptions
		WHEN NEW.event_type='` + last + `' BEGIN SELECT RAISE(ABORT, 'forced'); END;`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec(`DROP TRIGGER IF EXISTS fail_last_group_event`) })

	r := newRulesTestRouter(h, 7, "user")
	status, out := doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+gid,
		`{"enabled":true,"min_level":"warn","channel_ids":[1]}`)
	if status != http.StatusInternalServerError {
		t.Fatalf("事务内失败 status=%d body=%v，want 500", status, out)
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_subscriptions WHERE user_id=7`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("组写失败后残留 %d 行订阅（必须整组回滚）", count)
	}
}

func TestNotificationAdminStats_failVisibleOnReadError(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", int64(1))
		c.Set("role", "admin")
		c.Set("username", "tester")
		c.Next()
	})
	r.GET("/overview", h.GetAdminNotificationOverview)
	r.GET("/trend", h.GetDeliveryTrend)
	r.GET("/stats", h.GetDeliveryStats)

	// 读故障注入：删表 → 三个聚合端点必须 500（此前静默吞成零值/空图）。
	for _, table := range []string{"notification_deliveries", "notification_delivery_channels", "notification_channels", "notification_subscriptions"} {
		if _, err := db.DB.Exec(`DROP TABLE IF EXISTS ` + table); err != nil {
			t.Fatalf("drop %s: %v", table, err)
		}
	}
	for _, path := range []string{"/overview", "/trend", "/stats"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%s status=%d body=%s, want 500（读失败必须 fail-visible）", path, rec.Code, rec.Body.String())
		}
	}
}
