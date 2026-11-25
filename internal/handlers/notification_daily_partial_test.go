package handlers

// 日报端点部分更新 / 通道就绪门（2026-11-22）：
//   - PUT /notification/daily 的 enabled 是 *bool：缺省键不得静默停用日报
//     （非指针 bool 让任何只改 send_time 的调用方写 enabled=false）。
//   - POST /notification/rules/daily 的 channel_ids 与事件矩阵同口径走
//     sanitizeRuleChannelIDs；非空选择被清洗为空=400（不得静默落 "[]"
//     把规则变成「显式不投递」）。

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

func newNotificationDailyRouter(h *Handlers, uid int64, role string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", uid)
		c.Set("role", role)
		c.Set("username", "tester")
		c.Next()
	})
	r.PUT("/notification/daily", h.PutNotificationDaily)
	r.POST("/notification/rules/:id", h.UpdateNotificationRule)
	return r
}

func TestPutNotificationDaily_omittedEnabledPreservesState(t *testing.T) {
	h := newBackupTestHandlers(t)
	if err := notify.SaveDailyConfig(notify.DailyConfig{
		UserID: 7, Enabled: true, SendTime: "09:00", Items: []string{"requests"}, Formats: map[string]string{},
	}); err != nil {
		t.Fatalf("seed daily config: %v", err)
	}
	r := newNotificationDailyRouter(h, 7, "user")

	status, out := doNotifyRequest(t, r, http.MethodPut, "/notification/daily", `{"send_time":"10:30"}`)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("partial put status=%d body=%v", status, out)
	}
	cfg, err := notify.GetDailyConfig(7)
	if err != nil {
		t.Fatalf("read back daily config: %v", err)
	}
	if !cfg.Enabled {
		t.Fatalf("缺省 enabled 键后 enabled=false（静默停用），want 保持 true")
	}
	if cfg.SendTime != "10:30" {
		t.Fatalf("send_time=%q, want 10:30", cfg.SendTime)
	}

	// 显式 false 仍然生效（部分更新≠忽略该键）
	status, out = doNotifyRequest(t, r, http.MethodPut, "/notification/daily", `{"enabled":false,"send_time":"10:30"}`)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("explicit disable status=%d body=%v", status, out)
	}
	if cfg, err = notify.GetDailyConfig(7); err != nil || cfg.Enabled {
		t.Fatalf("显式 enabled=false 未生效: enabled=%v err=%v", cfg.Enabled, err)
	}
}

func TestUpdateNotificationRule_dailyChannelIDsSanitized(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 601=已测试通过；602=已测试失败（就绪门剔除）。
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled, last_test_at, last_test_ok) VALUES
		(601, 7, 'email', '好通道', '{"email":"a@b.c"}', 1, '2026-11-20 10:00:00', 1),
		(602, 7, 'email', '坏通道', '{"email":"c@d.e"}', 1, '2026-11-20 10:00:00', 0)`); err != nil {
		t.Fatalf("seed channels: %v", err)
	}
	r := newNotificationDailyRouter(h, 7, "user")

	// 混合选择：失效通道被剔除，仅就绪通道落库
	status, out := doNotifyRequest(t, r, http.MethodPost, "/notification/rules/daily", `{"channel_ids":[601,602]}`)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("daily mixed save status=%d body=%v", status, out)
	}
	var ids string
	if err := db.DB.QueryRow(`SELECT channel_ids FROM notification_subscriptions WHERE user_id=7 AND event_type=?`,
		notify.EvtDailyReport).Scan(&ids); err != nil {
		t.Fatalf("日报订阅行未落库: %v", err)
	}
	if strings.TrimSpace(ids) != "[601]" {
		t.Fatalf("channel_ids=%q, want [601]（失效通道剔除）", ids)
	}

	// 全部失效：清洗后为空必须 400，不得落 "[]"（=显式不投递）
	status, out = doNotifyRequest(t, r, http.MethodPost, "/notification/rules/daily", `{"channel_ids":[602]}`)
	if status != http.StatusBadRequest {
		t.Fatalf("daily all-invalid status=%d body=%v, want 400", status, out)
	}
	if out["message_key"] != "notify.selectedChannelsAllUnavailable" {
		t.Fatalf("message_key=%v, want %s", out["message_key"], "notify.selectedChannelsAllUnavailable")
	}
	if err := db.DB.QueryRow(`SELECT channel_ids FROM notification_subscriptions WHERE user_id=7 AND event_type=?`,
		notify.EvtDailyReport).Scan(&ids); err != nil {
		t.Fatalf("回读日报订阅行: %v", err)
	}
	if ids != "[601]" {
		t.Fatalf("400 后 channel_ids=%q, want 保持 [601]（拒绝不得半写）", ids)
	}

	// 显式空数组=不投递，仍然合法
	status, out = doNotifyRequest(t, r, http.MethodPost, "/notification/rules/daily", `{"channel_ids":[]}`)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("daily explicit empty status=%d body=%v", status, out)
	}
	if err := db.DB.QueryRow(`SELECT channel_ids FROM notification_subscriptions WHERE user_id=7 AND event_type=?`,
		notify.EvtDailyReport).Scan(&ids); err != nil || strings.TrimSpace(ids) != "[]" {
		t.Fatalf("显式空选 channel_ids=%q err=%v, want []", ids, err)
	}
}
