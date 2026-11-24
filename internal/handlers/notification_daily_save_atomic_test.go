package handlers

import (
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

// 日报规则保存必须原子：日报配置（notification_daily）与订阅行
// （notification_subscriptions）任一失败都不能留下半写状态——否则管理员
// 看到「保存失败」，刷新后时间/项目已改而通道选择仍旧，UI 与真实投递面分叉。
func TestUpdateNotificationRule_dailySaveAtomic(t *testing.T) {
	h := newBackupTestHandlers(t)
	if err := notify.SaveDailyConfig(notify.DailyConfig{
		UserID: 7, Enabled: true, SendTime: "09:00", Items: []string{"requests"}, Formats: map[string]string{},
	}); err != nil {
		t.Fatalf("seed daily config: %v", err)
	}
	// 制造订阅行写失败（日报配置写与订阅写必须同事务）。
	if _, err := db.DB.Exec(`ALTER TABLE notification_subscriptions RENAME TO notification_subscriptions_broken`); err != nil {
		t.Fatalf("rename subscriptions table: %v", err)
	}
	r := newNotificationDailyRouter(h, 7, "user")
	status, _ := doNotifyRequest(t, r, http.MethodPost, "/notification/rules/daily", `{"send_time":"10:30","items":["requests"]}`)
	if status != http.StatusInternalServerError {
		t.Fatalf("订阅写失败时 status=%d, want 500", status)
	}
	cfg, err := notify.GetDailyConfig(7)
	if err != nil {
		t.Fatalf("read back daily config: %v", err)
	}
	if cfg.SendTime != "09:00" {
		t.Fatalf("日报配置已半写：send_time=%q, want 09:00（订阅写失败必须整体回滚）", cfg.SendTime)
	}
}
