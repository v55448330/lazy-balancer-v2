package handlers

// 日报规则聚合的通道三态：ChannelIDs 读 sys.daily_report 订阅行后，
// Channels 必须与事件规则同口径按选择过滤——此前日报恒回全部启用通道，
// 与真实投递面（daemon 消费 channel_ids 三态）不一致。

import (
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

func dailyRuleFromResponse(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	data, _ := out["data"].(map[string]any)
	rules, _ := data["rules"].([]any)
	for _, raw := range rules {
		row, _ := raw.(map[string]any)
		if row["id"] == "daily" {
			return row
		}
	}
	t.Fatalf("响应缺少日报规则: %v", rules)
	return nil
}

func TestGetNotificationRules_dailyChannelsReflectChannelSelection(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled, last_test_ok) VALUES
		(701, 7, 'email', '邮箱一', '{"email":"a@b.c"}', 1, 1),
		(702, 7, 'email', '邮箱二', '{"email":"c@d.e"}', 1, 1)`); err != nil {
		t.Fatalf("seed channels: %v", err)
	}
	r := newRulesTestRouter(h, 7, "user")

	// 1) 无订阅行=缺省（全部启用通道）
	status, out := doNotifyRequest(t, r, http.MethodGet, "/notification/rules", "")
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("rules status=%d body=%v", status, out)
	}
	daily := dailyRuleFromResponse(t, out)
	if channels, _ := daily["channels"].([]any); len(channels) != 2 {
		t.Fatalf("缺省时 channels=%v, want 全部启用通道 2 个", daily["channels"])
	}
	if ids, ok := daily["channel_ids"].([]any); ok && len(ids) != 0 {
		t.Fatalf("缺省时 channel_ids=%v, want 空（nil）", daily["channel_ids"])
	}

	// 2) 显式选定子集=仅该通道
	if _, err := db.DB.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, channel_ids) VALUES (?,?,'[701]')`,
		int64(7), notify.EvtDailyReport); err != nil {
		t.Fatalf("seed daily subscription: %v", err)
	}
	status, out = doNotifyRequest(t, r, http.MethodGet, "/notification/rules", "")
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("rules status=%d body=%v", status, out)
	}
	daily = dailyRuleFromResponse(t, out)
	channels, _ := daily["channels"].([]any)
	if len(channels) != 1 {
		t.Fatalf("选定 701 后 channels=%v, want 仅 1 个", daily["channels"])
	}
	if row, _ := channels[0].(map[string]any); row["id"] != float64(701) {
		t.Fatalf("选定通道 id=%v, want 701", row["id"])
	}
	ids, _ := daily["channel_ids"].([]any)
	if len(ids) != 1 || ids[0] != float64(701) {
		t.Fatalf("channel_ids=%v, want [701]", daily["channel_ids"])
	}

	// 3) 显式空选=不投递（channels 必须为空，不得回退全部）
	if _, err := db.DB.Exec(`UPDATE notification_subscriptions SET channel_ids='[]' WHERE user_id=? AND event_type=?`,
		int64(7), notify.EvtDailyReport); err != nil {
		t.Fatalf("update daily subscription: %v", err)
	}
	status, out = doNotifyRequest(t, r, http.MethodGet, "/notification/rules", "")
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("rules status=%d body=%v", status, out)
	}
	daily = dailyRuleFromResponse(t, out)
	if channels, _ := daily["channels"].([]any); len(channels) != 0 {
		t.Fatalf("显式空选 channels=%v, want 空（不投递语义）", daily["channels"])
	}
	ids, _ = daily["channel_ids"].([]any)
	if ids == nil || len(ids) != 0 {
		t.Fatalf("显式空选 channel_ids=%v, want 空数组 []", daily["channel_ids"])
	}
}
