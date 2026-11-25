package handlers

// 规则保存的通道就绪门（矩阵分支）：显式非空选择被 sanitizeRuleChannelIDs
// 清洗为空时必须 400（不得静默落 "[]" 变成「显式不投递」，也不得让失效
// 通道的选择看起来保存成功）。

import (
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestUpdateNotificationRule_rejectsSelectionEmptiedByReadinessGate(t *testing.T) {
	h := newBackupTestHandlers(t)
	gid := certGroupID(t)
	// 已测试失败通道（就绪门剔除）；未测试通道保留（不算已知失败）。
	if _, err := db.DB.Exec(`INSERT INTO notification_channels (id, user_id, type, name, target, enabled, last_test_at, last_test_ok) VALUES
		(801, 7, 'email', '坏通道', '{"email":"a@b.c"}', 1, '2026-11-20 10:00:00', 0),
		(802, 7, 'email', '未测通道', '{"email":"c@d.e"}', 1, '', 0)`); err != nil {
		t.Fatalf("seed channels: %v", err)
	}
	r := newRulesTestRouter(h, 7, "user")

	status, out := doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+gid, `{"enabled":true,"channel_ids":[801]}`)
	if status != http.StatusBadRequest {
		t.Fatalf("失效选择 status=%d body=%v, want 400（不得静默保存为空）", status, out)
	}
	if out["message_key"] != "notify.selectedChannelsAllUnavailable" {
		t.Fatalf("message_key=%v, want %s", out["message_key"], "notify.selectedChannelsAllUnavailable")
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_subscriptions WHERE user_id=7 AND event_type='cert.failed'`).Scan(&rows); err != nil {
		t.Fatalf("count subscription: %v", err)
	}
	if rows != 0 {
		t.Fatalf("400 后仍落库 %d 行, want 0（事务回滚）", rows)
	}

	// 未测试通道保留：选择成功并原样落库
	status, out = doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+gid, `{"enabled":true,"channel_ids":[802]}`)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("未测通道保存 status=%d body=%v", status, out)
	}
	var ids string
	if err := db.DB.QueryRow(`SELECT channel_ids FROM notification_subscriptions WHERE user_id=7 AND event_type='cert.failed'`).Scan(&ids); err != nil {
		t.Fatalf("回读订阅: %v", err)
	}
	if ids != "[802]" {
		t.Fatalf("channel_ids=%q, want [802]", ids)
	}

	// 显式空数组仍合法（=显式不投递）
	status, out = doNotifyRequest(t, r, http.MethodPost, "/notification/rules/"+gid, `{"channel_ids":[]}`)
	if status != http.StatusOK || out["code"].(float64) != 0 {
		t.Fatalf("显式空选 status=%d body=%v", status, out)
	}
	if err := db.DB.QueryRow(`SELECT channel_ids FROM notification_subscriptions WHERE user_id=7 AND event_type='cert.failed'`).Scan(&ids); err != nil || ids != "[]" {
		t.Fatalf("显式空选 channel_ids=%q err=%v, want []", ids, err)
	}
}
