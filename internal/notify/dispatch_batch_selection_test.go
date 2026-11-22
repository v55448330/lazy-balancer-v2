package notify

// dispatch 订阅选择批查等价（收尾）：批查结果必须与逐用户
// 单查同口径（显式 '[]' → explicitEmpty；缺行 → 零值=默认订阅）。基线钉
// （钉既有正确行为，R-1 豁免；RED 证据= 审计实读的循环内单查）。

import "testing"

func TestSubscriptionChannelSelectionsFor_matchesSingleLookup(t *testing.T) {
	database := newNotifySchemaDB(t)
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS notification_subscriptions (user_id INTEGER NOT NULL, event_type TEXT NOT NULL,
			min_level TEXT NOT NULL DEFAULT 'info', body_template TEXT NOT NULL DEFAULT '',
			channel_ids TEXT NOT NULL DEFAULT '', channel_templates TEXT NOT NULL DEFAULT '',
			updated_at DATETIME, updated_by INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
			PRIMARY KEY (user_id, event_type))`,
	} {
		if _, err := database.Exec(ddl); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.Exec(`INSERT INTO notification_subscriptions (user_id, event_type, channel_ids) VALUES
		(11, 'cfg.caddy_apply_failed', '[]'),
		(12, 'cfg.caddy_apply_failed', '[7,8]'),
		(13, 'cfg.caddy_apply_failed', '')`); err != nil {
		t.Fatal(err)
	}
	got := subscriptionChannelSelectionsFor("cfg.caddy_apply_failed", []int64{11, 12, 13, 99})
	if !got[11].explicitEmpty {
		t.Fatal("user 11 显式空选未识别（explicitEmpty）")
	}
	if got[12].explicitEmpty || !got[12].ids[7] || !got[12].ids[8] {
		t.Fatalf("user 12 选择集错误: %+v", got[12])
	}
	if got[13].explicitEmpty || len(got[13].ids) != 0 {
		t.Fatalf("user 13 缺省空串应=零值默认语义: %+v", got[13])
	}
	if _, ok := got[99]; ok {
		t.Fatal("缺行用户不应出现在批查结果（零值默认）")
	}
	// 与单查逐字段等价
	for _, uid := range []int64{11, 12, 13} {
		single := subscriptionChannelSelectionFor(uid, "cfg.caddy_apply_failed")
		if single.explicitEmpty != got[uid].explicitEmpty || len(single.ids) != len(got[uid].ids) {
			t.Fatalf("user %d 批查/单查口径分叉: single=%+v batch=%+v", uid, single, got[uid])
		}
	}
}
