package handlers

// 通道就绪门写侧（2026-11-22 用户裁定）：规则保存时清洗不可发送的通道选择
// ——微信会话失效（会话待刷新）通道从 channel_ids 中剔除（取消选择），
// 直到重新绑定就绪后用户可再次选择。

import (
	"database/sql"
	"testing"
)

func TestSanitizeRuleChannelIDs_dropsStaleWxSession(t *testing.T) {
	database, err := sql.Open("sqlite", t.TempDir()+"/readiness.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if _, err := database.Exec(`CREATE TABLE notification_channels (
		id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL,
		name TEXT NOT NULL, target TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
		last_test_ok INTEGER DEFAULT 0, last_test_at TEXT DEFAULT '', style_config TEXT DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	// 1=邮件就绪；2=微信无会话上下文（stale）；3=已停用
	if _, err := database.Exec(`INSERT INTO notification_channels (user_id,type,name,target,enabled,last_test_ok) VALUES
		(1,'email','test','{"email":"a@b.c"}',1,1),
		(1,'wx_clawbot','微信测试','{"receiver":"wxid-x"}',1,1),
		(1,'email','停用','{"email":"x@y.z"}',0,1)`); err != nil {
		t.Fatal(err)
	}
	got := sanitizeRuleChannelIDs(database, 1, []int64{1, 2, 3})
	if len(got) != 1 || got[0] != 1 {
		t.Fatalf("清洗后应仅保留就绪通道 [1]，实际 %v", got)
	}
}

// 已知测试失败门（与保存清洗同口径）：last_test_at 非空且 last_test_ok=0 的通道
// 是「已知不可发送」，写入侧必须剔除；从未测试（last_test_at 空）保留——
// 未测≠失败，提前剔除会让用户无法配置新通道。
func TestSanitizeRuleChannelIDs_dropsKnownFailedChannel(t *testing.T) {
	database, err := sql.Open("sqlite", t.TempDir()+"/readiness-failed.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if _, err := database.Exec(`CREATE TABLE notification_channels (
		id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL,
		name TEXT NOT NULL, target TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
		last_test_ok INTEGER DEFAULT 0, last_test_at TEXT DEFAULT '', style_config TEXT DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	// 1=已测试通过；2=已测试失败（剔除）；3=从未测试（保留）
	if _, err := database.Exec(`INSERT INTO notification_channels (id,user_id,type,name,target,enabled,last_test_at,last_test_ok) VALUES
		(1,1,'email','通过','{"email":"a@b.c"}',1,'2026-11-20 10:00:00',1),
		(2,1,'email','失败','{"email":"c@d.e"}',1,'2026-11-20 10:00:00',0),
		(3,1,'email','未测','{"email":"x@y.z"}',1,'',0)`); err != nil {
		t.Fatal(err)
	}
	got := sanitizeRuleChannelIDs(database, 1, []int64{1, 2, 3})
	if len(got) != 2 || got[0] != 1 || got[1] != 3 {
		t.Fatalf("清洗后应保留 [1 3]（已测失败剔除/未测保留），实际 %v", got)
	}
}
