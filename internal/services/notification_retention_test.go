package services

// 通知投递保留清理钉测：读侧保留天数须与写侧校验同源钳位——带外改库/旧备份
// 带入 >Max 的超上限值时按上限裁剪，不得按荒谬天数做无差别保留。

import (
	"context"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestNotificationDeliveryRetentionCleanup_clampsDaysToMax(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	// 带外写入超上限保留期（写侧 UpdateConfig 会拒绝该值）。
	if _, err := db.DB.Exec(`UPDATE global_config SET notification_delivery_retention_days=? WHERE id=1`,
		db.MaxNotificationDeliveryRetentionDays+1350); err != nil {
		t.Fatal(err)
	}
	const layout = "2006-01-02 15:04:05"
	// 超过上限 50 天：钳位后（3650）属于过期行；不钳位（5000）则被保留。
	ancient := time.Now().AddDate(0, 0, -(db.MaxNotificationDeliveryRetentionDays + 50)).UTC().Format(layout)
	recent := time.Now().AddDate(0, 0, -5).UTC().Format(layout)
	insertDelivery := func(title, createdAt string) int64 {
		t.Helper()
		res, err := db.DB.Exec(`INSERT INTO notification_deliveries (user_id,event_type,level,title,status,created_at) VALUES (1,'task','info',?,'sent',?)`, title, createdAt)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		if _, err := db.DB.Exec(`INSERT INTO notification_delivery_channels (delivery_id,user_id,channel_id,channel_type,event_type,status,created_at) VALUES (?,1,1,'wecom','task','sent',?)`, id, createdAt); err != nil {
			t.Fatal(err)
		}
		return id
	}
	ancientID := insertDelivery("ancient", ancient)
	recentID := insertDelivery("recent", recent)

	result, err := NotificationDeliveryRetentionCleanup(context.Background())
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if result.Deliveries != 1 || result.Channels != 1 {
		t.Fatalf("cleanup 删除量=(deliveries=%d, channels=%d), want (1,1)——超上限保留期未钳位",
			result.Deliveries, result.Channels)
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE id=?`, ancientID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("超过上限 50 天的投递记录仍存在（保留期未按 3650 钳位）")
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries WHERE id=?`, recentID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("窗口内投递记录被误删")
	}
}
