package services

// 通知投递保留清理钉测：读侧保留天数须与写侧校验同源钳位——带外改库/旧备份
// 带入 >Max 的超上限值时按上限裁剪，不得按荒谬天数做无差别保留。

import (
	"context"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// initRetentionCleanupDB 装配保留清理用例的临时主库，返回「四句柄成对还原」
// 闭包并注册为 t.Cleanup。后台刷新链消费原子句柄 db.GetDB()：只还原导出
// 变量会让它继续指向已关闭的临时库（顺序相关假红/假绿），故必须同时
// db.SetDB(oldCurrent)。闭包可显式调用（幂等），供还原不变量的钉测使用。
func initRetentionCleanupDB(t *testing.T) func() {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB, oldCurrent := db.DB, db.MetricsDB, db.AuditDB, db.GetDB()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldCurrent)
	}
	t.Cleanup(restore)
	return restore
}

func TestInitRetentionCleanupDB_restoresAtomicDBHandle(t *testing.T) {
	// 外层活动库（模拟同包前序夹具已装配的库）：还原后 db.GetDB() 必须指回
	// 它，而不是内层临时库（已关闭）或 nil。
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize outer database: %v", err)
	}
	outer := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = nil, nil, nil
		db.SetDB(nil)
	})

	restore := initRetentionCleanupDB(t)
	inner := db.GetDB()
	if inner == nil || inner == outer {
		t.Fatalf("内层夹具必须装配自己的原子句柄（inner=%p outer=%p）", inner, outer)
	}
	restore()
	if got := db.GetDB(); got != outer {
		t.Fatalf("还原后 db.GetDB()=%p，必须指回外层库 %p（只还原导出变量会让后台读路径空转/读到已关闭的临时库）", got, outer)
	}
	if db.DB != outer {
		t.Fatalf("还原后 db.DB=%p，want 外层库 %p", db.DB, outer)
	}
}

func TestNotificationDeliveryRetentionCleanup_clampsDaysToMax(t *testing.T) {
	initRetentionCleanupDB(t)
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
