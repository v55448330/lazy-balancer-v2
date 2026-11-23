package services

// 保留清理批间取消必须返回可见错误（旧实现 return nil, result 把中断轮
// 谎报成「清理完成」）。

import (
	"context"
	"errors"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestNotificationDeliveryRetentionCleanup_cancelBetweenBatchesReportsError(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	ancient := time.Now().AddDate(0, 0, -60).UTC().Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO notification_deliveries (user_id,event_type,level,title,status,created_at) VALUES (1,'task','info','old','sent',?)`, ancient); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 批间检查立即命中取消

	result, err := NotificationDeliveryRetentionCleanup(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后必须返回 context.Canceled（不得伪装成功），got %v", err)
	}
	if result.Deliveries != 1 {
		t.Fatalf("已删除行必须计入部分计数，got %d want 1", result.Deliveries)
	}
}
