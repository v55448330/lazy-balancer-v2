package services

// 调度读侧句柄契约：auto-backup/threat/crawler 的 EnabledFn/stateFn 读点必须
// 经 db.GetDB 原子句柄（与 versionTableAutoUpdateState 同口径）——db.DB 裸读
// 在库交换窗口会读到旧句柄/已关闭库。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestScheduleReads_followAtomicDBHandle(t *testing.T) {
	database := setupIsolatedDB(t)
	isolateMetricsState(t)
	if _, err := database.Exec(`UPDATE global_config SET threat_auto_update=1, crawler_auto_update=1, auto_backup_enabled=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	// 库交换窗口形态：全局变量仍指向旧句柄，原子句柄已登记新库。
	// 读侧必须跟随原子句柄（生产 Initialize/SetDB 双写，此处分叉钉读侧口径）。
	db.DB = nil

	if enabled, known := globalTaskAutoUpdateState("threat"); !known || !enabled {
		t.Fatalf("threat state=(%v,%v), want (true,true)（读侧必须走 db.GetDB）", enabled, known)
	}
	if enabled, known := globalTaskAutoUpdateState("crawler"); !known || !enabled {
		t.Fatalf("crawler state=(%v,%v), want (true,true)（读侧必须走 db.GetDB）", enabled, known)
	}
	if enabled, known := AutoBackupEnabledState(); !known || !enabled {
		t.Fatalf("auto-backup state=(%v,%v), want (true,true)（读侧必须走 db.GetDB）", enabled, known)
	}
	row, err := loadAutoBackupSettings()
	if err != nil || !row.enabled {
		t.Fatalf("loadAutoBackupSettings=(%+v,%v), want enabled row（读侧必须走 db.GetDB）", row, err)
	}
	if _, ok := nextAutoBackupSlot(time.Now()); !ok {
		t.Fatal("nextAutoBackupSlot ok=false, want 正常算槽（读侧必须走 db.GetDB）")
	}
}
