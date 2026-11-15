package services

// 自动备份水位线推进的关停交错钉测：advanceAutoBackupWatermark 在引擎
// 排空放弃后仍可能跑（在途备份轮落定尾部），此时 db.Close() 已把句柄置 nil。
// 与 auditRetentionMonths 同口径：ctx 贯穿 + 局部快照 + nil 守卫——
// 不得 nil 解引用 panic，也不得在「已注销」句柄上继续写。

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// seedWatermarkSettings 种每日 03:00 的自动备份设置与既有水位线。
func seedWatermarkSettings(t *testing.T, lastRun string) {
	t.Helper()
	if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_enabled=1, auto_backup_frequency='daily',
		auto_backup_time='03:00', auto_backup_last_run=? WHERE id=1`, lastRun); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
}

// Given 关停已把句柄注销（GetDB()=nil，db.DB 残留旧句柄——Close 序列
// SetDB(nil) 先于 DB=nil 的真实交错形态）。
// When 在途备份轮尾部推进水位线。
// Then 返回可见错误（本轮落 failed 触发退避），不 panic、不写任何库。
func TestAdvanceAutoBackupWatermark_nilAtomicHandleErrors(t *testing.T) {
	setupAutoBackupTestDB(t)
	seedWatermarkSettings(t, "2025-12-31T03:00:00Z")
	oldCurrent := db.GetDB()
	db.SetDB(nil) // db.DB 保持非 nil：读同步句柄的实现会在已注销句柄上照写
	t.Cleanup(func() { db.SetDB(oldCurrent) })

	trigger := time.Date(2026, 1, 2, 2, 58, 0, 0, time.UTC)
	err := advanceAutoBackupWatermark(context.Background(), trigger)
	if err == nil {
		t.Fatal("句柄已注销时推进水位线必须返回错误（不得静默成功或在已注销句柄上写）")
	}
	var stored string
	if err := oldCurrent.QueryRow(`SELECT auto_backup_last_run FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatalf("read watermark: %v", err)
	}
	if stored != "2025-12-31T03:00:00Z" {
		t.Fatalf("已注销句柄上的水位线被改写: %q", stored)
	}
}

// Given 关停/角色降级已发出取消。
// When 推进水位线。
// Then 按取消原因返回（不把查询拖过关停预算），水位线零改写。
func TestAdvanceAutoBackupWatermark_cancelledContextSkipsWrite(t *testing.T) {
	setupAutoBackupTestDB(t)
	seedWatermarkSettings(t, "2025-12-31T03:00:00Z")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	trigger := time.Date(2026, 1, 2, 2, 58, 0, 0, time.UTC)
	err := advanceAutoBackupWatermark(ctx, trigger)
	if err == nil {
		t.Fatal("取消已发出时推进水位线必须按 ctx 返回错误")
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT auto_backup_last_run FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatalf("read watermark: %v", err)
	}
	if stored != "2025-12-31T03:00:00Z" {
		t.Fatalf("取消后水位线被改写: %q", stored)
	}
}

// 回归形状：句柄健康 + 未取消时照常推进（修复不得把正常记账改成恒失败）。
func TestAdvanceAutoBackupWatermark_healthyHandleAdvances(t *testing.T) {
	setupAutoBackupTestDB(t)
	seedWatermarkSettings(t, "2025-12-31T03:00:00Z")
	trigger := time.Date(2026, 1, 2, 2, 58, 0, 0, time.UTC)
	if err := advanceAutoBackupWatermark(context.Background(), trigger); err != nil {
		t.Fatalf("健康句柄推进失败: %v", err)
	}
	var stored sql.NullString
	if err := db.DB.QueryRow(`SELECT auto_backup_last_run FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatalf("read watermark: %v", err)
	}
	parsed, err := time.Parse(time.RFC3339, stored.String)
	if err != nil || !parsed.Equal(time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)) {
		t.Fatalf("watermark=%q (%v), want 2026-01-01T03:00:00Z（触发时刻的最近过去槽）", stored.String, err)
	}
}

// Given 关停交错的另一形态：db.DB 已被 Close 置 nil，而原子注册句柄
// 仍指向刚关闭的池（SetDB(nil) 与 DB=nil 之间的窗口/带外直清）。
// When 在途备份轮尾部推进水位线。
// Then 对快照句柄的查询返回真实驱动错误（sql: database is closed），
// 本轮落 failed——不得 nil 解引用 panic 掉进程。
func TestAdvanceAutoBackupWatermark_closedHandleReturnsDriverError(t *testing.T) {
	setupAutoBackupTestDB(t)
	seedWatermarkSettings(t, "2025-12-31T03:00:00Z")
	closed, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	oldDB, oldCurrent := db.DB, db.GetDB()
	db.DB = nil
	db.SetDB(closed)
	t.Cleanup(func() {
		db.DB = oldDB
		db.SetDB(oldCurrent)
	})

	trigger := time.Date(2026, 1, 2, 2, 58, 0, 0, time.UTC)
	err = advanceAutoBackupWatermark(context.Background(), trigger)
	if err == nil {
		t.Fatal("已关闭句柄上推进水位线必须返回错误（读同步句柄的实现会 nil 解引用 panic）")
	}
}
