package services

// 从端 apply 清桶不变量回归钉：快照携带 autoban 配置列变更时，内存计数桶
// 必须清零（旧计数不可与新口径混算——与 SetAutobanConfig resetCounters 同
// 口径）；未携带 autoban 列的快照不得清桶（对照组防过度清）。

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func TestApplySnapshot_autobanColumnChangeResetsCounters(t *testing.T) {
	_, database := newClusterTestService(t)
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService("http://127.0.0.1:1"))
	ctx := context.Background()

	// 目标形状：快照携带 autoban_window_minutes 变更 → 清桶。
	seedAutobanWindowForRoleTest(t)
	if autobanWindowCountForRoleTest() == 0 {
		t.Fatal("前置失败：陈旧计数未种入")
	}
	newWindow := 10
	snapshot := models.ClusterSnapshot{Version: 2}
	snapshot.BasicSettings.AutobanWindowMinutes = &newWindow
	if err := service.applySnapshot(ctx, snapshot); err != nil {
		t.Fatalf("applySnapshot: %v", err)
	}
	if n := autobanWindowCountForRoleTest(); n != 0 {
		t.Fatalf("autoban 列变更后计数桶残留 %d, want 0（旧计数不可与新口径混算）", n)
	}

	// 对照组：快照未携带任何 autoban 列 → 不得清桶。
	seedAutobanWindowForRoleTest(t)
	snapshotNoAutoban := models.ClusterSnapshot{Version: 3}
	if err := service.applySnapshot(ctx, snapshotNoAutoban); err != nil {
		t.Fatalf("applySnapshot no-autoban: %v", err)
	}
	if n := autobanWindowCountForRoleTest(); n != 1 {
		t.Fatalf("未携带 autoban 列的快照误清桶: 残留 %d, want 1", n)
	}
}
