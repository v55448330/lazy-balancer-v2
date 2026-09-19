package services

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// SEC42-2（第 42 轮审计）：CRS run() 起点角色复查的 is_master NULL 口径须与
// services.IsMaster / readonly 写闸 / 调度器 tick 一致（COALESCE(is_master,1)，
// 历史 NULL 视为主节点 fail-open）——NULL 行不应把主节点误判为从节点而中止更新。
func TestCRSUpdateRun_nullIsMasterRunsAsMaster(t *testing.T) {
	// Given a master-role row whose is_master is legacy NULL
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=NULL WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.14.0", nil }
	downloadCalled := false
	m.downloadTarball = func(context.Context, string, string, downloadProgressFunc) error { downloadCalled = true; return nil }

	// When the update pipeline runs
	m.run("auto")

	// Then it executes as master and reaches the latest-version skip branch
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "success" || message != "已是最新版本" {
		t.Fatalf("update_status=%q message=%q, want success/已是最新版本（NULL is_master 应按主节点执行）", status, message)
	}
	if downloadCalled {
		t.Fatal("must skip download when remote tag equals current version")
	}
}

// SEC42-2 回归形状：is_master=0 的从节点仍必须中止（语义不得翻转）。
func TestCRSUpdateRun_slaveAborts(t *testing.T) {
	// Given a slave-role row
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.14.0", nil }
	downloadCalled := false
	m.downloadTarball = func(context.Context, string, string, downloadProgressFunc) error { downloadCalled = true; return nil }

	// When the update pipeline runs
	m.run("auto")

	// Then it aborts before recording any terminal state（行保持种子默认 idle）
	_, status, _, _, _, _, _ := crsVersionRow(t)
	if status != "idle" {
		t.Fatalf("update_status=%q, want idle（从节点不得落终态）", status)
	}
	if downloadCalled {
		t.Fatal("slave node must not download")
	}
}
