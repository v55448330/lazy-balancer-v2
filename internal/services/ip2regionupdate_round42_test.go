package services

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// SEC42-1（第 42 轮审计）：ip2region 更新的「已是最新」判定须与 CRS
// （crsupdate.go，CRS-1）同口径——远端 tag 不新于当前版本（cmp<=0）即跳过，
// 防止上游 release 回退/删除时把本地 xdb 静默降级为更旧版本；格式不可比
// （cmpErr!=nil）保持「不等即更新」的既有行为。
func TestIP2RegionUpdateRun_versionComparisonGate(t *testing.T) {
	cases := []struct {
		name         string
		current      string
		remoteTag    string
		wantDownload bool
		wantVersion  string
		wantMessage  string
	}{
		// 目标形状：远端更旧 → 跳过（现行精确相等判定会下载安装更旧库）
		{"older remote tag skipped", "v4.5.0", "v4.4.0", false, "v4.5.0", "已是最新版本"},
		// 回归形状：相等 → 跳过
		{"equal remote tag skipped", "v4.5.0", "v4.5.0", false, "v4.5.0", "已是最新版本"},
		// 回归形状：远端更新 → 照常更新
		{"newer remote tag updates", "v4.4.0", "v4.5.0", true, "v4.5.0", ""},
		// 畸形形状：tag 不可解析 → 保持「不等即更新」
		{"malformed remote tag updates", "v4.5.0", "not-a-version", true, "not-a-version", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given a stored current version and a remote tag
			m := newTestIP2RegionManager(t)
			seedIP2RegionVersionRow(t, tc.current, true)
			m.fetchLatestTag = func(context.Context) (string, error) { return tc.remoteTag, nil }
			downloadCalled := false
			m.downloadXDB = func(ctx context.Context, tag, dest string, progress downloadProgressFunc) error {
				downloadCalled = true
				return fakeIP2RegionDownload(t, true)(ctx, tag, dest, progress)
			}
			reloads := 0
			m.reloader = func() error { reloads++; return nil }

			// When the update pipeline runs
			m.run("auto")

			// Then the version comparison gate decides skip vs update
			if downloadCalled != tc.wantDownload {
				t.Fatalf("downloadCalled=%v, want %v", downloadCalled, tc.wantDownload)
			}
			version, status, message, _, _, _, _ := ip2RegionVersionRow(t)
			if status != "success" {
				t.Fatalf("update_status=%q, want success", status)
			}
			if version != tc.wantVersion {
				t.Fatalf("version=%q, want %q", version, tc.wantVersion)
			}
			if message != tc.wantMessage {
				t.Fatalf("message=%q, want %q", message, tc.wantMessage)
			}
		})
	}
}

// SEC42-2（第 42 轮审计）：run() 起点角色复查的 is_master NULL 口径须与
// services.IsMaster / readonly 写闸 / 调度器 tick 一致（COALESCE(is_master,1)，
// 历史 NULL 视为主节点 fail-open）——NULL 行不应把主节点误判为从节点而中止更新。
func TestIP2RegionUpdateRun_nullIsMasterRunsAsMaster(t *testing.T) {
	// Given a master-role row whose is_master is legacy NULL
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=NULL WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.0.0", nil }
	downloadCalled := false
	m.downloadXDB = func(context.Context, string, string, downloadProgressFunc) error { downloadCalled = true; return nil }

	// When the update pipeline runs
	m.run("auto")

	// Then it executes as master and reaches the latest-version skip branch
	_, status, message, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "success" || message != "已是最新版本" {
		t.Fatalf("update_status=%q message=%q, want success/已是最新版本（NULL is_master 应按主节点执行）", status, message)
	}
	if downloadCalled {
		t.Fatal("must skip download when remote tag equals current version")
	}
}

// SEC42-2 回归形状：is_master=0 的从节点仍必须中止（语义不得翻转）。
func TestIP2RegionUpdateRun_slaveAborts(t *testing.T) {
	// Given a slave-role row
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.0.0", nil }
	downloadCalled := false
	m.downloadXDB = func(context.Context, string, string, downloadProgressFunc) error { downloadCalled = true; return nil }

	// When the update pipeline runs
	m.run("auto")

	// Then it aborts before recording any terminal state（行保持种子默认 idle）
	_, status, _, _, _, _, _ := ip2RegionVersionRow(t)
	if status != "idle" {
		t.Fatalf("update_status=%q, want idle（从节点不得落终态）", status)
	}
	if downloadCalled {
		t.Fatal("slave node must not download")
	}
}
