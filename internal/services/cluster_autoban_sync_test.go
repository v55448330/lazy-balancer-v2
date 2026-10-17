package services

// D1（第 74 轮审计·R74C）：自动封禁六列集群传播四段接线钉测——
//   ①主端快照恒携带六列（指针非 nil+线格式六键，镜像 CL41-1 自动备份组）；
//   ②快照携带时从端 apply 落库；③旧主端快照缺席（全 nil）时从端保留本地值；
//   ④主端保存（列变化）→ OF 触发器 bump（middleware 侧钉）→ 快照 → 从端收敛；
//   ⑤升主后按 AutobanEnabled() 重开 autoban 调度（从端期间调度未开）。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func TestLoadSnapshotGlobalSettings_carriesAutobanSettings(t *testing.T) {
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET autoban_enabled=1, autoban_threshold=42, autoban_window_minutes=13,
		autoban_duration='24h', autoban_scope='blocked', autoban_dry_run=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	s := snapshot.BasicSettings
	if s.AutobanEnabled == nil || !*s.AutobanEnabled ||
		s.AutobanThreshold == nil || *s.AutobanThreshold != 42 ||
		s.AutobanWindowMinutes == nil || *s.AutobanWindowMinutes != 13 ||
		s.AutobanDuration == nil || *s.AutobanDuration != "24h" ||
		s.AutobanScope == nil || *s.AutobanScope != "blocked" ||
		s.AutobanDryRun == nil || *s.AutobanDryRun {
		t.Fatalf("autoban settings=%+v, want six non-nil pointers carrying DB values", s)
	}
	// 线格式：六键必须出现在 basic_settings JSON（omitempty 仅省 nil，
	// 即旧主端缺席形态；新主端恒携带）。
	wire, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"autoban_enabled":true`, `"autoban_threshold":42`, `"autoban_window_minutes":13`,
		`"autoban_duration":"24h"`, `"autoban_scope":"blocked"`, `"autoban_dry_run":false`,
	} {
		if !strings.Contains(string(wire), want) {
			t.Fatalf("wire basic_settings=%s, must contain %s", wire, want)
		}
	}
}

func TestUpdateSnapshotSettings_autobanSettingsAppliedWhenPresent(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	enabled, dry := true, false
	threshold, window := 42, 13
	duration, scope := "24h", "blocked"
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateSnapshotSettings(ctx, tx, models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{
		JWTExpireMinutes:     20,
		AutobanEnabled:       &enabled,
		AutobanThreshold:     &threshold,
		AutobanWindowMinutes: &window,
		AutobanDuration:      &duration,
		AutobanScope:         &scope,
		AutobanDryRun:        &dry,
	}}); err != nil {
		t.Fatalf("apply settings: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var gotEnabled, gotDry bool
	var gotThreshold, gotWindow int
	var gotDuration, gotScope string
	if err := database.QueryRow(`SELECT COALESCE(autoban_enabled,0), COALESCE(autoban_threshold,0), COALESCE(autoban_window_minutes,0),
		COALESCE(autoban_duration,''), COALESCE(autoban_scope,''), COALESCE(autoban_dry_run,1) FROM global_config WHERE id=1`).
		Scan(&gotEnabled, &gotThreshold, &gotWindow, &gotDuration, &gotScope, &gotDry); err != nil {
		t.Fatal(err)
	}
	if !gotEnabled || gotThreshold != 42 || gotWindow != 13 || gotDuration != "24h" || gotScope != "blocked" || gotDry {
		t.Fatalf("applied autoban settings enabled=%v threshold=%d window=%d duration=%q scope=%q dry=%v, want snapshot values",
			gotEnabled, gotThreshold, gotWindow, gotDuration, gotScope, gotDry)
	}
}

// 偏斜面（镜像 CL41-1a 缺席语义）：旧主端快照缺该组字段（全 nil 指针）时，
// 从端 apply 必须跳过写入、保留本地设置——不得把从端本地值清成零值。
func TestUpdateSnapshotSettings_autobanSettingsAbsentPreservesLocal(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.Exec(`UPDATE global_config SET autoban_enabled=1, autoban_threshold=77, autoban_window_minutes=9,
		autoban_duration='6h', autoban_scope='logged', autoban_dry_run=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateSnapshotSettings(ctx, tx, models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{JWTExpireMinutes: 20}}); err != nil {
		t.Fatalf("apply settings: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var gotEnabled, gotDry bool
	var gotThreshold, gotWindow int
	var gotDuration, gotScope string
	if err := database.QueryRow(`SELECT COALESCE(autoban_enabled,0), COALESCE(autoban_threshold,0), COALESCE(autoban_window_minutes,0),
		COALESCE(autoban_duration,''), COALESCE(autoban_scope,''), COALESCE(autoban_dry_run,1) FROM global_config WHERE id=1`).
		Scan(&gotEnabled, &gotThreshold, &gotWindow, &gotDuration, &gotScope, &gotDry); err != nil {
		t.Fatal(err)
	}
	if !gotEnabled || gotThreshold != 77 || gotWindow != 9 || gotDuration != "6h" || gotScope != "logged" || gotDry {
		t.Fatalf("absent snapshot must preserve local settings, got enabled=%v threshold=%d window=%d duration=%q scope=%q dry=%v",
			gotEnabled, gotThreshold, gotWindow, gotDuration, gotScope, gotDry)
	}
}

// 全链路钉：主端六列非默认值 → bump → 快照 → 从端本地漂移值被收敛
// （镜像 L5-67-01 三库排程列传播钉测）。
func TestClusterSync_autobanColumnsPropagate(t *testing.T) {
	cluster, database, syncService, bump := syncSemanticsEnv(t)
	ctx := context.Background()

	// Given 主端六列全部非默认值
	if _, err := database.Exec(`UPDATE global_config SET autoban_enabled=1, autoban_threshold=42, autoban_window_minutes=13,
		autoban_duration='24h', autoban_scope='blocked', autoban_dry_run=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	bump(300)

	// When 主端快照（须携带六列）；从端本地值漂移（模拟未接线时代的存量从端）
	snap, _, err := cluster.Snapshot(ctx, 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET autoban_enabled=0, autoban_threshold=100, autoban_window_minutes=5,
		autoban_duration='1h', autoban_scope='all', autoban_dry_run=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := syncService.applySnapshot(ctx, snap); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Then 从端六列全部收敛到主端值
	var enabled, dry bool
	var threshold, window int
	var duration, scope string
	if err := database.QueryRow(`SELECT COALESCE(autoban_enabled,0), COALESCE(autoban_threshold,0), COALESCE(autoban_window_minutes,0),
		COALESCE(autoban_duration,''), COALESCE(autoban_scope,''), COALESCE(autoban_dry_run,1) FROM global_config WHERE id=1`).
		Scan(&enabled, &threshold, &window, &duration, &scope, &dry); err != nil {
		t.Fatal(err)
	}
	if !enabled || threshold != 42 || window != 13 || duration != "24h" || scope != "blocked" || dry {
		t.Fatalf("autoban 六列=(%v,%d,%d,%q,%q,%v), want (true,42,13,24h,blocked,false)——主端配置须随快照到达从端",
			enabled, threshold, window, duration, scope, dry)
	}
}

// 升主后调度恢复：从节点启动时未启用（调度未开）→ 主端快照把 autoban_enabled=1
// 落到从端库（配置传播，D1 前四段）→ 升主。Promote 尾部必须按 AutobanEnabled()
// 重开 autoban 调度——否则库值已启用而 loop 永不开（静默停摆）。
func TestClusterService_Promote_resumesAutobanScheduling(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() {
		StopTaskEngine()
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	te := InitTaskEngine("", t.TempDir()+"/app.log")
	te.SetRole(false) // 从节点角色

	// 前置：启动时未启用（autoban_enabled=0）→ 调度未开
	if m, _ := te.Lookup(AutobanTaskID); m.LoopOn {
		t.Fatal("前置失败：未启用时启动不得开调度")
	}
	// 模拟从端收到主端快照：六列落库（enabled=1）——配置传播不联动从端调度
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=1, autoban_threshold=42, is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When 升主
	service := NewClusterService(db.DB, "")
	installGlobalConfigVersionTrigger(t, db.DB)
	if err := service.Promote(context.Background()); err != nil {
		t.Fatalf("promote: %v", err)
	}

	// Then 调度恢复（loop_on=true）
	if m, _ := te.Lookup(AutobanTaskID); !m.LoopOn {
		t.Fatal("升主后 autoban_enabled=1 时 Promote 必须重开调度（静默停摆回归钉）")
	}
}

// 反向形状：升主时库内未启用（autoban_enabled=0）不得开调度——否则首 tick 被
// Run 体业务门拦停，每次升主落一行「未启用」假失败（与启动门同口径）。
func TestClusterService_Promote_doesNotStartAutobanWhenDisabled(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() {
		StopTaskEngine()
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	te := InitTaskEngine("", t.TempDir()+"/app.log")
	te.SetRole(false)
	if m, _ := te.Lookup(AutobanTaskID); m.LoopOn {
		t.Fatal("前置失败：未启用时启动不得开调度")
	}

	service := NewClusterService(db.DB, "")
	installGlobalConfigVersionTrigger(t, db.DB)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0, master_url='' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := service.Promote(context.Background()); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if m, _ := te.Lookup(AutobanTaskID); m.LoopOn {
		t.Fatal("未启用时升主不得开调度")
	}
}
