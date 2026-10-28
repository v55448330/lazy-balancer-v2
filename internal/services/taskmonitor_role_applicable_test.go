package services

// 任务视图的角色适用性由服务端派生：从节点上 master-only 族照常展示调度
// 开关与下次执行会误导排障（永不投递），视图需要「仅主节点运行」的显性结论。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestCollectEngineFamilies_roleApplicability(t *testing.T) {
	te := newWireTestEngine(t)
	masterOnly := []string{"crs", "threat", "ip2region", "cert-renewal-scan", "autoban", "auto-backup"}
	roleAny := []string{"cluster-sync", securityEventsIngestionTaskID}

	check := func(wantApplicable bool, label string) {
		t.Helper()
		rows := collectEngineFamilies(te)
		for _, id := range masterOnly {
			ti := findTaskInfo(t, rows, id)
			if ti.RoleApplicable != wantApplicable {
				t.Fatalf("%s: %s RoleApplicable=%v, want %v", label, id, ti.RoleApplicable, wantApplicable)
			}
		}
		for _, id := range roleAny {
			ti := findTaskInfo(t, rows, id)
			if !ti.RoleApplicable {
				t.Fatalf("%s: %s（RoleAny）RoleApplicable=false", label, id)
			}
		}
	}

	te.SetRole(true)
	check(true, "主节点")
	te.SetRole(false)
	check(false, "从节点")
}

// Given 从节点（master-only 周期族 RoleApplicable=false）与其最近运行行。
// When 聚合任务视图。
// Then 不推算「下次执行」（该族永不投递，推算出的具体时间与角色不适用标注
// 自相矛盾）；主节点同形态照常推算。
func TestCollectEngineFamilies_masterOnlyNextRunAtGatedByRole(t *testing.T) {
	te := newWireTestEngine(t)
	const id = "cert-renewal-scan"
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at)
		VALUES (?, 'cert', 'auto', 'success', ?)`, id, time.Now().In(CurrentLocation()).Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	te.SetRole(true)
	master := findTaskInfo(t, collectEngineFamilies(te), id)
	if !master.RoleApplicable || master.NextRunAt == "" {
		t.Fatalf("主节点上周期任务应推算下次执行, RoleApplicable=%v NextRunAt=%q", master.RoleApplicable, master.NextRunAt)
	}
	te.SetRole(false)
	slave := findTaskInfo(t, collectEngineFamilies(te), id)
	if slave.RoleApplicable {
		t.Fatal("前置条件：从节点上 master-only 任务应不适用")
	}
	if slave.NextRunAt != "" {
		t.Fatalf("角色不适用任务不得推算下次执行（实际永不投递）, got %q", slave.NextRunAt)
	}
}

// Given 从节点 + 已武装的定时族（Scheduled）槽。定时族的「下次执行」来自
// NextSlotFn 纯读本地库（从节点的槽值由主端快照带入），与本机角色无关。
// When 聚合任务视图。
// Then 定时族同样受角色门约束——不得对永不投递的任务给出具体时刻（API 直读
// 消费者会据此排程；UI 的另行遮蔽不构成契约）；主节点同形态照常给出。
func TestCollectEngineFamilies_scheduledNextRunAtGatedByRole(t *testing.T) {
	te := newWireTestEngine(t)
	const id = "threat"
	if _, err := db.DB.Exec(`UPDATE global_config SET threat_auto_update=1 WHERE id=1`); err != nil {
		t.Fatalf("enable threat auto update: %v", err)
	}
	res, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=1, next_update='2999-01-02 00:00:00' WHERE name='ustc'`)
	if err != nil {
		t.Fatalf("seed threat slot: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("威胁源注册行未命中（affected=%d），夹具失效", n)
	}

	te.SetRole(true)
	master := findTaskInfo(t, collectEngineFamilies(te), id)
	if !master.RoleApplicable || master.NextRunAt == "" {
		t.Fatalf("主节点上定时任务应给出下次执行, RoleApplicable=%v NextRunAt=%q", master.RoleApplicable, master.NextRunAt)
	}
	te.SetRole(false)
	slave := findTaskInfo(t, collectEngineFamilies(te), id)
	if slave.RoleApplicable {
		t.Fatal("前置条件：从节点上 master-only 定时任务应不适用")
	}
	if slave.NextRunAt != "" {
		t.Fatalf("角色不适用定时任务不得给出下次执行（实际永不投递）, got %q", slave.NextRunAt)
	}
}

// Given 主节点 + 24h 周期任务的最近一轮在 3 天前（长时间停止后刚恢复调度）。
// When 聚合任务视图。
// Then 「下次执行」不得展示已过去的兜底推算时刻（会误导运维「该跑没跑」）；
// 兜底仅在推算值落在未来时采用。
func TestCollectEngineFamilies_periodicFallbackSkipsPastNextRun(t *testing.T) {
	te := newWireTestEngine(t)
	te.SetRole(true)
	const id = "cert-renewal-scan"
	past := time.Now().In(CurrentLocation()).Add(-72 * time.Hour).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at)
		VALUES (?, 'cert', 'auto', 'success', ?)`, id, past); err != nil {
		t.Fatal(err)
	}
	info := findTaskInfo(t, collectEngineFamilies(te), id)
	if info.NextRunAt != "" {
		t.Fatalf("最近一轮早于一个周期时不得展示过去的「下次执行」, got %q", info.NextRunAt)
	}
}
