package services

// Round 62 第三批钉：cert-job 终态计数 / 常驻族 started_at+loop_on /
// 更新日志同源（三端点读任务日志文件）。

import (
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// Given cert_jobs 一行 issued（24h 内更新）+一行 failed。
// When collectCertJobRows。
// Then issued 行 Success24h=1、failed 行 Fail24h=1（终态映射——签发成功应成功+1）。
func TestCollectCertJobRows_TerminalCounts(t *testing.T) {
	oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA })
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, updated_at) VALUES ('r1','a.test','issued',?)`, now)
	db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, updated_at) VALUES ('r2','b.test','failed',?)`, now)
	rows := collectCertJobRows()
	byDomain := map[string]TaskInfo{}
	for _, r := range rows {
		byDomain[strings.TrimPrefix(r.Name, "ACME 签发 · ")] = r
	}
	if byDomain["a.test"].Success24h != 1 {
		t.Fatalf("issued 行 Success24h want 1, got %d", byDomain["a.test"].Success24h)
	}
	if byDomain["b.test"].Fail24h != 1 {
		t.Fatalf("failed 行 Fail24h want 1, got %d", byDomain["b.test"].Fail24h)
	}
}

// Given 引擎启动并按 v2.0 四类型注册（2026-10-03 裁定：cluster-sync 主从
// 两角色统一生命周期，镜像废除——主节点上真实启动）。
// When CollectSystemTasks 视图聚合。
// Then 常驻族 started_at=最近 boot 行（真实运行者非空；主节点 cluster-sync
// 亦真实启动，取本代 boot 行而非任何镜像兜底）；循环/定时族 started_at 为空；
// cert-waiting-ca 默认 loop_on=false。
func TestCollectSystemTasks_ContinuousStartedAtAndLoopOn(t *testing.T) {
	te := newWireTestEngine(t)
	got := map[string]TaskInfo{}
	for _, ti := range collectEngineFamilies(te) {
		got[ti.ID] = ti
	}
	// 真实启动的常驻任务（master 上 security-events-ingestion/cert-issuance
	// 随默认 StartLoop 拉起——boot 行落库）
	for _, id := range []string{"security-events-ingestion", "cert-issuance"} {
		if got[id].StartedAt == "" {
			t.Fatalf("%s（常驻·已启动）started_at 应非空", id)
		}
		if !got[id].LoopOn {
			t.Fatalf("%s（常驻）loop_on 应 true（StartLoop 默认开启）", id)
		}
	}
	// cluster-sync（2026-10-03 裁定：统一生命周期，镜像废除）：主节点上
	// 真实启动——started_at=本代 boot 行（真实运行者，非镜像引擎启动兜底）。
	if got["cluster-sync"].StartedAt == "" {
		t.Fatal("真实启动的常驻任务 started_at 应非空（本代 boot 行）")
	}
	if !got["cluster-sync"].LoopOn {
		t.Fatal("cluster-sync loop_on 应 true（调度开关保留）")
	}
	w := got["config-watchdog"]
	if w.StartedAt != "" {
		t.Fatal("循环族 started_at 应为空（仅常驻族有启动时刻）")
	}
	if !w.LoopOn {
		t.Fatal("循环族 loop_on 应 true")
	}
	if got["threat"].StartedAt != "" {
		t.Fatal("定时族 started_at 应为空")
	}
	if got["cert-waiting-ca"].LoopOn {
		t.Fatal("cert-waiting-ca 默认调度应关闭（loop_on=false）")
	}
}

// U1-66-06：从未运行的常驻任务 StartedAt 置零值——UI「常驻 · 启动于」已有
// '—' 兜底；不再回退引擎进程启动时刻（=uptime 语义，与「空闲」状态矛盾）。
func TestCollectSystemTasks_DaemonNeverRunStartedAtEmpty(t *testing.T) {
	te := newWireTestEngine(t)
	// 真零值形状：从未运行、无状态镜像（2026-10-03 裁定：镜像废除+角色门
	// ——cluster-sync 已真实运行，不再是任何镜像形态）、调度未开——注册
	// 测试专用常驻（不 StartLoop）。
	te.Register(taskengine.Descriptor{ID: "t-never", Family: "t", Name: "从未运行", Kind: taskengine.KindDaemon, RunsOn: taskengine.RoleAny,
		Run: func(rc taskengine.RunContext) error { return nil }})
	got := map[string]TaskInfo{}
	for _, ti := range collectEngineFamilies(te) {
		got[ti.ID] = ti
	}
	tn := got["t-never"]
	if tn.Kind != taskengine.KindDaemon {
		t.Fatalf("应为常驻族, got %s", tn.Kind)
	}
	if tn.StartedAt != "" {
		t.Fatalf("从未运行且未运行的常驻任务 StartedAt 应为零值（UI '—' 兜底）, got %q", tn.StartedAt)
	}
}

// Given 从节点证书材料物化行（message=「从主节点同步…」、created_at=同步时刻）。
// When collectCertJobRows。
// Then 物化行不进任务监控动态行（非签发任务——从节点禁签发，2026-10-01
// 用户裁定：幽灵行不得因同步时刻新鲜而显示）。
func TestCollectCertJobRows_excludesSyncedMaterialRows(t *testing.T) {
	oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA })
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, message, created_at) VALUES ('r1','ghost.test','issued','从主节点同步，源任务状态：issued',?)`, now)
	db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, message, created_at) VALUES ('r2','real.test','issued','',?)`, now)
	// L04-07：镜像行过滤绑定「本节点当前为从节点」——物化行只在从节点存在，
	// 主节点（promote 后）这些行归本节点，必须可见（见 mirrorFilterOnlyOnSlave）。
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("set slave role: %v", err)
	}
	rows := collectCertJobRows()
	for _, r := range rows {
		if strings.Contains(r.Name, "ghost.test") {
			t.Fatal("物化行（从主节点同步）不应出现在任务监控动态行")
		}
	}
	found := false
	for _, r := range rows {
		if strings.Contains(r.Name, "real.test") {
			found = true
		}
	}
	if !found {
		t.Fatal("真实签发行应保留显示")
	}
	// U1-P3-2：LIMIT 100（第 100 新行仍显示——20 截断回归钉）
	if len(rows) > 100 {
		t.Fatalf("上限 100, got %d", len(rows))
	}
}

// Given 超 1 天的 issued 签发任务行。
// When collectCertJobRows。
// Then 行存在即显示（2026-10-01 用户裁定——无状态/时间过滤）；但 24h 计数
// 归零（超窗不计数）。
func TestCollectCertJobRows_oldTerminalStillShown(t *testing.T) {
	oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA })
	old := time.Now().UTC().AddDate(0, 0, -3).Format("2006-01-02 15:04:05")
	db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, updated_at) VALUES ('r9','old.test','issued',?)`, old)
	rows := collectCertJobRows()
	found := false
	for _, r := range rows {
		if strings.Contains(r.Name, "old.test") {
			found = true
			if r.Success24h != 0 {
				t.Fatalf("超 24h 窗口的 issued 行不应计数, got %d", r.Success24h)
			}
		}
	}
	if !found {
		t.Fatal("超 1 天的 issued 行仍应显示（存在即显示）")
	}
}
