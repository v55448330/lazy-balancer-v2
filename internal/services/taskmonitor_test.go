package services

import (
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// 聚合视图两处 db.DB 裸用（collectCertJobRows 的
// cert_jobs 查询、cluster-sync 节奏的 sync_interval 查询）补 nil 防护——与
// 引擎侧导出 DB 函数（History/Stats24h 等 7 处）同形契约。
//
// cluster-sync 的 sync_interval 节奏覆写已删除（常驻族
// 节奏统一为「常驻自管理」，不再读库），本测试当前覆盖的一处 db.DB 裸用是
// collectCertJobRows；引擎族聚合走 RunOverview（内部 nil 守卫）。
//
// Given db.DB 未初始化（nil）。
// When 调用 cert 任务行收集与引擎族聚合。
// Then 不 panic：cert 行返回 nil，引擎族聚合返回降级视图（节奏兜底文案）。
func TestCollectSystemTasks_nilDBGuards(t *testing.T) {
	old, oldCurrent := db.DB, db.GetDB()
	db.DB = nil
	db.SetDB(nil)
	t.Cleanup(func() { db.DB = old; db.SetDB(oldCurrent) })

	if rows, _ := collectCertJobRows(); rows != nil {
		t.Fatalf("nil DB 时 collectCertJobRows=%v, want nil", rows)
	}

	e := taskengine.NewEngine(taskengine.Options{})
	t.Cleanup(e.Stop)
	e.Register(taskengine.Descriptor{ID: "cluster-sync", Family: "cluster", Name: "集群同步",
		Kind: taskengine.KindPeriodic, IntervalFn: func() time.Duration { return 60 * time.Second },
		Run: func(taskengine.RunContext) error { return nil }})
	out := collectEngineFamilies(e)
	if len(out) != 1 {
		t.Fatalf("nil DB 时 collectEngineFamilies 行数=%d, want 1（降级视图）", len(out))
	}
	if out[0].Cadence == "" {
		t.Fatal("nil DB 时节奏列应有兜底文案（每 1 分钟）")
	}
}

// disabled 证书行 Triggerable 必须 false——行级重试门
// 对 disabled 恒 409（certJobRetryBlocked 首条），按钮亮着是交互噪音（点了必 409）。
func TestCollectCertJobRows_disabledRowNotTriggerable(t *testing.T) {
	setupIsolatedDB(t)
	seedCertJobRowForTaskMonitor(t, "lb_tm_disabled", "disabled.example.com", "disabled")
	seedCertJobRowForTaskMonitor(t, "lb_tm_queued", "queued.example.com", "queued")

	rows, _ := collectCertJobRows()
	byDomain := map[string]TaskInfo{}
	for _, r := range rows {
		byDomain[strings.TrimPrefix(r.Name, "ACME 签发 · ")] = r
	}
	disabled, ok := byDomain["disabled.example.com"]
	if !ok {
		t.Fatalf("disabled 行缺失: %+v", rows)
	}
	if disabled.Triggerable {
		t.Fatal("disabled 证书行 Triggerable=true——重试门恒 409，按钮应为禁用态")
	}
	queued, ok := byDomain["queued.example.com"]
	if !ok {
		t.Fatalf("queued 行缺失: %+v", rows)
	}
	if !queued.Triggerable {
		t.Fatal("queued 证书行 Triggerable 应保持 true（回归）")
	}
}

func seedCertJobRowForTaskMonitor(t *testing.T, ruleID, domain, status string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES (?,?,?)`, ruleID, domain, status); err != nil {
		t.Fatalf("seed cert job %s: %v", ruleID, err)
	}
}

// Given cert_jobs 查询持续失败（5s 轮询形态）。
// When 连续两轮收集。
// Then 失败日志按状态转换节流（首轮一条 WARNING，持续失败静默）——旧形态
// 每个标签页每 5s 刷一条。
func TestCollectCertJobRows_throttlesReadFailureLogs(t *testing.T) {
	initServicesDB(t)
	buf := captureServiceLog(t)
	resetLogStateTransitionForTest(taskMonitorCertJobsLogKey)
	t.Cleanup(func() { resetLogStateTransitionForTest(taskMonitorCertJobsLogKey) })
	if err := db.DB.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	collectCertJobRows()
	collectCertJobRows()

	if got := countLogLines(buf, "cert 任务行查询失败"); got != 1 {
		t.Fatalf("失败日志行数=%d, want 1（状态未翻转不得重复告警）:\n%s", got, buf.String())
	}
}

// Given cert_jobs 不可读（锁/迁移窗口形态：表被重命名）。
// When 连续两轮聚合引擎任务族视图。
// Then cert-waiting-ca「下次执行」查询失败按状态转换留痕（首报一条、持续静默），
// 表恢复后补一条恢复日志——此前错误分支零留痕，页面「—」与「无 waiting_ca
// 任务」不可区分，读取故障无处排障。
func TestCollectEngineFamilies_logsWaitingCAQueryFailure(t *testing.T) {
	te := newWireTestEngine(t)
	te.SetRole(true)
	meta, ok := te.Lookup("cert-waiting-ca")
	if !ok || !meta.RoleApplicable {
		t.Fatalf("cert-waiting-ca 主节点适用前提未成立: ok=%v meta=%+v", ok, meta)
	}
	buf := captureServiceLog(t)
	resetLogStateTransitionForTest(taskMonitorWaitingCALogKey)
	t.Cleanup(func() { resetLogStateTransitionForTest(taskMonitorWaitingCALogKey) })
	if _, err := db.DB.Exec(`ALTER TABLE cert_jobs RENAME TO cert_jobs_bak`); err != nil {
		t.Fatalf("rename cert_jobs: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.DB.Exec(`ALTER TABLE cert_jobs_bak RENAME TO cert_jobs`)
	})

	collectEngineFamilies(te)
	collectEngineFamilies(te)
	if got := countLogLines(buf, "等待 CA 下次可用时间查询失败"); got != 1 {
		t.Fatalf("失败日志行数=%d, want 1（状态未翻转不得重复告警）:\n%s", got, buf.String())
	}

	if _, err := db.DB.Exec(`ALTER TABLE cert_jobs_bak RENAME TO cert_jobs`); err != nil {
		t.Fatalf("restore cert_jobs: %v", err)
	}
	buf.Reset()
	collectEngineFamilies(te)
	if got := countLogLines(buf, "等待 CA 下次可用时间查询恢复"); got != 1 {
		t.Fatalf("恢复日志行数=%d, want 1:\n%s", got, buf.String())
	}
}

// Given task_runs 不可读（DROP 形态：迁移窗口/库损坏）。
// When 连续两轮查询常驻族最近 boot 时刻。
// Then 读失败按状态转换留痕（首报一条、持续静默），表恢复后补一条恢复日志；
// 「从未 boot」（ErrNoRows）不属读失败，不得告警——此前错误分支静默返空串，
// 页面「—」与「从未运行」不可区分，读取故障无处排障。
func TestDaemonLatestBootStartedAt_logsReadFailureTransitions(t *testing.T) {
	initServicesDB(t)
	buf := captureServiceLog(t)
	resetLogStateTransitionForTest(taskMonitorDaemonBootLogKey)
	t.Cleanup(func() { resetLogStateTransitionForTest(taskMonitorDaemonBootLogKey) })

	// 无 boot 行（ErrNoRows）：静默空串，不留失败痕。
	if got := daemonLatestBootStartedAt("no-such-daemon"); got != "" {
		t.Fatalf("无 boot 行应返回空串, got %q", got)
	}
	if got := countLogLines(buf, "常驻任务启动时刻查询失败"); got != 0 {
		t.Fatalf("ErrNoRows 不得告警, 日志:\n%s", buf.String())
	}

	if _, err := db.DB.Exec(`DROP TABLE task_runs`); err != nil {
		t.Fatalf("drop task_runs: %v", err)
	}
	if got := daemonLatestBootStartedAt("metrics-collector"); got != "" {
		t.Fatalf("读失败应返回空串, got %q", got)
	}
	daemonLatestBootStartedAt("metrics-collector")
	if got := countLogLines(buf, "常驻任务启动时刻查询失败"); got != 1 {
		t.Fatalf("失败日志行数=%d, want 1（状态未翻转不得重复告警）:\n%s", got, buf.String())
	}

	if _, err := db.DB.Exec(`CREATE TABLE task_runs (
		id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL DEFAULT '',
		family TEXT NOT NULL DEFAULT '', trigger TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatalf("recreate task_runs: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at)
		VALUES ('metrics-collector', 'system', 'startup', 'success', '2026-01-01 00:00:00')`); err != nil {
		t.Fatalf("seed boot row: %v", err)
	}
	buf.Reset()
	daemonLatestBootStartedAt("metrics-collector")
	if got := countLogLines(buf, "常驻任务启动时刻查询恢复"); got != 1 {
		t.Fatalf("恢复日志行数=%d, want 1:\n%s", got, buf.String())
	}
}

// Given 配置上限=3；cert_jobs 三行未来退避窗口：超限 failed（attempts=3，
// 窗口较近）/未超限 failed（attempts=1，窗口较远）/遗留 waiting_ca（NULL
// attempts，窗口最远）。
// When 聚合引擎任务族视图（cert-waiting-ca 的「下次 CA 可用时间」展示查询）。
// Then 超限行不得进入展示（配置下调后该行不再被任何自动通道消费，仅手动
// 重试可达——展示其重排时刻会误导运维等待）；未超限 failed 与遗留
// waiting_ca 行照常展示，取未超限行中最早窗口（与 scanWaitingCACandidates/
// certJobsActive 的 attempts 门同口径）。
func TestCollectEngineFamilies_waitingCADisplaySkipsAttemptExhaustedRows(t *testing.T) {
	te := newWireTestEngine(t)
	te.SetRole(true)
	if _, err := db.DB.Exec(`UPDATE global_config SET cert_renewal_attempts=3 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	seedCertJobRowForTaskMonitor(t, "lb_wca_exhausted", "exhausted.example.test", "failed")
	seedCertJobRowForTaskMonitor(t, "lb_wca_active", "active.example.test", "failed")
	seedCertJobRowForTaskMonitor(t, "lb_wca_legacy", "legacy.example.test", "waiting_ca")
	base := time.Now().UTC().Truncate(time.Second)
	near := base.Add(1 * time.Hour).Format("2006-01-02 15:04:05")
	mid := base.Add(2 * time.Hour).Format("2006-01-02 15:04:05")
	far := base.Add(3 * time.Hour).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET renewal_attempts=3, ca_available_after=? WHERE rule_id='lb_wca_exhausted'`, near); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET renewal_attempts=1, ca_available_after=? WHERE rule_id='lb_wca_active'`, mid); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET ca_available_after=? WHERE rule_id='lb_wca_legacy'`, far); err != nil {
		t.Fatal(err)
	}

	info := findTaskInfo(t, collectEngineFamilies(te), "cert-waiting-ca")
	want := base.Add(2 * time.Hour).In(CurrentLocation()).Format("2006-01-02 15:04:05")
	if info.NextRunAt != want {
		t.Fatalf("下次 CA 可用时间=%q, want %q（超限 failed 行的窗口不得展示；未超限 failed 与遗留 waiting_ca 照常）", info.NextRunAt, want)
	}

	// 边界形状：仅剩超限行时展示为空（「—」）——不得给出永不消费的自动重排时刻。
	if _, err := db.DB.Exec(`DELETE FROM cert_jobs WHERE rule_id IN ('lb_wca_active','lb_wca_legacy')`); err != nil {
		t.Fatal(err)
	}
	info = findTaskInfo(t, collectEngineFamilies(te), "cert-waiting-ca")
	if info.NextRunAt != "" {
		t.Fatalf("仅剩超限 failed 行时不得展示下次 CA 可用时间, got %q", info.NextRunAt)
	}
}
