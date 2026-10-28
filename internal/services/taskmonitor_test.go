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
// 对 disabled 恒 429（certJobRetryBlocked 首条），按钮亮着是交互噪音（点了必 429）。
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
		t.Fatal("disabled 证书行 Triggerable=true——重试门恒 429，按钮应为禁用态")
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
