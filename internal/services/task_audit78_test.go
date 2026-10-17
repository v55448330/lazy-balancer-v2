package services

// 第 78 轮 B 域（services 任务引擎切片）：规则库首槽导入重装（U10-F01）、
// 日志大小缓存失效（U10-F04）、taskRun helper nil 库守卫（U10-F11）、
// 威胁任务 manager nil 响亮失败（L01-01）、角色读失败 fail-closed（L01-04）、
// 版本表闭包单源（U10-F03）、证书任务文案（L04-05）、从节点镜像行过滤
// （L04-07）、异步触发错误分类（L01-02）。

import (
	"errors"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// initServicesDB 临时目录全套库（含 audit 库），Cleanup 恢复全局句柄。
func initServicesDB(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
}

func auditCount(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=?`, action).Scan(&n); err != nil {
		t.Fatalf("count audit %s: %v", action, err)
	}
	return n
}

// U10-F01：配置导入提交后重装四族首槽——「enabled 但 next_update 空」的
// 导入行必须武装出非空槽（不依赖重启引擎）。
func TestRearmSecurityLibrarySlots_fillsImportedEmptySlots(t *testing.T) {
	te := newWireTestEngine(t)
	// 模拟导入包体：四表启用但槽空（引擎装配期已过，无人再武装）。
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET auto_update=TRUE, next_update='' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET auto_update=TRUE, next_update='' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET threat_auto_update=1, crawler_auto_update=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=1, next_update=''`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO security_crawler_sources (name, display_name, url, format) VALUES ('googlebot','Google 官方爬虫 IP','https://example.invalid/ips','json')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=1, next_update=''`); err != nil {
		t.Fatal(err)
	}

	RearmSecurityLibrarySlots()

	for _, id := range []string{"crs", "ip2region", "threat", "crawlerbot-update"} {
		m, ok := te.Lookup(id)
		if !ok {
			t.Fatalf("%s 未注册", id)
		}
		if m.NextSlot == "" {
			t.Errorf("%s 导入后空槽未武装——NextSlotFn 永不到期（需重启才恢复）", id)
		}
	}

	// 幂等：再调一次不得改写已有槽（已有槽的行一律不动）。
	before := versionTableNextUpdate("security_crs_version")
	RearmSecurityLibrarySlots()
	if after := versionTableNextUpdate("security_crs_version"); after != before {
		t.Errorf("重装非幂等：已有槽 %q 被改写为 %q", before, after)
	}
}

// U10-F04：日志大小缓存必须可失效——改库后下一行写入即用新阈值（曾仅
// 5 分钟 TTL 自然过期，设置保存后仍按旧阈值滚动）。
func TestInvalidateTaskLogSizeCache_usesNewValueImmediately(t *testing.T) {
	initServicesDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET task_log_size_mb=10 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	InvalidateTaskLogSizeCache()
	if got := getTaskLogSizeBytes(); got != 10<<20 {
		t.Fatalf("初始阈值=%d want 10MB", got)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET task_log_size_mb=20 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	InvalidateTaskLogSizeCache()
	if got := getTaskLogSizeBytes(); got != 20<<20 {
		t.Fatalf("缓存失效后阈值=%d want 20MB（仍命中旧缓存）", got)
	}
}

// U10-F11：taskRun 两 helper 的 nil 库守卫——不得 panic（同族 B1-8 口径：
// false / 当前 UTC）。
func TestTaskRunHelpers_nilDBNeitherPanics(t *testing.T) {
	old := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = old })

	if updateRunStillMaster() {
		t.Fatal("nil 库时角色复核必须 fail-closed 返回 false")
	}
	got := taskRunStartedAt(nil)
	if _, err := time.Parse(crsTimeLayout, got); err != nil {
		t.Fatalf("nil 库时 startedAt=%q 不是合法 UTC 时间串: %v", got, err)
	}
}

// L01-01：威胁任务在 manager 未初始化时必须响亮失败（曾 return nil→success，
// 装配顺序错误被静默吞掉）。
func TestThreatTask_nilManagerFailsLoudly(t *testing.T) {
	te := newWireTestEngine(t)
	ClearThreatUpdateManagerForTest()
	t.Cleanup(ResetThreatUpdateManagerForTest)
	te.SetRole(true)

	err := te.Trigger("threat", "manual", "")
	if err == nil {
		t.Fatal("manager nil 时威胁任务仍报 success——初始化时序缺陷不可见")
	}
	lr := te.LatestRun("threat")
	if lr == nil || lr.Status != "failed" {
		t.Fatalf("nil manager 应落 failed 终态，got %+v", lr)
	}
}

// L01-04：角色种子读失败必须 warn + 重试一次，仍失败按从节点启动
// （fail-closed：不得因读错误默认主节点而启动 master-only daemon）。
func TestInitTaskEngine_roleReadFailureFailsClosed(t *testing.T) {
	initServicesDB(t)
	SetConfigLoadRerun(func(string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	t.Cleanup(StopTaskEngine)
	if _, err := db.DB.Exec(`DELETE FROM global_config`); err != nil {
		t.Fatal(err)
	}
	te := InitTaskEngine("", t.TempDir()+"/app.log")
	if te.IsMaster() {
		t.Fatal("角色读取失败时引擎仍按主节点启动（fail-open）")
	}
}

// U10-F03：crs/ip2region 的开关/槽闭包统一读单源 helper——关闭即零槽、
// 开启且槽存在即展示。
func TestVersionTaskClosures_singleSourceSemantics(t *testing.T) {
	te := newWireTestEngine(t)
	const slot = "2026-12-01 04:00:00"
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET auto_update=0, next_update=? WHERE id=1`, slot); err != nil {
		t.Fatal(err)
	}
	m, _ := te.Lookup("crs")
	if m.Enabled {
		t.Fatal("auto_update=0 时 Enabled 应为 false")
	}
	if m.NextSlot != "" {
		t.Fatalf("auto_update=0 时不应展示槽，got %q", m.NextSlot)
	}
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET auto_update=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	m, _ = te.Lookup("crs")
	if !m.Enabled {
		t.Fatal("auto_update=1 时 Enabled 应为 true")
	}
	if m.NextSlot == "" {
		t.Fatal("auto_update=1 且槽存在时应展示槽")
	}
}

// L04-05：cert-manual-poll 文案必须与执行体（CertManualCheckOnce=手动上传
// 证书到期巡检）一致。
func TestCertManualPoll_copyMatchesExecution(t *testing.T) {
	te := newWireTestEngine(t)
	m, ok := te.Lookup("cert-manual-poll")
	if !ok {
		t.Fatal("cert-manual-poll 未注册")
	}
	if m.Name != "手动证书到期巡检" {
		t.Errorf("Name=%q want 手动证书到期巡检", m.Name)
	}
	if !strings.Contains(m.Description, "10 分钟") || !strings.Contains(m.Description, "过期") {
		t.Errorf("Description=%q 未描述真实执行语义（每 10 分钟检查过期/临期）", m.Description)
	}
}

// L04-07：从主节点同步的镜像行仅在「本节点当前为从节点」时隐藏——promote 后
// 这些行属于本节点自己的签发工作项，必须可见。
func TestCollectCertJobRows_mirrorFilterOnlyOnSlave(t *testing.T) {
	initServicesDB(t)
	seedCertJobRowForTaskMonitor(t, "lb_mirror", "mirror.example.com", "issued")
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET message='从主节点同步：issued' WHERE rule_id='lb_mirror'`); err != nil {
		t.Fatal(err)
	}
	seedCertJobRowForTaskMonitor(t, "lb_local", "local.example.com", "queued")

	visible := func() map[string]bool {
		out := map[string]bool{}
		for _, row := range collectCertJobRows() {
			out[strings.TrimPrefix(row.Name, "ACME 签发 · ")] = true
		}
		return out
	}

	// 主节点：镜像行是历史同步残留（promote 后归本节点），必须可见。
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got := visible(); !got["mirror.example.com"] {
		t.Fatalf("主节点隐藏了从主节点同步行（promote 后永久不可见）: %v", got)
	}
	// 从节点：镜像行非本节点签发任务，保持隐藏。
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	got := visible()
	if got["mirror.example.com"] {
		t.Fatalf("从节点应隐藏镜像行: %v", got)
	}
	if !got["local.example.com"] {
		t.Fatalf("从节点不应隐藏本节点任务行: %v", got)
	}
}

// L01-02：TriggerTaskAsync 统一错误分类——成功记「触发」；ErrAlreadyRunning/
// ErrTaskSkipped 静默（非故障）；其它错误记「触发失败」。
func TestTriggerTaskAsync_errorClassification(t *testing.T) {
	te := newWireTestEngine(t)
	for _, d := range []struct {
		id  string
		err error
	}{
		{"probe-ok", nil},
		{"probe-skip", taskengine.ErrTaskSkipped},
		{"probe-fail", errors.New("注入失败")},
	} {
		errValue := d.err
		if err := te.Register(taskengine.Descriptor{ID: d.id, Family: "probe", Name: d.id,
			Kind: taskengine.KindOneshot, RunsOn: taskengine.RoleAny,
			Run: func(taskengine.RunContext) error { return errValue }}); err != nil {
			t.Fatal(err)
		}
	}

	TriggerTaskAsync(te, "probe-ok", TriggerAuditContext{Operator: "tester", Family: "任务监控", Name: "probe-ok"})
	waitForCond(t, 2*time.Second, func() bool { return auditCount(t, "触发") == 1 })
	TriggerTaskAsync(te, "probe-skip", TriggerAuditContext{Operator: "tester", Family: "任务监控", Name: "probe-skip"})
	waitForCond(t, 2*time.Second, func() bool {
		lr := te.LatestRun("probe-skip")
		return lr != nil && lr.Status == "skipped"
	})
	TriggerTaskAsync(te, "probe-fail", TriggerAuditContext{Operator: "tester", Family: "任务监控", Name: "probe-fail"})
	waitForCond(t, 2*time.Second, func() bool { return auditCount(t, "触发失败") == 1 })

	if got := auditCount(t, "触发"); got != 1 {
		t.Errorf("「触发」审计=%d want 1（仅成功触发一次）", got)
	}
	if got := auditCount(t, "触发失败"); got != 1 {
		t.Errorf("「触发失败」审计=%d want 1（skipped 属非故障放弃，不得补偿记账）", got)
	}
}

// U10-F12：并发触发同一任务时，只有 CAS 胜者成功——「触发」审计必须只在
// Trigger 成功后记录（败者不得留孤儿审计行）。
func TestTriggerTaskAsync_concurrentOnlyWinnerAudits(t *testing.T) {
	te := newWireTestEngine(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	if err := te.Register(taskengine.Descriptor{ID: "probe-concurrent", Family: "probe", Name: "并发探针",
		Kind: taskengine.KindOneshot, RunsOn: taskengine.RoleAny,
		Run: func(taskengine.RunContext) error {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	before := auditCount(t, "触发")
	TriggerTaskAsync(te, "probe-concurrent", TriggerAuditContext{Operator: "tester", Family: "任务监控", Name: "并发探针"})
	<-entered
	TriggerTaskAsync(te, "probe-concurrent", TriggerAuditContext{Operator: "tester", Family: "任务监控", Name: "并发探针"})
	// 败者 CAS 落败路径已返回；放行胜者并等待审计落库。
	time.Sleep(100 * time.Millisecond)
	release <- struct{}{}
	waitForCond(t, 2*time.Second, func() bool {
		lr := te.LatestRun("probe-concurrent")
		return lr != nil && lr.Status == "success"
	})
	time.Sleep(200 * time.Millisecond)

	var runs int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id='probe-concurrent' AND trigger='manual'`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if got := auditCount(t, "触发") - before; got != runs || got != 1 {
		t.Fatalf("并发触发「触发」审计=%d, manual task_runs=%d（want 各 1：败者不得留孤儿审计）", got, runs)
	}
}
