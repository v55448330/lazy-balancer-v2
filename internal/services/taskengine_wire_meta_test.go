package services

// 历史 修复钉（引擎接线元数据）：NextSlotFn SQL/更新族单飞与
// 调度开关/证书族角色门。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func newWireTestEngine(t *testing.T) *taskengine.Engine {
	t.Helper()
	// runtimeLogFile 指向临时目录——避免默认 /app/logs 写出测试沙箱
	return newWireTestEngineWithRuntimeLog(t, t.TempDir()+"/app.log")
}

// newWireTestEngineWithRuntimeLog 同 newWireTestEngine，但显式指定
// runtimeLogFile（注入空串模拟「旋转写入器打开失败」形态）。
func newWireTestEngineWithRuntimeLog(t *testing.T, runtimeLogFile string) *taskengine.Engine {
	t.Helper()
	setupIsolatedDB(t)
	// 注入空载 configLoadRerun——否则
	// InitTaskEngine 尾部 BootSync（startup:config-load）因钩子 nil 恒落
	// failed 启动行（「配置重载未接线」），每个夹具用例都携带一行假失败
	// 残留。与 certJobsActiveFn 注入缝同模式：Cleanup 还原 nil。
	SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	// 后注册先执行：停引擎必须早于夹具的 db.Close。
	t.Cleanup(func() { StopTaskEngine() })
	return InitTaskEngine("", runtimeLogFile)
}

// 任务日志目录创建失败必须显式留痕，不能在只读/异常挂载下
// 静默退化为零任务日志。
func TestInitTaskEngine_logsTaskLogDirMkdirFailure(t *testing.T) {
	setupIsolatedDB(t)
	SetConfigLoadRerun(func(string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	t.Cleanup(func() { StopTaskEngine() })
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "tasks"), []byte("not a directory"), 0644); err != nil {
		t.Fatal(err)
	}
	logs := captureStandardLog(t)

	oldLogDir := taskengine.LogDir()
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	InitTaskEngine("", filepath.Join(root, "app.log"))

	if got := logs.String(); !strings.Contains(got, "任务日志目录创建失败") || !strings.Contains(got, filepath.Join(root, "tasks")) {
		t.Fatalf("MkdirAll 失败未形成可观测错误日志:\n%s", got)
	}
}

// reconciler 必须绑定启动它的引擎代际；StopTaskEngine 后快速
// 再 Init 时，上一代不得因读到新全局引擎而永久存活。
func TestStartRoleReconciler_stopsPreviousGeneration(t *testing.T) {
	oldInterval := roleReconcilerInterval
	roleReconcilerInterval = 5 * time.Millisecond
	t.Cleanup(func() { roleReconcilerInterval = oldInterval })
	previous := TaskEngine()
	first := taskengine.NewEngine(taskengine.Options{StartPaused: true, TickInterval: time.Hour})
	second := taskengine.NewEngine(taskengine.Options{StartPaused: true, TickInterval: time.Hour})
	t.Cleanup(func() {
		SetTaskEngineForTest(previous)
		first.Stop()
		second.Stop()
	})
	SetTaskEngineForTest(first)
	firstDone := startRoleReconciler(first)
	SetTaskEngineForTest(second)
	secondDone := startRoleReconciler(second)

	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("上一代 reconciler 在全局引擎换代后未退出")
	}
	select {
	case <-secondDone:
		t.Fatal("当前代 reconciler 被上一代退出信号误伤")
	case <-time.After(20 * time.Millisecond):
	}
	SetTaskEngineForTest(previous)
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("当前代 reconciler 在引擎替换/停止后未退出")
	}
}

func TestMustRegisterTask_panicsOnInvalidDescriptor(t *testing.T) {
	// Given：缺 IntervalFn 的非法 Periodic 描述符。
	e := taskengine.NewEngine(taskengine.Options{})
	t.Cleanup(e.Stop)
	defer func() {
		if recover() == nil {
			t.Fatal("注册校验失败必须 panic，不得静默少注册任务")
		}
	}()
	// When/Then：统一 wire 注册入口响亮失败。
	mustRegisterTask(e, taskengine.Descriptor{
		ID: "invalid-periodic", Family: "test", Name: "非法周期", Kind: taskengine.KindPeriodic,
		RunsOn: taskengine.RoleAny, Run: func(taskengine.RunContext) error { return nil },
	})
}

// 夹具注入空载 configLoadRerun 后，
// BootSync 启动行必须落 success——failed 残留形态（钩子 nil「配置重载未
// 接线」）回归即红。
func TestTaskEngineWire_bootConfigLoadRowSucceeds(t *testing.T) {
	te := newWireTestEngine(t)
	latest := te.LatestRun("startup:config-load")
	if latest == nil {
		t.Fatal("BootSync 应落一行 startup:config-load 运行记录")
	}
	if latest.Status != "success" {
		t.Fatalf("夹具启动行应 success（configLoadRerun 已注入空载），得到 status=%s message=%s", latest.Status, latest.Message)
	}
}

// 全新安装三安全库自动更新永不排程——引擎化后零槽
// 恒不到期，首槽武装须由引擎注册路径承担。钉：全新库+默认配置（auto_update
// 默认开）→ DescribeAll 中 threat/crs/ip2region 三族 NextSlot 全非空。
func TestTaskEngineWire_SecurityLibrariesFirstSlotArmed(t *testing.T) {
	te := newWireTestEngine(t)

	descs := te.DescribeAll()
	for _, id := range []string{"threat", "crs", "ip2region"} {
		var found bool
		for _, d := range descs {
			if d.ID == id {
				found = true
				if d.NextSlot == "" {
					t.Fatalf("task %s NextSlot is zero on fresh install（首槽未武装=永不自动更新）", id)
				}
			}
		}
		if !found {
			t.Fatalf("task %s not registered", id)
		}
	}
}

// Given 存在 waiting_ca 证书任务且 ca_available_after 非空。
// When 读取 Descriptor 与任务视图。
// Then Periodic 不携带 NextSlotFn；视图层仍解析最近 CA 可用时间。
func TestTaskEngineWire_CertWaitingCANextSlotResolves(t *testing.T) {
	te := newWireTestEngine(t)
	future := time.Now().UTC().Add(2 * time.Hour).Format(crsTimeLayout)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, ca_available_after) VALUES ('r1','a.example.com','waiting_ca',?)`, future); err != nil {
		t.Fatal(err)
	}
	meta, ok := te.Lookup("cert-waiting-ca")
	if !ok {
		t.Fatal("cert-waiting-ca 未注册")
	}
	if meta.Kind != taskengine.KindPeriodic || meta.NextSlot != "" {
		t.Fatalf("Periodic 不得携带 Scheduled 专用 NextSlotFn/NextSlot: kind=%s next=%q", meta.Kind, meta.NextSlot)
	}
	for _, ti := range collectEngineFamilies(te) {
		if ti.ID == "cert-waiting-ca" {
			if ti.NextRunAt == "" {
				t.Fatal("waiting_ca 存在时视图 NextRunAt 应非空（最近 CA 可用时间）")
			}
			return
		}
	}
	t.Fatal("cert-waiting-ca 未注册")
}

// Given 引擎完成全量注册（2026-10-03 裁定后）。
// When DescribeAll + 两角色调度。
// Then cert-issuance/cluster-sync/security-events-ingestion 均为真实可控
// 常驻（Controllable=true）；cluster-sync 为 RoleAny+RestartOnRoleFlip——
// 两角色统一生命周期（真实启停；状态镜像废除），主节点角色下真实运行
// （服务面巡检），不再有「主节点不运行」的角色门形态。
func TestTaskEngineWire_DaemonsFullyControllable(t *testing.T) {
	te := newWireTestEngine(t)
	for _, m := range te.DescribeAll() {
		switch m.ID {
		case "cert-issuance", "cluster-sync", "security-events-ingestion":
			if !m.Controllable {
				t.Errorf("%s 应 Controllable=true（B 完全标准化）", m.ID)
			}
		}
	}
	// cluster-sync RoleAny：主节点角色下真实运行（主分支=服务面巡检）
	te.SetRole(true)
	te.StartLoop("cluster-sync")
	// 固定 150ms sleep 在 CI 负载下会产生假红——与同域既有模式
	// （waitForCond）对齐。
	waitForCond(t, 2*time.Second, func() bool { return te.IsRunning("cluster-sync") })
	if !te.IsRunning("cluster-sync") {
		t.Fatal("主节点 cluster-sync 应真实运行（2026-10-03 裁定：统一生命周期，镜像废除）")
	}
	// 从节点角色下同样真实运行（从分支=同步轮询；Run 体按角色分流）
	te.SetRole(false)
	waitForCond(t, 2*time.Second, func() bool { return te.IsRunning("cluster-sync") })
	if !te.IsRunning("cluster-sync") {
		t.Fatal("从节点 cluster-sync 应真实运行（同步轮询）")
	}
}

// Given 主节点角色（is_master=1）——cluster-sync 真实启动（主分支巡检）。
// When 状态聚合。
// Then cluster-sync 显示运行中（真实 daemon 实态，非状态镜像——2026-10-03
// 裁定废除 masterSyncServingStatus）。
func TestTaskEngineWire_MasterSyncShowsServing(t *testing.T) {
	te := newWireTestEngine(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	te.SetRole(true)
	waitForCond(t, 2*time.Second, func() bool { return te.IsRunning("cluster-sync") })
	for _, ti := range collectEngineFamilies(te) {
		if ti.ID == "cluster-sync" {
			if ti.Status != TaskStatusRunning {
				t.Fatalf("主节点 cluster-sync 应运行中（真实 daemon 实态）, got %s", ti.Status)
			}
			if ti.Cadence != "常驻自管理" {
				t.Fatalf("常驻任务运行节奏=%q, want 常驻自管理（内部巡检周期不得进入任务详情）", ti.Cadence)
			}
			return
		}
	}
	t.Fatal("cluster-sync 未注册")
}

// wire 元数据钉：10 Periodic 精确间隔、5 Scheduled、3 Daemon、1 Oneshot。
// 注册全集以白名单（wantKindByID 及各 want* 表）为准——不写死总条数：
// 新增任务时逐 ID 验收（多一个/少一个/类型变更都指向具体 ID），而非在
// 「总数=19」上与标准要表达的逐 ID 验收相悖。缺口形态：删除/错改任一生产
// Fn 或误增未验收任务都会直接失败。
func TestTaskEngineWire_PeriodicIntervalAndScheduledSlotPresent(t *testing.T) {
	te := newWireTestEngine(t)
	metas := te.DescribeAll()
	if len(metas) == 0 {
		t.Fatal("DescribeAll empty")
	}
	wantPeriodic := map[string]int{
		"config-watchdog": 60, "log-cleanup": 86400, "audit-retention": 86400,
		"security-events-retention": 86400, "metrics-orphan-cleanup": 86400,
		"cert-renewal-scan": 21600, "cert-reconcile": 21600, "cert-manual-poll": 600,
		"cert-waiting-ca": 30, "autoban": 60,
	}
	seen := map[string]bool{}
	for _, m := range metas {
		seen[m.ID] = true
		wantKind, ok := expectedTaskKinds[m.ID]
		if !ok {
			t.Errorf("未验收任务 %s（Kind=%s）——新增任务须在唯一 Kind 表登记", m.ID, m.Kind)
			continue
		}
		if m.Kind != wantKind {
			t.Errorf("%s Kind=%s, want %s", m.ID, m.Kind, wantKind)
		}
		switch m.Kind {
		case taskengine.KindPeriodic:
			want, ok := wantPeriodic[m.ID]
			if !ok {
				t.Errorf("未验收 Periodic 任务 %s", m.ID)
				continue
			}
			if m.IntervalSec != want {
				t.Errorf("%s IntervalSec=%d, want %d", m.ID, m.IntervalSec, want)
			}
		case taskengine.KindScheduled:
			if m.NextSlot != "" {
				if _, err := time.ParseInLocation("2006-01-02 15:04:05", m.NextSlot, CurrentLocation()); err != nil {
					t.Errorf("%s NextSlot=%q 不可解析: %v", m.ID, m.NextSlot, err)
				}
			}
		}
	}
	for id := range expectedTaskKinds {
		if !seen[id] {
			t.Errorf("白名单任务 %s 未注册（漏注册或 Kind 变更）", id)
		}
	}
}

// 引擎 Trigger/RunSync 角色门曾只认 Descriptor.MasterOnly
// bool（三安全库专用），cert 族×5 与 auto-backup 仅声明 RunsOn=RoleMasterOnly
// ——从节点手动 Trigger 可绕过角色门直跑主节点任务体。收敛为
// roleAllows(RunsOn) 单机制后钉死拒绝形状。
// Given 从节点角色引擎。
// When Trigger cert 族/auto-backup 主节点任务。
// Then 全部返回「仅允许在主节点执行」，任务体不执行。
func TestTaskEngineWire_MasterOnlyFamiliesTriggerRejectedOnSlave(t *testing.T) {
	te := newWireTestEngine(t)
	// 从节点态须与 DB 单源一致（角色对账会按 DB 修正引擎角色）。
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	te.SetRole(false) // 从节点
	for _, id := range []string{"cert-renewal-scan", "cert-reconcile", "auto-backup"} {
		err := te.Trigger(id, "manual", "tester")
		if err == nil || !strings.Contains(err.Error(), "主节点") {
			t.Fatalf("从节点 Trigger %s 应被角色门拒绝，得到 err=%v", id, err)
		}
	}
}

// 类型派生触发规则（2026-10-11 用户裁定，取代 ManualRun 白名单手段）：
// CanTrigger 纯由任务类型派生——定时/循环/触发均可手动调度，常驻族恒不可
// （启停语义，由调度开关+重启承担）。config-watchdog（循环）此前被白名单
// 遗漏无「运行」操作，即白名单手段的结构性缺陷实例。
func TestTaskEngineWire_canTriggerDerivedFromKind(t *testing.T) {
	te := newWireTestEngine(t)
	for _, m := range te.DescribeAll() {
		want := m.Kind != "daemon"
		if m.CanTrigger != want {
			t.Fatalf("task %s (kind=%s) CanTrigger=%v, want %v（类型派生，非白名单）", m.ID, m.Kind, m.CanTrigger, want)
		}
	}
}

// StopTaskEngine 先 engine.Stop()（drain 超时即放弃等待）再置全局
// taskEngine=nil；daemon goroutine 若在超时后首次进入 Run，裸读 taskEngine
// 会 nil 解引用 panic。同族 cert-renewal-scan / cert-waiting-ca 已固定句柄
// 本处为第三处。
func TestClusterSyncDaemonRun_nilEngineReturnsWithoutPanic(t *testing.T) {
	old := TaskEngine()
	SetTaskEngineForTest(nil)
	t.Cleanup(func() { SetTaskEngineForTest(old) })
	if err := clusterSyncDaemonRun(taskengine.RunContext{Ctx: context.Background()}); err != nil {
		t.Fatalf("引擎已置 nil（关机窄窗）时集群同步 Run 必须安全退出, got err=%v", err)
	}
}

// Given 触发类任务 startup:config-load。
// When 以未知触发来源（非 manual/startup/caddy-restart）同步调度。
// Then 响亮失败——不得静默 return nil 落一条 success 行却零动作（silent
// success 会把装配缺陷伪装成正常执行）；task_runs 末行必须为 failed。
func TestTaskEngineWire_configLoadRejectsUnknownTrigger(t *testing.T) {
	te := newWireTestEngine(t)
	if _, err := te.RunSync("startup:config-load", "auto", ""); err == nil || !strings.Contains(err.Error(), "未知触发来源") {
		t.Fatalf("未知触发来源应返回错误，得到 err=%v", err)
	}
	runs := te.History("startup:config-load", 1)
	if len(runs) != 1 {
		t.Fatalf("startup:config-load 运行历史行数=%d, want 1", len(runs))
	}
	if runs[0].Status != "failed" {
		t.Fatalf("未知触发来源轮终态=%q, want failed（不得静默成功）", runs[0].Status)
	}
	if !strings.Contains(runs[0].Message, "未知触发来源") {
		t.Fatalf("失败行消息应说明未知触发来源, got %q", runs[0].Message)
	}
}
