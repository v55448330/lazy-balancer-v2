package services

// Round 62 修复钉（引擎接线元数据）：NextSlotFn SQL（P2-③）/更新族单飞与
// 调度开关（P3-7/U1-P4-2）/证书族角色门（U7-P3-2）。

import (
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func newWireTestEngine(t *testing.T) *taskengine.Engine {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	// TASK-3（第 72 轮·测试卫生）：注入空载 configLoadRerun——否则
	// InitTaskEngine 尾部 BootSync（startup:config-load）因钩子 nil 恒落
	// failed 启动行（「配置重载未接线」），每个夹具用例都携带一行假失败
	// 残留。与 certJobsActiveFn 注入缝同模式：Cleanup 还原 nil。
	SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	t.Cleanup(func() {
		StopTaskEngine()
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	// runtimeLogFile 指向临时目录——避免默认 /app/logs 写出测试沙箱
	return InitTaskEngine("", t.TempDir()+"/app.log")
}

// TASK-3（第 72 轮·测试卫生）：夹具注入空载 configLoadRerun 后，
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

// TASK-L1（第 69 轮 P1）：全新安装三安全库自动更新永不排程——引擎化后零槽
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
// When DescribeAll 读取 cert-waiting-ca 元数据。
// Then NextSlot 非空（P2-③：原 SQL 缺 2 右括号+NULLIF 3 参——恒语法错误，
// 「下次 CA 可用时间」上线即恒空）。
func TestTaskEngineWire_CertWaitingCANextSlotResolves(t *testing.T) {
	te := newWireTestEngine(t)
	future := time.Now().UTC().Add(2 * time.Hour).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, ca_available_after) VALUES ('r1','a.example.com','waiting_ca',?)`, future); err != nil {
		t.Fatal(err)
	}
	for _, m := range te.DescribeAll() {
		if m.ID != "cert-waiting-ca" {
			continue
		}
		if m.NextSlot == "" {
			t.Fatal("waiting_ca 存在时 cert-waiting-ca NextSlot 应非空（SQL 曾恒语法错误）")
		}
		return
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
	time.Sleep(150 * time.Millisecond)
	if !te.IsRunning("cluster-sync") {
		t.Fatal("主节点 cluster-sync 应真实运行（2026-10-03 裁定：统一生命周期，镜像废除）")
	}
	// 从节点角色下同样真实运行（从分支=同步轮询；Run 体按角色分流）
	te.SetRole(false)
	time.Sleep(150 * time.Millisecond)
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
			return
		}
	}
	t.Fatal("cluster-sync 未注册")
}

// TASK-L6（第 69 轮 P2）：wire 元数据钉——9 个 Periodic 生产任务 IntervalSec>0、
// 5 个 Scheduled 生产任务在启用形态下 NextSlot 可解析（disabled=空串合法）。
// 缺口形态：手术删除 wire.go 任一生产 Fn 块 → 排程静默停摆且套件全绿。
func TestTaskEngineWire_PeriodicIntervalAndScheduledSlotPresent(t *testing.T) {
	te := newWireTestEngine(t)
	metas := te.DescribeAll()
	if len(metas) == 0 {
		t.Fatal("DescribeAll empty")
	}
	periodic, scheduled := 0, 0
	for _, m := range metas {
		switch m.Kind {
		case "periodic":
			periodic++
			if m.IntervalSec <= 0 {
				t.Fatalf("periodic task %s IntervalSec=%d, want >0（IntervalFn 缺失/被手术删除会静默停摆）", m.ID, m.IntervalSec)
			}
		case "scheduled":
			scheduled++
		}
	}
	if periodic != 9 {
		t.Fatalf("periodic tasks=%d, want 9（wire.go 注册面；F73-A 起 autoban 循环族）", periodic)
	}
	if scheduled != 5 {
		t.Fatalf("scheduled tasks=%d, want 5（threat/crawler/crs/ip2region/auto-backup）", scheduled)
	}
}

// TASK-1（第 72 轮）：引擎 Trigger/RunSync 角色门曾只认 Descriptor.MasterOnly
// bool（三安全库专用），cert 族×5 与 auto-backup 仅声明 RunsOn=RoleMasterOnly
// ——从节点手动 Trigger 可绕过角色门直跑主节点任务体。收敛为
// roleAllows(RunsOn) 单机制后钉死拒绝形状。
// Given 从节点角色引擎。
// When Trigger cert 族/auto-backup 主节点任务。
// Then 全部返回「仅允许在主节点执行」，任务体不执行。
func TestTaskEngineWire_MasterOnlyFamiliesTriggerRejectedOnSlave(t *testing.T) {
	te := newWireTestEngine(t)
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
