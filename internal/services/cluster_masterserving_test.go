package services

// 2026-10-03 用户裁定：主节点 cluster-sync 纳入任务引擎统一生命周期
// （真实启动/停止/成功/失败/日志），废除 masterSyncServingStatus 纯状态镜像。
// 本文件钉四件事：
// ① 主节点角色下 cluster-sync 引擎真实拉起（boot 行 + running——镜像时代无 boot）；
// ② demote：主分支停 + 从分支起（promote 反向）——换代重启；
// ③ 服务面巡检零噪音口径：异常（离线/持续滞后）状态变化 WARN 一次不逐轮、
//    无异常轮零日志、小时级心跳一条；
// ④ 状态镜像角色门（引擎侧实现）在从节点 services 面的投影：cert-issuance
//    显示本节点实态（idle），不再被同步来的活跃 cert_jobs 伪造 running。

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// ---- helpers ----

func waitForCond(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("等待条件超时")
}

func readClusterSyncLog(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(taskengine.TaskLogPath("cluster-sync"))
	if err != nil {
		if os.IsNotExist(err) {
			return "" // 无 daemon 环境：尚无写入——空日志语义等价（2026-10-04）
		}
		t.Fatalf("读取 cluster-sync 任务日志: %v", err)
	}
	return string(body)
}

func servingLines(log string) []string {
	var out []string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "] serving - ") {
			out = append(out, line)
		}
	}
	return out
}

// seedServingNode 种子一个从节点；interval 写 global_config.sync_interval（真实
// 上报周期，L2-67-01 起巡检阈值随它）——nodes.sync_interval 是写侧从不写的死列
// （schema 默认 60），此前种子它掩盖了阈值钉死 120s 的 bug。
func seedServingNode(t *testing.T, name, lastSeenUTC string, version, interval int) int64 {
	t.Helper()
	res, err := db.DB.Exec(`INSERT INTO nodes (name, mode, ip_address, port, is_approved, status, last_seen, reported_version)
		VALUES (?, 'slave', ?, 8000, 1, 'online', ?, ?)`, name, "10.9.0."+name, lastSeenUTC, version)
	if err != nil {
		t.Fatalf("seed 节点: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET sync_interval=? WHERE id=1`, interval); err != nil {
		t.Fatalf("seed 全局同步间隔: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

// newServingTestEnv 轻量环境：只建 DB+日志目录，不启动 daemon——
// 直调 masterSyncServingRound 的测试使用（daemon 启动即首轮以 time.Now()
// 跑，diff≈8h 触发离线告警污染共享日志；2026-10-04 测试污染修复）。
func newServingTestEnv(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	taskengine.SetLogDir(t.TempDir() + "/tasks")
	_ = os.MkdirAll(taskengine.LogDir(), 0755)
}

func newServingWatch() *masterServingWatch {
	return &masterServingWatch{offlineAlerted: map[int64]bool{}, lagAlerted: map[int64]bool{}, lagSince: map[int64]time.Time{}}
}

var servingBase = time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)

// ---- ① 主节点真实生命周期 ----

// Given 主节点（is_master=1）+ 默认 StartLoop（InitTaskEngine 含 cluster-sync）。
// When 引擎拉起。
// Then daemon 真实运行（boot 行落 tasks/cluster-sync.log、task_runs 有 auto
// success 行、DescribeAll.Running=true）——镜像时代主节点无任何 boot 痕迹。
func TestTaskEngineWire_ClusterSyncMasterRunsForReal(t *testing.T) {
	te := newWireTestEngine(t)
	waitForCond(t, 2*time.Second, func() bool { return te.IsRunning("cluster-sync") })
	waitForCond(t, 2*time.Second, func() bool {
		return strings.Contains(readClusterSyncLog(t), "[start] 常驻启动")
	})
	var status string
	if err := db.DB.QueryRow(`SELECT status FROM task_runs WHERE task_id='cluster-sync' ORDER BY id DESC LIMIT 1`).Scan(&status); err != nil {
		t.Fatalf("boot 行应落 task_runs: %v", err)
	}
	if status != "success" {
		t.Fatalf("启动即记 success（2026-10-01 裁定）, got %s", status)
	}
	for _, m := range te.DescribeAll() {
		if m.ID == "cluster-sync" && !m.Running {
			t.Fatal("主节点 cluster-sync 应真实运行（DescribeAll.Running）")
		}
	}
}

// ---- ②④ 角色翻转换代 ----

// Given 主节点 cluster-sync 运行中（主分支=巡检；同步挂钩未被触碰）。
// When demote（SetRole(false)）。
// Then 主分支停（[done] stopped）+ 从分支起（syncLifecycleStart 被调）；
// promote 反向：从分支停（syncLifecycleStop）+ 主分支重新拉起。
func TestTaskEngineWire_ClusterSyncRoleFlipGenerations(t *testing.T) {
	var syncStarts, syncStops atomic.Int32
	SetSyncLifecycleHooks(func() { syncStarts.Add(1) }, func() { syncStops.Add(1) })
	t.Cleanup(func() { SetSyncLifecycleHooks(nil, nil) })

	te := newWireTestEngine(t)
	waitForCond(t, 2*time.Second, func() bool { return te.IsRunning("cluster-sync") })
	if n := strings.Count(readClusterSyncLog(t), "[start]"); n != 1 {
		t.Fatalf("初代应恰好一条 [start], got %d", n)
	}
	if syncStarts.Load() != 0 {
		t.Fatal("主节点不应触碰从节点同步挂钩（主分支=巡检）")
	}

	te.SetRole(false) // demote：换代 → 从分支
	waitForCond(t, 2*time.Second, func() bool { return syncStarts.Load() >= 1 })
	if syncStops.Load() != 0 {
		t.Fatal("主分支停止不得触碰同步挂钩")
	}
	waitForCond(t, 2*time.Second, func() bool {
		return strings.Count(readClusterSyncLog(t), "[done] stopped") >= 1
	})

	te.SetRole(true) // promote：换代回主分支
	waitForCond(t, 2*time.Second, func() bool { return syncStops.Load() >= 1 })
	waitForCond(t, 2*time.Second, func() bool { return te.IsRunning("cluster-sync") })
}

// ---- ③ 服务面巡检零噪音 ----

// 离线：超阈值节点首轮 WARN 一次，稳态轮不重复。
func TestMasterServingRound_offlineWarnsOnce(t *testing.T) {
	// 合成轮测试用轻量环境（不启动 daemon）——live 引擎的 cluster-sync daemon
	// 以真实时间巡检，seed 的旧 last_seen 必触发离线 WARN 污染合成轮断言
	//（第 69 轮修复期实证：RoleFlip 邻接形态下双 WARN/零日志断言被打穿）。
	newServingTestEnv(t)
	seedServingNode(t, "edge-a", servingBase.Add(-10*time.Minute).UTC().Format("2006-01-02 15:04:05"), 3, 60)
	w := newServingWatch()
	ctx := context.Background()
	masterSyncServingRound(ctx, servingBase, w)
	masterSyncServingRound(ctx, servingBase.Add(masterSyncInspectInterval), w)
	masterSyncServingRound(ctx, servingBase.Add(2*masterSyncInspectInterval), w)
	offline := 0
	for _, line := range servingLines(readClusterSyncLog(t)) {
		if strings.Contains(line, "WARN") && strings.Contains(line, "edge-a") && strings.Contains(line, "离线") {
			offline++
		}
	}
	if offline != 1 {
		t.Fatalf("离线应仅状态变化时 WARN 一次, got %d", offline)
	}
}

// L2-67-01（第 67 轮审计）：巡检离线阈值须跟随 global_config.sync_interval
// （与 cluster_sync 同口径）——此前读 nodes.sync_interval 死列（写侧从不写，
// schema 默认 60），阈值钉死 2×60=120s，interval>120s 部署逐轮误报离线。
func TestMasterServingRound_offlineThresholdFollowsGlobalSyncInterval(t *testing.T) {
	newServingTestEnv(t)
	// Given 全局同步间隔 300s（阈值=max(2×300,120s)=600s）+ 节点 200s 前上报
	nodeID := seedServingNode(t, "edge-c", servingBase.Add(-200*time.Second).UTC().Format("2006-01-02 15:04:05"), 3, 300)
	w := newServingWatch()
	ctx := context.Background()

	// When 巡检一轮
	masterSyncServingRound(ctx, servingBase, w)

	// Then 200s<600s 不判离线（死列口径 2×60=120s 会误报）
	for _, line := range servingLines(readClusterSyncLog(t)) {
		if strings.Contains(line, "edge-c") && strings.Contains(line, "离线") {
			t.Fatalf("200s 未超 600s 阈值不应判离线（阈值须跟随 global sync_interval=300）: %s", line)
		}
	}

	// 回归形状：同阈值下 700s 未上报须判离线，且 WARN 点名 600 秒阈值
	if _, err := db.DB.Exec(`UPDATE nodes SET last_seen=? WHERE id=?`,
		servingBase.Add(-700*time.Second).UTC().Format("2006-01-02 15:04:05"), nodeID); err != nil {
		t.Fatal(err)
	}
	masterSyncServingRound(ctx, servingBase.Add(masterSyncInspectInterval), w)
	found := false
	for _, line := range servingLines(readClusterSyncLog(t)) {
		if strings.Contains(line, "edge-c") && strings.Contains(line, "离线") && strings.Contains(line, "超时阈值 600 秒") {
			found = true
		}
	}
	if !found {
		t.Fatalf("700s 超 600s 阈值应 WARN 离线并点名阈值 600 秒, got %v", servingLines(readClusterSyncLog(t)))
	}
}

// 无异常轮：零日志（心跳轮距未到）。
func TestMasterServingRound_cleanRoundsSilent(t *testing.T) {
	// 合成轮测试用轻量环境（不启动 daemon）——live 引擎的 cluster-sync daemon
	// 以真实时间巡检，seed 的旧 last_seen 必触发离线 WARN 污染合成轮断言
	//（第 69 轮修复期实证：RoleFlip 邻接形态下双 WARN/零日志断言被打穿）。
	newServingTestEnv(t)
	seedServingNode(t, "edge-a", servingBase.Add(-10*time.Second).UTC().Format("2006-01-02 15:04:05"), 3, 3600)
	w := newServingWatch()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		masterSyncServingRound(ctx, servingBase.Add(time.Duration(i)*masterSyncInspectInterval), w)
	}
	if lines := servingLines(readClusterSyncLog(t)); len(lines) != 0 {
		t.Fatalf("无异常轮应零日志, got %v", lines)
	}
}

// 心跳：小时级一条（60 轮×60s）；无从节点时心跳记「无从节点注册」同样小时级。
func TestMasterServingRound_heartbeatHourly(t *testing.T) {
	newServingTestEnv(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET cluster_version=3 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	seedServingNode(t, "edge-a", servingBase.Add(-10*time.Second).UTC().Format("2006-01-02 15:04:05"), 3, 3600)
	w := newServingWatch()
	ctx := context.Background()
	for i := 0; i < masterSyncHeartbeatRounds; i++ {
		masterSyncServingRound(ctx, servingBase.Add(time.Duration(i)*masterSyncInspectInterval), w)
	}
	lines := servingLines(readClusterSyncLog(t))
	if len(lines) != 1 {
		t.Fatalf("小时级心跳应恰好一条, got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "服务面正常：从节点 1 在线，最新版本 3") {
		t.Fatalf("心跳形态不符: %s", lines[0])
	}

	// 无从节点：静默 + 小时级「无从节点注册」
	if _, err := db.DB.Exec(`DELETE FROM nodes`); err != nil {
		t.Fatal(err)
	}
	w2 := newServingWatch()
	for i := 0; i < masterSyncHeartbeatRounds; i++ {
		masterSyncServingRound(ctx, servingBase.Add(time.Duration(i)*masterSyncInspectInterval), w2)
	}
	lines2 := servingLines(readClusterSyncLog(t))
	if len(lines2) != 2 || !strings.Contains(lines2[1], "无从节点注册") {
		t.Fatalf("无从节点应小时级记一条, got %v", lines2)
	}
}

// 版本滞后：持续超 5 分钟才 WARN 一次；后续稳态轮不重复；恢复后再次滞后可再 WARN。
func TestMasterServingRound_lagWarnsAfterPersistence(t *testing.T) {
	newServingTestEnv(t)
	nodeID := seedServingNode(t, "edge-b", servingBase.Add(-10*time.Second).UTC().Format("2006-01-02 15:04:05"), 3, 3600)
	// cluster_version=7 > 从节点已应用 3：滞后
	if _, err := db.DB.Exec(`UPDATE global_config SET cluster_version=7 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec(`UPDATE global_config SET cluster_version=0 WHERE id=1`) })
	w := newServingWatch()
	ctx := context.Background()
	// 前 5 分钟（≤阈值）：静默
	for i := 0; i < 5; i++ {
		masterSyncServingRound(ctx, servingBase.Add(time.Duration(i)*masterSyncInspectInterval), w)
	}
	if lines := servingLines(readClusterSyncLog(t)); len(lines) != 0 {
		t.Fatalf("滞后未满 5 分钟不应告警, got %v", lines)
	}
	// 第 6-7 轮（>5 分钟）：首轮 WARN 一次
	for i := 5; i < 7; i++ {
		masterSyncServingRound(ctx, servingBase.Add(time.Duration(i)*masterSyncInspectInterval), w)
	}
	lines := servingLines(readClusterSyncLog(t))
	if len(lines) != 1 || !strings.Contains(lines[0], "版本滞后") || !strings.Contains(lines[0], "edge-b") {
		t.Fatalf("滞后超 5 分钟应 WARN 一次, got %v", lines)
	}
	// 稳态滞后不重复
	masterSyncServingRound(ctx, servingBase.Add(8*masterSyncInspectInterval), w)
	if lines := servingLines(readClusterSyncLog(t)); len(lines) != 1 {
		t.Fatalf("稳态滞后不得重复告警, got %v", lines)
	}
	// 追平后再滞后：告警态已清，可再次 WARN
	if _, err := db.DB.Exec(`UPDATE nodes SET reported_version=7 WHERE id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
	masterSyncServingRound(ctx, servingBase.Add(9*masterSyncInspectInterval), w)
	if _, err := db.DB.Exec(`UPDATE nodes SET reported_version=3 WHERE id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
	for i := 10; i < 17; i++ {
		masterSyncServingRound(ctx, servingBase.Add(time.Duration(i)*masterSyncInspectInterval), w)
	}
	lines = servingLines(readClusterSyncLog(t))
	if len(lines) != 2 {
		t.Fatalf("恢复后再滞后应可再次告警, got %d: %v", len(lines), lines)
	}
}

// 巡检错误：WARN 不中断（下轮继续）。
func TestMasterServingRound_dbErrorWarnsAndContinues(t *testing.T) {
	// 合成轮测试用轻量环境（不启动 daemon）——与 offlineWarnsOnce/cleanRoundsSilent 同格。
	newServingTestEnv(t)
	if _, err := db.DB.Exec(`DROP TABLE nodes`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := db.DB.Exec(`CREATE TABLE nodes (id INTEGER PRIMARY KEY, name TEXT, mode TEXT)`); err != nil {
			t.Fatal(err)
		}
	})
	w := newServingWatch()
	ctx := context.Background()
	masterSyncServingRound(ctx, servingBase, w)
	masterSyncServingRound(ctx, servingBase.Add(masterSyncInspectInterval), w)
	if lines := servingLines(readClusterSyncLog(t)); len(lines) != 2 {
		t.Fatalf("每轮错误应 WARN 且不中断, got %v", lines)
	}
}

// ---- ④ 镜像角色门在 services 面的投影 ----

// Given 活跃 cert_jobs 行（主端快照会同步到从节点——镜像时代从节点被伪造 running）。
// When 从节点角色聚合，再翻回主节点。
// Then 从节点 cert-issuance 显示本节点实态 idle（镜像被角色门拦截）；主节点 running。
func TestTaskEngineWire_CertIssuanceSlaveShowsLocalState(t *testing.T) {
	te := newWireTestEngine(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status) VALUES ('r1','a.test','pending')`); err != nil {
		t.Fatal(err)
	}
	te.SetRole(false)
	// demote 的 daemon 停止是异步的——先等本节点实态落定（真实运行位归 false）
	waitForCond(t, 2*time.Second, func() bool { return !te.IsRunning("cert-issuance") })
	for _, ti := range collectEngineFamilies(te) {
		if ti.ID == "cert-issuance" {
			if ti.Status != TaskStatusIdle {
				t.Fatalf("从节点 cert-issuance 应显示本节点实态 idle（镜像被角色门拦截）, got %s", ti.Status)
			}
		}
	}
	te.SetRole(true)
	saw := false
	for _, ti := range collectEngineFamilies(te) {
		if ti.ID == "cert-issuance" {
			saw = true
			if ti.Status != TaskStatusRunning {
				t.Fatalf("主节点 cert-issuance 应 running（真实业务态）, got %s", ti.Status)
			}
		}
	}
	if !saw {
		t.Fatal("cert-issuance 未注册")
	}
}
