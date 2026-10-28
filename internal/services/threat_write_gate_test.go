package services

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 成功写路径角色复核（与 CRS observeCancelAfterSwap 同族）：下载/解析完成到
// 写库之间存在降级窗口——现有钉测只覆盖下载期取消，本组补成功路径窗：
// 写前复核（updateRunWriteGate）命中降级/不可判定时不写库、不标成功。

// Given 主节点下载成功，但写库前节点已降级为从节点（is_master=0）。
// When updateOneSource 走到成功写路径。
// Then 不写名单文件、源行不落 success（从节点零写，由集群同步收敛），
// 返回 (changed=false, failed=false)（中止非故障）。
func TestThreatUpdateOneSource_demoteAtWriteGate_zeroWrite(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`) })

	var id int
	var url string
	if err := db.DB.QueryRow(`SELECT id, url FROM security_threat_sources WHERE name='ustc'`).Scan(&id, &url); err != nil {
		t.Fatal(err)
	}

	changed, failed := GetThreatUpdateManager().updateOneSource(context.Background(), threatSourceRow{id: id, name: "ustc", url: url}, "manual", "2026.10.22 00:00:00")

	if changed || failed {
		t.Fatalf("changed=%v failed=%v, want (false,false)（降级中止非故障）", changed, failed)
	}
	if _, err := os.Stat(filepath.Join(wafDir, "threat-ustc.iplist")); !os.IsNotExist(err) {
		t.Fatal("降级窗口不得写名单文件（从节点零写）")
	}
	if _, err := os.Stat(filepath.Join(wafDir, "threat-ustc.iplist.fast")); !os.IsNotExist(err) {
		t.Fatal("降级窗口不得写 .fast 编译产物（从节点零写）")
	}
	var status string
	if err := db.DB.QueryRow(`SELECT update_status FROM security_threat_sources WHERE id=?`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	// 精确断言：源行必须滞留 running——只比 !=success 会让写 failed/skipped
	// 等错误终态同样通过（写门本应在任何写库前中止）。
	if status != "running" {
		t.Fatalf("status=%q, want running（降级窗口不写任何终态，源行由集群同步收敛）", status)
	}
}

// Given 主节点下载成功，但写库前角色读取失败（global_config 行缺失→不可判定；
// 威胁源表读写仍可用——区分「复核未写」与「写了但失败」）。
// When updateOneSource 走到成功写路径。
// Then 不写库（名单文件不落盘、源行滞留 running），按源失败返回
// （failed=true，任务可见）——不得并入降级/取消。
func TestThreatUpdateOneSource_roleUndecidableAtWriteGate_failsLoudly(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)

	var id int
	var url string
	if err := db.DB.QueryRow(`SELECT id, url FROM security_threat_sources WHERE name='ustc'`).Scan(&id, &url); err != nil {
		t.Fatal(err)
	}
	// 角色不可判定形态：global_config 行缺失（RoleOf ErrNoRows），其余表正常。
	if _, err := db.DB.Exec(`DELETE FROM global_config WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	changed, failed := GetThreatUpdateManager().updateOneSource(context.Background(), threatSourceRow{id: id, name: "ustc", url: url}, "manual", "2026.10.22 00:00:00")

	if !failed || changed {
		t.Fatalf("changed=%v failed=%v, want (false,true)（角色不可判定按失败落定，不得写库）", changed, failed)
	}
	if _, err := os.Stat(filepath.Join(wafDir, "threat-ustc.iplist")); !os.IsNotExist(err) {
		t.Fatal("角色不可判定不得写名单文件")
	}
	var status string
	if err := db.DB.QueryRow(`SELECT update_status FROM security_threat_sources WHERE id=?`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		t.Fatalf("status=%q, want running（不可判定不落任何终态）", status)
	}
}

// Given 运行中手动取消且角色读取失败（降级/取消不可判定）。
// When RunUpdate 的取消归因复核读到角色故障。
// Then 任务终态=failed（非 cancelled——DB 故障不得误报「手动取消」），
// 且不进入收敛段（投影刷新/重载零调用）。
func TestThreatRunUpdate_roleUndecidableAbort_outcomeFailedNotCancelled(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)

	orig := db.DB
	fake := openThreatFailDB(t)
	t.Cleanup(func() { db.DB = orig })

	refreshCalls := 0
	SetThreatProjectionRefresher(func() (IPListProjectionOutcome, error) {
		refreshCalls++
		return ProjectionConverged, nil
	})
	t.Cleanup(func() { SetThreatProjectionRefresher(nil) })

	m := GetThreatUpdateManager()
	// 首个源下载期间：取消本轮 + DB 换故障连接（取消归因不可判定）。
	flipThreatSourceURL(t, "ustc", func() {
		db.DB = fake
		m.CancelRunning()
	})

	err := m.RunUpdate("manual", nil)

	if err == nil {
		t.Fatal("角色不可判定的中止必须回传错误（引擎落 failed 行）")
	}
	if got := m.StatusSnapshot().Outcome; got != "failed" {
		t.Fatalf("outcome=%q, want failed（DB 故障不得误报 cancelled/skipped）", got)
	}
	if refreshCalls != 0 {
		t.Fatalf("角色不可判定不得进入收敛段，投影刷新调用=%d", refreshCalls)
	}
}

// 下载期取消的归因不可判定分支（与爬虫族对齐）：不写源行、按失败返回。
// Given 源在途下载期间取消且 DB 换为故障连接（角色不可判定）。
// Then failed=true（旧形态并入 cancelled 分支返回 failed=false 且尝试写
// cancelSourceRow——DB 故障被误报为手动取消）。
func TestThreatUpdateOneSource_roleUndecidableOnCancel_noSourceRowWrite(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)

	orig := db.DB
	fake := openThreatFailDB(t)
	t.Cleanup(func() { db.DB = orig })
	ctx, cancel := context.WithCancel(context.Background())
	// 下载桩：标记 running（真实库）完成后取消本轮并切换故障连接。
	flipThreatSourceURL(t, "ustc", func() {
		cancel()
		db.DB = fake
	})

	var id int
	var url string
	if err := db.DB.QueryRow(`SELECT id, url FROM security_threat_sources WHERE name='ustc'`).Scan(&id, &url); err != nil {
		t.Fatal(err)
	}

	changed, failed := GetThreatUpdateManager().updateOneSource(ctx, threatSourceRow{id: id, name: "ustc", url: url}, "manual", "2026.10.22 00:00:00")

	if !failed || changed {
		t.Fatalf("changed=%v failed=%v, want (false,true)（取消归因不可判定按失败落定）", changed, failed)
	}
	// 不写源行终态（故障连接上 cancelSourceRow 也写不进——恢复真实库核对
	// 仍滞留 running 标记）。
	db.DB = orig
	var status string
	if err := db.DB.QueryRow(`SELECT update_status FROM security_threat_sources WHERE id=?`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		t.Fatalf("status=%q, want running（归因不可判定不写源行终态）", status)
	}
}

// ---- heal 可解析率门（复用下载侧 threatMinParseRatio 同源阈值）----

// Given 文本名单大面积损坏（可解析率 <50%）且 .fast 缺失（双故障形态）。
// When healThreatFastFromText 尝试从损坏文本重建。
// Then 拒绝重建（ok=false、不落 .fast）——不得以垃圾/空集修复并标成功
// （静默归零形态）。
func TestHealThreatFastFromText_rejectsLowParseRatio(t *testing.T) {
	restore := OverrideThreatWafDirForTest(t.TempDir())
	defer restore()

	var sb strings.Builder
	sb.WriteString("203.0.113.1\n198.51.100.0/24\n") // 2 条合法
	for range 8 {
		sb.WriteString("not-an-ip-garbage-line\n")
	}
	iplistPath := filepath.Join(wafDir, "threat-ustc.iplist")
	if err := os.WriteFile(iplistPath, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, ok := healThreatFastFromText("ustc")

	if ok {
		t.Fatalf("可解析率 2/10 低于 50%% 必须拒绝修复，得到 ok=true（%d 条）", len(entries))
	}
	if _, err := os.Stat(iplistPath + ".fast"); !os.IsNotExist(err) {
		t.Fatal("拒绝修复不得落 .fast（保留损坏现场，不得覆盖为垃圾编译产物）")
	}
}

// 回归形状：可解析率 ≥50% 的文本照常修复。
func TestHealThreatFastFromText_acceptsHealthyText(t *testing.T) {
	restore := OverrideThreatWafDirForTest(t.TempDir())
	defer restore()

	content := "203.0.113.1\n198.51.100.0/24\n10.0.0.0/8\nbogus-line\n"
	iplistPath := filepath.Join(wafDir, "threat-ustc.iplist")
	if err := os.WriteFile(iplistPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, ok := healThreatFastFromText("ustc")

	if !ok {
		t.Fatal("可解析率 3/4 应通过修复门")
	}
	if len(entries) != 3 {
		t.Fatalf("entries=%v, want 3 条合法条目（垃圾行不得入列）", entries)
	}
	if _, err := os.Stat(iplistPath + ".fast"); err != nil {
		t.Fatalf("修复成功须落 .fast: %v", err)
	}
}

// 双故障集成形态：文本损坏 + .fast 损坏 + 下载失败——源按失败落定，
// 既有库内名单不被静默归零（heal 拒绝 → 落入下载 → 下载失败 → 保留快照）。
func TestThreatUpdateOneSource_corruptTextAndFast_noSilentZeroing(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, map[string]bool{"ustc": true}, nil) // ustc 下载恒失败

	// 双故障现场：.iplist 大面积损坏 + .fast 缺失。
	var sb strings.Builder
	sb.WriteString("203.0.113.1\n")
	for range 6 {
		sb.WriteString("garbage-not-ip\n")
	}
	if err := os.WriteFile(filepath.Join(wafDir, "threat-ustc.iplist"), []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	var id int
	var url string
	if err := db.DB.QueryRow(`SELECT id, url FROM security_threat_sources WHERE name='ustc'`).Scan(&id, &url); err != nil {
		t.Fatal(err)
	}

	changed, failed := GetThreatUpdateManager().updateOneSource(context.Background(), threatSourceRow{id: id, name: "ustc", url: url}, "manual", "2026.10.22 00:00:00")

	if !failed {
		t.Fatalf("双故障+下载失败必须按源失败落定，得到 changed=%v failed=%v", changed, failed)
	}
	var status string
	if err := db.DB.QueryRow(`SELECT update_status FROM security_threat_sources WHERE id=?`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("status=%q, want failed（不得静默归零标 success）", status)
	}
	if _, err := os.Stat(filepath.Join(wafDir, "threat-ustc.iplist.fast")); !os.IsNotExist(err) {
		t.Fatal("heal 被拒后不得落 .fast")
	}
}

// ---- 测试辅助 ----

// openThreatFailDB 打开全部写失败、威胁源表读失败、其余读返回空集的故障库
// （角色读取=global_config 空集 → RoleOf ErrNoRows → 角色不可判定）。
func openThreatFailDB(t *testing.T) *sql.DB {
	t.Helper()
	f := sql.OpenDB(threatUpdateFailConnector{})
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// flipThreatSourceURL 把指定源的 URL 指向「先执行钩子再回合法名单」的桩。
func flipThreatSourceURL(t *testing.T, name string, hook func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hook()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("203.0.113.1\n10.9.0.0/24\n"))
	}))
	t.Cleanup(srv.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name=?`, srv.URL, name); err != nil {
		t.Fatal(err)
	}
}

// ---- 文本自愈（heal）写盘同样受角色写门约束 ----

// Given 主节点已在更新前的某个窗口降级为从节点，且本源的文本完好、.fast 缺失
// （自愈形态）。
// When updateOneSource 走到入口的自愈分支。
// Then 不得编译落盘 .fast（自愈是写盘副作用，与慢路径写库同权；从节点零写），
// 返回降级中止 (false,false)。
func TestThreatUpdateOneSource_demotedHealPath_zeroWrite(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	if err := os.WriteFile(filepath.Join(wafDir, "threat-ustc.iplist"), []byte("203.0.113.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`) })

	var id int
	var url string
	if err := db.DB.QueryRow(`SELECT id, url FROM security_threat_sources WHERE name='ustc'`).Scan(&id, &url); err != nil {
		t.Fatal(err)
	}

	changed, failed := GetThreatUpdateManager().updateOneSource(context.Background(), threatSourceRow{id: id, name: "ustc", url: url}, "manual", "2026.10.22 00:00:00")

	if changed || failed {
		t.Fatalf("changed=%v failed=%v, want (false,false)（降级中止非故障）", changed, failed)
	}
	if _, err := os.Stat(filepath.Join(wafDir, "threat-ustc.iplist.fast")); !os.IsNotExist(err) {
		t.Fatal("降级窗口内自愈不得编译落盘 .fast（从节点零写）")
	}
}

// Given 角色读取失败（不可判定），文本完好、.fast 缺失。
// When updateOneSource 走到入口的自愈分支。
// Then 不落盘 .fast，按源失败返回（failed=true，任务可见），源行滞留 running。
func TestThreatUpdateOneSource_roleUndecidableHealPath_failsLoudly(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	if err := os.WriteFile(filepath.Join(wafDir, "threat-ustc.iplist"), []byte("203.0.113.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var id int
	var url string
	if err := db.DB.QueryRow(`SELECT id, url FROM security_threat_sources WHERE name='ustc'`).Scan(&id, &url); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`DELETE FROM global_config WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	changed, failed := GetThreatUpdateManager().updateOneSource(context.Background(), threatSourceRow{id: id, name: "ustc", url: url}, "manual", "2026.10.22 00:00:00")

	if changed || !failed {
		t.Fatalf("changed=%v failed=%v, want (false,true)（角色不可判定按失败落定）", changed, failed)
	}
	if _, err := os.Stat(filepath.Join(wafDir, "threat-ustc.iplist.fast")); !os.IsNotExist(err) {
		t.Fatal("角色不可判定时自愈不得落盘 .fast")
	}
}
