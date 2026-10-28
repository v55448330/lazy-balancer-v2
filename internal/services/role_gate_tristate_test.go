package services

// 角色门三态化家族（角色门三态家族 / 看门狗角色读失败留痕 / 部分提交收敛 / 任务行读失败留痕）钉测。
//
// 家族缺陷：`err != nil || !isMaster` 把「角色读取失败（DB 瞬断/脏行）」并入
// 「非主节点」——任务被静默跳过并落 success/skipped，DB 异常在任务监控不可见。
// 正确形态（对照 certificates.go renewExpiringCertificates）：读失败 → 留痕 +
// 任务失败终态；确认从节点 → skipped 语义不变。
//
// 角色读失败形态：is_master 写入非布尔文本使 RoleOf 的 Scan 失败（DB 连接本身
// 健康——任务状态行/名单行写入仍可用）。

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// corruptClusterRole 把 is_master 置为非布尔文本（RoleOf Scan 失败=角色不可判定）。
func corruptClusterRole(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master='corrupt' WHERE id=1`); err != nil {
		t.Fatalf("corrupt role row: %v", err)
	}
}

// captureLogf 截获标准 log 输出（Logf 的落点）用于断言留痕形态。
func captureLogf(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	oldWriter, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
	})
	return buf
}

// Given 起点角色读失败（DB 健康、is_master 脏值）。When CRS 更新启动。
// Then 落 failed 终态并显性说明「角色读取失败」——不得当从节点静默 skipped。
func TestCRSUpdateRun_roleReadFailureAtStartFailsLoudly(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", false)
	newTaskLogDir(t)
	corruptClusterRole(t)

	done, err := m.StartUpdate("manual", &taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"})
	if err != nil {
		t.Fatalf("StartUpdate: %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("角色读取失败后 CRS 更新未在合理时间内落定")
	}
	snap := m.StatusSnapshot()
	if snap.Status != string(CRSStatusFailed) {
		t.Fatalf("status=%q, want failed（角色读取失败≠从节点，不得静默 skipped）", snap.Status)
	}
	if !strings.Contains(snap.Message, "角色读取失败") {
		t.Fatalf("message=%q 必须显性说明角色读取失败", snap.Message)
	}
	var status, message string
	if err := db.DB.QueryRow(`SELECT COALESCE(update_status,''), COALESCE(message,'') FROM security_crs_version WHERE id=1`).Scan(&status, &message); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(message, "角色读取失败") {
		t.Fatalf("版本行 status=%q message=%q, want failed + 角色读取失败", status, message)
	}
}

// 同族镜像形状：IP2Region 起点角色读失败按失败落定。
func TestIP2RegionUpdateRun_roleReadFailureAtStartFailsLoudly(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v1.0.0", false)
	newTaskLogDir(t)
	corruptClusterRole(t)

	done, err := m.StartUpdate("manual", &taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"})
	if err != nil {
		t.Fatalf("StartUpdate: %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("角色读取失败后 IP2Region 更新未在合理时间内落定")
	}
	var status, message string
	if err := db.DB.QueryRow(`SELECT COALESCE(update_status,''), COALESCE(message,'') FROM security_ip2region_version WHERE id=1`).Scan(&status, &message); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(message, "角色读取失败") {
		t.Fatalf("版本行 status=%q message=%q, want failed + 角色读取失败", status, message)
	}
}

// 威胁情报库起点角色读失败：outcome=failed + 任务错误回传（引擎落 failed 行）。
func TestThreatRunUpdate_roleReadFailureAtStartFailsLoudly(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	newTaskLogDir(t)
	corruptClusterRole(t)

	err := GetThreatUpdateManager().RunUpdate("manual", &taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"})
	if !errors.Is(err, ErrThreatUpdateFailed) {
		t.Fatalf("err=%v, want ErrThreatUpdateFailed（角色读取失败必须任务可见）", err)
	}
	if got := GetThreatUpdateManager().StatusSnapshot().Outcome; got != "failed" {
		t.Fatalf("outcome=%q, want failed（不得记 skipped——角色读取失败≠从节点）", got)
	}
	if logText := readTaskLog(t, "threat"); !strings.Contains(logText, "角色读取失败") {
		t.Fatalf("威胁任务日志缺少「角色读取失败」留痕:\n%s", logText)
	}
}

// 爬虫地址库起点角色读失败：返回错误（非 ErrTaskSkipped）——引擎落 failed 行。
func TestCrawlerRunUpdate_roleReadFailureAtStartFailsLoudly(t *testing.T) {
	newClusterTestService(t)
	newTaskLogDir(t)
	corruptClusterRole(t)

	err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"})
	if err == nil {
		t.Fatal("角色读取失败必须返回错误（此前当从节点静默 skipped）")
	}
	if errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v, 不得是 ErrTaskSkipped（角色读取失败≠从节点）", err)
	}
	if !strings.Contains(err.Error(), "角色读取失败") {
		t.Fatalf("err=%v 必须显性说明角色读取失败", err)
	}
	if logText := readTaskLog(t, "crawlerbot-update"); !strings.Contains(logText, "角色读取失败") {
		t.Fatalf("爬虫任务日志缺少「角色读取失败」留痕:\n%s", logText)
	}
}

// 自动封禁角色门三形态：master 越过角色门（到业务门）、slave 保持 skipped、
// unknown（DB 故障）按失败返回。
func TestAutobanRunCycle_roleGateThreeForms(t *testing.T) {
	installAutobanEngineFixture(t)
	setAutobanConfigRaw(t, false, 1, 5, "1h", "all", true)

	// slave：确认从节点 → skipped 语义不变。
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "manual"}); !errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("slave err=%v, want ErrTaskSkipped", err)
	}

	// unknown：角色读失败 → 错误（任务可见），不得静默 skipped。
	corruptClusterRole(t)
	err := RunAutobanCycle(taskengine.RunContext{Trigger: "manual"})
	if err == nil || errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("unknown err=%v, want 角色读取失败错误（非 skipped）", err)
	}
	if !strings.Contains(err.Error(), "角色读取失败") {
		t.Fatalf("unknown err=%v 必须显性说明角色读取失败", err)
	}

	// master：越过角色门 → 到业务门（未启用 → 拒绝执行），证明角色门未误拦。
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	err = RunAutobanCycle(taskengine.RunContext{Trigger: "manual"})
	if err == nil || !strings.Contains(err.Error(), "未启用") {
		t.Fatalf("master err=%v, want 业务门「未启用」错误（角色门必须放行主节点）", err)
	}
}

// 配置看门狗角色读失败（看门狗角色读失败留痕）：计入 skipped 轮簿记、任务错误返回、
// 不宣称一致（与 !checked 跳轮同口径）。
func TestWatchdogCheckOnce_roleReadFailureCountsSkippedAndFails(t *testing.T) {
	newClusterTestService(t)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	corruptClusterRole(t)

	err := WatchdogCheckOnce(context.Background())
	if err == nil {
		t.Fatal("角色读取失败必须返回错误（此前 return nil → task_runs 恒 success）")
	}
	if !strings.Contains(err.Error(), "角色读取失败") {
		t.Fatalf("err=%v 必须显性说明角色读取失败", err)
	}
	drift := CurrentConfigDrift()
	if got := currentSkippedRounds(); got != 1 {
		t.Fatalf("跳过轮计数=%d, want 1（角色读失败计入跳过轮簿记）", got)
	}
	if !drift.Consistent {
		t.Fatalf("角色读失败不得置漂移/不一致结论（未判定≠不一致）: %+v", drift)
	}
	if logText := readTaskLog(t, "config-watchdog"); !strings.Contains(logText, "角色读取失败") {
		t.Fatalf("看门狗任务日志缺少「角色读取失败」留痕:\n%s", logText)
	}
}

// CRS 状态对账角色读失败：warn 留痕（此前零日志静默返回）。
func TestReconcileCRSState_roleReadFailureLogsWarn(t *testing.T) {
	// 复用单源隔离夹具（四句柄成对还原）。
	setupIsolatedDB(t)
	corruptClusterRole(t)
	buf := captureLogf(t)

	ReconcileCRSState()

	if !strings.Contains(buf.String(), "角色读取失败") {
		t.Fatalf("对账跳过必须留痕「角色读取失败」（此前零日志）: %q", buf.String())
	}
}

// 证书任务行动态收集（任务行读失败留痕）：Query/Scan 失败必须 warn 留痕，不再静默空列表。
func TestTaskMonitorCertJobs_queryFailureLogsWarn(t *testing.T) {
	// 复用单源隔离夹具（四句柄成对还原）。
	setupIsolatedDB(t)
	// 去掉 cert_jobs 表制造 Query 失败（其余读取面不受影响）。
	if _, err := db.DB.Exec(`ALTER TABLE cert_jobs RENAME TO cert_jobs_offline`); err != nil {
		t.Fatal(err)
	}
	buf := captureLogf(t)

	if got, _ := collectCertJobRows(); got != nil {
		t.Fatalf("查询失败应返回空列表, got %d 行", len(got))
	}
	if !strings.Contains(buf.String(), "cert 任务行查询失败") {
		t.Fatalf("查询失败必须 warn 留痕（此前静默返回空列表）: %q", buf.String())
	}
}

// 爬虫快照部分提交收敛（部分提交收敛）：DB 已更新而运行快照写失败时，仍须消费
// changed 触发投影收敛——否则 DB/投影/插件快照分叉且无收敛动作。
func TestCrawlerRunUpdate_snapshotWriteFailureStillConverges(t *testing.T) {
	_, database := newClusterTestService(t)
	newTaskLogDir(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"66.249.68.0/24"},{"ipv4Prefix":"66.249.69.0/24"}]}`))
	}))
	t.Cleanup(ts.Close)
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0;
		UPDATE security_crawler_sources SET update_enabled=1,url=? WHERE name='googlebot'`, ts.URL); err != nil {
		t.Fatal(err)
	}
	// 预置当前快照 2 条（收缩/扩张门基线走 DB 分支，同生产形态）。
	if err := upsertCrawlerIPList("googlebot", []string{"66.249.66.0/24", "66.249.67.0/24"}); err != nil {
		t.Fatal(err)
	}
	// 运行交换文件不可写（目录缺失）→ DB 更新成功后快照写失败=部分提交。
	crawlerIPListFile = filepath.Join(t.TempDir(), "missing-dir", "crawler-ip-lists.json")

	refreshed := 0
	oldRefresher, oldReloader := threatProjectionRefresher, threatReloader
	threatProjectionRefresher = func() (IPListProjectionOutcome, error) {
		refreshed++
		return ProjectionConverged, nil
	}
	threatReloader = func() error { return nil }
	t.Cleanup(func() {
		threatProjectionRefresher, threatReloader = oldRefresher, oldReloader
	})

	err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"})
	if err == nil {
		t.Fatal("快照写失败必须以错误返回（源行 failed）")
	}
	// DB 已更新（部分提交的事实面）。
	var entries string
	if qerr := database.QueryRow(`SELECT COALESCE(entries,'') FROM security_ip_lists WHERE name=? AND system=1`, CrawlerIPListName("googlebot")).Scan(&entries); qerr != nil {
		t.Fatal(qerr)
	}
	if !strings.Contains(entries, "66.249.68.0/24") {
		t.Fatalf("前置：DB 应已更新为新内容, got %q", entries)
	}
	if refreshed == 0 {
		t.Fatal("DB 已更新而快照写失败时必须触发投影收敛（changed 必须在 err 分支被消费）")
	}
}
