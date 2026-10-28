package services

// demote 在途 Scheduled 中止——三库 Run 体的
// runCtx 曾是独立 context.Background（crsupdate/ip2regionupdate/threatupdate），
// 引擎 SetRole 对 Scheduled 在途的取消（rc.Ctx）传不进去，demote 后任务跑完、
// 从节点写版本行/名单/规则树，打破只读不变量。修复：runCtx 派生自 rc.Ctx
// （nil 回退 Background——测试/内部路径不变）；中止点复核角色——非主节点落
// skipped（与三库起点角色复查同语义），主节点保持手动取消 cancelled 口径。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

type demoteVersionRowSnapshot struct {
	version, status, message            string
	finishedAt, lastChecked, nextUpdate string
	autoUpdate                          bool
}

func snapshotCRSVersionForDemote(t *testing.T) demoteVersionRowSnapshot {
	t.Helper()
	version, status, message, finishedAt, lastChecked, nextUpdate, autoUpdate := crsVersionRow(t)
	return demoteVersionRowSnapshot{version, status, message, finishedAt, lastChecked, nextUpdate, autoUpdate}
}

func snapshotIP2RegionVersionForDemote(t *testing.T) demoteVersionRowSnapshot {
	t.Helper()
	version, status, message, finishedAt, lastChecked, nextUpdate, autoUpdate := ip2RegionVersionRow(t)
	return demoteVersionRowSnapshot{version, status, message, finishedAt, lastChecked, nextUpdate, autoUpdate}
}

type demoteFileSnapshot struct {
	exists bool
	data   string
}

func snapshotDemoteFile(t *testing.T, path string) demoteFileSnapshot {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return demoteFileSnapshot{}
	}
	if err != nil {
		t.Fatalf("snapshot %s: %v", path, err)
	}
	return demoteFileSnapshot{exists: true, data: string(data)}
}

func assertDemoteFileUnchanged(t *testing.T, path string, before demoteFileSnapshot) {
	t.Helper()
	if after := snapshotDemoteFile(t, path); after != before {
		t.Fatalf("demote 中止改写了 %s：before=%+v after=%+v", path, before, after)
	}
}

type demoteThreatSourceSnapshot struct {
	entryCount, consecutiveFailures                        int
	version, status, message, lastChecked, nextUpdate      string
	trigger, startedAt, finishedAt, rawHash, lastUpdatedAt string
}

func snapshotThreatSourceForDemote(t *testing.T, name string) demoteThreatSourceSnapshot {
	t.Helper()
	var s demoteThreatSourceSnapshot
	if err := db.DB.QueryRow(`SELECT entry_count, version, update_status, message,
		COALESCE(last_checked,''), COALESCE(next_update,''), trigger, COALESCE(started_at,''),
		COALESCE(finished_at,''), consecutive_failures, COALESCE(raw_hash,''), COALESCE(updated_at,'')
		FROM security_threat_sources WHERE name=?`, name).Scan(
		&s.entryCount, &s.version, &s.status, &s.message, &s.lastChecked, &s.nextUpdate,
		&s.trigger, &s.startedAt, &s.finishedAt, &s.consecutiveFailures, &s.rawHash, &s.lastUpdatedAt,
	); err != nil {
		t.Fatalf("snapshot threat source %s: %v", name, err)
	}
	return s
}

func assertSingleDemoteSkipAudit(t *testing.T, resource, wantAction string) {
	t.Helper()
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE resource=?`, resource).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("%s demote 审计条数=%d, want 1", resource, count)
	}
	var action, detail string
	if err := db.AuditDB.QueryRow(`SELECT action, COALESCE(detail,'') FROM audit_log WHERE resource=?`, resource).Scan(&action, &detail); err != nil {
		t.Fatal(err)
	}
	if action != wantAction || !strings.Contains(detail, "更新跳过") {
		t.Fatalf("%s demote 审计=(%q,%q), want action=%q 且终态词=更新跳过", resource, action, detail, wantAction)
	}
}

// Given CRS 更新在途（fetchLatestTag 阻塞于 runCtx）。
// When 运行中 demote（is_master=0）+ 引擎侧 rc.Ctx 取消（SetRole 中止语义）。
// Then 任务立即中止且落 skipped（旧形态：runCtx 独立 Background，取消传不入，
// 跑完才退出——RED 超时）。
func TestCRSUpdateRun_demoteMidFlightAbortsAsSkipped(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)

	entered := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var once sync.Once
	m.fetchLatestTag = func(ctx context.Context) (string, error) {
		once.Do(func() { close(entered) })
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-release:
			return "", errors.New("released without cancel")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done, err := m.StartUpdate("auto", &taskengine.RunContext{Ctx: ctx, Trigger: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	waitUpdateTestSignal(t, entered, "CRS demote 用例进入下载")
	versionBefore := snapshotCRSVersionForDemote(t)
	sidecarBefore := snapshotDemoteFile(t, filepath.Join(m.liveDir(), crsVersionFile))
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("demote 后在途 CRS 更新未被中止（runCtx 未随 rc.Ctx 取消）")
	}
	if snap := m.StatusSnapshot(); snap.Status != string(CRSStatusSkipped) {
		t.Fatalf("status=%q, want skipped（demote 中止与起点角色复查同语义）", snap.Status)
	}
	if got := snapshotCRSVersionForDemote(t); got != versionBefore {
		t.Fatalf("CRS demote 中止改写版本行: before=%+v after=%+v", versionBefore, got)
	}
	assertDemoteFileUnchanged(t, filepath.Join(m.liveDir(), crsVersionFile), sidecarBefore)
	assertSingleDemoteSkipAudit(t, "CRS规则库", "更新")
}

// Given IP2Region 更新在途（fetchLatestTag 阻塞于 runCtx）。
// When 运行中 demote + rc.Ctx 取消。
// Then 立即中止且落 skipped（镜像 CRS 口径）。
func TestIP2RegionUpdateRun_demoteMidFlightAbortsAsSkipped(t *testing.T) {
	m := newTestIP2RegionManager(t)

	entered := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var once sync.Once
	m.fetchLatestTag = func(ctx context.Context) (string, error) {
		once.Do(func() { close(entered) })
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-release:
			return "", errors.New("released without cancel")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done, err := m.StartUpdate("auto", &taskengine.RunContext{Ctx: ctx, Trigger: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	waitUpdateTestSignal(t, entered, "IP2Region demote 用例进入下载")
	versionBefore := snapshotIP2RegionVersionForDemote(t)
	sidecarBefore := snapshotDemoteFile(t, ip2regionLivePath+".version")
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("demote 后在途 IP2Region 更新未被中止（runCtx 未随 rc.Ctx 取消）")
	}
	if snap := m.StatusSnapshot(); snap.Status != string(IP2RegionStatusSkipped) {
		t.Fatalf("status=%q, want skipped（demote 中止与起点角色复查同语义）", snap.Status)
	}
	if got := snapshotIP2RegionVersionForDemote(t); got != versionBefore {
		t.Fatalf("IP2Region demote 中止改写版本行: before=%+v after=%+v", versionBefore, got)
	}
	assertDemoteFileUnchanged(t, ip2regionLivePath+".version", sidecarBefore)
	assertSingleDemoteSkipAudit(t, "IP数据库", "更新")
}

// Given 威胁库更新在途（源下载阻塞于请求 ctx——经 runCtx 派生）。
// When 运行中 demote + rc.Ctx 取消。
// Then 立即中止且 outcome=skipped（非 cancelled——非用户取消；非 failed——非源失败语义）。
func TestThreatRunUpdate_demoteMidFlightAbortsAsSkipped(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)

	entered := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var once sync.Once
	blocking := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(blocking.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='ustc'`, blocking.URL); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- GetThreatUpdateManager().RunUpdate("manual", &taskengine.RunContext{Ctx: ctx, Trigger: "manual"})
	}()
	waitUpdateTestSignal(t, entered, "威胁库 demote 用例进入下载")
	sourceBefore := snapshotThreatSourceForDemote(t, "ustc")
	iplistBefore := snapshotDemoteFile(t, filepath.Join(wafDir, "threat-ustc.iplist"))
	fastBefore := snapshotDemoteFile(t, filepath.Join(wafDir, "threat-ustc.iplist.fast"))
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	cancel()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("demote 中止属跳过语义，RunUpdate err=%v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("demote 后在途威胁库更新未被中止（runCtx 未随 rc.Ctx 取消）")
	}
	if got := GetThreatUpdateManager().StatusSnapshot().Outcome; got != "skipped" {
		t.Fatalf("outcome=%q, want skipped（demote 中止与起点角色复查同语义）", got)
	}
	if got := snapshotThreatSourceForDemote(t, "ustc"); got != sourceBefore {
		t.Fatalf("威胁库 demote 中止改写源行: before=%+v after=%+v", sourceBefore, got)
	}
	assertDemoteFileUnchanged(t, filepath.Join(wafDir, "threat-ustc.iplist"), iplistBefore)
	assertDemoteFileUnchanged(t, filepath.Join(wafDir, "threat-ustc.iplist.fast"), fastBefore)
	assertSingleDemoteSkipAudit(t, "威胁情报库", "跳过")
}

// 边界形状：demote 发生在末源在途（循环自然结束、不再经过顶部取消检查）——
// 中止点归一补判仍须落 skipped（不得因末源下载被中止而记 failed）。
func TestThreatRunUpdate_demoteOnLastSourceAbortsAsSkipped(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)

	var entriesMu sync.Mutex
	entries := 0
	enteredLast := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entriesMu.Lock()
		entries++
		last := entries == 3 // 三源按 id 序——第 3 个=末源
		entriesMu.Unlock()
		if !last {
			_, _ = w.Write([]byte("203.0.113.1\n10.9.0.0/24\n"))
			return
		}
		close(enteredLast)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(server.Close)
	for _, name := range []string{"ustc", "firehol_l1", "et_compromised"} {
		if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name=?`, server.URL, name); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- GetThreatUpdateManager().RunUpdate("manual", &taskengine.RunContext{Ctx: ctx, Trigger: "manual"})
	}()
	waitUpdateTestSignal(t, enteredLast, "威胁库 demote 用例进入末源下载")
	sourceBefore := snapshotThreatSourceForDemote(t, "et_compromised")
	iplistBefore := snapshotDemoteFile(t, filepath.Join(wafDir, "threat-et_compromised.iplist"))
	fastBefore := snapshotDemoteFile(t, filepath.Join(wafDir, "threat-et_compromised.iplist.fast"))
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	cancel()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("demote 中止属跳过语义，RunUpdate err=%v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("demote 后末源在途更新未被中止")
	}
	if got := GetThreatUpdateManager().StatusSnapshot().Outcome; got != "skipped" {
		t.Fatalf("末源在途 demote outcome=%q, want skipped（中止点归一补判）", got)
	}
	if got := snapshotThreatSourceForDemote(t, "et_compromised"); got != sourceBefore {
		t.Fatalf("末源在途 demote 中止改写源行: before=%+v after=%+v", sourceBefore, got)
	}
	assertDemoteFileUnchanged(t, filepath.Join(wafDir, "threat-et_compromised.iplist"), iplistBefore)
	assertDemoteFileUnchanged(t, filepath.Join(wafDir, "threat-et_compromised.iplist.fast"), fastBefore)
	assertSingleDemoteSkipAudit(t, "威胁情报库", "跳过")
}

// 手动取消必须立即打断任务内重试，且 manager/DB/审计与
// task_runs 同为 cancelled；不得重试后落 failed + 「更新失败」。
func TestWireLibraryUpdates_manualCancelAlignsTerminalAndAudit(t *testing.T) {
	tests := []struct {
		id            string
		table         string
		resource      string
		reset         func()
		initManager   func()
		setFetch      func(func(context.Context) (string, error))
		managerStatus func() string
	}{
		{
			id: "crs", table: "security_crs_version", resource: "CRS规则库",
			reset: ResetCRSUpdateManagerForTest,
			initManager: func() {
				InitCRSUpdateManager(nil)
			},
			setFetch: func(fn func(context.Context) (string, error)) {
				GetCRSUpdateManager().fetchLatestTag = fn
			},
			managerStatus: func() string { return GetCRSUpdateManager().StatusSnapshot().Status },
		},
		{
			id: "ip2region", table: "security_ip2region_version", resource: "IP数据库",
			reset: ResetIP2RegionUpdateManagerForTest,
			initManager: func() {
				InitIP2RegionUpdateManager(nil)
			},
			setFetch: func(fn func(context.Context) (string, error)) {
				GetIP2RegionUpdateManager().fetchLatestTag = fn
			},
			managerStatus: func() string { return GetIP2RegionUpdateManager().StatusSnapshot().Status },
		},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			stubUpdateRetrySleep(t)
			te := newWireTestEngine(t)
			tc.reset()
			tc.initManager()
			t.Cleanup(tc.reset)
			var calls atomic.Int32
			entered := make(chan struct{})
			var once sync.Once
			tc.setFetch(func(ctx context.Context) (string, error) {
				calls.Add(1)
				once.Do(func() { close(entered) })
				<-ctx.Done()
				return "", ctx.Err()
			})
			if err := te.RunAsync(tc.id, "manual", "tester"); err != nil {
				t.Fatalf("启动更新: %v", err)
			}
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("更新未进入下载/版本查询")
			}
			if !te.Cancel(tc.id) {
				t.Fatal("运行中任务 Cancel=false")
			}
			waitForCond(t, 3*time.Second, func() bool {
				latest := te.LatestRun(tc.id)
				return latest != nil && latest.Status != "running"
			})

			if latest := te.LatestRun(tc.id); latest == nil || latest.Status != "cancelled" {
				t.Fatalf("task_runs 终态=%+v, want cancelled", latest)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("取消后底层操作次数=%d, want 1（不得继续重试）", got)
			}
			if got := tc.managerStatus(); got != "cancelled" {
				t.Fatalf("manager 终态=%q, want cancelled", got)
			}
			var storedStatus string
			if err := db.DB.QueryRow(`SELECT update_status FROM ` + tc.table + ` WHERE id=1`).Scan(&storedStatus); err != nil {
				t.Fatal(err)
			}
			if storedStatus != "cancelled" {
				t.Fatalf("DB update_status=%q, want cancelled", storedStatus)
			}
			var action string
			if err := db.AuditDB.QueryRow(`SELECT action FROM audit_log WHERE resource=? ORDER BY id DESC LIMIT 1`, tc.resource).Scan(&action); err != nil {
				t.Fatal(err)
			}
			if action != "取消" {
				t.Fatalf("审计动作=%q, want 取消（不得记更新失败）", action)
			}
		})
	}
}

// 同族收敛：威胁/爬虫源下载中的手动取消不得把源行与审计写成失败。
func TestThreatRunUpdate_manualCancelDoesNotFailSourceOrAudit(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	var requests atomic.Int32
	entered := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		once.Do(func() { close(entered) })
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='ustc'`, server.URL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- GetThreatUpdateManager().RunUpdate("manual", &taskengine.RunContext{Ctx: ctx, Trigger: "manual"})
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("威胁源下载未进入")
	}
	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("手动取消 RunUpdate err=%v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("手动取消未中断威胁源下载/重试")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("取消后请求次数=%d, want 1", got)
	}
	if got := GetThreatUpdateManager().StatusSnapshot().Outcome; got != "cancelled" {
		t.Fatalf("任务 outcome=%q, want cancelled", got)
	}
	var status string
	if err := db.DB.QueryRow(`SELECT update_status FROM security_threat_sources WHERE name='ustc'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "cancelled" {
		t.Fatalf("源 update_status=%q, want cancelled", status)
	}
	var action string
	if err := db.AuditDB.QueryRow(`SELECT action FROM audit_log WHERE resource='威胁情报库' ORDER BY id DESC LIMIT 1`).Scan(&action); err != nil {
		t.Fatal(err)
	}
	if action != "取消" {
		t.Fatalf("审计动作=%q, want 取消", action)
	}
}

func TestCrawlerRunUpdate_manualCancelDoesNotFailSourceOrAudit(t *testing.T) {
	_, database := newClusterTestService(t)
	newTaskLogDir(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	entered := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		once.Do(func() { close(entered) })
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0;
		UPDATE security_crawler_sources SET update_enabled=1,url=? WHERE name='googlebot'`, server.URL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- GetCrawlerUpdateManager().RunUpdate(ctx, taskengine.RunContext{Ctx: ctx, Trigger: "manual"})
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("爬虫源下载未进入")
	}
	cancel()
	select {
	case err := <-runErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("手动取消 RunUpdate err=%v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("手动取消未中断爬虫源下载/重试")
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("取消后请求次数=%d, want 1", got)
	}
	var status string
	if err := database.QueryRow(`SELECT update_status FROM security_crawler_sources WHERE name='googlebot'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "cancelled" {
		t.Fatalf("源 update_status=%q, want cancelled", status)
	}
	var action string
	if err := db.AuditDB.QueryRow(`SELECT action FROM audit_log WHERE resource='爬虫地址库' ORDER BY id DESC LIMIT 1`).Scan(&action); err != nil {
		t.Fatal(err)
	}
	if action != "取消" {
		t.Fatalf("审计动作=%q, want 取消", action)
	}
}

// 复核：取消发生在安装循环入口前（op 从未执行）时，runWithInTaskRetry
// 返回 ctx 错误但 installErr 仍 nil；不得据此写 success/推进版本。
func TestUpdateInstallEntryCancellationDoesNotWriteSuccess(t *testing.T) {
	t.Run("crs", func(t *testing.T) {
		m := newTestCRSManager(t)
		seedCRSVersionRow(t, "v4.14.0", true)
		m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
		ctx, cancel := context.WithCancel(context.Background())
		oldVersion := crsCurrentVersionForRun
		crsCurrentVersionForRun = func() (string, error) {
			cancel()
			return "v4.14.0", nil
		}
		t.Cleanup(func() { crsCurrentVersionForRun = oldVersion })
		done, err := m.StartUpdate("manual", &taskengine.RunContext{Ctx: ctx, Trigger: "manual"})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("安装入口取消后未退出")
		}
		if got := m.StatusSnapshot().Status; got != "cancelled" {
			t.Fatalf("manager 终态=%q, want cancelled", got)
		}
		var status, version string
		if err := db.DB.QueryRow(`SELECT update_status,version FROM security_crs_version WHERE id=1`).Scan(&status, &version); err != nil {
			t.Fatal(err)
		}
		if status != "cancelled" || version != "v4.14.0" {
			t.Fatalf("update_status=%q version=%q, want cancelled/v4.14.0（未安装不得写成功版本）", status, version)
		}
	})

	t.Run("ip2region", func(t *testing.T) {
		m := newTestIP2RegionManager(t)
		seedIP2RegionVersionRow(t, "v3.0.0", true)
		m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
		ctx, cancel := context.WithCancel(context.Background())
		oldVersion := ip2RegionCurrentVersionForRun
		ip2RegionCurrentVersionForRun = func() string {
			cancel()
			return "v3.0.0"
		}
		t.Cleanup(func() { ip2RegionCurrentVersionForRun = oldVersion })
		done, err := m.StartUpdate("manual", &taskengine.RunContext{Ctx: ctx, Trigger: "manual"})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("安装入口取消后未退出")
		}
		if got := m.StatusSnapshot().Status; got != "cancelled" {
			t.Fatalf("manager 终态=%q, want cancelled", got)
		}
		var status, version string
		if err := db.DB.QueryRow(`SELECT update_status,version FROM security_ip2region_version WHERE id=1`).Scan(&status, &version); err != nil {
			t.Fatal(err)
		}
		if status != "cancelled" || version != "v3.0.0" {
			t.Fatalf("update_status=%q version=%q, want cancelled/v3.0.0（未安装不得写成功版本）", status, version)
		}
	})
}

// 取消发生在树交换之后（重载阶段）时，交换段已把
// security_crs_version.version 与 live VERSION 落为新 tag——旧 cancel 路径只
// 还原文件树（restoreBackup）不回滚版本行/标记，留下「旧树+新版本号」并被
// 下轮 tag==current「已是最新」短路永久固化（ReconcileCRSState 因 liveV==dbV
// 也不修复）。修复：交换完成后观察到取消一律走 rollbackAfterReloadFailure
// 同代回滚（树+VERSION 标记+DB 版本行，同一 wafFileMu 临界区）。
func TestCRSUpdateRun_cancelDuringReloadRollsBackVersionRowAndMarker(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, crsVersionFile), "v4.14.0\n")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-NEW.conf":     "SecRule new\n",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 重载期间用户取消（reloader 无 ctx 入参——取消只能在其返回后被观察到）。
	m.reloader = func() error { cancel(); return nil }

	done, err := m.StartUpdate("manual", &taskengine.RunContext{Ctx: ctx, Trigger: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("重载阶段取消后未退出")
	}

	if got := m.StatusSnapshot().Status; got != "cancelled" {
		t.Fatalf("manager 终态=%q, want cancelled", got)
	}
	// 树必须回到更新前（cancel 的 restore 编舞）
	data, err := os.ReadFile(filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"))
	if err != nil || string(data) != "SecRule old" {
		t.Fatalf("rules 树未回滚: %q,%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-NEW.conf")); !os.IsNotExist(err) {
		t.Fatal("新树残影 REQUEST-NEW.conf 不得留在 live")
	}
	// VERSION 标记与 DB 版本行必须与树同代回滚——不得停在 v4.15.0。
	if got := readCRSVersionMarker(m.crsDir); got != "v4.14.0" {
		t.Fatalf("VERSION 标记=%q, want v4.14.0（同代回滚，否则 liveV!=dbV 对账也不治）", got)
	}
	var version, status string
	if err := db.DB.QueryRow(`SELECT version, COALESCE(update_status,'') FROM security_crs_version WHERE id=1`).Scan(&version, &status); err != nil {
		t.Fatal(err)
	}
	if version != "v4.14.0" {
		t.Fatalf("DB 版本行=%q, want v4.14.0（否则下轮被「已是最新」短路永久固化）", version)
	}
	if status != "cancelled" {
		t.Fatalf("update_status=%q, want cancelled", status)
	}
}

// 取消观察点曾用二态角色复核（已退役的 updateRunStillMaster）——DB 读
// 失败被并入「非主节点」而跳过同代回滚；随后 run() 的 cancel(..., true) 走
// restoreBackup 只还文件树、不还 VERSION 标记与 DB 版本行 → 「旧树+新版本行」
// 被下轮 tag==current「已是最新」短路永久固化（ReconcileCRSState 因
// liveV==dbV 也不修复——版本行没回滚，liveV 反而是旧的，对账会把 live 标
// 记成新版本的假象固化）。修复=三态门 updateRunRole：!known（角色
// 不可判定）按主节点口径执行同代回滚（主节点避免固化；真从节点多回滚一次
// 由集群同步自愈）；known &&!master（真降级）保持 不回滚语义。
//
// 角色读失败形态：is_master 写入非布尔文本使 RoleOf 的 Scan 失败（DB 连接
// 本身健康——回滚与 cancel 的版本行写入仍可用）。
func TestCRSUpdateRun_cancelWithRoleReadFailureStillRollsBack(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"), "SecRule old")
	writeTestFile(t, filepath.Join(m.crsDir, crsVersionFile), "v4.14.0\n")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-NEW.conf":     "SecRule new\n",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.reloader = func() error {
		// 重载期间用户取消 + 角色读取故障（is_master 非布尔 → RoleOf Scan 失败）。
		// 二次调用（cancel 路径的恢复重载）幂等。
		if _, err := db.DB.Exec(`UPDATE global_config SET is_master='corrupt' WHERE id=1`); err != nil {
			t.Errorf("corrupt role row: %v", err)
		}
		cancel()
		return nil
	}

	done, err := m.StartUpdate("manual", &taskengine.RunContext{Ctx: ctx, Trigger: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("重载阶段取消后未退出")
	}

	if got := m.StatusSnapshot().Status; got != "cancelled" {
		t.Fatalf("manager 终态=%q, want cancelled", got)
	}
	// 树必须回到更新前。
	data, err := os.ReadFile(filepath.Join(m.crsDir, "rules", "REQUEST-OLD.conf"))
	if err != nil || string(data) != "SecRule old" {
		t.Fatalf("rules 树未回滚: %q,%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(m.crsDir, "rules", "REQUEST-NEW.conf")); !os.IsNotExist(err) {
		t.Fatal("新树残影 REQUEST-NEW.conf 不得留在 live")
	}
	// 角色不可判定时必须按主节点口径同代回滚：VERSION 标记与 DB 版本行
	// 与树同代——旧形态跳回滚留下 v4.15.0，被下轮「已是最新」短路永久固化。
	if got := readCRSVersionMarker(m.crsDir); got != "v4.14.0" {
		t.Fatalf("VERSION 标记=%q, want v4.14.0（角色读失败跳回滚 → 旧树+新标记固化）", got)
	}
	var version, status string
	if err := db.DB.QueryRow(`SELECT version, COALESCE(update_status,'') FROM security_crs_version WHERE id=1`).Scan(&version, &status); err != nil {
		t.Fatal(err)
	}
	if version != "v4.14.0" {
		t.Fatalf("DB 版本行=%q, want v4.14.0（角色读失败跳回滚 → 旧树+新版本行被「已是最新」短路永久固化）", version)
	}
	if status != "cancelled" {
		t.Fatalf("update_status=%q, want cancelled", status)
	}
}
