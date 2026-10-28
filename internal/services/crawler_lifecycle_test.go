package services

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/taskengine"
)

func TestRunCrawlerBotUpdate_taskLifecycleLogsAndTimestamps(t *testing.T) {
	// Given：一个启用源 + 任务引擎预插的运行行（started_at 为唯一时间源）
	_, database := newClusterTestService(t)
	newTaskLogDir(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// 源声明 format=json（官方源同形）：响应必须是合法 JSON——
		// 自此 json 源的非 JSON 响应按错误页失败（保留上次快照）。
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"66.249.66.0/24"},{"ipv4Prefix":"66.249.67.0/24"}]}`))
	}))
	defer ts.Close()
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0;
		UPDATE security_crawler_sources SET update_enabled=1,url=? WHERE name='googlebot'`, ts.URL); err != nil {
		t.Fatal(err)
	}
	// 内置首版已与官方快照对齐（googlebot 170 条），收缩门
	// 基线在「DB 无行」时取内置条数——2 条的合成响应会被判截断。生产形态恒有
	// DB 行（首轮由 Prime 落库），此处按同一形态预置当前快照 2 条，使基线走
	// DB 分支（本用例的断言对象是任务生命周期日志与时间，不是收缩门）。
	if err := upsertCrawlerIPList("googlebot", []string{"66.249.66.0/24", "66.249.67.0/24"}); err != nil {
		t.Fatal(err)
	}
	const wantStart = "2026-10-17 14:09:17"
	res, err := database.Exec(`INSERT INTO task_runs (task_id,family,trigger,status,started_at)
		VALUES ('crawlerbot-update','security','manual','running',?)`, wantStart)
	if err != nil {
		t.Fatal(err)
	}
	runID, _ := res.LastInsertId()

	// When
	if err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "manual", RunID: runID}); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Then：任务日志含业务流水，不只是引擎 start/done
	logText := readTaskLog(t, "crawlerbot-update")
	for _, want := range []string{"开始更新爬虫地址库（1 个启用源）", "下载 googlebot", "源 googlebot 更新成功（2 条，版本", "爬虫地址更新完成"} {
		if !strings.Contains(logText, want) {
			t.Errorf("任务日志缺少 %q:\n%s", want, logText)
		}
	}
	// 源状态与任务监控共用 started_at；完成时间单独落 finished_at。
	var lastChecked, startedAt, finishedAt, status string
	if err := database.QueryRow(`SELECT COALESCE(last_checked,''),COALESCE(started_at,''),COALESCE(finished_at,''),update_status
		FROM security_crawler_sources WHERE name='googlebot'`).Scan(&lastChecked, &startedAt, &finishedAt, &status); err != nil {
		t.Fatal(err)
	}
	// 源状态与任务监控是同一时刻：task_runs 为配置时区墙钟，源表统一
	// 转 UTC 存储，前端 formatDate 再按配置时区显示，禁止出现 +8h 二次偏移。
	gotInstant, parseErr := time.ParseInLocation(crsTimeLayout, lastChecked, time.UTC)
	if parseErr != nil {
		t.Fatalf("last_checked 非 UTC 形态: %q err=%v", lastChecked, parseErr)
	}
	wantInstant, parseErr := time.ParseInLocation(crsTimeLayout, wantStart, CurrentLocation())
	if parseErr != nil || !gotInstant.Equal(wantInstant) {
		t.Errorf("last_checked 与任务开始时刻不一致: last=%q task=%q err=%v", lastChecked, wantStart, parseErr)
	}
	if startedAt != lastChecked {
		t.Errorf("started_at=%q 与 last_checked=%q 未统一为同一 UTC 时刻", startedAt, lastChecked)
	}
	if finishedAt == "" || status != "success" {
		t.Errorf("完成态缺失: finished_at=%q status=%q", finishedAt, status)
	}
	var taskStart string
	if err := database.QueryRow(`SELECT started_at FROM task_runs WHERE id=?`, runID).Scan(&taskStart); err != nil {
		t.Fatal(err)
	}
	taskInstant, parseErr := time.ParseInLocation(crsTimeLayout, taskStart, CurrentLocation())
	if parseErr != nil || !gotInstant.Equal(taskInstant) {
		t.Errorf("卡片时刻=%q 与任务监控时刻=%q 不一致", lastChecked, taskStart)
	}
}

func TestRunCrawlerBotUpdate_downloadFailureMarksFailedAndLogs(t *testing.T) {
	// Given：下载返回 500 的启用源
	_, database := newClusterTestService(t)
	newTaskLogDir(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0;
		UPDATE security_crawler_sources SET update_enabled=1,url=? WHERE name='googlebot'`, ts.URL); err != nil {
		t.Fatal(err)
	}

	// When
	err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"})

	// Then：任务返回失败且源落 failed，不停留 running；日志含失败原因
	if err == nil {
		t.Fatal("下载失败应返回错误")
	}
	var status, finishedAt string
	if err := database.QueryRow(`SELECT update_status,COALESCE(finished_at,'') FROM security_crawler_sources WHERE name='googlebot'`).Scan(&status, &finishedAt); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || finishedAt == "" {
		t.Errorf("失败生命周期错误: status=%q finished_at=%q", status, finishedAt)
	}
	if logText := readTaskLog(t, "crawlerbot-update"); !strings.Contains(logText, "源 googlebot 更新失败") {
		t.Errorf("任务日志缺少源失败行:\n%s", logText)
	}
}

// RunUpdate 取消/降级分支 ——

// 下载在途取消：源行落 cancelled、保留上次快照（排程槽与版本不动）。
func TestCrawlerRunUpdate_cancelMarksSourceCancelled(t *testing.T) {
	_, database := newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-release // 模拟下载在途（取消发生在响应前）
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(func() { close(release) })
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=1, url=? WHERE name='googlebot'`, ts.URL); err != nil {
		t.Fatal(err)
	}
	var nextBefore string
	if err := database.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE name='googlebot'`).Scan(&nextBefore); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- GetCrawlerUpdateManager().RunUpdate(ctx, taskengine.RunContext{Ctx: ctx, Trigger: "manual"})
	}()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("下载未开始")
	}
	cancel()
	var runErr error
	select {
	case runErr = <-errCh:
	case <-time.After(15 * time.Second):
		t.Fatal("取消后 RunUpdate 未返回")
	}
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("取消须回传 ctx 错误，得到 %v", runErr)
	}

	var status, message, nextAfter, version string
	if err := database.QueryRow(`SELECT update_status, COALESCE(message,''), COALESCE(next_update,''), COALESCE(version,'') FROM security_crawler_sources WHERE name='googlebot'`).
		Scan(&status, &message, &nextAfter, &version); err != nil {
		t.Fatal(err)
	}
	if status != "cancelled" {
		t.Fatalf("取消后源状态=%q, want cancelled（保留上次快照）", status)
	}
	if !strings.Contains(message, "已手动取消") {
		t.Fatalf("取消提示=%q, want 含「已手动取消」", message)
	}
	if nextAfter != nextBefore {
		t.Fatalf("取消不得推进排程槽: next_update %q -> %q", nextBefore, nextAfter)
	}
	var lists int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=?`, CrawlerIPListName("googlebot")).Scan(&lists); err != nil {
		t.Fatal(err)
	}
	if lists != 0 {
		t.Fatalf("取消不得写入名单行: rows=%d", lists)
	}
}

// 下载在途降级为从节点（demote 同时取消 ctx）：任务落 skipped、源行不被改写
// （从节点只读不变量）、名单不写。
func TestCrawlerRunUpdate_demoteSkipsWithoutWriting(t *testing.T) {
	_, database := newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	var once sync.Once
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
			t.Errorf("flip role: %v", err)
		}
		cancel()
	}))
	t.Cleanup(ts.Close)
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=1, url=? WHERE name='googlebot'`, ts.URL); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- GetCrawlerUpdateManager().RunUpdate(ctx, taskengine.RunContext{Ctx: ctx, Trigger: "manual"})
	}()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("下载未开始")
	}
	var runErr error
	select {
	case runErr = <-errCh:
	case <-time.After(15 * time.Second):
		t.Fatal("降级后 RunUpdate 未返回")
	}
	if !errors.Is(runErr, taskengine.ErrTaskSkipped) {
		t.Fatalf("降级须落 skipped，得到 %v", runErr)
	}

	var status string
	if err := database.QueryRow(`SELECT update_status FROM security_crawler_sources WHERE name='googlebot'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		t.Fatalf("降级后从节点不得改写源行终态: status=%q, want running（未落终态）", status)
	}
	var lists int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=?`, CrawlerIPListName("googlebot")).Scan(&lists); err != nil {
		t.Fatal(err)
	}
	if lists != 0 {
		t.Fatalf("降级后不得写入名单行: rows=%d", lists)
	}
}

// 取消轮的后置投影收敛 ——

// 前序源已成功写库（changedCount>0）后在下一源下载期间取消：循环后的唯一
// 收敛块被提前 return 绕过，内置名单的 ACL/信任投影会停留旧版（同名内容
// 不再变化，后续轮次不会重试）。取消轮必须仍执行一次收敛——主节点、非降级、
// 用不随用户取消中止的复核口径，且整轮只收敛一次。
func TestCrawlerRunUpdate_cancelAfterCommittedSourceConvergesProjection(t *testing.T) {
	_, database := newClusterTestService(t)
	secondStarted := setupCrawlerCommitThenCancelFixture(t, database, func() {})

	var refreshed atomic.Int64
	oldRefresher, oldReloader := threatProjectionRefresher, threatReloader
	threatProjectionRefresher = func() (IPListProjectionOutcome, error) {
		refreshed.Add(1)
		return ProjectionConverged, nil
	}
	threatReloader = func() error {
		t.Error("热路径已证实收敛，不得回退重载")
		return nil
	}
	t.Cleanup(func() { threatProjectionRefresher, threatReloader = oldRefresher, oldReloader })

	runErr := runCrawlerUpdateUntilSecondSourceThenCancel(t, secondStarted)
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("取消须回传 ctx 错误，得到 %v", runErr)
	}
	if got := refreshed.Load(); got != 1 {
		t.Fatalf("取消轮投影收敛次数=%d, want 1（已成功源的名单必须进入运行投影）", got)
	}
	assertCrawlerCommitThenCancelSourceStates(t, database)
}

// 取消发生在已成功源之后、且节点已降级：投影收敛是主节点写面动作，从节点
// 必须零写（引用方由主节点后续轮次收敛）。
func TestCrawlerRunUpdate_cancelAfterCommittedSourceOnSlaveSkipsProjection(t *testing.T) {
	_, database := newClusterTestService(t)
	secondStarted := setupCrawlerCommitThenCancelFixture(t, database, func() {
		if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
			t.Errorf("demote: %v", err)
		}
	})

	var refreshed atomic.Int64
	oldRefresher, oldReloader := threatProjectionRefresher, threatReloader
	threatProjectionRefresher = func() (IPListProjectionOutcome, error) {
		refreshed.Add(1)
		return ProjectionConverged, nil
	}
	threatReloader = func() error {
		refreshed.Add(1)
		return nil
	}
	t.Cleanup(func() { threatProjectionRefresher, threatReloader = oldRefresher, oldReloader })

	runErr := runCrawlerUpdateUntilSecondSourceThenCancel(t, secondStarted)
	if !errors.Is(runErr, taskengine.ErrTaskSkipped) {
		t.Fatalf("降级轮须回传 ErrTaskSkipped，得到 %v", runErr)
	}
	if got := refreshed.Load(); got != 0 {
		t.Fatalf("从节点取消轮写投影 %d 次, want 0（从节点零写）", got)
	}
}

// 取消发生在已成功源之后、且角色已不可判定（DB 行缺失）：不得猜测主从，
// 收敛零写并按失败归因（引用方由后续轮次收敛）。
func TestCrawlerRunUpdate_cancelAfterCommittedSourceWithUnknownRoleSkipsProjection(t *testing.T) {
	_, database := newClusterTestService(t)
	secondStarted := setupCrawlerCommitThenCancelFixture(t, database, func() {
		if _, err := database.Exec(`DELETE FROM global_config WHERE id=1`); err != nil {
			t.Errorf("drop global_config: %v", err)
		}
	})

	var refreshed atomic.Int64
	oldRefresher, oldReloader := threatProjectionRefresher, threatReloader
	threatProjectionRefresher = func() (IPListProjectionOutcome, error) {
		refreshed.Add(1)
		return ProjectionConverged, nil
	}
	threatReloader = func() error {
		refreshed.Add(1)
		return nil
	}
	t.Cleanup(func() { threatProjectionRefresher, threatReloader = oldRefresher, oldReloader })

	runErr := runCrawlerUpdateUntilSecondSourceThenCancel(t, secondStarted)
	if runErr == nil || errors.Is(runErr, taskengine.ErrTaskSkipped) {
		t.Fatalf("角色不可判定须回传普通错误（非降级哨兵），得到 %v", runErr)
	}
	if got := refreshed.Load(); got != 0 {
		t.Fatalf("角色不可判定时投影收敛 %d 次, want 0", got)
	}
}

// 正常轮（无取消/无降级）：收敛仍只发生一次，取消轮的后置通道不得叠加。
func TestCrawlerRunUpdate_completedRoundConvergesProjectionOnce(t *testing.T) {
	_, database := newClusterTestService(t)
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
		UPDATE security_crawler_sources SET update_enabled=1,url=? WHERE name IN ('googlebot','bingbot')`, ts.URL); err != nil {
		t.Fatal(err)
	}
	for _, engine := range []string{"googlebot", "bingbot"} {
		if err := upsertCrawlerIPList(engine, []string{"66.249.66.0/24", "66.249.67.0/24"}); err != nil {
			t.Fatal(err)
		}
	}

	var refreshed atomic.Int64
	oldRefresher, oldReloader := threatProjectionRefresher, threatReloader
	threatProjectionRefresher = func() (IPListProjectionOutcome, error) {
		refreshed.Add(1)
		return ProjectionConverged, nil
	}
	threatReloader = func() error {
		t.Error("热路径已证实收敛，不得回退重载")
		return nil
	}
	t.Cleanup(func() { threatProjectionRefresher, threatReloader = oldRefresher, oldReloader })

	if err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"}); err != nil {
		t.Fatalf("RunUpdate: %v", err)
	}
	if got := refreshed.Load(); got != 1 {
		t.Fatalf("正常轮投影收敛次数=%d, want 1", got)
	}
}

// setupCrawlerCommitThenCancelFixture 造「两个启用源共享一个测试服务器」的
// 形态：首个请求返回合法名单（源已提交），后续请求阻塞到取消（下载在途）。
// mutateBeforeBlock 在该请求阻塞前执行（注入降级/角色不可判定）。
func setupCrawlerCommitThenCancelFixture(t *testing.T, database *sql.DB, mutateBeforeBlock func()) <-chan struct{} {
	t.Helper()
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	secondStarted := make(chan struct{})
	release := make(chan struct{})
	var secondOnce sync.Once
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"66.249.68.0/24"},{"ipv4Prefix":"66.249.69.0/24"}]}`))
			return
		}
		// 第二个源：先把运行时状态改到目标形态，再阻塞到取消。
		secondOnce.Do(func() {
			mutateBeforeBlock()
			close(secondStarted)
		})
		<-release
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(func() { close(release) })
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=1, url=? WHERE name IN ('googlebot','bingbot')`, ts.URL); err != nil {
		t.Fatal(err)
	}
	// 收缩/扩张门基线走 DB 分支（先置 2 条既有快照，同生产形态）。
	for _, engine := range []string{"googlebot", "bingbot"} {
		if err := upsertCrawlerIPList(engine, []string{"66.249.66.0/24", "66.249.67.0/24"}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		// 测试间不得残留从节点/缺行形态（隔离库仍保持一致性语义）。
		_, _ = database.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`)
	})
	return secondStarted
}

// runCrawlerUpdateUntilSecondSourceThenCancel 等第二个源进入下载（此时第一个
// 源已提交）后取消 ctx，确定性触发「已成功源之后取消」窗口（无 sleep 猜时序）。
func runCrawlerUpdateUntilSecondSourceThenCancel(t *testing.T, started <-chan struct{}) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- GetCrawlerUpdateManager().RunUpdate(ctx, taskengine.RunContext{Ctx: ctx, Trigger: "manual"})
	}()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("第二个源未开始下载")
	}
	cancel()
	select {
	case err := <-errCh:
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("取消后 RunUpdate 未返回")
		return nil
	}
}

// assertCrawlerCommitThenCancelSourceStates 取消轮源状态：一个源 success
// （已提交），另一个 cancelled（在途取消）。
func assertCrawlerCommitThenCancelSourceStates(t *testing.T, database *sql.DB) {
	t.Helper()
	var success, cancelled int
	if err := database.QueryRow(`SELECT
		SUM(IIF(update_status='success',1,0)), SUM(IIF(update_status='cancelled',1,0))
		FROM security_crawler_sources WHERE update_enabled=1`).Scan(&success, &cancelled); err != nil {
		t.Fatal(err)
	}
	if success != 1 || cancelled != 1 {
		t.Fatalf("源状态 success=%d cancelled=%d, want 1/1（已成功源保持 success）", success, cancelled)
	}
}
