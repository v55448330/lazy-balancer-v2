package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
		_, _ = w.Write([]byte("66.249.66.0/24\n66.249.67.0/24\n"))
	}))
	defer ts.Close()
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0;
		UPDATE security_crawler_sources SET update_enabled=1,url=? WHERE name='googlebot'`, ts.URL); err != nil {
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
