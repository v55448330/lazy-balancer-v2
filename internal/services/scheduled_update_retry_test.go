package services

// 任务内重试 + 排程槽语义（2026-09-25 用户裁定）：
// ①定时任务必须真正按用户设置的日期+时间触发（下次更新=真实触发时间）；
// ②失败重试在当前任务内完成（最多 3 次尝试，等待 30s/60s，日志「第 x 次，共 x 次」），
// 失败退避不得改写 next_update（排程槽不污染）。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// stubUpdateRetrySleep 把任务内重试等待替换为即时返回，恢复在 cleanup。
func stubUpdateRetrySleep(t *testing.T) {
	t.Helper()
	old := updateRetrySleep
	updateRetrySleep = func(time.Duration) {}
	t.Cleanup(func() { updateRetrySleep = old })
}

// Given：fetchLatestTag 连续 2 次瞬断、第 3 次成功（且 tag 更新）。
// When：执行一次更新。Then：任务内重试后成功（共 3 次尝试），版本推进。
func TestCRSRun_inTaskRetry_succeedsAfterTransientFailures(t *testing.T) {
	stubUpdateRetrySleep(t)
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	var calls int32
	m.fetchLatestTag = func(context.Context) (string, error) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			return "", fmt.Errorf("GitHub 返回 403（瞬断模拟 %d）", n)
		}
		return "v4.14.0", nil
	}

	m.run("auto")

	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("fetchLatestTag 调用 %d 次, want 3（任务内重试）", got)
	}
	_, status, message, _, _, _, _ := crsVersionRow(t)
	if status != "success" {
		t.Fatalf("status=%q, want success（重试后成功）", status)
	}
	if message != "已是最新版本" {
		t.Fatalf("message=%q, want 已是最新版本", message)
	}
}

// Given：fetchLatestTag 恒失败，行内已有 tick 预写的未来排程槽。
// When：执行一次更新。Then：尝试 3 次后失败落定，next_update 保持排程槽
// （失败退避不改写——下一运行=下一排程槽，非 now+1h）。
func TestCRSRun_inTaskRetry_exhaustedKeepsScheduleSlot(t *testing.T) {
	stubUpdateRetrySleep(t)
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	const slot = "2099-01-01 04:00:00"
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET next_update=? WHERE id=1`, slot); err != nil {
		t.Fatal(err)
	}

	var calls int32
	m.fetchLatestTag = func(context.Context) (string, error) {
		atomic.AddInt32(&calls, 1)
		return "", errors.New("GitHub 返回 403")
	}

	m.run("auto")

	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("fetchLatestTag 调用 %d 次, want 3（最多 3 次尝试后落定）", got)
	}
	_, status, _, _, _, nextUpdate, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("status=%q, want failed", status)
	}
	if nextUpdate != slot {
		t.Fatalf("next_update=%q, want 保持排程槽 %q（重试不污染排程）", nextUpdate, slot)
	}
}

// Given：调度 tick 到期启动的自动更新失败（fetch 恒失败）。
// When：schedulerTick 完成整个生命周期。Then：next_update 保持 tick 预写的
// 排程槽（rearm 失败退避重写已撤除——用户裁定下次更新=真实排程触发时间）。
func TestCRSSchedulerTick_failedRunKeepsScheduleSlot(t *testing.T) {
	stubUpdateRetrySleep(t)
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	now := time.Date(2026, 9, 25, 20, 0, 0, 0, time.UTC)
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET next_update=? WHERE id=1`, now.Add(-time.Minute).Format(crsTimeLayout)); err != nil {
		t.Fatal(err)
	}
	want := versionTableNextSlot("security_crs_version", now)

	m.fetchLatestTag = func(context.Context) (string, error) {
		return "", errors.New("GitHub 返回 403")
	}
	stop := make(chan struct{})
	defer close(stop)
	m.schedulerTick(now, stop)

	deadline := time.Now().Add(5 * time.Second)
	for m.IsRunning() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// rearm 等待 run 完成是异步的——状态落定后再读行
	deadline = time.Now().Add(5 * time.Second)
	for {
		_, status, _, _, _, _, _ := crsVersionRow(t)
		if status == "failed" || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	_, status, _, _, _, nextUpdate, _ := crsVersionRow(t)
	if status != "failed" {
		t.Fatalf("status=%q, want failed", status)
	}
	if nextUpdate != want {
		t.Fatalf("next_update=%q, want 保持 tick 预写排程槽 %q（退避重写已撤除）", nextUpdate, want)
	}
}

// Given：IP2Region fetchLatestTag 恒失败。When：执行一次更新。
// Then：尝试 3 次后失败落定，next_update 保持排程槽。
func TestIP2RegionRun_inTaskRetry_exhaustedKeepsScheduleSlot(t *testing.T) {
	stubUpdateRetrySleep(t)
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.17.0", true)
	const slot = "2099-01-01 04:00:00"
	if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET next_update=? WHERE id=1`, slot); err != nil {
		t.Fatal(err)
	}

	var calls int32
	m.fetchLatestTag = func(context.Context) (string, error) {
		atomic.AddInt32(&calls, 1)
		return "", errors.New("GitHub 返回 403")
	}

	m.run("auto")

	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("fetchLatestTag 调用 %d 次, want 3（任务内重试）", got)
	}
	var status, nextUpdate string
	if err := db.DB.QueryRow(`SELECT COALESCE(update_status,''), COALESCE(next_update,'') FROM security_ip2region_version WHERE id=1`).Scan(&status, &nextUpdate); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("status=%q, want failed", status)
	}
	if nextUpdate != slot {
		t.Fatalf("next_update=%q, want 保持排程槽 %q", nextUpdate, slot)
	}
}

// Given：威胁源下载前 2 次 500、第 3 次 200 返回合法名单。
// When：更新该源。Then：任务内重试后成功（共 3 次请求）。
func TestThreatUpdateOneSource_inTaskRetry_succeedsAfterTransientFailures(t *testing.T) {
	stubUpdateRetrySleep(t)
	newClusterTestService(t)

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("1.2.3.4\n5.6.7.8\n"))
	}))
	defer srv.Close()
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='ustc'`, srv.URL); err != nil {
		t.Fatal(err)
	}

	m := GetThreatUpdateManager()
	_, failed := m.updateOneSource(threatSourceRow{id: 1, name: "ustc", url: srv.URL}, "auto")

	if failed {
		t.Fatal("源更新失败, want 任务内重试后成功")
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("下载请求 %d 次, want 3（任务内重试）", got)
	}
}

// Given：威胁源失败落库。Then：next_update=下一排程槽（非失败退避点）。
func TestThreatFailSource_nextUpdateIsScheduleSlot(t *testing.T) {
	newClusterTestService(t)
	want := threatNextSlot(time.Now().UTC())

	failSourceRow(1, time.Now().UTC().Format(crsTimeLayout), errors.New("HTTP 500"))

	var next string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE id=1`).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if next != want {
		t.Fatalf("next_update=%q, want 排程槽 %q（失败退避不污染排程）", next, want)
	}
}

// Given：失败退避形态的 CRS 版本行。When：保存新排程。
// Then：next_update 一律重排为新槽（失败行不再保留退避——退避机制已撤除）。
func TestSetCRSSchedule_failedRowRearmedToSlot(t *testing.T) {
	newTestCRSManager(t)
	loc := useShanghaiLocation(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET update_status='failed', next_update='2026-01-01 01:00:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	if err := SetCRSSchedule([]int{2}, "04:30"); err != nil {
		t.Fatal(err)
	}

	want := NextScheduledSlot(time.Now().UTC(), []int{2}, "04:30", loc).UTC().Format(crsTimeLayout)
	_, _, nextUpdate := readVersionSchedule(t, "security_crs_version")
	if nextUpdate != want {
		t.Fatalf("next_update=%q, want 重排为新槽 %q（失败行不保留退避）", nextUpdate, want)
	}
}

// Given：失败退避形态的威胁源。When：保存威胁库排程。
// Then：全部启用源（含失败源）重排到新槽。
func TestSetThreatSchedule_failedSourceRearmedToSlot(t *testing.T) {
	newClusterTestService(t)
	loc := useShanghaiLocation(t)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='failed', next_update='2026-01-01 01:00:00' WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}

	if err := SetThreatSchedule([]int{3}, "05:00"); err != nil {
		t.Fatal(err)
	}

	want := NextScheduledSlot(time.Now().UTC(), []int{3}, "05:00", loc).UTC().Format(crsTimeLayout)
	var next string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE name='ustc'`).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if next != want {
		t.Fatalf("失败源 next_update=%q, want 重排为新槽 %q", next, want)
	}
}
