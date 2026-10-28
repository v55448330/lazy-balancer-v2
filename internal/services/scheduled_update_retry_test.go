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
	updateRetrySleep = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(func() { updateRetrySleep = old })
}

// 边界基线钉：取消发生在首次失败后的退避中（而非底层请求中）时，
// 默认等待同样必须立即退出，且不得进入第二次尝试。
func TestRunWithInTaskRetry_cancelInterruptsBackoff(t *testing.T) {
	oldWaits := updateAttemptWaits
	updateAttemptWaits = []time.Duration{time.Hour}
	t.Cleanup(func() { updateAttemptWaits = oldWaits })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var attempts atomic.Int32
	waiting := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- runWithInTaskRetry(ctx, func() error {
			attempts.Add(1)
			return errors.New("transient")
		}, func(int, time.Duration, error) {
			close(waiting)
		})
	}()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("未进入首次失败后的退避")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("退避取消 err=%v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("取消未中断任务内退避")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("退避取消后尝试次数=%d, want 1", got)
	}
}

// Given：fetchLatestTag 连续 2 次瞬断、第 3 次成功（且 tag 更新）。
// When：执行一次更新。Then：任务内重试后成功（共 3 次尝试），版本推进。
func TestCRSRun_inTaskRetry_succeedsAfterTransientFailures(t *testing.T) {
	overrideWafDirForTest(t)
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

	m.run("auto", nil)

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
	overrideWafDirForTest(t)
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

	m.run("auto", nil)

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

// Given：IP2Region fetchLatestTag 恒失败。When：执行一次更新。
// Then：尝试 3 次后失败落定，next_update 保持排程槽。
func TestIP2RegionRun_inTaskRetry_exhaustedKeepsScheduleSlot(t *testing.T) {
	overrideWafDirForTest(t)
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

	m.run("auto", nil)

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
	overrideWafDirForTest(t)
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
	_, failed := m.updateOneSource(context.Background(), threatSourceRow{id: 1, name: "ustc", url: srv.URL}, "auto", taskRunStartedAt(nil))

	if failed {
		t.Fatal("源更新失败, want 任务内重试后成功")
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("下载请求 %d 次, want 3（任务内重试）", got)
	}
}

// Given：威胁源失败落库。Then：next_update=下一排程槽（非失败退避点）。
func TestThreatFailSource_nextUpdateIsScheduleSlot(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	clockBefore := time.Now().UTC()

	failSourceRow(1, time.Now().UTC().Format(crsTimeLayout), errors.New("HTTP 500"), "auto")

	var next string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE id=1`).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if got := parseSlotUTC(t, next); !got.After(clockBefore) {
		t.Fatalf("next_update=%v 必须真实晚于失败轮开始时间 %v", got, clockBefore)
	}
	wantBefore := threatNextSlot(clockBefore)
	wantAfter := threatNextSlot(time.Now().UTC())
	if next != wantBefore && next != wantAfter {
		t.Fatalf("next_update=%q，不在稳定时钟 bracket 的合法槽位 [%q, %q]（失败退避不污染排程）", next, wantBefore, wantAfter)
	}
}

// Given：失败退避形态的 CRS 版本行。When：保存新排程。
// Then：next_update 一律重排为新槽（失败行不再保留退避——退避机制已撤除）。
func TestSetCRSSchedule_failedRowRearmedToSlot(t *testing.T) {
	overrideWafDirForTest(t)
	newTestCRSManager(t)
	loc := useShanghaiLocation(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET update_status='failed', next_update='2026-01-01 01:00:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	clockBefore := time.Now().UTC()
	if err := SetCRSSchedule([]int{2}, "04:30"); err != nil {
		t.Fatal(err)
	}

	_, _, nextUpdate := readVersionSchedule(t, "security_crs_version")
	assertNextScheduledSlot(t, nextUpdate, clockBefore, []int{2}, "04:30", loc)
}

// Given：失败退避形态的威胁源。When：保存威胁库排程。
// Then：全部启用源（含失败源）重排到新槽。
func TestSetThreatSchedule_failedSourceRearmedToSlot(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	loc := useShanghaiLocation(t)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_status='failed', next_update='2026-01-01 01:00:00' WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}

	clockBefore := time.Now().UTC()
	if err := SetThreatSchedule([]int{3}, "05:00"); err != nil {
		t.Fatal(err)
	}

	var next string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE name='ustc'`).Scan(&next); err != nil {
		t.Fatal(err)
	}
	assertNextScheduledSlot(t, next, clockBefore, []int{3}, "05:00", loc)
}
