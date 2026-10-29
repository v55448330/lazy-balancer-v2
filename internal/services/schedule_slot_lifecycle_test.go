package services

// 排程槽生命周期统一：
// ① auto 触发任意终态（成功/失败/跳过）→ next_update 推进到紧邻下一排程槽；
// ② manual 触发不改变既有预约（未来槽不回拨），但**成功**轮必须推进已过期槽
//    （引擎成功轮会消费过期槽，业务不推进则水位单边前进=四族自动更新停摆）；
//    空槽仍不补写（预约只由排程保存/启用/启动武装路径建立）。
// 四族（CRS/IP2Region/威胁库/爬虫库）统一口径。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func crsNextUpdate(t *testing.T) string {
	t.Helper()
	var s string
	if err := db.DB.QueryRow("SELECT COALESCE(next_update,'') FROM security_crs_version WHERE id=1").Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func setCRSSlot(t *testing.T, slot string) {
	t.Helper()
	if _, err := db.DB.Exec("UPDATE security_crs_version SET next_update=? WHERE id=1", slot); err != nil {
		t.Fatal(err)
	}
}

// Given 手动触发且「已是最新」（成功终态）。When run 完成。
// Then next_update 保持预约槽不变（旧码随 auto_update=1 无条件推进）。
func TestCRSUpdate_manualSuccessKeepsScheduledSlot(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.30.0", true)
	const slot = "2026-12-01 04:00:00"
	setCRSSlot(t, slot)
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.30.0", nil }

	m.run("manual", nil)

	if got := crsNextUpdate(t); got != slot {
		t.Fatalf("手动成功后 next_update=%q, want 预约槽不变 %q", got, slot)
	}
}

// Given auto 触发且查询失败（失败终态）。When run 完成。
// Then next_update 推进到紧邻下一排程槽（未来值，非过期槽——旧码失败不推进致排程停摆）。
func TestCRSUpdate_autoFailureAdvancesToNextSlot(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	setCRSSlot(t, "2020-01-01 04:00:00") // 过期槽
	m.fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("GitHub 返回 403") }

	m.run("auto", nil)

	got := crsNextUpdate(t)
	if got == "" || got == "2020-01-01 04:00:00" {
		t.Fatalf("auto 失败后 next_update=%q, want 推进到紧邻下一排程槽", got)
	}
	if !strings.HasPrefix(got, "20") {
		t.Fatalf("next_update 形态异常: %q", got)
	}
	parsed, err := time.ParseInLocation(crsTimeLayout, got, time.UTC)
	if err != nil {
		t.Fatalf("next_update 不可解析: %q: %v", got, err)
	}
	if !parsed.After(time.Now().UTC().Add(-time.Minute)) {
		t.Fatalf("auto 失败后 next_update=%q 仍在过去（排程停摆）", got)
	}
}

// Given auto 触发且「已是最新」（成功终态）。When run 完成。
// Then next_update 推进到紧邻下一排程槽（既有语义，回归形状）。
func TestCRSUpdate_autoSuccessAdvancesToNextSlot(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.30.0", true)
	setCRSSlot(t, "2020-01-01 04:00:00")
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.30.0", nil }

	m.run("auto", nil)

	got := crsNextUpdate(t)
	parsed, err := time.ParseInLocation(crsTimeLayout, got, time.UTC)
	if err != nil || !parsed.After(time.Now().UTC().Add(-time.Minute)) {
		t.Fatalf("auto 成功后 next_update=%q, want 未来排程槽", got)
	}
}

// ---- IP2Region 族（与 CRS 同构三形状） ----

func ip2rNextUpdate(t *testing.T) string {
	t.Helper()
	var s string
	if err := db.DB.QueryRow("SELECT COALESCE(next_update,'') FROM security_ip2region_version WHERE id=1").Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func setIP2RSlot(t *testing.T, slot string) {
	t.Helper()
	if _, err := db.DB.Exec("UPDATE security_ip2region_version SET next_update=? WHERE id=1", slot); err != nil {
		t.Fatal(err)
	}
}

func TestIP2RegionUpdate_manualSuccessKeepsScheduledSlot(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.18.0", true)
	const slot = "2026-12-01 04:00:00"
	setIP2RSlot(t, slot)
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.18.0", nil }

	m.run("manual", nil)

	if got := ip2rNextUpdate(t); got != slot {
		t.Fatalf("手动成功后 next_update=%q, want 预约槽不变 %q", got, slot)
	}
}

func TestIP2RegionUpdate_autoFailureAdvancesToNextSlot(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	setIP2RSlot(t, "2020-01-01 04:00:00")
	m.fetchLatestTag = func(context.Context) (string, error) { return "", errors.New("GitHub 返回 403") }

	m.run("auto", nil)

	got := ip2rNextUpdate(t)
	parsed, err := time.ParseInLocation(crsTimeLayout, got, time.UTC)
	if err != nil || !parsed.After(time.Now().UTC().Add(-time.Minute)) {
		t.Fatalf("auto 失败后 next_update=%q, want 未来排程槽（排程停摆防护）", got)
	}
}

func TestIP2RegionUpdate_autoSuccessAdvancesToNextSlot(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.18.0", true)
	setIP2RSlot(t, "2020-01-01 04:00:00")
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.18.0", nil }

	m.run("auto", nil)

	got := ip2rNextUpdate(t)
	parsed, err := time.ParseInLocation(crsTimeLayout, got, time.UTC)
	if err != nil || !parsed.After(time.Now().UTC().Add(-time.Minute)) {
		t.Fatalf("auto 成功后 next_update=%q, want 未来排程槽", got)
	}
}

// ---- 威胁族（排程槽生命周期同构） ----

func threatSourceSlot(t *testing.T, id int) string {
	t.Helper()
	var s string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE id=?`, id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestThreatUpdateOneSource_manualSuccessKeepsSlot(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	const slot = "2026-12-01 04:00:00"
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=? WHERE id=1`, slot); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("1.2.3.4\n5.6.7.8\n"))
	}))
	defer srv.Close()

	m := GetThreatUpdateManager()
	_, failed, _ := m.updateOneSource(context.Background(), threatSourceRow{id: 1, name: "ustc", url: srv.URL}, "manual", taskRunStartedAt(nil))
	if failed {
		t.Fatal("源更新应成功")
	}
	if got := threatSourceSlot(t, 1); got != slot {
		t.Fatalf("手动成功后源 next_update=%q, want 预约槽不变 %q", got, slot)
	}
}

func TestThreatUpdateOneSource_autoFailureAdvancesSlot(t *testing.T) {
	overrideWafDirForTest(t)
	stubUpdateRetrySleep(t)
	newClusterTestService(t)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update='2020-01-01 04:00:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	m := GetThreatUpdateManager()
	_, failed, _ := m.updateOneSource(context.Background(), threatSourceRow{id: 1, name: "ustc", url: srv.URL}, "auto", taskRunStartedAt(nil))
	if !failed {
		t.Fatal("源更新应失败（500 恒失败）")
	}
	got := threatSourceSlot(t, 1)
	parsed, err := time.ParseInLocation(crsTimeLayout, got, time.UTC)
	if err != nil || !parsed.After(time.Now().UTC().Add(-time.Minute)) {
		t.Fatalf("auto 失败后源 next_update=%q, want 未来排程槽", got)
	}
}

func TestThreatFailSource_manualKeepsSlot(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	const slot = "2026-12-01 04:00:00"
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=? WHERE id=1`, slot); err != nil {
		t.Fatal(err)
	}

	failSourceRow(1, time.Now().UTC().Format(crsTimeLayout), errors.New("HTTP 500"), "manual")

	if got := threatSourceSlot(t, 1); got != slot {
		t.Fatalf("手动失败后源 next_update=%q, want 预约槽不变 %q", got, slot)
	}
}

// ---- 过期槽上的手动成功必须推进业务槽（四族同口径） ----
//
// 停摆链路：业务槽已过期（上轮推进写失败/旧版本遗留）→ 引擎在手动轮成功时
// 消费该槽（schedDoneSlot=过期槽）→ 业务侧不推进则 tick 的「槽 > 已消费水位」
// 门永不成立：既无投递也无 failed 行，自动更新永久静默停摆。故手动成功后
// 空槽仍不补写、未来槽不回拨，但**过期槽必须推进**到紧邻下一排程槽。

// assertSlotAdvancedToFuture 断言槽已推进为可解析的未来时刻。
func assertSlotAdvancedToFuture(t *testing.T, got, stale string) {
	t.Helper()
	if got == "" || got == stale {
		t.Fatalf("成功轮 next_update=%q, want 由过期槽 %q 推进到下一排程槽", got, stale)
	}
	parsed, err := time.ParseInLocation(crsTimeLayout, got, time.UTC)
	if err != nil {
		t.Fatalf("next_update=%q 不可解析: %v", got, err)
	}
	if !parsed.After(time.Now().UTC().Add(-time.Minute)) {
		t.Fatalf("成功轮 next_update=%q 仍在过去（引擎水位与业务槽分叉=停摆）", got)
	}
}

func TestCRSUpdate_manualSuccessAdvancesExpiredSlot(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.30.0", true)
	const stale = "2020-01-01 04:00:00"
	setCRSSlot(t, stale)
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.30.0", nil }

	m.run("manual", nil)

	assertSlotAdvancedToFuture(t, crsNextUpdate(t), stale)
}

func TestIP2RegionUpdate_manualSuccessAdvancesExpiredSlot(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.18.0", true)
	const stale = "2020-01-01 04:00:00"
	setIP2RSlot(t, stale)
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.18.0", nil }

	m.run("manual", nil)

	assertSlotAdvancedToFuture(t, ip2rNextUpdate(t), stale)
}

func TestThreatUpdateOneSource_manualSuccessAdvancesExpiredSlot(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	const stale = "2020-01-01 04:00:00"
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=? WHERE id=1`, stale); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("1.2.3.4\n5.6.7.8\n"))
	}))
	defer srv.Close()

	m := GetThreatUpdateManager()
	if _, failed, _ := m.updateOneSource(context.Background(), threatSourceRow{id: 1, name: "ustc", url: srv.URL}, "manual", taskRunStartedAt(nil)); failed {
		t.Fatal("源更新应成功")
	}

	assertSlotAdvancedToFuture(t, threatSourceSlot(t, 1), stale)
}

func TestCrawlerUpdateSource_manualSuccessAdvancesExpiredSlot(t *testing.T) {
	_, database := newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	const stale = "2020-01-01 04:00:00"
	if _, err := database.Exec(`UPDATE security_crawler_sources SET next_update=? WHERE name='googlebot'`, stale); err != nil {
		t.Fatal(err)
	}

	if err := markCrawlerSourceSuccess("googlebot", "manual", 2); err != nil {
		t.Fatalf("写成功态: %v", err)
	}

	var got string
	if err := database.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE name='googlebot'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	assertSlotAdvancedToFuture(t, got, stale)
}

// 回归：手动**失败**不得推进过期槽——引擎按退避重投同一槽，业务抢先推进会把
// 该自动槽静默吃掉（失败门与成功门分权）。
func TestThreatFailSource_manualFailureKeepsExpiredSlot(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	const stale = "2020-01-01 04:00:00"
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=? WHERE id=1`, stale); err != nil {
		t.Fatal(err)
	}

	failSourceRow(1, time.Now().UTC().Format(crsTimeLayout), errors.New("HTTP 500"), "manual")

	if got := threatSourceSlot(t, 1); got != stale {
		t.Fatalf("手动失败后源 next_update=%q, want 保留过期槽 %q（由引擎退避重投）", got, stale)
	}
}

func TestCrawlerUpdateSource_manualFailureKeepsExpiredSlot(t *testing.T) {
	_, database := newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	const stale = "2020-01-01 04:00:00"
	if _, err := database.Exec(`UPDATE security_crawler_sources SET next_update=? WHERE name='googlebot'`, stale); err != nil {
		t.Fatal(err)
	}

	if err := markCrawlerSourceFailed("googlebot", "manual", "测试失败"); err != nil {
		t.Fatal(err)
	}

	var got string
	if err := database.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE name='googlebot'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != stale {
		t.Fatalf("手动失败后源 next_update=%q, want 保留过期槽 %q（由引擎退避重投）", got, stale)
	}
}

// 回归：手动成功不得替空槽建立预约（空槽零值不会进入引擎消费分支，无停摆面；
// 预约只由排程保存/启用/启动武装路径建立）。两族各钉一次。
func TestCRSUpdate_manualSuccessKeepsEmptySlot(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.30.0", true)
	setCRSSlot(t, "")
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.30.0", nil }

	m.run("manual", nil)

	if got := crsNextUpdate(t); got != "" {
		t.Fatalf("手动成功后空槽=%q, want 保持空（不得替空槽建立预约）", got)
	}
}

func TestIP2RegionUpdate_manualSuccessKeepsEmptySlot(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.18.0", true)
	setIP2RSlot(t, "")
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.18.0", nil }

	m.run("manual", nil)

	if got := ip2rNextUpdate(t); got != "" {
		t.Fatalf("手动成功后空槽=%q, want 保持空（不得替空槽建立预约）", got)
	}
}

func TestThreatUpdateOneSource_manualSuccessKeepsEmptySlot(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update='' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("1.2.3.4\n"))
	}))
	defer srv.Close()

	m := GetThreatUpdateManager()
	if _, failed, _ := m.updateOneSource(context.Background(), threatSourceRow{id: 1, name: "ustc", url: srv.URL}, "manual", taskRunStartedAt(nil)); failed {
		t.Fatal("源更新应成功")
	}

	if got := threatSourceSlot(t, 1); got != "" {
		t.Fatalf("手动成功后空槽=%q, want 保持空（不得替空槽建立预约）", got)
	}
}
