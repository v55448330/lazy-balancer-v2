package services

// 排程槽生命周期统一（2026-10-11 用户裁定）：
// ① auto 触发任意终态（成功/失败/跳过）→ next_update 推进到紧邻下一排程槽；
// ② manual 触发不动预约槽（手动执行不得改变下一次预约执行时间）。
// 三族（CRS/IP2Region/威胁库）统一口径。

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
	_, failed := m.updateOneSource(context.Background(), threatSourceRow{id: 1, name: "ustc", url: srv.URL}, "manual", taskRunStartedAt(nil))
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
	_, failed := m.updateOneSource(context.Background(), threatSourceRow{id: 1, name: "ustc", url: srv.URL}, "auto", taskRunStartedAt(nil))
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
