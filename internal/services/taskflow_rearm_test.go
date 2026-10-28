package services

// 任务流域修复钉测：时区变更重排已武装排程槽 / 常驻 started_at 零值契约 /
// 集群同步重载失败面登记。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// Given 四个排程族已按旧时区武装未来槽（+ 过期槽/关开关行作对照）。
// When 时区从 Asia/Shanghai 切到 UTC 后调用 RearmScheduleSlotsAfterTimezoneChange。
// Then 未来槽按新时区重算（04:00 本地 = 04:00 UTC）；过期槽与关开关行不动。
func TestRearmScheduleSlotsAfterTimezoneChange(t *testing.T) {
	setupIsolatedDB(t)
	if _, err := ConfigureLocation("Asia/Shanghai"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = ConfigureLocation("UTC") })

	shanghai, _ := time.LoadLocation("Asia/Shanghai")
	futureSh := NextScheduledSlot(time.Now(), allWeek(), "04:00", shanghai).UTC().Format(crsTimeLayout)
	pastSlot := time.Now().Add(-time.Hour).UTC().Format(crsTimeLayout)

	// 版本表两族：CRS=未来槽（应重排）；IP2Region=过期槽（保留补跑，不动）。
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO security_crs_version (id, version, auto_update, next_update) VALUES (1,'v1',1,?)`, futureSh); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO security_ip2region_version (id, version, auto_update, next_update) VALUES (1,'u',1,?)`, pastSlot); err != nil {
		t.Fatal(err)
	}
	// 威胁源表：注册表源启用+未来槽（应重排）、注册表源停用+未来槽（不动）、
	// 注册表外启用行+未来槽（槽域=运行域，不重排——其槽由启动期清理收敛）。
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=1, next_update=? WHERE name='ustc'`, futureSh); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=0, next_update=? WHERE name='firehol_l1'`, futureSh); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_threat_sources (name, update_enabled, next_update) VALUES ('src-legacy',1,?)`, futureSh); err != nil {
		t.Fatal(err)
	}

	if _, err := ConfigureLocation("UTC"); err != nil {
		t.Fatal(err)
	}
	RearmScheduleSlotsAfterTimezoneChange()

	assertSlot := func(table, where string, arg any, wantRearmed bool, orig string) {
		t.Helper()
		var stored string
		if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM `+table+` WHERE `+where, arg).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		slot := parseUTCSlot(stored)
		if slot.IsZero() {
			t.Fatalf("%s %s=%v 槽清空: %q", table, where, arg, stored)
		}
		if wantRearmed {
			if stored == orig {
				t.Fatalf("%s %s=%v 时区变更后槽未重排（仍按旧偏移）: %q", table, where, arg, stored)
			}
			if h, m := slot.In(time.UTC).Hour(), slot.In(time.UTC).Minute(); h != 4 || m != 0 {
				t.Fatalf("%s %s=%v 重排后应为 04:00 UTC（新时区本地日历）, got %02d:%02d", table, where, arg, h, m)
			}
		} else if stored != orig {
			t.Fatalf("%s %s=%v 不应重排: got %q want %q", table, where, arg, stored, orig)
		}
	}
	assertSlot("security_crs_version", "id=?", 1, true, futureSh)
	assertSlot("security_ip2region_version", "id=?", 1, false, pastSlot) // 过期槽保留补跑
	assertSlot("security_threat_sources", "name=?", "ustc", true, futureSh)
	assertSlot("security_threat_sources", "name=?", "firehol_l1", false, futureSh)
	assertSlot("security_threat_sources", "name=?", "src-legacy", false, futureSh) // 槽域=运行域
}

// Given 威胁/爬虫源表已有未来槽，且任务级排程列不可读。
// When 时区变更重排。
// Then 两张源表槽保持原值（不得用读侧 fail-soft 的默认 04:00 回写）；版本表族
// 照常重排；读恢复后源表族按新时区重排。
func TestRearmScheduleSlotsAfterTimezoneChange_scheduleReadFailureKeepsSourceSlots(t *testing.T) {
	setupIsolatedDB(t)
	if _, err := ConfigureLocation("Asia/Shanghai"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = ConfigureLocation("UTC") })

	shanghai, _ := time.LoadLocation("Asia/Shanghai")
	futureSh := NextScheduledSlot(time.Now(), allWeek(), "04:00", shanghai).UTC().Format(crsTimeLayout)

	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO security_crs_version (id, version, auto_update, next_update) VALUES (1,'v1',1,?)`, futureSh); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=1, next_update=? WHERE name='ustc'`, futureSh); err != nil {
		t.Fatal(err)
	}
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	const crawlerSource = "googlebot"
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=1, next_update=? WHERE name=?`, futureSh, crawlerSource); err != nil {
		t.Fatal(err)
	}

	if _, err := ConfigureLocation("UTC"); err != nil {
		t.Fatal(err)
	}
	restoreThreat := injectScheduleReadFailure(t, "global_config", "threat_schedule_days")
	restoreCrawler := injectScheduleReadFailure(t, "global_config", "crawler_schedule_days")
	t.Cleanup(func() {
		restoreThreat()
		restoreCrawler()
	})

	RearmScheduleSlotsAfterTimezoneChange()

	sourceSlot := func(table, where string, arg any) string {
		t.Helper()
		var s string
		if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM `+table+` WHERE `+where, arg).Scan(&s); err != nil {
			t.Fatalf("读取 %s 排程槽: %v", table, err)
		}
		return s
	}
	assertAt4UTC := func(label, slot string) {
		t.Helper()
		ts := parseUTCSlot(slot)
		if ts.IsZero() {
			t.Fatalf("%s 槽不可解析: %q", label, slot)
		}
		if h, m := ts.In(time.UTC).Hour(), ts.In(time.UTC).Minute(); h != 4 || m != 0 {
			t.Fatalf("%s 重排后应为 04:00 UTC（新时区本地日历）, got %02d:%02d", label, h, m)
		}
	}

	crsSlot := crsNextUpdate(t)
	if crsSlot == futureSh {
		t.Fatalf("版本表族槽未重排（任务级读失败不得影响版本表读取）: %q", crsSlot)
	}
	if got := sourceSlot("security_threat_sources", "name=?", "ustc"); got != futureSh {
		t.Fatalf("威胁源槽=%q, want 保持原值 %q（排程不可读不得写默认 04:00）", got, futureSh)
	}
	if got := crawlerSourceSlot(t, crawlerSource); got != futureSh {
		t.Fatalf("爬虫源槽=%q, want 保持原值 %q（排程不可读不得写默认 04:00）", got, futureSh)
	}

	restoreThreat()
	restoreCrawler()
	RearmScheduleSlotsAfterTimezoneChange()

	assertAt4UTC("威胁源槽（读恢复后）", sourceSlot("security_threat_sources", "name=?", "ustc"))
	assertAt4UTC("爬虫源槽（读恢复后）", crawlerSourceSlot(t, crawlerSource))
}

// Given 常驻任务运行中但 task_runs boot 行缺失（插入失败仅 WARN 的残留形态）。
// When CollectSystemTasks 聚合。
// Then started_at 置零（UI '—'），不回退引擎进程启动时刻（uptime 语义与
// 「常驻 · 启动于」契约矛盾）。
func TestCollectSystemTasks_daemonStartedAtZeroWhenBootRowMissing(t *testing.T) {
	te := newWireTestEngine(t)
	const id = "cluster-sync"
	te.StartLoop(id)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m, ok := te.Lookup(id); ok && m.Running {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if m, ok := te.Lookup(id); !ok || !m.Running {
		t.Fatalf("%s 未进入运行态", id)
	}
	// 抹除 boot 行——模拟插入失败/短窗残留（Running=true 且 latestRun=nil）。
	if _, err := db.DB.Exec(`DELETE FROM task_runs WHERE task_id=?`, id); err != nil {
		t.Fatal(err)
	}

	tasks, _ := CollectSystemTasks()
	for _, ti := range tasks {
		if ti.ID == id {
			if ti.StartedAt != "" {
				t.Fatalf("boot 行缺失时 started_at 应置零（UI '—'），got %q（不得回退引擎启动时刻）", ti.StartedAt)
			}
			return
		}
	}
	t.Fatalf("%s 未出现在任务视图", id)
}

// Given 从节点集群同步重载失败（快照已提交、Caddy /load 失败）。
// When RecordBackgroundApplyFailure(BackgroundApplyClusterSync) 登记。
// Then 后台失败面快照/横幅可见该来源（从节点「库态≠运行态」分叉的全局信号）；
// 成功收敛后 ClearBackgroundApplyFailure 清除。
func TestBackgroundApplyClusterSyncSourceRoundTrip(t *testing.T) {
	// 与 applystatus_test 同口径：用例间隔离失败面（包级进程内存储）。
	backgroundApplyStore.mu.Lock()
	backgroundApplyStore.failures = map[string]BackgroundApplyFailure{}
	backgroundApplyStore.mu.Unlock()
	t.Cleanup(func() {
		backgroundApplyStore.mu.Lock()
		backgroundApplyStore.failures = map[string]BackgroundApplyFailure{}
		backgroundApplyStore.mu.Unlock()
	})
	RecordBackgroundApplyFailure(BackgroundApplyClusterSync, errTestClusterReload)

	snap := BackgroundApplyFailureSnapshot()
	if snap == nil || snap.Source != string(BackgroundApplyClusterSync) {
		t.Fatalf("失败面快照未含集群同步来源: %+v", snap)
	}
	if banner := BackgroundApplyFailureBanner(); banner == "" {
		t.Fatal("集群同步重载失败应产生全局横幅文案")
	}

	ClearBackgroundApplyFailure(BackgroundApplyClusterSync)
	if snap := BackgroundApplyFailureSnapshot(); snap != nil {
		t.Fatalf("清除后失败面应为空, got %+v", snap)
	}
}

var errTestClusterReload = errStringTest("集群同步重载测试错误")

type errStringTest string

func (e errStringTest) Error() string { return string(e) }

// ParseUTCTimeDual 双布局单源：RFC3339 与平面 UTC 墙串（crsTimeLayout）同权
// 解析——cert_jobs 等 UTC 时间列消费方统一走本入口，单布局解析在驱动/列
// 表达式形态变化时静默归零。
func TestParseUTCTimeDual_bothLayouts(t *testing.T) {
	rfc, ok := ParseUTCTimeDual("2026-10-20T04:00:00Z")
	if !ok || rfc.UTC().Format("2006-01-02 15:04:05") != "2026-10-20 04:00:00" {
		t.Fatalf("RFC3339 解析失败: %v %v", rfc, ok)
	}
	flat, ok := ParseUTCTimeDual("2026-10-20 04:00:00")
	if !ok || flat.UTC().Format("2006-01-02 15:04:05") != "2026-10-20 04:00:00" {
		t.Fatalf("平面 UTC 墙串解析失败（双布局口径断裂）: %v %v", flat, ok)
	}
	if rfc != flat {
		t.Fatalf("双布局同值应相等: %v vs %v", rfc, flat)
	}
	if _, ok := ParseUTCTimeDual("garbage"); ok {
		t.Fatal("非法串应解析失败")
	}
	if _, ok := ParseUTCTimeDual(""); ok {
		t.Fatal("空串应解析失败")
	}
}

// 版本表 auto_update 关闭时仍重排展示槽：next_update 是「下次更新」展示的
// 唯一来源（GetCRSInfo/GetIP2RegionInfo 直读），与 setVersionTableSchedule
// 「关闭也重排、调度器仍受开关门控」同口径——切换时区后不得停留在旧偏移。
func TestRearmScheduleSlotsAfterTimezoneChange_reschedulesDisplaySlotWhenAutoUpdateOff(t *testing.T) {
	setupIsolatedDB(t)
	if _, err := ConfigureLocation("Asia/Shanghai"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = ConfigureLocation("UTC") })

	shanghai, _ := time.LoadLocation("Asia/Shanghai")
	// 23:59 远离当前时刻，避免用例跨过 04:00 边界时槽变为过期而跳过重排。
	const scheduleTime = "23:59"
	futureSh := NextScheduledSlot(time.Now(), allWeek(), scheduleTime, shanghai).UTC().Format(crsTimeLayout)
	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		if _, err := db.DB.Exec(`INSERT OR REPLACE INTO `+table+` (id, version, auto_update, schedule_days, schedule_time, next_update) VALUES (1,'v',0,?,?,?)`,
			FormatScheduleDays(allWeek()), scheduleTime, futureSh); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := ConfigureLocation("UTC"); err != nil {
		t.Fatal(err)
	}
	RearmScheduleSlotsAfterTimezoneChange()

	want := parseUTCSlot(NextScheduledSlot(time.Now().UTC(), allWeek(), scheduleTime, time.UTC).UTC().Format(crsTimeLayout))
	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		var got string
		if err := db.DB.QueryRow(`SELECT next_update FROM ` + table + ` WHERE id=1`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if slot := parseUTCSlot(got); !slot.Equal(want) {
			t.Fatalf("%s next_update=%q（parsed %v）, want %v（auto_update 关闭也要重排展示槽）", table, got, slot, want)
		}
		var autoUpdate int
		if err := db.DB.QueryRow(`SELECT auto_update FROM ` + table + ` WHERE id=1`).Scan(&autoUpdate); err != nil {
			t.Fatal(err)
		}
		if autoUpdate != 0 {
			t.Fatalf("%s auto_update=%d，重排展示槽不得改动开关", table, autoUpdate)
		}
	}
}
