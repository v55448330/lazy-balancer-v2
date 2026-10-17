package services

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestVersionTasks_autoUpdateDisabledHasNoSlotOrEnabled(t *testing.T) {
	te := newWireTestEngine(t)
	for _, tc := range []struct{ id, table string }{
		{id: "crs", table: "security_crs_version"},
		{id: "ip2region", table: "security_ip2region_version"},
	} {
		if _, err := db.DB.Exec(`UPDATE ` + tc.table + ` SET auto_update=0 WHERE id=1`); err != nil {
			t.Fatal(err)
		}
		meta, ok := te.Lookup(tc.id)
		if !ok {
			t.Fatalf("%s 未注册", tc.id)
		}
		if meta.NextSlot != "" || meta.Enabled {
			t.Errorf("%s auto_update=0 时 NextSlot=%q Enabled=%v，want 空/false", tc.id, meta.NextSlot, meta.Enabled)
		}
	}
}

func TestVersionTasks_expiredSlotTriggersManager(t *testing.T) {
	for _, kind := range []string{"crs", "ip2region"} {
		t.Run(kind, func(t *testing.T) {
			stubUpdateRetrySleep(t)
			te := newWireTestEngine(t)
			var calls atomic.Int32
			table := "security_crs_version"
			if kind == "crs" {
				ResetCRSUpdateManagerForTest()
				InitCRSUpdateManager(nil)
				t.Cleanup(ResetCRSUpdateManagerForTest)
				m := GetCRSUpdateManager()
				m.fetchLatestTag = func(context.Context) (string, error) {
					calls.Add(1)
					return "", errors.New("stop after trigger")
				}
			} else {
				table = "security_ip2region_version"
				ResetIP2RegionUpdateManagerForTest()
				InitIP2RegionUpdateManager(nil)
				t.Cleanup(ResetIP2RegionUpdateManagerForTest)
				m := GetIP2RegionUpdateManager()
				m.fetchLatestTag = func(context.Context) (string, error) {
					calls.Add(1)
					return "", errors.New("stop after trigger")
				}
			}
			past := time.Now().UTC().Add(-time.Hour).Format(crsTimeLayout)
			if _, err := db.DB.Exec(`UPDATE `+table+` SET auto_update=1,next_update=? WHERE id=1`, past); err != nil {
				t.Fatal(err)
			}
			te.SetRole(true)
			te.StartLoop(kind)
			waitForCond(t, 3*time.Second, func() bool {
				return calls.Load() > 0 && versionTableNextUpdate(table) != past
			})
			if calls.Load() == 0 {
				t.Fatal("过期槽未触发管理器")
			}
			if got := versionTableNextUpdate(table); got == past {
				t.Fatal("失败落定未推进排程槽")
			}
		})
	}
}

func TestVersionTasks_slaveRoleRejectsManualTrigger(t *testing.T) {
	te := newWireTestEngine(t)
	for _, tc := range []struct{ id, table string }{
		{id: "crs", table: "security_crs_version"},
		{id: "ip2region", table: "security_ip2region_version"},
	} {
		past := time.Now().UTC().Add(-time.Hour).Format(crsTimeLayout)
		if _, err := db.DB.Exec(`UPDATE `+tc.table+` SET auto_update=1,next_update=? WHERE id=1`, past); err != nil {
			t.Fatal(err)
		}
		te.SetRole(false)
		if err := te.Trigger(tc.id, "manual", ""); err == nil {
			t.Errorf("%s 从节点手动触发未被角色门拒绝", tc.id)
		}
	}
}

func TestVersionTasks_slaveRoleSuppressesTick(t *testing.T) {
	for _, kind := range []string{"crs", "ip2region"} {
		t.Run(kind, func(t *testing.T) {
			stubUpdateRetrySleep(t)
			te := newWireTestEngine(t)
			var calls atomic.Int32
			table := "security_crs_version"
			if kind == "crs" {
				ResetCRSUpdateManagerForTest()
				InitCRSUpdateManager(nil)
				t.Cleanup(ResetCRSUpdateManagerForTest)
				GetCRSUpdateManager().fetchLatestTag = func(context.Context) (string, error) {
					calls.Add(1)
					return "", errors.New("unexpected tick")
				}
			} else {
				table = "security_ip2region_version"
				ResetIP2RegionUpdateManagerForTest()
				InitIP2RegionUpdateManager(nil)
				t.Cleanup(ResetIP2RegionUpdateManagerForTest)
				GetIP2RegionUpdateManager().fetchLatestTag = func(context.Context) (string, error) {
					calls.Add(1)
					return "", errors.New("unexpected tick")
				}
			}
			past := time.Now().UTC().Add(-time.Hour).Format(crsTimeLayout)
			if _, err := db.DB.Exec(`UPDATE `+table+` SET auto_update=1,next_update=? WHERE id=1`, past); err != nil {
				t.Fatal(err)
			}
			te.SetRole(false)
			te.StartLoop(kind)
			// U10-F09：窗口必须覆盖 >2 个 tick（生产 tick=1s）——曾 20ms 窗口
			// 在 1s tick 下必然零调用，断言恒真（假绿）。同时断言槽未被推进。
			before := versionTableNextUpdate(table)
			time.Sleep(2200 * time.Millisecond)
			if got := calls.Load(); got != 0 {
				t.Fatalf("从节点到期槽仍触发 %d 次", got)
			}
			if after := versionTableNextUpdate(table); after != before {
				t.Fatalf("从节点不得推进排程槽: before=%q after=%q", before, after)
			}
		})
	}
}

func TestVersionTasks_concurrentStartDoesNotAdvanceSlot(t *testing.T) {
	for _, kind := range []string{"crs", "ip2region"} {
		t.Run(kind, func(t *testing.T) {
			stubUpdateRetrySleep(t)
			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			const slot = "2026-12-01 04:00:00"
			if kind == "crs" {
				m := newTestCRSManager(t)
				seedCRSVersionRow(t, "v4.14.0", true)
				if _, err := db.DB.Exec(`UPDATE security_crs_version SET next_update=? WHERE id=1`, slot); err != nil {
					t.Fatal(err)
				}
				m.fetchLatestTag = func(context.Context) (string, error) {
					select {
					case entered <- struct{}{}:
					default:
					}
					<-release
					return "", errors.New("stop")
				}
				done, err := m.StartUpdate("auto", nil)
				if err != nil {
					t.Fatal(err)
				}
				<-entered
				if _, err := m.StartUpdate("auto", nil); !errors.Is(err, ErrCRSUpdateRunning) {
					t.Fatalf("并发 StartUpdate err=%v, want ErrCRSUpdateRunning", err)
				}
				if got := versionTableNextUpdate("security_crs_version"); got != slot {
					t.Fatalf("并发未启动时 next_update=%q, want 原槽 %q", got, slot)
				}
				close(release)
				<-done
			} else {
				m := newTestIP2RegionManager(t)
				seedIP2RegionVersionRow(t, "v3.0.0", true)
				if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET next_update=? WHERE id=1`, slot); err != nil {
					t.Fatal(err)
				}
				m.fetchLatestTag = func(context.Context) (string, error) {
					select {
					case entered <- struct{}{}:
					default:
					}
					<-release
					return "", errors.New("stop")
				}
				done, err := m.StartUpdate("auto", nil)
				if err != nil {
					t.Fatal(err)
				}
				<-entered
				if _, err := m.StartUpdate("auto", nil); !errors.Is(err, ErrIP2RegionUpdateRunning) {
					t.Fatalf("并发 StartUpdate err=%v, want ErrIP2RegionUpdateRunning", err)
				}
				if got := versionTableNextUpdate("security_ip2region_version"); got != slot {
					t.Fatalf("并发未启动时 next_update=%q, want 原槽 %q", got, slot)
				}
				close(release)
				<-done
			}
		})
	}
}

func TestVersionTasks_firstSlotUsesConfiguredSchedule(t *testing.T) {
	newWireTestEngine(t)
	if err := SetCRSSchedule([]int{2}, "04:30"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET next_update='' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	want := versionTableNextSlot("security_crs_version", time.Now().UTC())
	armSecurityLibraryFirstSlots()
	if got := versionTableNextUpdate("security_crs_version"); got != want {
		t.Fatalf("首槽=%q, want 配置化排程槽 %q", got, want)
	}
}

func TestPromote_realignsBusinessTaskLoops(t *testing.T) {
	// Given：库内全部启用，但六个业务驱动任务均被停止。
	te := newWireTestEngine(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET threat_auto_update=1,crawler_auto_update=1,auto_backup_enabled=1,autoban_enabled=1,is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
		if _, err := db.DB.Exec(`UPDATE ` + table + ` SET auto_update=1 WHERE id=1`); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"threat", "crs", "ip2region", "crawlerbot-update", "auto-backup", "autoban"} {
		te.StopLoop(id)
	}
	service := NewClusterService(db.DB, "")

	// When：升主。
	if err := service.Promote(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Then：六任务统一按库实态恢复调度，而非只恢复 autoban。
	for _, id := range []string{"threat", "crs", "ip2region", "crawlerbot-update", "auto-backup", "autoban"} {
		meta, ok := te.Lookup(id)
		if !ok || !meta.LoopOn {
			t.Errorf("%s Promote 后 LoopOn=false，业务与调度失配", id)
		}
	}
}
