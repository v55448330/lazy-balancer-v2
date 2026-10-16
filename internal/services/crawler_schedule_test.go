package services

import (
	"reflect"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func TestCrawlerSchedule_independentFromThreat(t *testing.T) {
	// Given：威胁库已有独立排程与下一槽，爬虫地址库源已种子
	newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET threat_schedule_days='1', threat_schedule_time='03:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update='2099-01-01 00:00:00'`); err != nil {
		t.Fatal(err)
	}

	// When：保存爬虫地址库自己的星期集与时间
	if err := SetCrawlerSchedule([]int{2, 4}, "05:30"); err != nil {
		t.Fatalf("save crawler schedule: %v", err)
	}

	// Then：爬虫配置与重排生效，威胁排程和威胁源槽位均不受影响
	days, hhmm := CrawlerSchedule()
	if !reflect.DeepEqual(days, []int{2, 4}) || hhmm != "05:30" {
		t.Fatalf("CrawlerSchedule=%v %s", days, hhmm)
	}
	threatDays, threatTime := ThreatSchedule()
	if !reflect.DeepEqual(threatDays, []int{1}) || threatTime != "03:00" {
		t.Fatalf("威胁排程被爬虫保存污染: %v %s", threatDays, threatTime)
	}
	var crawlerNext, threatNext string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE name='googlebot'`).Scan(&crawlerNext); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE name='ustc'`).Scan(&threatNext); err != nil {
		t.Fatal(err)
	}
	wantNext := NextScheduledSlot(time.Now().UTC(), []int{2, 4}, "05:30", CurrentLocation()).UTC().Format(crsTimeLayout)
	if crawlerNext != wantNext {
		t.Errorf("爬虫下一槽=%q want %q", crawlerNext, wantNext)
	}
	if threatNext != "2099-01-01 00:00:00" {
		t.Errorf("威胁源下一槽被爬虫重排: %q", threatNext)
	}
}

func TestCrawlerAutoUpdate_independentFromThreat(t *testing.T) {
	// Given
	newClusterTestService(t)
	if err := SetThreatAutoUpdate(true); err != nil {
		t.Fatal(err)
	}

	// When：只关闭爬虫地址库总闸
	if err := SetCrawlerAutoUpdate(false); err != nil {
		t.Fatalf("SetCrawlerAutoUpdate: %v", err)
	}

	// Then：两个任务总闸互不影响
	if CrawlerAutoUpdateEnabled() {
		t.Fatal("爬虫地址库总闸应关闭")
	}
	if !ThreatAutoUpdateEnabled() {
		t.Fatal("威胁库总闸不应被爬虫开关影响")
	}
}

func TestCrawlerAutoUpdate_drivesLoop(t *testing.T) {
	// Given：爬虫任务调度当前关闭
	te := newWireTestEngine(t)
	te.StopLoop("crawlerbot-update")

	// When：开启业务自动更新
	if err := SetCrawlerAutoUpdate(true); err != nil {
		t.Fatal(err)
	}
	// Then：业务开启必须同步开启任务调度
	if m, _ := te.Lookup("crawlerbot-update"); !m.LoopOn {
		t.Fatal("开启业务自动更新未同步 StartLoop")
	}

	// When：关闭业务自动更新
	if err := SetCrawlerAutoUpdate(false); err != nil {
		t.Fatal(err)
	}
	// Then：业务关闭必须同步停止任务调度
	if m, _ := te.Lookup("crawlerbot-update"); m.LoopOn {
		t.Fatal("关闭业务自动更新未同步 StopLoop")
	}
}

func TestCrawlerDueSources_autoUsesOwnDueSlots(t *testing.T) {
	// Given：爬虫地址库一个到期源、一个未来源，均启用
	newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET next_update=CASE name
		WHEN 'googlebot' THEN '2000-01-01 00:00:00' ELSE '2099-01-01 00:00:00' END`); err != nil {
		t.Fatal(err)
	}

	// When
	autoSources, err := crawlerDueSources("auto")
	if err != nil {
		t.Fatal(err)
	}
	manualSources, err := crawlerDueSources("manual")
	if err != nil {
		t.Fatal(err)
	}

	// Then：自动轮只取到期源，手动轮取全部启用源
	if len(autoSources) != 1 || autoSources[0].Name != "googlebot" {
		t.Fatalf("auto sources=%+v, want only googlebot", autoSources)
	}
	if len(manualSources) != 4 {
		t.Fatalf("manual sources=%d, want 4", len(manualSources))
	}
}

func TestArmSecurityLibraryFirstSlots_includesCrawler(t *testing.T) {
	// Given：启用自动更新的爬虫源没有下一槽
	newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET next_update='', update_enabled=1`); err != nil {
		t.Fatal(err)
	}

	// When
	armSecurityLibraryFirstSlots()

	// Then：爬虫源也必须完成首槽武装，不能只有三旧库
	var next string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE name='googlebot'`).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if next == "" {
		t.Fatal("爬虫源首槽未武装")
	}
}

func TestInitTaskEngine_nonExemptTasksLoopOn(t *testing.T) {
	// Given：默认启动装配（crawler_auto_update 默认开启）
	te := newWireTestEngine(t)
	// Then：除明确豁免（cert-waiting-ca 默认关、autoban/auto-backup 按业务开关）外，
	// 所有非 oneshot 任务都必须 loop_on，新增任务不得漏进默认 StartLoop。
	exempt := map[string]bool{"cert-waiting-ca": true, "autoban": true, "auto-backup": true}
	for _, meta := range te.DescribeAll() {
		if meta.Kind == taskengine.KindOneshot || exempt[meta.ID] {
			continue
		}
		if !meta.LoopOn {
			t.Errorf("任务 %s 未进入默认调度（kind=%s）", meta.ID, meta.Kind)
		}
	}
}
