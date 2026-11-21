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
	// notification-node-stats-report 必须同受本条约束：RoleSlaveOnly 只由引擎
	// 角色门（roleAllows）在执行面拦停主节点，**不设** loopEnabled——把它列进
	// 豁免会让「从节点上报永不调度」的装配缺口重新静默通过。
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

// 到期判定必须与同族「双布局单源解析」同口径：库内 RFC3339 形态的未来槽
// 不得被单布局解析失败误判为「已到期」而提前下载。
func TestCrawlerDueSources_parsesRFC3339Slots(t *testing.T) {
	// Given：一个到期源（平面串）+ 一个未来源（RFC3339）
	newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339)
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET next_update=CASE name
		WHEN 'googlebot' THEN '2000-01-01T00:00:00Z'
		WHEN 'bingbot' THEN ?
		ELSE '2099-01-01 00:00:00' END`, future); err != nil {
		t.Fatal(err)
	}

	// When
	autoSources, err := crawlerDueSources("auto")
	if err != nil {
		t.Fatal(err)
	}

	// Then：RFC3339 未来槽的 bingbot 不得进入到期集
	for _, src := range autoSources {
		if src.Name == "bingbot" {
			t.Fatalf("RFC3339 未来槽被误判为到期: %+v", autoSources)
		}
	}
	if len(autoSources) != 1 || autoSources[0].Name != "googlebot" {
		t.Fatalf("auto sources=%+v, want only googlebot", autoSources)
	}

	// 单一启用源的混合格式槽在「最早槽」读取侧与到期判定同口径：RFC3339
	// 未来槽归一为平面串返回（不得因格式而漏掉）。
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=CASE name WHEN 'bingbot' THEN 1 ELSE 0 END`); err != nil {
		t.Fatal(err)
	}
	wantEarliest := future
	if parsed, ok := ParseUTCTimeDual(future); ok {
		wantEarliest = parsed.UTC().Format(crsTimeLayout)
	}
	if got := earliestCrawlerNextUpdate(); got != wantEarliest {
		t.Fatalf("earliestCrawlerNextUpdate=%q, want %q", got, wantEarliest)
	}
}
