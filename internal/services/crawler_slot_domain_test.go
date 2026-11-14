package services

// 爬虫族写面槽域收窄钉：运行域=内置注册表名（filterBuiltinCrawlerSources
// 跳过未知名行），三个写面（保存排程重排/首槽武装/用户取消推进）必须与读侧
// 同源收窄到 crawlerSourceRegistryNames——否则带外 INSERT 的未知名启用行
// 会被写入/推进出惰性槽：读侧「最早槽」排除它，写面却反复补回，与启动期
// 注册表外槽清理互相抵消（威胁族同机理，已收窄；爬虫族此前传 nil=全部行）。

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// seedOutOfRegistryCrawlerRow 造带外未知名启用行（惰性槽形态），返回其槽值。
func seedOutOfRegistryCrawlerRow(t *testing.T, slot string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO security_crawler_sources (name,display_name,url,format,update_enabled,next_update)
		VALUES ('out-of-registry','带外源','http://127.0.0.1:1/none','plain',1,?)`, slot); err != nil {
		t.Fatalf("seed out-of-registry crawler row: %v", err)
	}
}

func outOfRegistryCrawlerSlot(t *testing.T) string {
	t.Helper()
	var slot string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE name='out-of-registry'`).Scan(&slot); err != nil {
		t.Fatalf("read out-of-registry slot: %v", err)
	}
	return slot
}

// Given 注册表外启用行携带过期槽。When 保存爬虫排程（重排写面）。
// Then 内置源槽被重排，注册表外行槽保持原值（不得写回惰性槽）。
func TestSetCrawlerSchedule_leavesOutOfRegistrySlotUntouched(t *testing.T) {
	newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	stale := expiredSlot()
	seedOutOfRegistryCrawlerRow(t, stale)

	if err := SetCrawlerSchedule([]int{2, 4}, "05:30"); err != nil {
		t.Fatalf("save crawler schedule: %v", err)
	}

	if got := outOfRegistryCrawlerSlot(t); got != stale {
		t.Fatalf("注册表外行槽被保存排程改写: %q → %q（槽域必须 ⊆ 运行域）", stale, got)
	}
	assertFutureSlot(t, "内置源重排", crawlerSourceSlot(t, "googlebot"))
}

// Given 注册表外启用行空槽。When 首槽武装。
// Then 内置源被武装，注册表外行保持空槽（武装它只会造惰性槽）。
func TestArmCrawlerFirstSlots_leavesOutOfRegistryRowUnarmed(t *testing.T) {
	newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if err := SetCrawlerAutoUpdate(true); err != nil {
		t.Fatal(err)
	}
	// 清掉全部槽后重新武装（首槽形态）。
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET next_update=''`); err != nil {
		t.Fatal(err)
	}
	seedOutOfRegistryCrawlerRow(t, "")

	armCrawlerFirstSlots()

	if got := outOfRegistryCrawlerSlot(t); got != "" {
		t.Fatalf("注册表外行被首槽武装: %q（运行体不处理该行，武装即惰性槽）", got)
	}
	assertFutureSlot(t, "内置源首槽", crawlerSourceSlot(t, "googlebot"))
}

// Given auto 轮用户取消（无到期源的空轮形态）。When 取消推进写面。
// Then 内置源槽推进，注册表外行槽保持原值。
func TestCrawlerUserCancel_leavesOutOfRegistrySlotUntouched(t *testing.T) {
	newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	if err := SetCrawlerAutoUpdate(true); err != nil {
		t.Fatal(err)
	}
	stale := expiredSlot()
	// 内置源全部置未来槽（无到期源 → 空轮），注册表外行置过期槽。
	future := "2099-01-01 00:00:00"
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET next_update=?`, future); err != nil {
		t.Fatal(err)
	}
	seedOutOfRegistryCrawlerRow(t, stale)

	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(taskengine.ErrUserCancelled)
	err := GetCrawlerUpdateManager().RunUpdate(ctx, taskengine.RunContext{Ctx: ctx, Trigger: "auto"})
	if err == nil {
		t.Fatal("用户取消轮必须返回取消错误")
	}

	if got := outOfRegistryCrawlerSlot(t); got != stale {
		t.Fatalf("注册表外行槽被取消推进改写: %q → %q（取消写面必须与运行域同收窄）", stale, got)
	}
	if got := crawlerSourceSlot(t, "googlebot"); got != future {
		t.Fatalf("未来槽被回拨: %q（推进门只覆盖到期/空槽）", got)
	}
}
