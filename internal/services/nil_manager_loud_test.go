package services

// crs/ip2region nil-manager 响亮失败钉测（与 threat 同构）：manager 未初始化
// 时 Run 曾 return nil（静默 success）+ 不推进排程槽——装配顺序缺陷被吞掉，
// 且过期槽每 tick 重投（引擎层退避兜底之前的双重放大）。

import (
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// Given crs 管理器未初始化。When 触发 crs 任务。Then 返回错误 + task_runs
// 落 failed + 任务日志留失败行；auto 触发还须推进排程槽（防过期槽每 tick
// 重投）。
func TestCRSTask_nilManagerFailsLoudly(t *testing.T) {
	te := newWireTestEngine(t)
	ResetCRSUpdateManagerForTest() // once 已消费态：Get 不再重建
	t.Cleanup(ResetCRSUpdateManagerForTest)
	te.SetRole(true)

	err := te.Trigger("crs", "manual", "")
	if err == nil {
		t.Fatal("manager nil 时 CRS 任务仍报 success——初始化时序缺陷不可见")
	}
	lr := te.LatestRun("crs")
	if lr == nil || lr.Status != "failed" {
		t.Fatalf("nil manager 应落 failed 终态，got %+v", lr)
	}
	if logText := readTaskLog(t, "crs"); !strings.Contains(logText, "未初始化") {
		t.Fatalf("nil manager 缺任务日志失败行:\n%s", logText)
	}
}

func TestIP2RegionTask_nilManagerFailsLoudly(t *testing.T) {
	te := newWireTestEngine(t)
	ResetIP2RegionUpdateManagerForTest()
	t.Cleanup(ResetIP2RegionUpdateManagerForTest)
	te.SetRole(true)

	err := te.Trigger("ip2region", "manual", "")
	if err == nil {
		t.Fatal("manager nil 时 IP2Region 任务仍报 success——初始化时序缺陷不可见")
	}
	lr := te.LatestRun("ip2region")
	if lr == nil || lr.Status != "failed" {
		t.Fatalf("nil manager 应落 failed 终态，got %+v", lr)
	}
	if logText := readTaskLog(t, "ip2region"); !strings.Contains(logText, "未初始化") {
		t.Fatalf("nil manager 缺任务日志失败行:\n%s", logText)
	}
}

// auto 触发的 nil-manager 失败必须推进排程槽（与 m.advanceSlotIfAuto 同口径：
// 仅 auto、仅空/过期槽）——否则过期槽每 tick 重投。
func TestCRSTask_nilManagerAutoAdvancesSlot(t *testing.T) {
	te := newWireTestEngine(t)
	ResetCRSUpdateManagerForTest()
	t.Cleanup(ResetCRSUpdateManagerForTest)
	te.SetRole(true)
	// 过期槽形态。
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET auto_update=1, next_update='2020-01-01 00:00:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	if err := te.Trigger("crs", "auto", ""); err == nil {
		t.Fatal("auto 触发 nil manager 也必须失败落定")
	}
	var next string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crs_version WHERE id=1`).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if next == "" {
		t.Fatal("nil-manager 失败轮未写入排程槽")
	}
	if got := parseSlotUTC(t, next); !got.After(time.Now().UTC()) {
		t.Fatalf("nil-manager 失败轮槽位=%v，必须真实晚于当前时间（过期槽会每 tick 重投）", got)
	}
}

func TestIP2RegionTask_nilManagerAutoAdvancesSlot(t *testing.T) {
	te := newWireTestEngine(t)
	ResetIP2RegionUpdateManagerForTest()
	t.Cleanup(ResetIP2RegionUpdateManagerForTest)
	te.SetRole(true)
	if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET auto_update=1, next_update='2020-01-01 00:00:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	if err := te.Trigger("ip2region", "auto", ""); err == nil {
		t.Fatal("auto 触发 nil manager 也必须失败落定")
	}
	var next string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_ip2region_version WHERE id=1`).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if next == "" {
		t.Fatal("nil-manager 失败轮未写入排程槽")
	}
	if got := parseSlotUTC(t, next); !got.After(time.Now().UTC()) {
		t.Fatalf("nil-manager 失败轮槽位=%v，必须真实晚于当前时间（过期槽会每 tick 重投）", got)
	}
}
