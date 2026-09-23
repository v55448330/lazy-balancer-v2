package services

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 威胁库自动更新总开关（v2.3.2 用户裁定）：global_config.threat_auto_update
// 为任务级总闸（卡片父行开关）；逐源 update_enabled 决定任务更新哪些源
// （弹框内开关）。调度器：总闸关闭时整任务不启动（即使源全开且到期）。
func TestThreatScheduler_masterSwitchGatesTask(t *testing.T) {
	newClusterTestService(t)
	// Given：三源全开且全部到期（next_update 空）
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=NULL`); err != nil {
		t.Fatal(err)
	}
	m := GetThreatUpdateManager()
	if m == nil {
		InitThreatUpdateManager()
		m = GetThreatUpdateManager()
	}
	// 调度器不经网络——用 due 探测代替真跑：总闸开 → 有到期源
	due, err := threatDueSources("auto")
	if err != nil || len(due) != 3 {
		t.Fatalf("due=%v err=%v, want 3", len(due), err)
	}

	// 总闸关闭 → tick 整任务不启动
	if err := SetThreatAutoUpdate(false); err != nil {
		t.Fatalf("set master off: %v", err)
	}
	if ThreatAutoUpdateEnabled() {
		t.Fatal("总闸关闭后 threatAutoUpdateEnabled 须为 false")
	}
	// 总闸开 → true
	if err := SetThreatAutoUpdate(true); err != nil {
		t.Fatal(err)
	}
	if !ThreatAutoUpdateEnabled() {
		t.Fatal("总闸开启后须为 true")
	}
}
