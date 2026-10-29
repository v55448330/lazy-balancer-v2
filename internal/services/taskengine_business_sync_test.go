package services

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// setAutoBackupEnabledForTest 是业务开关写侧的测试专用组合：生产写侧唯一
// 入口是 SetAutoBackupEnabledTx（调用方事务）+ SyncAutoBackupTaskLoop，本 helper
// 只在本测试里把两步拼成「自开事务」形态（测试消费的旧入口已删除）。
func setAutoBackupEnabledForTest(enabled bool) error {
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := SetAutoBackupEnabledTx(tx, enabled); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	SyncAutoBackupTaskLoop(enabled)
	return nil
}

// Given global_config 单行缺失（损坏库/半迁移窗口可达）。
// When 写任务级自动更新总闸（关闭方向——列默认 1，只有真实写入才能得到 0）。
// Then 行先补建、开关真实落库、读侧（EnabledFn 同源）与调度面三方一致；
// 不得出现「开关响应成功、库中无记录、调度面永不投递」的静默分裂。
func TestSetGlobalTaskAutoUpdate_seedsMissingRow(t *testing.T) {
	te := newWireTestEngine(t)
	if _, err := db.DB.Exec(`DELETE FROM global_config`); err != nil {
		t.Fatalf("delete global_config: %v", err)
	}
	readFlag := func() int {
		t.Helper()
		var v int
		if err := db.DB.QueryRow(`SELECT threat_auto_update FROM global_config WHERE id=1`).Scan(&v); err != nil {
			t.Fatalf("global_config 行未补建: %v", err)
		}
		return v
	}

	if err := setGlobalTaskAutoUpdate("threat", false); err != nil {
		t.Fatalf("行缺失时写侧应补建并落库，得到 err=%v", err)
	}
	if got := readFlag(); got != 0 {
		t.Fatalf("threat_auto_update=%d, want 0（开关未落库）", got)
	}
	if ThreatAutoUpdateEnabled() {
		t.Fatal("写侧关闭后读侧仍为开启——写读口径分裂")
	}
	if m, ok := te.Lookup("threat"); !ok || m.LoopOn {
		t.Fatalf("关闭后调度未联动: ok=%v LoopOn=%v", ok, m.LoopOn)
	}

	if err := setGlobalTaskAutoUpdate("threat", true); err != nil {
		t.Fatalf("开启写侧: %v", err)
	}
	if got := readFlag(); got != 1 {
		t.Fatalf("threat_auto_update=%d, want 1", got)
	}
	if !ThreatAutoUpdateEnabled() {
		t.Fatal("写侧开启后读侧仍为关闭")
	}
	if m, ok := te.Lookup("threat"); !ok || !m.LoopOn {
		t.Fatalf("开启后调度未联动: ok=%v LoopOn=%v", ok, m.LoopOn)
	}
}

// 前缀→任务 ID 映射单源一致性：setGlobalTaskAutoUpdate 写侧按
// businessTaskDrivers 的 globalAutoUpdatePrefix 列反查任务 ID（唯一映射，
// crawler→crawlerbot-update 特例不再内联在写侧构成第二份映射知识）。本钉测
// 保证登记列与 schema/读侧不漂移：列名拼错（读库失败）或 crawler 反查回字面
// 前缀即红。
func TestBusinessTaskDrivers_autoUpdatePrefixesRegistered(t *testing.T) {
	initServicesDB(t)
	for _, driver := range businessTaskDrivers {
		if driver.globalAutoUpdatePrefix == "" {
			continue // 版本表族/备份/封禁不走 global_config 前缀列
		}
		if _, known := globalTaskAutoUpdateState(driver.globalAutoUpdatePrefix); !known {
			t.Errorf("driver %s 登记的前缀 %q 读库不可判定——列名与 schema 漂移", driver.id, driver.globalAutoUpdatePrefix)
		}
	}
	if id, ok := businessTaskIDForAutoUpdatePrefix("crawler"); !ok || id != "crawlerbot-update" {
		t.Fatalf("crawler 前缀反查=%q ok=%v, want crawlerbot-update/true（不得回退字面前缀）", id, ok)
	}
	if id, ok := businessTaskIDForAutoUpdatePrefix("threat"); !ok || id != "threat" {
		t.Fatalf("threat 前缀反查=%q ok=%v, want threat/true", id, ok)
	}
	if id, ok := businessTaskIDForAutoUpdatePrefix("nonexistent"); ok || id != "" {
		t.Fatalf("未登记前缀反查=%q ok=%v, want 空串/false", id, ok)
	}
}

// 业务开关写侧 → 引擎 LoopOn：四个规则库/备份任务逐一直测，
// 与 crawler/autoban 的既有钉共同覆盖全部六个业务驱动任务。
func TestBusinessSetters_syncEngineLoop(t *testing.T) {
	cases := []struct {
		id  string
		set func(bool) error
	}{
		{id: "threat", set: SetThreatAutoUpdate},
		{id: "crs", set: SetCRSAutoUpdate},
		{id: "ip2region", set: SetIP2RegionAutoUpdate},
		{id: "auto-backup", set: setAutoBackupEnabledForTest},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			te := newWireTestEngine(t)
			loopOn := func() bool {
				meta, ok := te.Lookup(tc.id)
				if !ok {
					t.Fatalf("%s 未注册", tc.id)
				}
				return meta.LoopOn
			}
			if err := tc.set(false); err != nil {
				t.Fatal(err)
			}
			if loopOn() {
				t.Errorf("%s 禁用后 LoopOn=true", tc.id)
			}
			if err := tc.set(true); err != nil {
				t.Fatal(err)
			}
			if !loopOn() {
				t.Errorf("%s 启用后 LoopOn=false", tc.id)
			}
		})
	}
}
