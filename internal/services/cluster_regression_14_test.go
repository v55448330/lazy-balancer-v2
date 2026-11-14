package services

import (
	"context"
	"testing"
)

// 排程 → 快照 → 从端 apply → 从端库五列（security_crs_version.schedule_days/
// schedule_time、security_ip2region_version.schedule_days/schedule_time、
// global_config threat_schedule_days/threat_schedule_time/threat_auto_update）
// 全部收敛到主端值。
func TestClusterSync_ruleLibScheduleColumnsPropagate(t *testing.T) {
	cluster, database, syncService, bump := syncSemanticsEnv(t)
	ctx := context.Background()

	// Given 主端自定义排程（五列全部非默认值）
	if _, err := database.Exec(`INSERT OR REPLACE INTO security_crs_version (id, version, schedule_days, schedule_time) VALUES (1, 'v4.28.0', '3', '05:00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT OR REPLACE INTO security_ip2region_version (id, version, schedule_days, schedule_time) VALUES (1, 'v3.17.0', '1,3,5', '23:15')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET threat_auto_update=0, threat_schedule_days='3', threat_schedule_time='05:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	bump(300)

	// When 主端快照（须携带排程列）
	snap := snapshotAsMaster(t, cluster, database)
	// And 从端本地值已漂移（模拟从未收到排程的存量从端）
	if _, err := database.Exec(`UPDATE security_crs_version SET schedule_days='7', schedule_time='06:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_ip2region_version SET schedule_days='7', schedule_time='06:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET threat_auto_update=1, threat_schedule_days='7', threat_schedule_time='06:00' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := syncService.applySnapshot(ctx, snap); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Then 从端五列全部收敛到主端值
	var crsDays, crsTime string
	if err := database.QueryRow(`SELECT schedule_days, schedule_time FROM security_crs_version WHERE id=1`).Scan(&crsDays, &crsTime); err != nil {
		t.Fatal(err)
	}
	if crsDays != "3" || crsTime != "05:00" {
		t.Fatalf("crs 排程=(%q,%q), want (3,05:00)（主端排程须随快照到达从端）", crsDays, crsTime)
	}
	var ipDays, ipTime string
	if err := database.QueryRow(`SELECT schedule_days, schedule_time FROM security_ip2region_version WHERE id=1`).Scan(&ipDays, &ipTime); err != nil {
		t.Fatal(err)
	}
	if ipDays != "1,3,5" || ipTime != "23:15" {
		t.Fatalf("ip2region 排程=(%q,%q), want (1,3,5,23:15)", ipDays, ipTime)
	}
	var threatAuto bool
	var threatDays, threatTime string
	if err := database.QueryRow(`SELECT threat_auto_update, threat_schedule_days, threat_schedule_time FROM global_config WHERE id=1`).Scan(&threatAuto, &threatDays, &threatTime); err != nil {
		t.Fatal(err)
	}
	if threatAuto || threatDays != "3" || threatTime != "05:00" {
		t.Fatalf("威胁库排程=(%v,%q,%q), want (false,3,05:00)", threatAuto, threatDays, threatTime)
	}
}
