package services

// logSyncSwitchGuards 的告警去重版本推进是从端专有写（与
// recordAppliedSectionHashes 的 applied_waf_ref_* 写同口径）：apply 提交与
// 告警之间升主时，在途推进不得把旧拓扑的去重版本写回新主节点——升主已把
// 该列清零，写回会让新主节点（或再降级后）的告警去重依据失真。

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// Given 从节点语境（security 开关关闭、主端引用更新）触发告警并推进去重版本。
// When 升主提交后在途的版本推进晚到（同一告警链路）。
// Then UPDATE 0 行生效——新主节点的 applied_waf_ref_version 保持清零。
func TestLogSyncSwitchGuards_dedupAdvanceRespectsSlaveRoleGate(t *testing.T) {
	_, database := newClusterTestService(t)
	overrideWafPathsForServicesTest(t)
	setNodeMasterRole(t, database, false)
	if _, err := database.Exec(`UPDATE global_config SET applied_waf_ref_version=7 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	snapshot := models.ClusterSnapshot{
		Version:  8,
		WafFiles: &models.ClusterWafFilesRef{CRSVersion: "v1", CRSSha256: "deadbeef"},
	}
	sk := &sectionSkips{disabled: map[string]bool{"security": true}, unchanged: map[string]bool{}}

	// 从端语义不回归：告警后去重版本推进到快照版本。
	logSyncSwitchGuards(context.Background(), database, snapshot, sk, SyncSwitches{})
	var applied int
	if err := database.QueryRow(`SELECT COALESCE(applied_waf_ref_version,0) FROM global_config WHERE id=1`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 8 {
		t.Fatalf("从节点去重版本=%d, want 8（从端语义不回归）", applied)
	}

	// When：升主提交（清零文件态记账）后，在途告警的版本推进晚到。
	setNodeMasterRole(t, database, true)
	if _, err := database.Exec(`UPDATE global_config SET applied_waf_ref_hash='', applied_waf_ref_version=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	snapshot2 := models.ClusterSnapshot{
		Version:  9,
		WafFiles: &models.ClusterWafFilesRef{CRSVersion: "v2", CRSSha256: "cafebabe"},
	}
	logSyncSwitchGuards(context.Background(), database, snapshot2, sk, SyncSwitches{})

	// Then：主节点不得被写回去重版本（角色谓词 0 行生效）。
	if err := database.QueryRow(`SELECT COALESCE(applied_waf_ref_version,0) FROM global_config WHERE id=1`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 0 {
		t.Fatalf("升主后在途去重推进写回版本=%d, want 0（从端专有写必须带角色谓词）", applied)
	}
}
