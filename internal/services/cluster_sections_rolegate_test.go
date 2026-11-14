package services

// 已应用节记账是从端专有写（cluster_applied_sections 只由从端 apply 维护，
// 升主清空）：与从端专有列写同口径携带 slaveRoleConditionSQL——apply 提交
// 与记账之间升主时，在途记账不得把旧拓扑节行重插回新主节点。

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// Given 从节点语境下的快照应用完成。
// When recordAppliedSectionHashes。
// Then 节哈希与文件态记账照常落库（从端语义不回归）。
func TestRecordAppliedSectionHashes_slaveRoleGate(t *testing.T) {
	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, false)
	snapshot := models.ClusterSnapshot{Version: 7, SectionHashes: map[string]string{"users": "u7", "rules": "r7", "security": "s7"}}
	switches := SyncSwitches{Users: true, Rules: true, Security: true}
	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}
	if err := recordAppliedSectionHashes(context.Background(), database, snapshot, sk, switches, nil); err != nil {
		t.Fatalf("slave bookkeeping: %v", err)
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cluster_applied_sections`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != len(syncSections) {
		t.Fatalf("从节点记账行数=%d, want %d", count, len(syncSections))
	}
	var refHash string
	var refVersion int
	if err := database.QueryRow(`SELECT COALESCE(applied_waf_ref_hash,''), COALESCE(applied_waf_ref_version,0) FROM global_config WHERE id=1`).Scan(&refHash, &refVersion); err != nil {
		t.Fatal(err)
	}
	if refHash == "" || refVersion != 7 {
		t.Fatalf("从节点文件态记账=(%q,%d), want 非空哈希+版本 7", refHash, refVersion)
	}

	// When 升主提交后在途记账晚到（apply 提交→记账窗口的角色翻转）。
	setNodeMasterRole(t, database, true)
	if _, err := database.Exec(`DELETE FROM cluster_applied_sections`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET applied_waf_ref_hash='', applied_waf_ref_version=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	snapshot2 := models.ClusterSnapshot{Version: 8, SectionHashes: map[string]string{"users": "u8", "rules": "r8", "security": "s8"}}
	if err := recordAppliedSectionHashes(context.Background(), database, snapshot2, sk, switches, nil); err != nil {
		t.Fatalf("master-side late bookkeeping err=%v, want nil（角色门 0 行不是错误）", err)
	}

	// Then 主节点不得被重插旧拓扑节行/写回文件态记账。
	if err := database.QueryRow(`SELECT COUNT(*) FROM cluster_applied_sections`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("升主后在途记账重插了 %d 行节记账（从端专有写必须带角色谓词）", count)
	}
	if err := database.QueryRow(`SELECT COALESCE(applied_waf_ref_hash,''), COALESCE(applied_waf_ref_version,0) FROM global_config WHERE id=1`).Scan(&refHash, &refVersion); err != nil {
		t.Fatal(err)
	}
	if refHash != "" || refVersion != 0 {
		t.Fatalf("升主后文件态记账被写回=(%q,%d), want 空/0", refHash, refVersion)
	}
}

// Given 从节点已有节记账行（unchanged 跳过路径的 UPDATE 目标）。
// When 升主后在途 unchanged-UPDATE 晚到。
// Then UPDATE 同样 0 行生效（角色谓词覆盖两条写路径）。
func TestRecordAppliedSectionHashes_unchangedUpdateRespectsRoleGate(t *testing.T) {
	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, false)
	snapshot := models.ClusterSnapshot{Version: 7, SectionHashes: map[string]string{"rules": "r7"}}
	switches := SyncSwitches{Rules: true}
	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}
	if err := recordAppliedSectionHashes(context.Background(), database, snapshot, sk, switches, nil); err != nil {
		t.Fatalf("seed bookkeeping: %v", err)
	}
	setNodeMasterRole(t, database, true)
	// unchanged 路径：UPDATE 命中既有行——升主后必须 0 行生效。
	sk2 := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{"rules": true}}
	snapshot2 := models.ClusterSnapshot{Version: 9, SectionHashes: map[string]string{"rules": "r7"}}
	if err := recordAppliedSectionHashes(context.Background(), database, snapshot2, sk2, switches, nil); err != nil {
		t.Fatalf("master-side unchanged update err=%v, want nil", err)
	}
	var version int
	if err := database.QueryRow(`SELECT applied_version FROM cluster_applied_sections WHERE section='rules'`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 7 {
		t.Fatalf("升主后 unchanged-UPDATE 改写了节记账版本=%d, want 保持 7（0 行生效）", version)
	}
}
