package services

import (
	"context"
	"encoding/json"
	"testing"
)

// 威胁情报库源表随 security 节同步（v2.3.x）：快照携带行、从端全量替换
// 落库；开关值端到端存活；节哈希感知行变化（镜像 security_ip_lists 先例）。
func TestClusterSnapshot_threatSourcesRoundTrip(t *testing.T) {
	// Given
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE security_threat_sources SET update_enabled=0, apply_enabled=0, entry_count=14030, version='2026.09.23', update_status='success' WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}

	// When
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	// Then：快照携带三源行
	var rows []map[string]any
	if err := json.Unmarshal(snapshot.SecurityThreatSources, &rows); err != nil {
		t.Fatalf("快照未携带 security_threat_sources: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows=%d, want 3", len(rows))
	}

	// 从端清空后重放快照 → 忠实还原
	if _, err := database.Exec("DELETE FROM security_threat_sources"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}
	var updateEnabled, applyEnabled bool
	var version, status string
	var count int
	if err := database.QueryRow(`SELECT update_enabled, apply_enabled, version, update_status, entry_count FROM security_threat_sources WHERE name='ustc'`).
		Scan(&updateEnabled, &applyEnabled, &version, &status, &count); err != nil {
		t.Fatal(err)
	}
	if updateEnabled || applyEnabled || version != "2026.09.23" || status != "success" || count != 14030 {
		t.Fatalf("applied ustc=(%v,%v,%q,%q,%d), want 快照值", updateEnabled, applyEnabled, version, status, count)
	}
	var total int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_threat_sources`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("rows=%d after apply, want 3", total)
	}
}

// security 节哈希必须感知威胁库行变化（开关切换后节哈希变化，从节点据此
// 前置触发 security 节重放）。
func TestClusterSnapshot_securitySectionHashTracksThreatSources(t *testing.T) {
	cluster, database := newClusterTestService(t)
	first, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// When：仅切换开关（不动其他表行）
	if _, err := database.Exec(`UPDATE security_threat_sources SET apply_enabled=0 WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}
	clusterSnapshotCaches.Delete(database)
	second, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if first.SectionHashes["security"] == second.SectionHashes["security"] {
		t.Fatal("威胁库行变化必须改变 security 节哈希")
	}
}
