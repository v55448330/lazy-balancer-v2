package services

import (
	"context"
	"encoding/json"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// W2：security_ip_lists 随 security 节同步——快照携带列表行与策略 refs 列，
// 全量替换语义下从节点忠实复制，策略引用端到端存活。
func TestClusterSnapshot_securityIPListsRoundTrip(t *testing.T) {
	// Given
	cluster, database := newClusterTestService(t)
	entries := `[{"value":"10.0.0.0/8","remark":"内网段"}]`
	if _, err := database.Exec(`INSERT INTO security_ip_lists (id,name,description,category,entries,created_by,created_at,updated_by,updated_at)
		VALUES (11,'office','办公网','allow',?,2,'2026-08-20 10:00:00',3,'2026-08-21 11:00:00')`, entries); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode,ip_acl_list_refs,ip_whitelist_refs)
		VALUES (5,'refs policy','blocking','[11]','[11]')`); err != nil {
		t.Fatal(err)
	}

	// When
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then：快照携带列表行（可空列 COALESCE 归一）与策略 refs 列
	var lists []map[string]any
	if err := json.Unmarshal(snapshot.SecurityIPLists, &lists); err != nil {
		t.Fatalf("parse security ip lists: %v", err)
	}
	if len(lists) != 1 {
		t.Fatalf("ip lists=%d, want 1", len(lists))
	}
	if lists[0]["name"] != "office" || lists[0]["category"] != "allow" || lists[0]["entries"] != entries {
		t.Fatalf("ip list row mismatch: %+v", lists[0])
	}
	var policies []map[string]any
	if err := json.Unmarshal(snapshot.SecurityPolicies, &policies); err != nil {
		t.Fatalf("parse security policies: %v", err)
	}
	if len(policies) != 1 || policies[0]["ip_acl_list_refs"] != "[11]" || policies[0]["ip_whitelist_refs"] != "[11]" {
		t.Fatalf("policy refs columns missing from snapshot: %+v", policies)
	}

	// When：从节点清空两表后重放快照
	if _, err := database.Exec("DELETE FROM security_ip_lists; DELETE FROM security_policies"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then：列表行逐列存活，策略 refs 端到端存活
	var name, gotEntries string
	var updatedBy int
	if err := database.QueryRow("SELECT name,entries,updated_by FROM security_ip_lists WHERE id=11").Scan(&name, &gotEntries, &updatedBy); err != nil {
		t.Fatalf("read applied ip list: %v", err)
	}
	if name != "office" || gotEntries != entries || updatedBy != 3 {
		t.Fatalf("applied ip list mismatch: name=%q entries=%q updated_by=%d", name, gotEntries, updatedBy)
	}
	var aclRefs, wlRefs string
	if err := database.QueryRow("SELECT ip_acl_list_refs,ip_whitelist_refs FROM security_policies WHERE id=5").Scan(&aclRefs, &wlRefs); err != nil {
		t.Fatalf("read applied policy refs: %v", err)
	}
	if aclRefs != "[11]" || wlRefs != "[11]" {
		t.Fatalf("applied policy refs mismatch: acl=%q whitelist=%q", aclRefs, wlRefs)
	}
}

// W2：security 节哈希必须感知 security_ip_lists 行变化——列表条目更新后
// 节哈希变化，从节点据此前置触发 security 节重放（而非依赖策略行变动）。
func TestClusterSnapshot_securitySectionHashTracksIPLists(t *testing.T) {
	// Given
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_ip_lists (id,name,entries) VALUES (11,'office','[{"value":"10.0.0.1","remark":""}]')`); err != nil {
		t.Fatal(err)
	}
	first, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	firstHash := first.SectionHashes["security"]
	if firstHash == "" {
		t.Fatal("security section hash must be non-empty")
	}

	// When：仅改动列表条目（不动任何策略行）
	if _, err := database.Exec(`UPDATE security_ip_lists SET entries='[{"value":"192.168.1.1","remark":""}]' WHERE id=11`); err != nil {
		t.Fatal(err)
	}
	clusterSnapshotCaches.Delete(database)
	second, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then
	if second.SectionHashes["security"] == firstHash {
		t.Fatal("security section hash must change when an ip list row changes")
	}
}

// W2：空 SecurityIPLists 载荷的全量替换语义——主节点清空列表后从节点同步删除。
func TestApplySnapshot_emptySecurityIPListsDeletesRows(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_ip_lists (id,name,entries) VALUES (11,'doomed','[]')`); err != nil {
		t.Fatal(err)
	}
	snapshot := models.ClusterSnapshot{
		Version:             9,
		SecurityPolicies:    json.RawMessage("[]"),
		SecurityBindings:    json.RawMessage("[]"),
		SecurityCustomRules: []models.SecurityCustomRule{},
		SecurityBlockPages:  []models.SecurityBlockPage{},
		SecurityIPLists:     json.RawMessage("[]"),
		SecurityCRSVersion:  []models.ClusterSecurityCRSVersion{},
	}

	// When
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM security_ip_lists").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("security_ip_lists rows=%d after empty snapshot, want 0", count)
	}
}
