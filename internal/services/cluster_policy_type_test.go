package services

import (
	"context"
	"encoding/json"
	"testing"
)

// policy_type 集群同步面：快照 dump 携带该列（新主节点显式值透传）；旧主节点
// 快照（缺列）在从端 apply 时按内容推断（snapshotPolicyType → models.
// InferPolicyType），从端落库后类型不滞留 ”。
func TestClusterSnapshot_policyTypeRoundTrip(t *testing.T) {
	// Given：主端两条类型策略
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode,policy_type,rate_limit_enabled,rate_limit_rps,enabled) VALUES
		(5,'sync-waf','blocking','stage3',0,0,1),(6,'sync-rl','off','stage2',1,100,1)`); err != nil {
		t.Fatal(err)
	}

	// When：快照导出
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Then：快照携带 policy_type
	var policies []map[string]any
	if err := json.Unmarshal(snapshot.SecurityPolicies, &policies); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range policies {
		got[p["name"].(string)] = p["policy_type"].(string)
	}
	if got["sync-waf"] != "stage3" || got["sync-rl"] != "stage2" {
		t.Fatalf("snapshot policy_type=%v, want stage3/stage2", got)
	}

	// When：从端清空后重放
	if _, err := database.Exec("DELETE FROM security_policies"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then：逐值存活
	for name, want := range map[string]string{"sync-waf": "stage3", "sync-rl": "stage2"} {
		var gotType string
		if err := database.QueryRow(`SELECT policy_type FROM security_policies WHERE name=?`, name).Scan(&gotType); err != nil {
			t.Fatal(err)
		}
		if gotType != want {
			t.Fatalf("%s applied policy_type=%q, want %q", name, gotType, want)
		}
	}
}

// 旧主节点快照（缺 policy_type 列）在从端按内容推断落库。
func TestClusterSnapshot_policyTypeInferredForLegacySnapshot(t *testing.T) {
	// Given
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode,ip_acl_enabled,ip_acl_mode,ip_acl_list,enabled) VALUES
		(7,'legacy-acl','off',1,'deny','["10.0.0.0/8"]',1)`); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// 构造旧形态：剥掉 policy_type 键（模拟旧主节点快照）
	var policies []map[string]any
	if err := json.Unmarshal(snapshot.SecurityPolicies, &policies); err != nil {
		t.Fatal(err)
	}
	for i := range policies {
		delete(policies[i], "policy_type")
	}
	stripped, err := json.Marshal(policies)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.SecurityPolicies = stripped

	// When
	if _, err := database.Exec("DELETE FROM security_policies"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply legacy snapshot: %v", err)
	}

	// Then：按内容推断为 stage1
	var gotType string
	if err := database.QueryRow(`SELECT policy_type FROM security_policies WHERE id=7`).Scan(&gotType); err != nil {
		t.Fatal(err)
	}
	if gotType != "stage1" {
		t.Fatalf("legacy snapshot applied policy_type=%q, want stage1 (inferred)", gotType)
	}
}
