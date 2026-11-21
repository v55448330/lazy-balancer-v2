package services

import (
	"context"
	"encoding/json"
	"testing"
)

// policy_type 集群同步面：快照 dump 携带该列（新主节点显式值透传）；旧主节点
// 快照（缺列）在从端 apply 时按内容推断（InferSnapshotPolicyType →
// models.InferPolicyType），从端落库后类型不滞留 ”。
func TestClusterSnapshot_policyTypeRoundTrip(t *testing.T) {
	// Given：主端两条类型策略
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode,policy_type,human_verify_mode,enabled) VALUES
		(5,'sync-waf','blocking','stage3','off',1),(6,'sync-cc','off','stage2','force',1)`); err != nil {
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
	if got["sync-waf"] != "stage3" || got["sync-cc"] != "stage2" {
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
	for name, want := range map[string]string{"sync-waf": "stage3", "sync-cc": "stage2"} {
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

// 滚动升级哈希收敛：旧主节点快照缺 is_default_policy 键（或显式 null）——
// apply 写侧经 policyIsDefault 回退 0 落库；哈希输入必须同形，否则缺键/nil 与
// 落库后读回的 0 编码不同，主从 security 节哈希恒不等（每轮重放+强制重载）。
func TestCanonicalSnapshotPolicyContent_normalizesIsDefaultPolicy(t *testing.T) {
	base := map[string]interface{}{"id": float64(9), "name": "legacy", "mode": "blocking"}
	withZero := map[string]interface{}{"id": float64(9), "name": "legacy", "mode": "blocking", "is_default_policy": int64(0)}
	withNil := map[string]interface{}{"id": float64(9), "name": "legacy", "mode": "blocking", "is_default_policy": nil}
	want, err := canonicalSnapshotPolicyContent(withZero)
	if err != nil {
		t.Fatal(err)
	}
	for name, row := range map[string]map[string]interface{}{"missing-key": base, "nil-value": withNil} {
		got, err := canonicalSnapshotPolicyContent(row)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != want {
			t.Fatalf("%s 归一后指纹与显式 0 不同（主从哈希会漂移）:\n got=%s\nwant=%s", name, got, want)
		}
	}
}

// 快照往返：缺 is_default_policy 键的载荷 apply 后落库为 0，且从端导出的行
// 与原载荷归一后同指纹（滚动升级窗口不产生持久哈希差）。
func TestClusterSnapshot_isDefaultPolicyRoundTripNormalizesMissingKey(t *testing.T) {
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode,enabled) VALUES (11,'legacy-default','blocking',1)`); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var policies []map[string]any
	if err := json.Unmarshal(snapshot.SecurityPolicies, &policies); err != nil {
		t.Fatal(err)
	}
	legacy := make([]map[string]any, 0, len(policies))
	for _, row := range policies {
		if int64(toFloat64(row["id"])) == 11 {
			delete(row, "is_default_policy")
		}
		legacy = append(legacy, row)
	}
	stripped, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.SecurityPolicies = stripped

	if _, err := database.Exec("DELETE FROM security_policies"); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply legacy snapshot: %v", err)
	}
	var applied int
	if err := database.QueryRow(`SELECT COALESCE(is_default_policy,-1) FROM security_policies WHERE id=11`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 0 {
		t.Fatalf("applied is_default_policy=%d, want 0（缺键回退）", applied)
	}
	// 从端导出行的归一指纹必须与「缺键载荷」一致（否则全量哈希漂移）。
	roundTrip, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var roundTripPolicies []map[string]interface{}
	if err := json.Unmarshal(roundTrip.SecurityPolicies, &roundTripPolicies); err != nil {
		t.Fatal(err)
	}
	var appliedRow map[string]interface{}
	for _, row := range roundTripPolicies {
		if int64(toFloat64(row["id"])) == 11 {
			appliedRow = row
		}
	}
	if appliedRow == nil {
		t.Fatal("round-trip snapshot 缺少 id=11 行")
	}
	appliedHash, err := canonicalSnapshotPolicyContent(appliedRow)
	if err != nil {
		t.Fatal(err)
	}
	var originalHash string
	found := false
	for _, row := range legacy {
		if int64(toFloat64(row["id"])) == 11 {
			originalHash, err = canonicalSnapshotPolicyContent(row)
			if err != nil {
				t.Fatal(err)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("legacy 载荷缺少 id=11 行")
	}
	if appliedHash != originalHash {
		t.Fatalf("往返后指纹漂移（主从会每轮重放）:\n applied=%s\noriginal=%s", appliedHash, originalHash)
	}
}
