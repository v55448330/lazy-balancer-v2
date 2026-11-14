package services

// 绑定顺序（rank）钉测（2026-11 用户裁定：绑定链上移/下移，请求序即执行序）。
//   - 读路径次序键 = (rank ASC, policy_id ASC)：rank=0 遗留行按 policy_id 兜底，
//     升级后旧库行为与旧版唯一执行序逐点等价（回填 1..N 即此序）。
//   - 快照转储按 (rule_caddy_id, rank, policy_id) 确定性排序：同集合 + 同 rank 的
//     不同物理插入序必须得到逐字节相同的载荷（节哈希主从对齐前提）。

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func seedRankPolicy(t *testing.T, id int, name string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,enabled) VALUES (?,?,'off',1)`, id, name); err != nil {
		t.Fatalf("seed policy %d: %v", id, err)
	}
}

// TestBindings_rankOrderWithLegacyFallback：显式 rank 决定执行序；rank=0 行
// （旧库未回填/旧主端载荷）由 policy_id 次序键兜底。
func TestBindings_rankOrderWithLegacyFallback(t *testing.T) {
	setupIsolatedDB(t)
	for _, p := range []struct {
		id   int
		name string
	}{{1, "p1"}, {2, "p2"}, {3, "p3"}} {
		seedRankPolicy(t, p.id, p.name)
	}
	// p3 rank=1、p1 rank=2、p2 rank=0（遗留）。
	for _, b := range []struct {
		pid  int
		rank int
	}{{3, 1}, {1, 2}, {2, 0}} {
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id, rank) VALUES ('lb_rank', ?, ?)`, b.pid, b.rank); err != nil {
			t.Fatalf("seed binding: %v", err)
		}
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_rank','r','http','r.test',8081,1)`); err != nil {
		t.Fatal(err)
	}
	got := GetSecurityPoliciesForRule("lb_rank")
	if len(got) != 3 {
		t.Fatalf("bound policies=%d, want 3", len(got))
	}
	want := []int{2, 3, 1} // rank 0 行最前（旧语义：未排序行按 policy_id 兜底于显式 rank 前）
	// 次序键 (rank ASC, policy_id ASC)：2(rank0) → 3(rank1) → 1(rank2)。
	for i, id := range want {
		if got[i].ID != id {
			t.Fatalf("order=%v, want %v", []int{got[0].ID, got[1].ID, got[2].ID}, want)
		}
	}

	// 内容寻址回归：rank 列在 fresh DDL 中 NOT NULL DEFAULT 0——不带 rank 的
	// 旧式写入落 0（不得因缺列报错）。
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_rank', 1)`); err == nil {
		t.Fatal("duplicate (rule,policy) must still fail (PK)")
	}
}

// TestSnapshotSecurityBindings_byteDeterministic：同集合 + 同 rank、不同物理
// 插入序 → 快照绑定载荷逐字节一致；旧载荷（无 rank 键）→ 从端 rank 兜底 0。
func TestSnapshotSecurityBindings_byteDeterministic(t *testing.T) {
	s := &ClusterService{}
	rows := []struct {
		pid  int
		rank int
	}{{7, 1}, {3, 2}, {9, 3}}

	dump := func(order []int) string {
		setupIsolatedDB(t)
		for i, idx := range order {
			_ = i
			r := rows[idx]
			if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id, rank) VALUES ('lb_snap', ?, ?)`, r.pid, r.rank); err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
		payload, err := s.snapshotSecurityBindings(t.Context(), db.DB)
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		return string(payload)
	}
	forward := dump([]int{0, 1, 2})
	reverse := dump([]int{2, 1, 0})
	if forward != reverse {
		t.Fatalf("绑定快照必须字节确定（正/反插入序）:\nforward=%s\nreverse=%s", forward, reverse)
	}
	// 顺序语义：rank 1..3 → policy_id 7,3,9（不是 id 升序）。
	var decoded []map[string]any
	if err := json.Unmarshal([]byte(forward), &decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var order []int
	for _, row := range decoded {
		pid, _ := row["policy_id"].(float64)
		order = append(order, int(pid))
	}
	if len(order) != 3 || order[0] != 7 || order[1] != 3 || order[2] != 9 {
		t.Fatalf("snapshot order=%v, want [7 3 9]（rank 序）", order)
	}
	if !strings.Contains(forward, `"rank"`) {
		t.Fatalf("snapshot payload must carry rank: %s", forward)
	}

	// 旧主端载荷（无 rank 键）→ 从端兜底 0（读路径次序键退化为 policy_id ASC）。
	if got := snapshotBindingRank(nil); got != 0 {
		t.Fatalf("nil rank → %d, want 0", got)
	}
	if got := snapshotBindingRank(float64(3)); got != 3 {
		t.Fatalf("rank 3 → %d, want 3", got)
	}
}
