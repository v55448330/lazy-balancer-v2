package services

// MCP IP 白名单的带外归一与落库形态门：
//   - 快照（主节点下发）不经 REST 写侧校验，畸形条目必须在落库前被丢弃并留痕
//     （白名单语义下丢弃=收紧允许来源），全部条目非法时落显式 "[]"（解析成功
//     但 0 条网络 → 恒不匹配 = deny-all）。绝不能落 ''（等同「无白名单」= 全来源
//     放行，把畸形数据变成访问面放宽）。
//   - 合法条目统一规范化（裸 IP→/32 或 /128、去重、掩码归位），与写侧
//     NormalizeCIDRs 的落库形态一致，认证中间件可直接 net.ParseCIDR。

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

func TestNormalizeMCPIPWhitelistStrings(t *testing.T) {
	cases := []struct {
		name        string
		values      []string
		wantNormal  []string
		wantDropped []string
	}{
		{name: "裸 IPv4", values: []string{"192.168.1.5"}, wantNormal: []string{"192.168.1.5/32"}},
		{name: "裸 IPv6", values: []string{"::1"}, wantNormal: []string{"::1/128"}},
		{name: "重复条目去重", values: []string{"10.0.0.0/8", " 10.0.0.1/8 "}, wantNormal: []string{"10.0.0.0/8"}},
		{name: "非法条目丢弃并回传", values: []string{"10.0.0.0/8", "nope", ""}, wantNormal: []string{"10.0.0.0/8"}, wantDropped: []string{"nope", ""}},
		{name: "全部非法", values: []string{"nope"}, wantDropped: []string{"nope"}},
		{name: "空输入", values: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			normal, dropped := NormalizeMCPIPWhitelistStrings(tc.values)
			if len(normal) != len(tc.wantNormal) {
				t.Fatalf("normalized=%v, want %v", normal, tc.wantNormal)
			}
			for i := range tc.wantNormal {
				if normal[i] != tc.wantNormal[i] {
					t.Fatalf("normalized=%v, want %v", normal, tc.wantNormal)
				}
			}
			if len(dropped) != len(tc.wantDropped) {
				t.Fatalf("dropped=%v, want %v", dropped, tc.wantDropped)
			}
			for i := range tc.wantDropped {
				if dropped[i] != tc.wantDropped[i] {
					t.Fatalf("dropped=%v, want %v", dropped, tc.wantDropped)
				}
			}
		})
	}
}

// 快照落库：合法条目规范化落 JSON 数组；混合形态只保留合法条目（收紧）；
// 全部非法落 "[]"（deny-all，绝不落 ”）；空白名单仍落 ”。
func TestInsertSnapshotUsersAndKeysNormalizesMCPIPWhitelist(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	keys := []models.ClusterAPIKey{
		{ID: 11, Name: "normal", KeyHash: "h1", KeyPrefix: "p1", CreatedBy: 1, IsEnabled: true, CreatedAt: time.Now(), MCPIPWhitelist: []string{"192.168.1.5", "192.168.1.5", "10.0.0.0/8"}},
		{ID: 12, Name: "mixed", KeyHash: "h2", KeyPrefix: "p2", CreatedBy: 1, IsEnabled: true, CreatedAt: time.Now(), MCPIPWhitelist: []string{"10.0.0.0/8", "garbage"}},
		{ID: 13, Name: "all-bad", KeyHash: "h3", KeyPrefix: "p3", CreatedBy: 1, IsEnabled: true, CreatedAt: time.Now(), MCPIPWhitelist: []string{"garbage"}},
		{ID: 14, Name: "empty", KeyHash: "h4", KeyPrefix: "p4", CreatedBy: 1, IsEnabled: true, CreatedAt: time.Now()},
	}

	tx, err := database.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	if err := insertSnapshotUsersAndKeys(ctx, tx, models.ClusterSnapshot{APIKeys: keys}); err != nil {
		t.Fatalf("insert snapshot keys: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	read := func(name string) string {
		t.Helper()
		var raw string
		if err := database.QueryRow(`SELECT COALESCE(mcp_ip_whitelist,'') FROM api_keys WHERE name=?`, name).Scan(&raw); err != nil {
			t.Fatalf("read %s whitelist: %v", name, err)
		}
		return raw
	}
	assertCIDRs := func(name string, want []string) {
		t.Helper()
		raw := read(name)
		var got []string
		if err := json.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("%s whitelist %q 不是合法 JSON 数组: %v", name, raw, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s whitelist=%v, want %v", name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s whitelist=%v, want %v", name, got, want)
			}
		}
	}

	assertCIDRs("normal", []string{"192.168.1.5/32", "10.0.0.0/8"})
	assertCIDRs("mixed", []string{"10.0.0.0/8"})
	// 全部非法：显式 deny-all 形态（非空串 → 中间件解析成功但 0 条网络）。
	if raw := read("all-bad"); raw != "[]" {
		t.Fatalf("all-bad whitelist=%q, want %q（deny-all；绝不能落 '' 变成全来源放行）", raw, "[]")
	}
	// 空白名单：''（无白名单语义，与写侧 encodeMCPIPWhitelist 一致）。
	if raw := read("empty"); raw != "" {
		t.Fatalf("empty whitelist=%q, want ''", raw)
	}

	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM api_keys`).Scan(&count); err != nil {
		t.Fatalf("count keys: %v", err)
	}
	if count != 4 {
		t.Fatalf("api_keys count=%d, want 4", count)
	}
}
