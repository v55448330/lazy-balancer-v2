package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// seedDriftGuardData 为漂移守卫哈希测试写入 rules/users/security 三节的种子数据。
func seedDriftGuardData(t *testing.T, database *sql.DB) {
	t.Helper()
	stmts := []string{
		`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_dg','dg','http','dg.example',80,1)`,
		`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_dg','127.0.0.1',8080,1,1)`,
		`INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES ('lb_dg',0,'prefix','/api')`,
		`INSERT INTO users (id,username,password_hash,role,is_enabled,last_login) VALUES (1,'admin','h','admin',1,datetime('now'))`,
		`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,last_used) VALUES ('k','kh','kp',1,1,datetime('now'))`,
		`INSERT INTO security_policies (id,name,mode,enabled) VALUES (1,'policy-dg','block',1)`,
		`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_dg',1)`,
		`INSERT INTO security_custom_rules (name,action,score,enabled) VALUES ('cr-dg','block',5,1)`,
		`INSERT INTO security_crs_version (id,version) VALUES (1,'v4.0.0') ON CONFLICT(id) DO UPDATE SET version=excluded.version`,
		`INSERT INTO security_ip2region_version (id,version) VALUES (1,'v3.17.0') ON CONFLICT(id) DO UPDATE SET version=excluded.version`,
	}
	for _, stmt := range stmts {
		if _, err := database.Exec(stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
}

func TestDriftGuardSectionHashes_matchesFullSnapshotHashes(t *testing.T) {
	// 哈希奇偶不变式：漂移守卫哈希对 rules/users/security 三键必须等于全量
	// 快照路径 ComputeSnapshotSectionHashes 的结果，否则漂移比对口径不一致。
	service, database := newClusterTestService(t)
	seedDriftGuardData(t, database)

	full, _, err := service.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("full snapshot: %v", err)
	}
	guard, err := service.driftGuardSectionHashes(context.Background())
	if err != nil {
		t.Fatalf("drift guard hashes: %v", err)
	}

	for _, key := range driftGuardSections {
		want := full.SectionHashes[key]
		if want == "" {
			t.Fatalf("full snapshot hash for %q is empty", key)
		}
		if got := guard[key]; got != want {
			t.Fatalf("drift guard hash mismatch for %q: guard=%q full=%q", key, got, want)
		}
	}
}

func TestDriftGuardSectionHashes_detectsMutation(t *testing.T) {
	// 种子后记录基线，再分别改动三节（删上游→rules、改用户名→users、
	// 改策略 mode→security），漂移守卫哈希必须全部改变。
	service, database := newClusterTestService(t)
	seedDriftGuardData(t, database)

	baseline, err := service.driftGuardSectionHashes(context.Background())
	if err != nil {
		t.Fatalf("baseline hashes: %v", err)
	}

	if _, err := database.Exec(`DELETE FROM upstreams WHERE rule_id='lb_dg'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE users SET username='admin2' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_policies SET mode='off' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	after, err := service.driftGuardSectionHashes(context.Background())
	if err != nil {
		t.Fatalf("after-mutation hashes: %v", err)
	}

	if after["rules"] == baseline["rules"] {
		t.Fatal("rules hash must change after upstream deletion")
	}
	if after["users"] == baseline["users"] {
		t.Fatal("users hash must change after username change")
	}
	if after["security"] == baseline["security"] {
		t.Fatal("security hash must change after policy mode change")
	}
}

// TestSnapshotSecurityPolicies_nullEnabledDumpsAsDisabled 锁定 R-I1：主节点读路径
// 一律把 NULL enabled 当禁用（WHERE ... AND enabled=1），dump 却 COALESCE(enabled,1)
// 落成启用——主节点不执行的策略经快照在从节点变成启用，且提升后永久分叉。
// dump 必须与读路径同构：NULL → 禁用（0）。
func TestSnapshotSecurityPolicies_nullEnabledDumpsAsDisabled(t *testing.T) {
	// Given：一条 enabled 为 NULL 的策略（带外编辑/restoreTable 透传可产生）
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_policies (name, enabled) VALUES ('null-enabled', NULL)`); err != nil {
		t.Fatalf("seed null-enabled policy: %v", err)
	}

	// When：主节点快照 dump
	payload, err := service.snapshotSecurityPolicies(context.Background(), database)

	// Then：enabled 键存在且为禁用表示（dump 整数列经 JSON 序列化为数字 0，
	// 解码为 float64(0)——与 rate_limit_enabled 等 COALESCE(...,0) 列同形）
	if err != nil {
		t.Fatalf("snapshotSecurityPolicies: %v", err)
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(payload, &rows); err != nil {
		t.Fatalf("parse dump payload %s: %v", string(payload), err)
	}
	if len(rows) != 1 {
		t.Fatalf("dump rows=%d, want 1: %s", len(rows), string(payload))
	}
	enabled, ok := rows[0]["enabled"]
	if !ok {
		t.Fatalf("dump 缺少 enabled 键: %s", string(payload))
	}
	if enabled != float64(0) {
		t.Fatalf("enabled = %#v, want 0（NULL enabled 必须与读路径 WHERE enabled=1 同构落禁用）: %s", enabled, string(payload))
	}
}

// TestSnapshotSecurityCustomRules_toleratesNullTimestamps 锁定 R-I7：
// security_custom_rules.created_at/updated_at 可空（DEFAULT datetime('now')，
// 无 NOT NULL），一行 NULL 即让快照 scan 失败——主节点快照端点与每个从节点
// 拉取全挂，漂移守卫哈希每 304 周期丢失漂移检测。必须 COALESCE 归一化为空串。
func TestSnapshotSecurityCustomRules_toleratesNullTimestamps(t *testing.T) {
	// Given：一条 created_at/updated_at 为 NULL 的自定义规则
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_custom_rules (name, created_at, updated_at) VALUES ('cr-null-ts', NULL, NULL)`); err != nil {
		t.Fatalf("seed null-ts custom rule: %v", err)
	}

	// When：快照读取
	rules, err := service.snapshotSecurityCustomRules(context.Background(), database)

	// Then：不得 scan 失败；两时间列归一化为 ''
	if err != nil {
		t.Fatalf("snapshotSecurityCustomRules 不得因 NULL 时间列报错: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules=%d, want 1", len(rules))
	}
	if rules[0].CreatedAt != "" {
		t.Fatalf("CreatedAt = %q, want COALESCE 归一化后的 %q", rules[0].CreatedAt, "")
	}
	if rules[0].UpdatedAt != "" {
		t.Fatalf("UpdatedAt = %q, want COALESCE 归一化后的 %q", rules[0].UpdatedAt, "")
	}
}

// TestSnapshotSecurityBlockPages_toleratesNullTimestamps 锁定 R-I7：
// security_block_pages.created_at/updated_at 同样可空，与 custom_rules 同缺陷。
func TestSnapshotSecurityBlockPages_toleratesNullTimestamps(t *testing.T) {
	// Given：一条 created_at/updated_at 为 NULL 的拦截页面
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO security_block_pages (name, created_at, updated_at) VALUES ('bp-null-ts', NULL, NULL)`); err != nil {
		t.Fatalf("seed null-ts block page: %v", err)
	}

	// When：快照读取
	pages, err := service.snapshotSecurityBlockPages(context.Background(), database)

	// Then：不得 scan 失败；两时间列归一化为 ''
	if err != nil {
		t.Fatalf("snapshotSecurityBlockPages 不得因 NULL 时间列报错: %v", err)
	}
	if len(pages) == 0 {
		t.Fatal("pages 为空，种子行未读出")
	}
	var seeded *models.SecurityBlockPage
	for i := range pages {
		if pages[i].Name == "bp-null-ts" {
			seeded = &pages[i]
			break
		}
	}
	if seeded == nil {
		t.Fatal("找不到种子行 bp-null-ts")
	}
	if seeded.CreatedAt != "" {
		t.Fatalf("CreatedAt = %q, want COALESCE 归一化后的 %q", seeded.CreatedAt, "")
	}
	if seeded.UpdatedAt != "" {
		t.Fatalf("UpdatedAt = %q, want COALESCE 归一化后的 %q", seeded.UpdatedAt, "")
	}
}

func TestNearestSnapshotCertificateExpiry_missingExpiryDoesNotMaskNearerRealExpiry(t *testing.T) {
	// Given
	now := time.Now().UTC().Truncate(time.Second)
	near := now.Add(5 * time.Second).Format(time.RFC3339)

	// When
	got := nearestSnapshotCertificateExpiry([]models.ClusterCertificate{
		{RuleID: "lb_near", Domain: "near.example.com", CertPEM: "pem", ExpiresAt: near},
		{RuleID: "lb_acme_missing", Domain: "missing.example.com", CertPEM: "pem", ExpiresAt: ""},
	}, now)

	// Then：缺失证书的重建窗口（30s）不得覆盖更近的 5s 真实到期时间
	if want := now.Add(5 * time.Second); !got.Equal(want) {
		t.Fatalf("expiry=%v, want %v (missing-expiry window must not mask nearer expiry)", got, want)
	}
}
