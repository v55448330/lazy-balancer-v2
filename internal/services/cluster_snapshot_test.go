package services

import (
	"context"
	"database/sql"
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
