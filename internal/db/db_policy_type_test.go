package db

import "testing"

// policy_type 迁移：newColumns 加列（TEXT NOT NULL DEFAULT ”）+ 存量行按
// 内容推断一次性 backfill（models.InferPolicyType 单一事实源，幂等——仅
// policy_type=” 的行参与，重跑无副作用；显式值不被覆盖）。
func TestRunMigrations_policyTypeColumnAndBackfill(t *testing.T) {
	// Given：迁移前形态（无 policy_type 列）的存量策略行
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (name,mode,ip_acl_enabled,ip_acl_mode,ip_acl_list,rate_limit_enabled,rate_limit_rps,enabled) VALUES
		('legacy-waf','blocking',0,'','[]',0,0,1),
		('legacy-acl','off',1,'deny','["10.0.0.0/8"]',0,0,1),
		('legacy-rl','off',0,'','[]',1,100,1),
		('legacy-mixed','blocking',1,'deny','["10.0.0.0/8"]',0,0,1),
		('legacy-empty','off',0,'','[]',0,0,1)`); err != nil {
		t.Fatalf("seed legacy policies: %v", err)
	}

	// When
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then：列存在且逐行推断落值
	want := map[string]string{
		"legacy-waf":   "stage3",
		"legacy-acl":   "stage1",
		"legacy-rl":    "stage2",
		"legacy-mixed": "mixed",
		"legacy-empty": "stage3",
	}
	for name, wantType := range want {
		var got string
		if err := database.QueryRow(`SELECT policy_type FROM security_policies WHERE name=?`, name).Scan(&got); err != nil {
			t.Fatalf("read %s policy_type: %v", name, err)
		}
		if got != wantType {
			t.Fatalf("%s policy_type=%q, want %q", name, got, wantType)
		}
	}

	// 幂等：显式值不被重跑覆盖
	if _, err := database.Exec(`UPDATE security_policies SET policy_type='stage1' WHERE name='legacy-waf'`); err != nil {
		t.Fatal(err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("re-run migrations: %v", err)
	}
	var got string
	if err := database.QueryRow(`SELECT policy_type FROM security_policies WHERE name='legacy-waf'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "stage1" {
		t.Fatalf("explicit policy_type overwritten by re-run: got %q, want stage1", got)
	}
}
