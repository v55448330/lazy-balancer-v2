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
	if _, err := database.Exec(`INSERT INTO security_policies (name,mode,ip_acl_enabled,ip_acl_mode,ip_acl_list,enabled) VALUES
		('legacy-waf','blocking',0,'','[]',1),
		('legacy-acl','off',1,'deny','["10.0.0.0/8"]',1),
		('legacy-rl','off',0,'','[]',1),
		('legacy-mixed','blocking',1,'deny','["10.0.0.0/8"]',1),
		('legacy-empty','off',0,'','[]',1)`); err != nil {
		t.Fatalf("seed legacy policies: %v", err)
	}

	// When
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then：列存在且逐行推断落值
	// 五阶段模型（2026-11-12）：WAF=stage4（人机验证占 stage3）；无特征存量行
	// 同样归 stage4（InferPolicyType default 分支）。
	want := map[string]string{
		"legacy-waf":   "stage3",
		"legacy-acl":   "stage1",
		"legacy-rl":    "stage3", // 仅限流的存量策略在配额下线后无阶段能力
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

// 阶段 3 退役面（2026-11-12 用户裁定；2026-11-13 修订人机页条款）：
//   - human_exempt_ips / human_challenge_page_id 两列不得再存在于 security_policies
//     （IP 级放行唯一入口=阶段 0 信任名单；挑战页由 lb_human 内置渲染）；
//   - 内置人机页 9005/9006 是策略可选的真实挑战页载体（2026-11-13 推翻
//     「9005 退役」裁定）：迁移不得删除 9005——旧名空占位行由
//     SeedDefaultBlockPage 播种自愈归位；自定义页不受影响。
func TestRunMigrations_retiresHumanExemptIPsAndChallengePage(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	// 旧库形态：两列存在，9005 以旧名空占位行存在，自定义页并存。
	for _, col := range []string{"human_exempt_ips", "human_challenge_page_id"} {
		if _, err := database.Exec("ALTER TABLE security_policies ADD COLUMN " + col + " TEXT NOT NULL DEFAULT ''"); err != nil {
			t.Fatalf("seed legacy column %s: %v", col, err)
		}
	}
	if _, err := database.Exec(`INSERT INTO security_block_pages (id,name,description,content,is_default,is_builtin) VALUES (9005,'人机验证页面','','',0,1)`); err != nil {
		t.Fatalf("seed builtin page 9005: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_block_pages (id,name,description,content,is_default,is_builtin) VALUES (9100,'自定义页','','',0,0)`); err != nil {
		t.Fatalf("seed custom page: %v", err)
	}

	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	for _, col := range []string{"human_exempt_ips", "human_challenge_page_id"} {
		var n int
		if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('security_policies') WHERE name=?", col).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("退役列 %s 仍存在（应按 deadColumnDrops 删除）", col)
		}
	}
	// 9005（含旧名空占位行）+自定义页都保留：占位行归位交给播种自愈，
	// 迁移层不得删内置人机页（否则内置页每次启动先删后播，中间态不可选）。
	var retained int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_block_pages WHERE id IN (9005,9100)`).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if retained != 2 {
		t.Fatalf("迁移后 9005 与自定义页 9100 均应保留：retained=%d", retained)
	}
	var custom int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_block_pages WHERE id=9100`).Scan(&custom); err != nil {
		t.Fatal(err)
	}
	if custom != 1 {
		t.Fatal("自定义页 9100 不得被迁移误删")
	}
}
