package db

import "testing"

// 阶段合并迁移（2026-11-12 用户裁定）：CC 防护 = 阶段 2（配额+人机挑战），
// 内容防护(WAF) = 阶段 3；旧的人机阶段 3 并入阶段 2，旧 WAF 阶段 4 重编号为 3。
//   - 同一规则同时绑定旧 stage2(限流) 与旧 stage3(人机) → 合并为一条 stage2：
//     保留限流配额，吸收人机模式/方式/有效期/豁免与 cc_* 阈值，绑定去重后
//     人机行删除；
//   - 仅人机：原行改型为 stage2；
//   - 全部旧 stage4 → stage3；
//   - 一次性：marker 置位后重跑不改写（否则会把人机语义再套到 WAF 行上）。
func TestRunMigrations_mergesHumanIntoCCAndRenumbersWAF(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	// 存量库形态：策略列由 newColumnsRegistry 补齐（含人机/CC 各列）。
	if err := ensureNewColumns(newColumnsRegistry, nil); err != nil {
		t.Fatalf("ensure new columns: %v", err)
	}
	// 规则 a：CC 策略 10 + 人机策略 11；规则 b：仅人机 12；策略 13/14：旧 WAF
	if _, err := database.Exec(`INSERT INTO security_policies
		(id,name,mode,policy_type,human_verify_mode,cc_detect_enabled,cc_rps_limit,enabled)
		VALUES
		(10,'CC-A','off','stage2','off',0,40,1),
		(11,'人机A','off','stage3','force',1,99,1),
		(12,'仅人机B','off','stage3','auto',1,55,1),
		(13,'WAF-C','blocking','stage4','off',0,40,1),
		(14,'WAF-D','detection','stage4','off',0,40,1)`); err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id,rank) VALUES
		('rule-a',10,1),('rule-a',11,2),('rule-b',12,1),('rule-c',13,1),('rule-c',14,2)`); err != nil {
		t.Fatalf("seed bindings: %v", err)
	}

	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// 合并：规则 a 只剩一条 stage2，且配额来自 10、人机配置来自 11
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='rule-a'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rule-a 绑定应去重为 1 条，实际 %d", n)
	}
	var typ, humanMode string
	var ccLimit int
	if err := database.QueryRow(`SELECT p.policy_type, p.human_verify_mode, p.cc_rps_limit
		FROM security_policies p JOIN security_policy_bindings b ON b.policy_id=p.id WHERE b.rule_caddy_id='rule-a'`).
		Scan(&typ, &humanMode, &ccLimit); err != nil {
		t.Fatal(err)
	}
	if typ != "stage2" || humanMode != "force" || ccLimit != 99 {
		t.Fatalf("合并结果 type=%s human=%s cc=%d，want stage2/force/99", typ, humanMode, ccLimit)
	}
	// 人机行 11 已被合并删除；仅人机 12 改型为 stage2 且保留其阈值
	var remaining int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE id=11`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("合并后的人机行应删除")
	}
	if err := database.QueryRow(`SELECT policy_type FROM security_policies WHERE id=12`).Scan(&typ); err != nil {
		t.Fatal(err)
	}
	if typ != "stage2" {
		t.Fatalf("仅人机策略改型=%s，want stage2", typ)
	}
	// 旧 WAF 全部重编号为 stage3，且不再存在 stage4
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE policy_type='stage4'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("迁移后不得残留 stage4：%d 条", n)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_policies WHERE id IN (13,14) AND policy_type='stage3'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("旧 WAF 应重编号为 stage3，命中 %d 条", n)
	}

	// 幂等：再次运行不得把 WAF(stage3) 再当人机合并
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode,policy_type,human_verify_mode,enabled) VALUES (15,'WAF-E','blocking','stage3','force',1)`); err != nil {
		t.Fatal(err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("re-run migrations: %v", err)
	}
	if err := database.QueryRow(`SELECT policy_type FROM security_policies WHERE id=15`).Scan(&typ); err != nil {
		t.Fatal(err)
	}
	if typ != "stage3" {
		t.Fatalf("重跑迁移把 stage3 改成了 %s（一次性门失效）", typ)
	}
}
