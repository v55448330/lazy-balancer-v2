package db

import "testing"

// 孤儿 path_rules 清理必须与 caddy_id 回填顺序无关：存量库里 lb_rules 仍有
// NULL caddy_id 时，`rule_id NOT IN (SELECT caddy_id …)` 因 NULL 让谓词恒为
// NULL → 该次启动零删除（清理被无声推迟/永不发生）。NOT EXISTS 形态在同一次
// 启动内即收敛。
func TestInitialize_orphanPathRulesCleanupIgnoresNullCaddyID(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	// 存量形态：规则尚未获得 caddy_id（历史库/中断迁移），且 FK OFF 时代
	// 遗留孤儿 path_rules 行。
	if _, err := DB.Exec(`INSERT INTO lb_rules (id, name, protocol, listen_port, caddy_id) VALUES (99, 'legacy','http',8082,NULL)`); err != nil {
		t.Fatalf("seed legacy rule with null caddy_id: %v", err)
	}
	if _, err := DB.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES ('lb_ghost',1,'prefix','/x')`); err != nil {
		t.Fatalf("seed orphan path rule: %v", err)
	}

	if err := Initialize(dir); err != nil {
		t.Fatalf("re-initialize database: %v", err)
	}

	var orphan int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM path_rules WHERE rule_id='lb_ghost'`).Scan(&orphan); err != nil {
		t.Fatalf("count orphan path rules: %v", err)
	}
	if orphan != 0 {
		t.Fatalf("orphan path_rules=%d, want 0（NULL caddy_id 存在时清理也必须生效）", orphan)
	}
}
