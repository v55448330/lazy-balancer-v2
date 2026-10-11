package db

import "testing"

// 内置威胁名单专业化改名迁移（2026-09-24 用户裁定）：存量 system=1 行按旧名
// 更新为新名（保 id——策略 refs 按 id 引用），新库直接以新名种子。
func TestThreatSystemListRename_migratesLegacyNames(t *testing.T) {
	openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// 模拟存量：旧名三行 + 一条引用旧名单的策略不丢（id 稳定）
	if _, err := DB.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at) VALUES
		('威胁情报库-中科大黑 IP', '旧', '恶意 IP', '[]', 1, datetime('now'), datetime('now')),
		('威胁情报库-FireHOL level1', '旧', '恶意 IP', '[]', 1, datetime('now'), datetime('now')),
		('威胁情报库-ET Compromised', '旧', '恶意 IP', '[]', 1, datetime('now'), datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	oldID := 0
	if err := DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name='威胁情报库-中科大黑 IP'`).Scan(&oldID); err != nil {
		t.Fatal(err)
	}

	if err := migrateThreatSystemListNames(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// 新名存在且 id 不变；旧名清零
	var newID int
	if err := DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND system=1`, ThreatListNameBySource("ustc")).Scan(&newID); err != nil {
		t.Fatalf("新名行不存在: %v", err)
	}
	if newID != oldID {
		t.Fatalf("id 漂移: %d→%d", oldID, newID)
	}
	var legacy int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name LIKE '威胁情报库-%'`).Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	if legacy != 0 {
		t.Fatalf("旧名残留 %d 行", legacy)
	}
	// 幂等：二次执行无变化
	if err := migrateThreatSystemListNames(); err != nil {
		t.Fatalf("二次执行: %v", err)
	}
}

func TestThreatSystemListRename_skipsWhenNewNameOccupied(t *testing.T) {
	// Given 旧名 system=1 行 + 用户手工占用的同名（新名）system=0 行——CORE-U3
	//（第 69 轮）：name 无 UNIQUE 约束，无守卫改名会产出同名双行（选择器混淆），
	// 须跳过改名留给人工处置。
	openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	newName := ThreatListNameBySource("ustc")
	if _, err := DB.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at) VALUES
		('威胁情报库-中科大黑 IP', '旧', '恶意 IP', '[]', 1, datetime('now'), datetime('now')),
		(?, '用户自建同名名单', '恶意 IP', '[]', 0, datetime('now'), datetime('now'))`, newName); err != nil {
		t.Fatal(err)
	}

	// When
	if err := migrateThreatSystemListNames(); err != nil {
		t.Fatalf("migrate: %v（同名冲突须跳过改名而非报错阻断启动）", err)
	}

	// Then 旧名行保持旧名（未改名），用户同名行不受影响，同名双行未产生
	var legacyCount int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE system=1 AND name='威胁情报库-中科大黑 IP'`).Scan(&legacyCount); err != nil {
		t.Fatal(err)
	}
	if legacyCount != 1 {
		t.Fatalf("旧名 system=1 行=%d, want 1（同名占用时须跳过改名）", legacyCount)
	}
	var sameName int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=?`, newName).Scan(&sameName); err != nil {
		t.Fatal(err)
	}
	if sameName != 1 {
		t.Fatalf("新名行=%d, want 1（不得产出同名双行）", sameName)
	}
	// And 幂等：二次执行仍跳过且不报错
	if err := migrateThreatSystemListNames(); err != nil {
		t.Fatalf("二次执行: %v", err)
	}
}

// 新名口径：去「威胁情报库-」前缀，专业化命名
func TestThreatSystemLists_professionalNames(t *testing.T) {
	names := map[string]string{}
	for _, sl := range ThreatSystemLists {
		names[sl.Source] = sl.Name
	}
	want := map[string]string{
		"ustc":           "中科大恶意 IP 名单（USTC）",
		"firehol_l1":     "FireHOL Level 1 综合黑名单",
		"et_compromised": "Emerging Threats 失陷主机名单",
	}
	for src, w := range want {
		if names[src] != w {
			t.Fatalf("%s 名单名=%q, want %q", src, names[src], w)
		}
	}
}
