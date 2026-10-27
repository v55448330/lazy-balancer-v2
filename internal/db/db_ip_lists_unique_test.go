package db

import (
	"strconv"
	"testing"
)

// system=1 名单必须有 name 唯一性兜底；同名 system=0 用户列表
// 仍允许存在（部分索引只覆盖 system=1）。
func TestMigrateSystemIPListUniqueIndex_dedupesAndEnforces(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// 模拟历史 check-then-act 竞态留下的重复 system 行。
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system,created_at,updated_at) VALUES
		('自动封禁名单','旧A','自动封禁','[]',1,datetime('now'),datetime('now')),
		('自动封禁名单','旧B','自动封禁','[]',1,datetime('now'),datetime('now')),
		('自动封禁名单','用户','自定义','[]',0,datetime('now'),datetime('now'))`); err != nil {
		t.Fatalf("seed duplicates: %v", err)
	}
	var keptID int
	if err := database.QueryRow(`SELECT MIN(id) FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&keptID); err != nil {
		t.Fatal(err)
	}
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var systemRows, userRows int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&systemRows); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='自动封禁名单' AND system=0`).Scan(&userRows); err != nil {
		t.Fatal(err)
	}
	if systemRows != 1 || userRows != 1 {
		t.Fatalf("system rows=%d user rows=%d, want 1/1", systemRows, userRows)
	}
	var survivingID int
	if err := database.QueryRow(`SELECT id FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&survivingID); err != nil {
		t.Fatal(err)
	}
	if survivingID != keptID {
		t.Fatalf("surviving id=%d, want MIN(id)=%d", survivingID, keptID)
	}
	// 唯一索引生效：重复 system=1 必须被拒。
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system) VALUES ('自动封禁名单','dup','x','[]',1)`); err == nil {
		t.Fatal("duplicate system=1 insert must fail after unique index")
	}
	// 同名 system=0 不受约束。
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system) VALUES ('自动封禁名单','user2','x','[]',0)`); err != nil {
		t.Fatalf("same-name user list must be allowed: %v", err)
	}
}

// EnsureSystemIPList 在唯一索引下重复调用仍幂等（OR IGNORE 路径）。
func TestEnsureSystemIPList_idempotentWithUniqueIndex(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	created, err := EnsureSystemIPList(database, "自动封禁名单", "文案", "自动封禁")
	if err != nil || !created {
		t.Fatalf("first seed created=%v err=%v, want true/nil", created, err)
	}
	created, err = EnsureSystemIPList(database, "自动封禁名单", "文案2", "自动封禁")
	if err != nil || created {
		t.Fatalf("second seed created=%v err=%v, want false/nil", created, err)
	}
	var rows int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("rows=%d, want 1", rows)
	}
}

// 启动期索引探测门：唯一部分索引已在位时，重启必须跳过重复查重/重建
// （security_ip_lists 的 GROUP BY 查重是纯启动成本）。存量库索引缺失仍重建。
func TestMigrateSystemIPListUniqueIndex_skipsRebuildWhenIndexInPlace(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}

	dedupesBefore, skipsBefore := systemIPListUniqueIndexDedupes.Load(), systemIPListUniqueIndexSkips.Load()

	// Given 首次启动：索引缺失 → 查重 + 建索引。
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if got := systemIPListUniqueIndexDedupes.Load() - dedupesBefore; got != 1 {
		t.Fatalf("首次启动查重次数=%d, want 1", got)
	}
	if got := systemIPListUniqueIndexSkips.Load() - skipsBefore; got != 0 {
		t.Fatalf("首次启动跳过次数=%d, want 0", got)
	}

	// When 二次启动（索引已在位）。
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	// Then 零查重、零重建。
	if got := systemIPListUniqueIndexDedupes.Load() - dedupesBefore; got != 1 {
		t.Fatalf("二次启动累计查重=%d, want 1（重启不得重复查重）", got)
	}
	if got := systemIPListUniqueIndexSkips.Load() - skipsBefore; got != 1 {
		t.Fatalf("二次启动跳过次数=%d, want 1", got)
	}

	// And 索引被删（存量库形态）仍重新查重并补建——探测门不吞真实迁移。
	if _, err := database.Exec(`DROP INDEX u_security_ip_lists_system_name`); err != nil {
		t.Fatal(err)
	}
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("reinit after index drop: %v", err)
	}
	if got := systemIPListUniqueIndexDedupes.Load() - dedupesBefore; got != 2 {
		t.Fatalf("索引缺失后累计查重=%d, want 2", got)
	}
	var indexCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='u_security_ip_lists_system_name'`).Scan(&indexCount); err != nil {
		t.Fatal(err)
	}
	if indexCount != 1 {
		t.Fatalf("索引重建后条数=%d, want 1", indexCount)
	}
}

// 去重保留优先级：同名重复 system 行中被策略/全局配置引用的行必须存活，
// 指向被删行的引用重写为存活 id——此前按 MIN(id) 删行不修引用，策略引用
// 被删 id 时渲染期该名单条目整体消失（少拦/少放，安全面静默）。
func TestMigrateSystemIPListUniqueIndex_keepsReferencedRowAndRewritesRefs(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system,created_at,updated_at) VALUES
		('威胁情报甲','早','恶意 IP','[]',1,datetime('now'),datetime('now')),
		('威胁情报甲','晚','恶意 IP','[]',1,datetime('now'),datetime('now'))`); err != nil {
		t.Fatalf("seed duplicates: %v", err)
	}
	var earlyID, lateID int
	if err := database.QueryRow(`SELECT MIN(id) FROM security_ip_lists WHERE name='威胁情报甲' AND system=1`).Scan(&earlyID); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT MAX(id) FROM security_ip_lists WHERE name='威胁情报甲' AND system=1`).Scan(&lateID); err != nil {
		t.Fatal(err)
	}
	// trusted_proxy_range_refs 走 newColumns 补列通道（fresh CREATE 不携带）——
	// 本测试直接建库后补列，模拟迁移后形态。
	if _, err := database.Exec(`ALTER TABLE global_config ADD COLUMN trusted_proxy_range_refs TEXT NOT NULL DEFAULT '[]'`); err != nil {
		t.Fatalf("add trusted_proxy_range_refs: %v", err)
	}
	// 策略引用较晚行（非 MIN(id)）；全局受信代理引用较早行——两 id 均被引用
	// 时保留 MIN(被引用 id)，指向被删 id 的引用重写为存活 id。
	if _, err := database.Exec(`INSERT INTO security_policies (name,ip_acl_list_refs,ip_whitelist_refs) VALUES (?,?,?)`,
		"引用策略", `[`+strconv.Itoa(lateID)+`]`, `[]`); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config,trusted_proxy_range_refs) VALUES (1,'{}',?)`, `[`+strconv.Itoa(earlyID)+`]`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}

	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// 只断言存活 id：此前还 Scan 了 description 并配一个从未赋值的
	// survivingDesc + `_ = survivingDesc`，读起来像存在 description 断言。
	var survivingID int
	if err := database.QueryRow(`SELECT id FROM security_ip_lists WHERE name='威胁情报甲' AND system=1`).Scan(&survivingID); err != nil {
		t.Fatalf("surviving row: %v", err)
	}
	if survivingID != earlyID {
		t.Fatalf("surviving id=%d, want %d（被引用行优先，两个被引用 id 取 MIN）", survivingID, earlyID)
	}
	var aclRefs string
	if err := database.QueryRow(`SELECT ip_acl_list_refs FROM security_policies WHERE name='引用策略'`).Scan(&aclRefs); err != nil {
		t.Fatalf("read policy refs: %v", err)
	}
	if aclRefs != `[`+strconv.Itoa(earlyID)+`]` {
		t.Fatalf("policy ip_acl_list_refs=%s, want [%d]（被删 id %d 必须重写为存活 id）", aclRefs, earlyID, lateID)
	}
	var proxyRefs string
	if err := database.QueryRow(`SELECT trusted_proxy_range_refs FROM global_config WHERE id=1`).Scan(&proxyRefs); err != nil {
		t.Fatalf("read proxy refs: %v", err)
	}
	if proxyRefs != `[`+strconv.Itoa(earlyID)+`]` {
		t.Fatalf("trusted_proxy_range_refs=%s, want [%d]（存活引用不得改写）", proxyRefs, earlyID)
	}
}

// 单侧引用形态：只有较晚行被引用时必须保留较晚行（而非 MIN(id)）。
func TestMigrateSystemIPListUniqueIndex_referencedNonMinRowSurvives(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system,created_at,updated_at) VALUES
		('威胁情报乙','早','恶意 IP','[]',1,datetime('now'),datetime('now')),
		('威胁情报乙','晚','恶意 IP','[]',1,datetime('now'),datetime('now'))`); err != nil {
		t.Fatalf("seed duplicates: %v", err)
	}
	var lateID int
	if err := database.QueryRow(`SELECT MAX(id) FROM security_ip_lists WHERE name='威胁情报乙' AND system=1`).Scan(&lateID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (name,ip_whitelist_refs) VALUES (?,?)`,
		"白名单策略", `[`+strconv.Itoa(lateID)+`]`); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var survivingID int
	if err := database.QueryRow(`SELECT id FROM security_ip_lists WHERE name='威胁情报乙' AND system=1`).Scan(&survivingID); err != nil {
		t.Fatalf("surviving row: %v", err)
	}
	if survivingID != lateID {
		t.Fatalf("surviving id=%d, want 被引用行 %d", survivingID, lateID)
	}
	var wlRefs string
	if err := database.QueryRow(`SELECT ip_whitelist_refs FROM security_policies WHERE name='白名单策略'`).Scan(&wlRefs); err != nil {
		t.Fatalf("read policy refs: %v", err)
	}
	if wlRefs != `[`+strconv.Itoa(lateID)+`]` {
		t.Fatalf("policy ip_whitelist_refs=%s, want [%d]（存活行引用保持原样）", wlRefs, lateID)
	}
}
