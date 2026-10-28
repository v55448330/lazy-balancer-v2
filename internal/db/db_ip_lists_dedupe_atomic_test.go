package db

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 去重三步（删重复行 → 重写引用 → 建唯一索引）必须同一事务：中途失败整体
// 回滚。否则「已删行 + 未重写引用」的中间态会让策略引用永久指向不存在的
// 名单 id（渲染期该名单条目整体消失：少拦/少放）。本测用同名占位表迫使第三
// 步 CREATE INDEX 失败，断言前两步的数据改写全部回滚。
func TestMigrateSystemIPListUniqueIndex_dedupeRollsBackAtomically(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// 同名 system=1 三行：id1 未被引用，id2/id3 被策略引用。
	// 保留 MIN(被引用 id)=id2，remap={id1:id2, id3:id2}——引用 [2,3] 应被
	// 重写为 [2,2]（重写是第三步失败前必须一并回滚的写）。
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system,created_at,updated_at) VALUES
		('自动封禁名单','旧A','自动封禁','["1.1.1.1"]',1,'2026-01-01 00:00:00','2026-01-01 00:00:00'),
		('自动封禁名单','旧B','自动封禁','[]',1,'2026-01-01 00:00:00','2026-01-01 00:00:00'),
		('自动封禁名单','旧C','自动封禁','[]',1,'2026-01-01 00:00:00','2026-01-01 00:00:00')`); err != nil {
		t.Fatalf("seed duplicates: %v", err)
	}
	var id2, id3 int
	if err := database.QueryRow(`SELECT id FROM security_ip_lists WHERE name='自动封禁名单' AND description='旧B'`).Scan(&id2); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT id FROM security_ip_lists WHERE name='自动封禁名单' AND description='旧C'`).Scan(&id3); err != nil {
		t.Fatal(err)
	}
	refs := "[" + strconv.Itoa(id2) + "," + strconv.Itoa(id3) + "]"
	if _, err := database.Exec(`INSERT INTO security_policies (id, name, ip_acl_list_refs) VALUES (1, 'p', ?)`, refs); err != nil {
		t.Fatalf("seed policy refs: %v", err)
	}
	// 同名占位表：CREATE UNIQUE INDEX 会以「already a table named …」失败，
	// 模拟「去重与引用重写已执行、建索引阶段出错」的崩溃窗口。
	if _, err := database.Exec(`CREATE TABLE u_security_ip_lists_system_name (placeholder INTEGER)`); err != nil {
		t.Fatalf("create index-name placeholder: %v", err)
	}
	// 只观察本用例产生的审计；其它迁移用例的缓冲残留不属于本回滚契约。
	drainSystemAuditBuffer()

	if err := migrateSystemIPListUniqueIndex(); err == nil {
		t.Fatal("create unique index must fail with the placeholder table occupying the index name")
	}

	var rows int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 3 {
		t.Fatalf("system rows=%d, want 3（失败必须整体回滚：DELETE 不得先提交）", rows)
	}
	var keptRefs string
	if err := database.QueryRow(`SELECT ip_acl_list_refs FROM security_policies WHERE id=1`).Scan(&keptRefs); err != nil {
		t.Fatal(err)
	}
	if keptRefs != refs {
		t.Fatalf("policy refs=%q, want %q（引用重写必须与删行同事务回滚）", keptRefs, refs)
	}
	// 失败后不留写迁移审计（删行未发生）。
	for _, entry := range drainSystemAuditBuffer() {
		if strings.Contains(entry.detail, "已去重") {
			t.Fatalf("回滚后不得留去重审计: %+v", entry)
		}
	}
}

// 去重删除的是整行，而 system=1 的「自动封禁名单」行携带 entries（已入库的
// 封禁 IP）：删行不并条目=被删行里的 IP 静默消失（少拦，等于静默解封）。
// 归一口径：保留行（被引用优先，否则 MIN(id)）持有并集，身份=条目的
// value/remark/created_at/expires_at 四元组（与渲染/更新判变化同口径）；
// 审计详情报告并入与被跳过（身份重复）的条目数。
func TestMigrateSystemIPListUniqueIndex_mergesEntriesOfDedupedRows(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_ip_lists (id,name,description,category,entries,system,created_at,updated_at) VALUES
		(1,'自动封禁名单','保留行','自动封禁','[{"value":"1.1.1.1","remark":""}]',1,'2026-01-01 00:00:00','2026-01-01 00:00:00'),
		(2,'自动封禁名单','重复B','自动封禁','[{"value":"1.1.1.1","remark":""},{"value":"2.2.2.2","remark":""}]',1,'2026-01-01 00:00:00','2026-01-01 00:00:00'),
		(3,'自动封禁名单','重复C','自动封禁','[{"value":"3.3.3.3","remark":"手工封禁"}]',1,'2026-01-01 00:00:00','2026-01-01 00:00:00')`); err != nil {
		t.Fatalf("seed duplicates: %v", err)
	}
	drainSystemAuditBuffer()
	t.Cleanup(func() { drainSystemAuditBuffer() })

	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var rows int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("system rows=%d, want 1", rows)
	}
	var survivorID int
	var rawEntries string
	if err := database.QueryRow(`SELECT id, entries FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&survivorID, &rawEntries); err != nil {
		t.Fatal(err)
	}
	if survivorID != 1 {
		t.Fatalf("survivor id=%d, want 1（无引用时保留 MIN(id)）", survivorID)
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(rawEntries), &entries); err != nil {
		t.Fatalf("survivor entries=%q 非法 JSON: %v", rawEntries, err)
	}
	wantValues := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	gotValues := make([]string, 0, len(entries))
	for _, entry := range entries {
		gotValues = append(gotValues, entry.Value)
	}
	if !slices.Equal(gotValues, wantValues) {
		t.Fatalf("并入后条目=%v, want %v（被删行条目并集，身份重复跳过，顺序稳定）", gotValues, wantValues)
	}
	// 备注随条目一起并入（并集按四元组身份，不是仅按 value）。
	if entries[2].Remark != "手工封禁" {
		t.Fatalf("并入条目 remark=%q, want 原样保留", entries[2].Remark)
	}
	entriesAudit := false
	for _, entry := range drainSystemAuditBuffer() {
		if entry.resource != "IP 名单" || !strings.Contains(entry.detail, "已去重") {
			continue
		}
		entriesAudit = true
		if !strings.Contains(entry.detail, "已并入保留行 2 条") || !strings.Contains(entry.detail, "身份重复跳过 1 条") {
			t.Fatalf("去重审计详情=%q, want 报告并入 2 条/身份重复跳过 1 条", entry.detail)
		}
	}
	if !entriesAudit {
		t.Fatal("缺少名单去重审计")
	}
}

// 条目形态无法解析（带外写入/历史脏值）时不得猜测修复，也不得静默丢行：
// 保留行条目原样保留，并留 WARN + 审计计数（人工核对依据）。
func TestMigrateSystemIPListUniqueIndex_reportsUnparseableEntries(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_ip_lists (id,name,description,category,entries,system) VALUES
		(1,'自动封禁名单','保留行','自动封禁','[{"value":"1.1.1.1","remark":""}]',1),
		(2,'自动封禁名单','脏行','自动封禁','not-json',1)`); err != nil {
		t.Fatalf("seed duplicates: %v", err)
	}
	drainSystemAuditBuffer()
	t.Cleanup(func() { drainSystemAuditBuffer() })

	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("unparseable entries must not fail startup: %v", err)
	}

	var survivorEntries string
	if err := database.QueryRow(`SELECT entries FROM security_ip_lists WHERE id=1`).Scan(&survivorEntries); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(survivorEntries, "1.1.1.1") || strings.Contains(survivorEntries, "not-json") {
		t.Fatalf("survivor entries=%q, want 原样保留可解析条目且不写入脏值", survivorEntries)
	}
	reported := false
	for _, entry := range drainSystemAuditBuffer() {
		if entry.resource == "IP 名单" && strings.Contains(entry.detail, "无法解析") {
			reported = true
		}
	}
	if !reported {
		t.Fatal("无法解析的条目行必须在审计里留痕（不得静默丢失）")
	}
}

// 历史非原子去重窗口的残留形态（引用指向已删 id、重复行已不存在）无法自动
// 修好：迁移只统计并告警，不改写引用（被引用行已删，无法推断用户意图）。
func TestMigrateSystemIPListUniqueIndex_reportsDanglingReferences(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	var validID int
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system) VALUES ('存活名单','','自定义','[]',0)`); err != nil {
		t.Fatalf("seed live list: %v", err)
	}
	if err := database.QueryRow(`SELECT id FROM security_ip_lists WHERE name='存活名单'`).Scan(&validID); err != nil {
		t.Fatal(err)
	}
	// 一行引用存活 id（不计悬空），一行引用不存在的 id=999，一行同时含两者（只计一次）。
	if _, err := database.Exec(`INSERT INTO security_policies (id, name, ip_acl_list_refs) VALUES
		(7, 'ok', ?),
		(8, 'dangling', '[999]'),
		(9, 'mixed', ?)`,
		"["+strconv.Itoa(validID)+"]", "["+strconv.Itoa(validID)+",999]"); err != nil {
		t.Fatalf("seed policy refs: %v", err)
	}

	before := systemIPListDanglingRefs.Load()
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := systemIPListDanglingRefs.Load() - before; got != 2 {
		t.Fatalf("悬空引用行数=%d, want 2（行 8 与行 9 各计一次）", got)
	}
	// 迁移不自动改引用：悬空 id 原样保留，供用户按告警自行修正。
	var mixedRefs string
	if err := database.QueryRow(`SELECT ip_acl_list_refs FROM security_policies WHERE id=9`).Scan(&mixedRefs); err != nil {
		t.Fatal(err)
	}
	if mixedRefs != "["+strconv.Itoa(validID)+",999]" {
		t.Fatalf("mixed refs=%q, want 原样保留（迁移不得自动摘除引用）", mixedRefs)
	}
}
