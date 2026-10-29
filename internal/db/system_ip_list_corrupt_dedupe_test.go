package db

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateSystemIPListUniqueIndex_corruptEntriesPreserveWholeGroup(t *testing.T) {
	for _, tc := range []struct {
		name, survivorEntries, duplicateEntries string
	}{
		{name: "survivor corrupt", survivorEntries: "not-json", duplicateEntries: `[{"value":"203.0.113.10","remark":"auto ban"}]`},
		{name: "duplicate corrupt", survivorEntries: `[{"value":"203.0.113.10","remark":"auto ban"}]`, duplicateEntries: "not-json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := openMigrationTestDB(t)
			if err := createTables(); err != nil {
				t.Fatalf("create tables: %v", err)
			}
			if _, err := database.Exec(`INSERT INTO security_ip_lists (id,name,description,category,entries,system) VALUES
				(1,'自动封禁名单','保留行','自动封禁',?,1),
				(2,'自动封禁名单','重复行','自动封禁',?,1)`, tc.survivorEntries, tc.duplicateEntries); err != nil {
				t.Fatalf("seed duplicates: %v", err)
			}
			drainSystemAuditBuffer()
			t.Cleanup(func() { drainSystemAuditBuffer() })

			if err := migrateSystemIPListUniqueIndex(); err != nil {
				t.Fatalf("corrupt legacy entries must defer dedupe without failing startup: %v", err)
			}

			rows, err := database.Query(`SELECT id,entries FROM security_ip_lists WHERE name='自动封禁名单' ORDER BY id`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			got := map[int]string{}
			for rows.Next() {
				var id int
				var entries string
				if err := rows.Scan(&id, &entries); err != nil {
					t.Fatal(err)
				}
				got[id] = entries
			}
			if len(got) != 2 || got[1] != tc.survivorEntries || got[2] != tc.duplicateEntries {
				t.Fatalf("rows after deferred dedupe=%v, want both original rows unchanged", got)
			}
			var indexes int
			if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='u_security_ip_lists_system_name'`).Scan(&indexes); err != nil {
				t.Fatal(err)
			}
			if indexes != 0 {
				t.Fatal("unique index must be deferred while duplicate rows are intentionally preserved")
			}
			foundAudit := false
			for _, entry := range drainSystemAuditBuffer() {
				if entry.resource == "IP 名单" && strings.Contains(entry.detail, "无法解析") && strings.Contains(entry.detail, "保留") {
					foundAudit = true
				}
			}
			if !foundAudit {
				t.Fatal("deferred dedupe must leave an actionable audit entry")
			}
		})
	}
}

// 去重延期是只能人工处置的僵持态：同一条「延期 + 无法解析行 id」详情的全生命
// 周期只落一条系统审计（落库时 audit_log 已有逐字相同行即跳过）；脏行集合变化
// （新行 id=新指纹）才重报。该状态每次启动都会重新进入延期分支，不设一次性
// 判据时逐字相同的审计随重启线性增长，冲淡真实信号。
func TestMigrateSystemIPListUniqueIndex_deferredAuditWrittenOnce(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// 审计库就位：flush 落点（生产启动序=迁移先缓冲、InitializeAuditDB 末尾落库）
	auditDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open audit database: %v", err)
	}
	t.Cleanup(func() { _ = auditDB.Close() })
	if _, err := auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(100),
		action VARCHAR(50) NOT NULL,
		resource VARCHAR(100),
		detail TEXT,
		ip_address VARCHAR(45),
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create audit_log table: %v", err)
	}
	oldAuditDB := AuditDB
	AuditDB = auditDB
	t.Cleanup(func() { AuditDB = oldAuditDB })

	countIPListAudits := func(t *testing.T) int {
		t.Helper()
		var count int
		if err := auditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE username='system' AND action='启动迁移' AND resource='IP 名单'`).Scan(&count); err != nil {
			t.Fatalf("count system audits: %v", err)
		}
		return count
	}
	seedCorruptPair := func(t *testing.T, badID int) {
		t.Helper()
		goodID := badID - 1
		if _, err := database.Exec(`INSERT INTO security_ip_lists (id,name,description,category,entries,system) VALUES
			(?,'自动封禁名单','保留行','自动封禁','[]',1),
			(?,'自动封禁名单','重复行','自动封禁','not-json',1)`, goodID, badID); err != nil {
			t.Fatalf("seed corrupt duplicate pair (%d,%d): %v", goodID, badID, err)
		}
	}

	// 首次启动：延期详情落一条。
	seedCorruptPair(t, 2)
	drainSystemAuditBuffer()
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	flushSystemAuditLogs()
	if got := countIPListAudits(t); got != 1 {
		t.Fatalf("首次启动系统审计=%d 条, want 1", got)
	}

	// 第二次启动（同一僵持态）：不新增——同详情只留一条。
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	flushSystemAuditLogs()
	if got := countIPListAudits(t); got != 1 {
		t.Fatalf("二次启动后系统审计=%d 条, want 1（同一僵持态不重复留痕）", got)
	}

	// 人工修好（删除重复组）后重启：正常收敛，零新增。
	if _, err := database.Exec(`DELETE FROM security_ip_lists WHERE name='自动封禁名单'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("migrate after manual fix: %v", err)
	}
	flushSystemAuditLogs()
	if got := countIPListAudits(t); got != 1 {
		t.Fatalf("修好后系统审计=%d 条, want 1（收敛态零新增）", got)
	}

	// 带外重造新脏行（新行 id=新指纹）：重报一条。
	if _, err := database.Exec(`DROP INDEX IF EXISTS u_security_ip_lists_system_name`); err != nil {
		t.Fatal(err)
	}
	seedCorruptPair(t, 4)
	drainSystemAuditBuffer()
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("migrate with new dirty rows: %v", err)
	}
	flushSystemAuditLogs()
	if got := countIPListAudits(t); got != 2 {
		t.Fatalf("新脏行后系统审计=%d 条, want 2（指纹变化必须重报）", got)
	}
}
