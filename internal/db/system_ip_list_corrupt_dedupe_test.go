package db

import (
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
