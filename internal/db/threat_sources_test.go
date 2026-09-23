package db

import (
	"testing"
)

// 威胁情报库（v2.3.x）：security_threat_sources 表 + 三源种子
// （ustc/firehol_l1/et_compromised），双开关默认开。
func TestThreatSourcesTable_seeded(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}

	rows, err := database.Query(`SELECT name, display_name, url, format, update_enabled, apply_enabled, update_status FROM security_threat_sources ORDER BY id`)
	if err != nil {
		t.Fatalf("query threat sources: %v", err)
	}
	defer rows.Close()
	type row struct {
		name, display, url, format, status string
		updateEnabled, applyEnabled        bool
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.name, &r.display, &r.url, &r.format, &r.updateEnabled, &r.applyEnabled, &r.status); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	if len(got) != 3 {
		t.Fatalf("seeded %d sources, want 3", len(got))
	}
	wantNames := []string{"ustc", "firehol_l1", "et_compromised"}
	wantURLs := []string{
		"https://blackip.ustc.edu.cn/list.php?txt",
		"https://iplists.firehol.org/files/firehol_level1.netset",
		"https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
	}
	for i, r := range got {
		if r.name != wantNames[i] || r.url != wantURLs[i] {
			t.Fatalf("source %d = %q %q, want %q %q", i, r.name, r.url, wantNames[i], wantURLs[i])
		}
		if !r.updateEnabled || !r.applyEnabled {
			t.Fatalf("source %q: 双开关默认开（update=%v apply=%v）", r.name, r.updateEnabled, r.applyEnabled)
		}
		if r.status != "idle" {
			t.Fatalf("source %q status=%q, want idle", r.name, r.status)
		}
	}

	// 幂等：二次 createTables（存量库重启路径）种子不重复
	if err := createTables(); err != nil {
		t.Fatalf("re-create tables: %v", err)
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_threat_sources`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("count=%d after re-seed, want 3", count)
	}
}
