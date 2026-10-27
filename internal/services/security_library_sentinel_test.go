package services

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 导入哨兵行崩溃窗口自愈：导入事务提交后、提交后 CAS 清理前进程被杀，
// 哨兵行会永久残留（版本页显示哨兵串，auto_update=0 让该库自动更新永久停摆）。
// 启动/重装首槽必须把哨兵行改写为内置真实种子并恢复自动更新。

func TestArmSecurityLibraryFirstSlots_healsImportSentinelRow(t *testing.T) {
	setupIsolatedDB(t)

	cases := []struct{ table, seed string }{
		{"security_crs_version", CRSBundledVersion},
		{"security_ip2region_version", "unknown"},
	}
	for _, tc := range cases {
		if _, err := db.DB.Exec(`DELETE FROM ` + tc.table); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.Exec(`INSERT INTO `+tc.table+` (id, version, auto_update) VALUES (1, ?, 0)`, SecurityVersionImportSentinel); err != nil {
			t.Fatalf("seed sentinel row: %v", err)
		}
	}

	healSecurityVersionImportSentinels()
	armSecurityLibraryFirstSlots()

	for _, tc := range cases {
		var version string
		var autoUpdate int
		var nextUpdate string
		if err := db.DB.QueryRow(`SELECT COALESCE(version,''), COALESCE(auto_update,0), COALESCE(next_update,'') FROM `+tc.table+` WHERE id=1`).Scan(&version, &autoUpdate, &nextUpdate); err != nil {
			t.Fatal(err)
		}
		if version == SecurityVersionImportSentinel {
			t.Errorf("%s 残留哨兵版本串（会被版本页展示）", tc.table)
		}
		if version != tc.seed {
			t.Errorf("%s version=%q, want 内置种子 %q", tc.table, version, tc.seed)
		}
		if autoUpdate != 1 {
			t.Errorf("%s auto_update=%d, want 1（哨兵行会让自动更新永久停摆）", tc.table, autoUpdate)
		}
		if nextUpdate == "" {
			t.Errorf("%s 未武装首槽（自动更新仍不会启动）", tc.table)
		}
	}
}

func TestArmSecurityLibraryFirstSlots_leavesHealthyVersionRowUntouched(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	// 用户已有真实版本且关闭自动更新：自愈/武装路径不得改写版本行。
	if _, err := db.DB.Exec(`INSERT INTO security_crs_version (id, version, auto_update) VALUES (1, '9.9.9', 0)`); err != nil {
		t.Fatal(err)
	}
	armSecurityLibraryFirstSlots()
	var version string
	var autoUpdate int
	if err := db.DB.QueryRow(`SELECT version, COALESCE(auto_update,0) FROM security_crs_version WHERE id=1`).Scan(&version, &autoUpdate); err != nil {
		t.Fatal(err)
	}
	if version != "9.9.9" || autoUpdate != 0 {
		t.Fatalf("非哨兵行被改写：version=%q auto_update=%d", version, autoUpdate)
	}
}
