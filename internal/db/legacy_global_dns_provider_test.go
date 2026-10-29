package db

import "testing"

func TestRunMigrationsDropsLegacyGlobalDNSProvider(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	var hasColumn int
	if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='dns_provider'").Scan(&hasColumn); err != nil {
		t.Fatal(err)
	}
	if hasColumn == 0 {
		if _, err := database.Exec("ALTER TABLE global_config ADD COLUMN dns_provider VARCHAR(50) DEFAULT 'dnspod'"); err != nil {
			t.Fatalf("simulate legacy column: %v", err)
		}
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config,dns_provider) VALUES (1,'{}','legacy-provider')`); err != nil {
		t.Fatalf("seed legacy provider: %v", err)
	}
	if _, err := database.Exec(`CREATE TRIGGER cluster_version_global_config_update AFTER UPDATE OF dns_provider ON global_config WHEN 1 BEGIN SELECT 1; END`); err != nil {
		t.Fatalf("seed legacy trigger: %v", err)
	}

	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='dns_provider'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("global_config.dns_provider count=%d, want 0", count)
	}
	var id int
	if err := database.QueryRow("SELECT id FROM global_config WHERE id=1").Scan(&id); err != nil {
		t.Fatalf("config row must survive: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("second run: %v", err)
	}
}
