package db

import (
	"testing"
)

func TestCreateTables_creates_geoip_columns_with_defaults(t *testing.T) {
	// Given a fresh database
	database := openMigrationTestDB(t)

	// When the tables are created
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}

	// Then security_policies carries the GeoIP columns with their defaults
	var countries, mode string
	if err := database.QueryRow(`SELECT dflt_value FROM pragma_table_info('security_policies') WHERE name='geoip_countries'`).Scan(&countries); err != nil {
		t.Fatalf("read security_policies.geoip_countries schema: %v", err)
	}
	if err := database.QueryRow(`SELECT dflt_value FROM pragma_table_info('security_policies') WHERE name='geoip_mode'`).Scan(&mode); err != nil {
		t.Fatalf("read security_policies.geoip_mode schema: %v", err)
	}
	if countries != "'[]'" {
		t.Fatalf("geoip_countries default=%q, want '[]'", countries)
	}
	if mode != "'deny'" {
		t.Fatalf("geoip_mode default=%q, want 'deny'", mode)
	}
}

func TestRunMigrations_adds_geoip_columns_to_existing_database(t *testing.T) {
	// Given a database upgraded from a schema that predates GeoIP columns
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		ALTER TABLE security_policies DROP COLUMN geoip_countries;
		ALTER TABLE security_policies DROP COLUMN geoip_mode`); err != nil {
		t.Fatalf("simulate legacy security_policies schema: %v", err)
	}

	// When migrations run
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then the GeoIP columns are restored with their defaults
	var countries, mode string
	if err := database.QueryRow(`SELECT dflt_value FROM pragma_table_info('security_policies') WHERE name='geoip_countries'`).Scan(&countries); err != nil {
		t.Fatalf("read migrated geoip_countries: %v", err)
	}
	if err := database.QueryRow(`SELECT dflt_value FROM pragma_table_info('security_policies') WHERE name='geoip_mode'`).Scan(&mode); err != nil {
		t.Fatalf("read migrated geoip_mode: %v", err)
	}
	if countries != "'[]'" || mode != "'deny'" {
		t.Fatalf("migrated geoip defaults=(%q,%q), want ('[]','deny')", countries, mode)
	}
}

func TestCreateTables_creates_ip2region_version_table_and_seed(t *testing.T) {
	// Given a fresh database
	database := openMigrationTestDB(t)

	// When the tables are created
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}

	// Then the ip2region version table mirrors security_crs_version and is seeded
	var columnCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('security_ip2region_version') WHERE name IN
		('id','version','updated_at','auto_update','update_status','message','last_checked','next_update','trigger','started_at','finished_at')`).Scan(&columnCount); err != nil {
		t.Fatalf("read security_ip2region_version schema: %v", err)
	}
	if columnCount != 11 {
		t.Fatalf("security_ip2region_version columns=%d, want 11", columnCount)
	}
	var version string
	var autoUpdate int
	if err := database.QueryRow("SELECT version, auto_update FROM security_ip2region_version WHERE id=1").Scan(&version, &autoUpdate); err != nil {
		t.Fatalf("read seeded ip2region version row: %v", err)
	}
	// R72 二十六次 D2（裁决）：IP 库自动更新默认 ON（与 CRS 种子/schema 对齐）。
	if version != "unknown" || autoUpdate != 1 {
		t.Fatalf("seeded ip2region version=(%q,%d), want (unknown,1)", version, autoUpdate)
	}
	// The seed is idempotent across restarts
	if err := createTables(); err != nil {
		t.Fatalf("repeat create tables: %v", err)
	}
	var rowCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM security_ip2region_version").Scan(&rowCount); err != nil {
		t.Fatalf("count ip2region version rows: %v", err)
	}
	if rowCount != 1 {
		t.Fatalf("ip2region version rows=%d, want 1", rowCount)
	}
}

func TestRunMigrations_adds_ip2region_version_columns_to_existing_table(t *testing.T) {
	// Given a database whose ip2region version table predates the status columns
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// Rebuild the table without the migration-only columns, keeping the seed row.
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}');
		DROP TABLE security_ip2region_version;
		CREATE TABLE security_ip2region_version (
			id INTEGER PRIMARY KEY,
			version TEXT NOT NULL,
			updated_at DATETIME DEFAULT (datetime('now')),
			auto_update BOOLEAN DEFAULT TRUE
		);
		INSERT OR IGNORE INTO security_ip2region_version (id, version, auto_update) VALUES (1, 'unknown', 0);`); err != nil {
		t.Fatalf("simulate legacy ip2region version table: %v", err)
	}

	// When migrations run
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then the status columns are added
	var columnCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('security_ip2region_version') WHERE name IN
		('update_status','message','last_checked','next_update','trigger','started_at','finished_at')`).Scan(&columnCount); err != nil {
		t.Fatalf("read migrated ip2region version columns: %v", err)
	}
	if columnCount != 7 {
		t.Fatalf("migrated ip2region version columns=%d, want 7", columnCount)
	}
}
