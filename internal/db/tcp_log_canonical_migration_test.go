package db

import "testing"

func TestMigrateTCPRuleDeadFields_normalizesNullLogEnabled(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id,caddy_config,cluster_version) VALUES (1,'{}',0)"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,compress_types,log_enabled)
		VALUES ('lb_tcp_null_log','tcp-null-log','tcp',19001,'',NULL),
		       ('lb_http_null_log','http-null-log','http',19002,'',NULL)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var tcpNull, httpNull int
	if err := database.QueryRow(`SELECT log_enabled IS NULL FROM lb_rules WHERE caddy_id='lb_tcp_null_log'`).Scan(&tcpNull); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT log_enabled IS NULL FROM lb_rules WHERE caddy_id='lb_http_null_log'`).Scan(&httpNull); err != nil {
		t.Fatal(err)
	}
	if tcpNull != 0 || httpNull != 1 {
		t.Fatalf("log_enabled NULL flags tcp=%d http=%d, want 0/1", tcpNull, httpNull)
	}
	var version int
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("cluster_version=%d, want 1 after canonicalization", version)
	}
	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("idempotent rerun: %v", err)
	}
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("cluster_version=%d after rerun, want 1", version)
	}
}
