package db

// 自动封禁第七列（escalation）与累犯表迁移钉：newColumns 补列通道承载
// autoban_escalation（NOT NULL DEFAULT 'off'，与六列同族）；autoban_recidivism
// 表启动幂等建表；带外脏枚举下次启动复位默认，合法值恒不触碰。

import (
	"testing"
)

func TestInitialize_freshSchemaCarriesAutobanEscalationAndRecidivism(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}

	var dflt *string
	if err := DB.QueryRow(`SELECT dflt_value FROM pragma_table_info('global_config') WHERE name='autoban_escalation'`).Scan(&dflt); err != nil {
		t.Fatalf("autoban_escalation 列缺失: %v", err)
	}
	if dflt == nil || *dflt != "'"+DefaultAutobanEscalation+"'" {
		t.Fatalf("autoban_escalation DDL DEFAULT=%v, want '%s'", dflt, DefaultAutobanEscalation)
	}
	var got string
	if err := DB.QueryRow(`SELECT autoban_escalation FROM global_config WHERE id=1`).Scan(&got); err != nil {
		t.Fatalf("read autoban_escalation: %v", err)
	}
	if got != DefaultAutobanEscalation {
		t.Fatalf("autoban_escalation=%q, want %q（默认 off 保持现行）", got, DefaultAutobanEscalation)
	}

	rows, err := DB.Query(`PRAGMA table_info(autoban_recidivism)`)
	if err != nil {
		t.Fatalf("pragma table_info: %v", err)
	}
	defer rows.Close()
	type col struct {
		name, typ string
		pk        int
	}
	var cols []col
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dfltValue *string
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan pragma row: %v", err)
		}
		cols = append(cols, col{name, typ, pk})
	}
	want := []col{
		{"identity", "TEXT", 1},
		{"offense_count", "INTEGER", 0},
		{"last_ban_at", "TEXT", 0},
		{"escalated_duration", "TEXT", 0},
	}
	if len(cols) != len(want) {
		t.Fatalf("autoban_recidivism 列=%+v, want %+v", cols, want)
	}
	for i, w := range want {
		if cols[i] != w {
			t.Fatalf("列 %d=%+v, want %+v", i, cols[i], w)
		}
	}
}

func TestInitialize_backfillsAutobanEscalation(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	for _, tc := range []struct {
		name  string
		write string
		want  string
	}{
		{"escalation-bogus", `UPDATE global_config SET autoban_escalation='bogus' WHERE id=1`, DefaultAutobanEscalation},
		{"escalation-empty", `UPDATE global_config SET autoban_escalation='' WHERE id=1`, DefaultAutobanEscalation},
		{"escalation-valid-standard", `UPDATE global_config SET autoban_escalation='standard' WHERE id=1`, "standard"},
		{"escalation-valid-aggressive", `UPDATE global_config SET autoban_escalation='aggressive' WHERE id=1`, "aggressive"},
		{"escalation-valid-off", `UPDATE global_config SET autoban_escalation='off' WHERE id=1`, "off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DB.Exec(tc.write); err != nil {
				t.Fatalf("seed dirty value: %v", err)
			}
			if err := runMigrations(); err != nil {
				t.Fatalf("rerun migrations: %v", err)
			}
			assertAutobanText(t, "autoban_escalation", tc.want)
		})
	}
}

// 存量库（无第七列/无累犯表）经迁移补齐；重复迁移幂等（已有行不被重置）。
func TestRunMigrations_addsEscalationAndRecidivismToLegacyDB(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if _, err := DB.Exec(`ALTER TABLE global_config DROP COLUMN autoban_escalation`); err != nil {
		t.Fatalf("drop escalation column: %v", err)
	}
	if _, err := DB.Exec(`DROP TABLE autoban_recidivism`); err != nil {
		t.Fatalf("drop recidivism table: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("migrate legacy shape: %v", err)
	}
	assertAutobanText(t, "autoban_escalation", DefaultAutobanEscalation)

	if _, err := DB.Exec(`INSERT INTO autoban_recidivism (identity, offense_count, last_ban_at, escalated_duration) VALUES ('45.33.32.1', 2, '2026-11-15 10:00:00', '24h')`); err != nil {
		t.Fatalf("seed recidivism row: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var count int
	var escalated string
	if err := DB.QueryRow(`SELECT offense_count, escalated_duration FROM autoban_recidivism WHERE identity='45.33.32.1'`).Scan(&count, &escalated); err != nil {
		t.Fatalf("recidivism row lost after re-migration: %v", err)
	}
	if count != 2 || escalated != "24h" {
		t.Fatalf("幂等迁移不得重置累犯行: (%d,%q)", count, escalated)
	}
	var n int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='autoban_escalation'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("escalation 列重复/缺失: n=%d err=%v", n, err)
	}
}

// NAT 两列退役钉（deadColumnDrops 通道，与 count_human_failed 同惯例）：
// 存量库携带 autoban_nat_detection/autoban_nat_fingerprint_threshold 时启动
// 迁移删列；fresh 库不再补列；重复迁移幂等。
func TestRunMigrations_dropsRetiredAutobanNatColumns(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	// fresh 库：两列不得存在（newColumns 已摘除登记）。
	for _, column := range []string{"autoban_nat_detection", "autoban_nat_fingerprint_threshold"} {
		var n int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name=?`, column).Scan(&n); err != nil || n != 0 {
			t.Fatalf("fresh 库不得携带退役列 %s: n=%d err=%v", column, n, err)
		}
	}
	// 存量形态：带外补回两列（旧版本库形态），启动迁移必须删除。
	if _, err := DB.Exec(`ALTER TABLE global_config ADD COLUMN autoban_nat_detection INTEGER NOT NULL DEFAULT 0`); err != nil {
		t.Fatalf("re-add nat_detection: %v", err)
	}
	if _, err := DB.Exec(`ALTER TABLE global_config ADD COLUMN autoban_nat_fingerprint_threshold INTEGER NOT NULL DEFAULT 3`); err != nil {
		t.Fatalf("re-add nat_fingerprint_threshold: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("migrate legacy nat shape: %v", err)
	}
	for _, column := range []string{"autoban_nat_detection", "autoban_nat_fingerprint_threshold"} {
		var n int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name=?`, column).Scan(&n); err != nil || n != 0 {
			t.Fatalf("退役列 %s 必须被启动迁移删除: n=%d err=%v", column, n, err)
		}
	}
	// 幂等：二次迁移不报错、不复活。
	if err := runMigrations(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	for _, column := range []string{"autoban_nat_detection", "autoban_nat_fingerprint_threshold"} {
		var n int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name=?`, column).Scan(&n); err != nil || n != 0 {
			t.Fatalf("二次迁移后退役列 %s 不得复活: n=%d err=%v", column, n, err)
		}
	}
}
