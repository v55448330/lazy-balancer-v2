package db

// 自动封禁 NAT 两列（nat_detection/nat_fingerprint_threshold）迁移钉：
// newColumns 补列通道承载（NOT NULL DEFAULT，与七列同族）；带外脏值
// （0-1 外布尔/边界外阈值/NULL）下次启动复位默认，合法值恒不触碰。

import (
	"testing"
)

func TestInitialize_freshSchemaCarriesAutobanNatColumns(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	for _, tc := range []struct {
		column string
		dflt   string
	}{
		{"autoban_nat_detection", "0"},
		{"autoban_nat_fingerprint_threshold", "3"},
	} {
		var dflt *string
		if err := DB.QueryRow(`SELECT dflt_value FROM pragma_table_info('global_config') WHERE name=?`, tc.column).Scan(&dflt); err != nil {
			t.Fatalf("%s 列缺失: %v", tc.column, err)
		}
		if dflt == nil || *dflt != tc.dflt {
			t.Fatalf("%s DDL DEFAULT=%v, want %s", tc.column, dflt, tc.dflt)
		}
	}
	assertAutobanInt(t, "autoban_nat_detection", DefaultAutobanNatDetection)
	assertAutobanInt(t, "autoban_nat_fingerprint_threshold", DefaultAutobanNatFingerprintThreshold)
}

func TestInitialize_backfillsAutobanNatColumns(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	for _, tc := range []struct {
		name  string
		seed  string
		check func(t *testing.T)
	}{
		{"nat-detection-bogus", `UPDATE global_config SET autoban_nat_detection=2 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_nat_detection", DefaultAutobanNatDetection)
		}},
		{"nat-detection-valid-on", `UPDATE global_config SET autoban_nat_detection=1 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_nat_detection", 1)
		}},
		{"nat-threshold-below-min", `UPDATE global_config SET autoban_nat_fingerprint_threshold=1 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_nat_fingerprint_threshold", DefaultAutobanNatFingerprintThreshold)
		}},
		{"nat-threshold-over-max", `UPDATE global_config SET autoban_nat_fingerprint_threshold=101 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_nat_fingerprint_threshold", DefaultAutobanNatFingerprintThreshold)
		}},
		{"nat-threshold-valid-untouched", `UPDATE global_config SET autoban_nat_fingerprint_threshold=5 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_nat_fingerprint_threshold", 5)
		}},
		{"nat-threshold-boundary-min", `UPDATE global_config SET autoban_nat_fingerprint_threshold=2 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_nat_fingerprint_threshold", 2)
		}},
		{"nat-threshold-boundary-max", `UPDATE global_config SET autoban_nat_fingerprint_threshold=100 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_nat_fingerprint_threshold", 100)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DB.Exec(tc.seed); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if err := Close(); err != nil {
				t.Fatalf("close before re-initialize: %v", err)
			}
			if err := Initialize(dir); err != nil {
				t.Fatalf("re-initialize database: %v", err)
			}
			tc.check(t)
		})
	}
}

// 补列通道自愈：丢列后重启必须补回（与 escalation 列同族）。
func TestInitialize_readdsDroppedAutobanNatColumns(t *testing.T) {
	dir := t.TempDir()
	preserveDatabaseHandles(t)
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if _, err := DB.Exec(`ALTER TABLE global_config DROP COLUMN autoban_nat_detection`); err != nil {
		t.Fatalf("drop nat_detection column: %v", err)
	}
	if _, err := DB.Exec(`ALTER TABLE global_config DROP COLUMN autoban_nat_fingerprint_threshold`); err != nil {
		t.Fatalf("drop nat_fingerprint_threshold column: %v", err)
	}
	if err := Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := Initialize(dir); err != nil {
		t.Fatalf("re-initialize: %v", err)
	}
	assertAutobanInt(t, "autoban_nat_detection", DefaultAutobanNatDetection)
	assertAutobanInt(t, "autoban_nat_fingerprint_threshold", DefaultAutobanNatFingerprintThreshold)
	for _, column := range []string{"autoban_nat_detection", "autoban_nat_fingerprint_threshold"} {
		var n int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name=?`, column).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s 列重复/缺失: n=%d err=%v", column, n, err)
		}
	}
}
