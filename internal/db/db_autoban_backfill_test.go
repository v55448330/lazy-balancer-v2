package db

// 自动封禁六列启动回填钉测——带外直写/畸形备份
// 导入的脏行（越界数值/枚举外文本/0-1 外布尔/NULL）在下次启动幂等收敛到
// 治理默认；用户已设有效值恒不触碰。镜像 TestInitialize_backfillsCertExpiryDays。

import (
	"testing"
)

func TestInitialize_backfillsAutobanColumns(t *testing.T) {
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
		{"threshold-zero", `UPDATE global_config SET autoban_threshold=0 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_threshold", 100)
		}},
		{"threshold-over-max", `UPDATE global_config SET autoban_threshold=10001 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_threshold", 100)
		}},
		{"threshold-valid-untouched", `UPDATE global_config SET autoban_threshold=42 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_threshold", 42)
		}},
		{"window-zero", `UPDATE global_config SET autoban_window_minutes=0 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_window_minutes", 5)
		}},
		{"window-over-max", `UPDATE global_config SET autoban_window_minutes=61 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_window_minutes", 5)
		}},
		{"window-valid-untouched", `UPDATE global_config SET autoban_window_minutes=13 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_window_minutes", 13)
		}},
		{"duration-bogus", `UPDATE global_config SET autoban_duration='bogus' WHERE id=1`, func(t *testing.T) {
			assertAutobanText(t, "autoban_duration", "1h")
		}},
		{"duration-valid-untouched", `UPDATE global_config SET autoban_duration='24h' WHERE id=1`, func(t *testing.T) {
			assertAutobanText(t, "autoban_duration", "24h")
		}},
		{"scope-bogus", `UPDATE global_config SET autoban_scope='bogus' WHERE id=1`, func(t *testing.T) {
			assertAutobanText(t, "autoban_scope", "all")
		}},
		{"scope-valid-untouched", `UPDATE global_config SET autoban_scope='blocked' WHERE id=1`, func(t *testing.T) {
			assertAutobanText(t, "autoban_scope", "blocked")
		}},
		{"enabled-out-of-bool-domain", `UPDATE global_config SET autoban_enabled=2 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_enabled", 0)
		}},
		{"enabled-negative", `UPDATE global_config SET autoban_enabled=-1 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_enabled", 0)
		}},
		{"enabled-valid-untouched", `UPDATE global_config SET autoban_enabled=1 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_enabled", 1)
		}},
		{"dry-run-out-of-bool-domain", `UPDATE global_config SET autoban_dry_run=2 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_dry_run", 1)
		}},
		{"dry-run-valid-untouched", `UPDATE global_config SET autoban_dry_run=0 WHERE id=1`, func(t *testing.T) {
			assertAutobanInt(t, "autoban_dry_run", 0)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DB.Exec(tc.seed); err != nil {
				t.Fatalf("seed: %v", err)
			}
			// 每轮重初始化前关闭上一轮主/metrics/audit 三个句柄；真实文件保留，
			// 既验证重启回填路径，也避免前序连接泄漏到后续 14 轮。
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

func assertAutobanInt(t *testing.T, column string, want int) {
	t.Helper()
	var got int
	if err := DB.QueryRow("SELECT COALESCE(" + column + ",-1) FROM global_config WHERE id=1").Scan(&got); err != nil {
		t.Fatalf("read %s: %v", column, err)
	}
	if got != want {
		t.Fatalf("%s=%d after backfill, want %d", column, got, want)
	}
}

func assertAutobanText(t *testing.T, column, want string) {
	t.Helper()
	var got string
	if err := DB.QueryRow("SELECT COALESCE(" + column + ",'') FROM global_config WHERE id=1").Scan(&got); err != nil {
		t.Fatalf("read %s: %v", column, err)
	}
	if got != want {
		t.Fatalf("%s=%q after backfill, want %q", column, got, want)
	}
}
