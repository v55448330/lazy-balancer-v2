package db

import (
	"database/sql"
	"fmt"
)

// applySQLiteRuntimePragmas 在 open 后显式落运行期 PRAGMA 并回读验证。
// glebarez/go-sqlite 的 applyQueryParams 仅识别 _pragma/_txlock/_time_format 三类
// DSN 参数——_journal_mode/_busy_timeout/_synchronous 写在 DSN 里会被静默忽略，
// 且驱动无条件 busy_timeout=5000；因此这些参数必须在这里落地（v2.2.0 生产事故：
// 主库实际长期跑 delete+5s，任一长写事务即全线 SQLITE_BUSY）。
// foreign_keys 刻意不动：驱动默认 OFF 是既有行为，开启强制属于独立的行为变更。
func applySQLiteRuntimePragmas(db *sql.DB) error {
	pragmas := []struct{ apply, verify, want string }{
		{"journal_mode=WAL", "journal_mode", "wal"},
		{"busy_timeout=30000", "busy_timeout", "30000"},
		{"synchronous=NORMAL", "synchronous", "1"},
	}
	for _, p := range pragmas {
		if _, err := db.Exec("PRAGMA " + p.apply); err != nil {
			return fmt.Errorf("apply pragma %q: %w", p.apply, err)
		}
		var got string
		if err := db.QueryRow("PRAGMA " + p.verify).Scan(&got); err != nil {
			return fmt.Errorf("verify pragma %q: %w", p.verify, err)
		}
		if got != p.want {
			return fmt.Errorf("pragma %q took effect as %q, want %q", p.apply, got, p.want)
		}
	}
	return nil
}
