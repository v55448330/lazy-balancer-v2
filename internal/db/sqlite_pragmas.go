package db

import (
	"context"
	"database/sql"
	"fmt"
)

// applySQLiteRuntimePragmas 落 journal_mode=WAL 并在专用连接上只读回读验证全部运行期
// PRAGMA。glebarez/go-sqlite 的 applyQueryParams 仅识别 _pragma/_txlock/_time_format 三类
// DSN 参数——_journal_mode/_busy_timeout/_synchronous 写在 DSN 里会被静默忽略，
// 且驱动无条件 busy_timeout=5000（v2.2.0 生产事故：主库实际长期跑 delete+5s，
// 任一长写事务即全线 SQLITE_BUSY）。
//
// busy_timeout=30000 / synchronous=NORMAL 是连接级参数，生效通道只能是 DSN 的
// _pragma（驱动对每条新连接执行）；这里刻意不再 Exec 落地——在池上采样一条连接
// Exec 只会修复那一条，其余连接仍跑驱动默认值，而随后的回读又恰好命中被修复的
// 连接，守卫会把不存在的健康状态证明为通过（自遮蔽）。改为 db.Conn 签出一条
// 本函数从未触碰过的专用连接做只读回读：若驱动 _pragma 处理回退（274f3028 修复的
// 静默忽略同类回归），该连接会如实呈现 busy_timeout=5000/synchronous=2，守卫报错。
//
// journal_mode=WAL 是唯一的例外保留 apply：它是文件级参数，把旧的 delete 模式库文件
// 迁移到 WAL 后持久生效，且无法在连接间被遮蔽（迁移是对文件的，不是对连接的）。
// 注意 PRAGMA journal_mode=WAL 不能在事务内执行——本函数只在 open 后、任何事务
// 开始前调用（调用顺序：Ping → apply journal_mode → 专用连接只读回读）。
// foreign_keys 刻意不动：驱动默认 OFF 是既有行为，开启强制属于独立的行为变更。
func applySQLiteRuntimePragmas(db *sql.DB) error {
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return fmt.Errorf("apply pragma %q: %w", "journal_mode=WAL", err)
	}

	conn, err := db.Conn(context.Background())
	if err != nil {
		return fmt.Errorf("checkout dedicated conn for pragma verify: %w", err)
	}
	defer conn.Close()

	expected := []struct{ pragma, want string }{
		{"journal_mode", "wal"},
		{"busy_timeout", "30000"},
		{"synchronous", "1"}, // NORMAL=1
	}
	for _, e := range expected {
		var got string
		if err := conn.QueryRowContext(context.Background(), "PRAGMA "+e.pragma).Scan(&got); err != nil {
			return fmt.Errorf("verify pragma %q: %w", e.pragma, err)
		}
		if got != e.want {
			return fmt.Errorf("pragma %q = %q on fresh conn, want %q (DSN _pragma enforcement regressed?)", e.pragma, got, e.want)
		}
	}
	return nil
}
