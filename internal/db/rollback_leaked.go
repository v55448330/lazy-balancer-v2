package db

// 提交失败后的连接池补发 ROLLBACK（跨包单源）。
//
// 机制：database/sql 在 Commit 失败后把 Tx 标记 done 且不再调用
// driver.Rollback（releaseConn 直接归还连接）。SQLite 的 deferred 约束/IO
// 类失败会让底层事务保持活动——泄漏连接归还池后仍持写锁，后续写事务
// busy_timeout 全线失败，复用该连接的读看到未提交数据。defer tx.Rollback
// 只回 ErrTxDone 不触达 driver，必须池级补发。
//
// 覆盖语义：逐个签出池内连接（至多 poolSize 条）并各自执行 ROLLBACK——
// 不能依赖池级 Exec 的 LIFO 重试：泄漏连接非栈顶时（并发读把其它空闲
// 连接压到其上），重试全部命中同一条无事务的栈顶连接，写锁持续滞留。
// 签出把连接从空闲列表摘走，逐条遍历必然覆盖泄漏连接；无活动事务的连接
// 报 "no transaction is active"，忽略即可。泄漏事务持写锁期间其它连接
// 不可能有写事务，重复 ROLLBACK 不会误伤。
//
// 调用契约：仅在 Commit 返回错误后调用（错误恢复语境无请求 ctx 可言，
// 自带 500ms 饱和探测预算）；ReadOnly 事务无需调用（无写锁）。poolSize 传该库
// applySQLitePool 的 maxOpen（主库 10/metrics 5/audit 5）。

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"time"
)

// RollbackLeakedTx 在指定连接池上补发 ROLLBACK 回收泄漏写事务（见包注释
// 机制与覆盖语义）。database 为 nil 时 no-op。
func RollbackLeakedTx(database *sql.DB, poolSize int) {
	if database == nil || poolSize <= 0 {
		return
	}
	// 饱和探测预算：签出空闲连接零阻塞（不受 ctx 影响）；仅池满（在用连
	// 接占满）时 Conn(ctx) 才等待——等待在用连接无意义（其上不可能有泄漏
	// 事务），预算内拿不到即放弃（下方 break），不为调用方叠加长阻塞。
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var held []*sql.Conn
	defer func() {
		for _, conn := range held {
			_ = conn.Close()
		}
	}()
	for range poolSize {
		conn, err := database.Conn(ctx)
		if err != nil {
			// 池饱和（500ms 预算内拿不到空闲连接）：在用连接正被其它请求
			// 持有——持写锁的泄漏事务不可能在用（其 Tx 已 done 归还），
			// 剩余空闲连接已遍历完。
			break
		}
		held = append(held, conn)
		if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil &&
			!strings.Contains(err.Error(), "no transaction is active") {
			log.Printf("WARN: 提交失败后补发 ROLLBACK 失败（第 %d 条连接）: %v", len(held), err)
		}
	}
}

// 三库池尺寸单源（applySQLitePool 调用点同源常量；RollbackLeakedTx 遍历
// 上界与池 maxOpen 一致——池尺寸变更时两处同步，由 pool_size 钉测对账）。
const (
	MainPoolMaxOpen    = 10
	MetricsPoolMaxOpen = 5
	AuditPoolMaxOpen   = 5
)
