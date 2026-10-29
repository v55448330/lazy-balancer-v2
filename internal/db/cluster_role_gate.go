package db

import (
	"context"
	"database/sql"
	"fmt"
)

// 节点角色判定（主节点 / 从节点）的 SQL 单源。
//
// global_config.is_master 的历史 NULL 行一律视为主节点（COALESCE(is_master,1)）：
// middleware 写闸（readonly.go）、cluster_version 触发器 WHEN 子句与后台
// flusher 都按此口径判定，三者分裂的表征是「写闸放行但触发器不 bump 版本」
// 或「主节点仍被允许写从端专有列」。迁移已回填存量 NULL，COALESCE 为纵深
// 防御。
//
// 使用的不是「读一次角色再写」而是把条件编进语句：handler 的 requireMaster
// 与写之间没有共享锁，BecomeSlave 可在窗口内提交 is_master=0，带条件的写
// 语句在降级后恒 0 行，消除该 TOCTOU 类别。
const (
	// globalConfigIsMasterValueSQL 是角色列的单源取值表达式。
	globalConfigIsMasterValueSQL = "COALESCE(is_master,1)"

	// MasterRoleConditionSQL 是「当前库为主节点」的 SQL 条件（节点簿记表的
	// 写语句必须带上，避免降级后仍审批/上报/改访问地址）。
	MasterRoleConditionSQL = "(SELECT " + globalConfigIsMasterValueSQL + " FROM global_config WHERE id=1)=1"

	// SlaveRoleConditionSQL 是 MasterRoleConditionSQL 的逆谓词：从端专有状态
	// （同步错误、补偿标记、节点站点坐标）只能在从节点语境落库——升主会清空
	// 这些列，在途的从端写若不带该条件会在升主提交后被写回。
	SlaveRoleConditionSQL = "(SELECT " + globalConfigIsMasterValueSQL + " FROM global_config WHERE id=1)=0"

	// roleOfQuery 是角色读取的单源 SELECT。
	roleOfQuery = "SELECT " + globalConfigIsMasterValueSQL + " FROM global_config WHERE id=1"
)

// RoleQuerier 是 *sql.DB 与 *sql.Tx 的公共读句柄面。事务内的降级复核必须
// 读同一事务视图（读事务外的 *sql.DB 会看到降级前/后的另一个快照），所以
// 角色读取不能只接受 *sql.DB。
type RoleQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// IsMasterNode 读取当前节点角色（主节点=true）。
//
// 读失败语义由调用方决定（fail-open / 500 / 跳过本轮），本函数只做单源读取，
// 不做策略；错误已带「读取节点模式」上下文，调用方按需再包一层业务语义。
func IsMasterNode(ctx context.Context, querier RoleQuerier) (bool, error) {
	var isMaster bool
	if err := querier.QueryRowContext(ctx, roleOfQuery).Scan(&isMaster); err != nil {
		return false, fmt.Errorf("读取节点模式: %w", err)
	}
	return isMaster, nil
}
