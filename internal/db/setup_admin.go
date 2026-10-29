package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// SetupAdminFallbackUserID 是「初始化创建的首个用户」的历史恒等值：旧库/旧
// 备份不带 is_setup_admin 标记时，保护判定回落到该 id（标记缺失即缺省）。
const SetupAdminFallbackUserID = 1

// setupAdminExecer 抽象 *sql.DB 与 *sql.Tx：迁移、导入事务与快照应用都要在
// 各自的事务内完成同一套标记归一。
type setupAdminExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// setupAdmin 归一的三个谓词单源：探测 SQL 与三条 UPDATE 共用同一字面量，
// 任何一侧改判据都必须同步另一侧（漂移由 setupAdminPredicateParity 启动期
// 自检＋启动路径测试共同拦截；此前探测门是同一组条件的第二份手写，
// 只改 UPDATE 会让归一静默跳过——无任何错误信号）。
const (
	setupAdminLowestEnabledAdmin = `(SELECT id FROM users WHERE role='admin' AND is_enabled=1 ORDER BY id LIMIT 1)`
	// S1 陈旧标记：标记落在非「启用管理员」行（账号被降级/禁用后残留）。
	setupAdminStalePredicate = `COALESCE(is_setup_admin,0)=1 AND NOT (role='admin' AND is_enabled=1)`
	// S2 多标记并存：仅多标记时收敛到最低 id（单标记哪怕落在非最低 id 也是
	// 配置备份载荷里的显式事实，归一不得迁移。集群快照不在此列：其 canonical
	// 载荷下发前已清零标记，从端恒由下方 S3 重建）。
	setupAdminMultiPredicate = `COALESCE(is_setup_admin,0)=1 AND role='admin' AND is_enabled=1
	  AND id <> ` + setupAdminLowestEnabledAdmin + `
	  AND (SELECT COUNT(*) FROM users WHERE COALESCE(is_setup_admin,0)=1 AND role='admin' AND is_enabled=1) > 1`
	// S3 无标记补标：没有任何启用管理员带标记（旧库补列、旧备份/快照还原、
	// 表重建、标记行被带外改写）。
	setupAdminBackfillPredicate = `id=` + setupAdminLowestEnabledAdmin + `
	  AND NOT EXISTS (SELECT 1 FROM users WHERE COALESCE(is_setup_admin,0)=1 AND role='admin' AND is_enabled=1)`
)

// setupAdminColumnBackfill 是 newColumns 补列通道（users.is_setup_admin）的
// 首标回填语句：判据由 setupAdminBackfillPredicate 单源拼接，与运行期
// EnsureSetupAdminFlag 的 S3 补标逐字同源——setupAdminPredicateParity 启动期
// 自检看守，禁止再手写第二份判据（此前 db.go 侧的副本改判据即静默分叉）。
var setupAdminColumnBackfill = "UPDATE users SET is_setup_admin=1 WHERE " + setupAdminBackfillPredicate

// EnsureSetupAdminFlag 归一 break-glass 管理入口标记：
//   - 标记只允许落在「启用的管理员」行上，非管理员/禁用行的陈旧标记先清除；
//   - 多条启用管理员同时带标记（导入的配置备份或带外改库的形态）收敛为
//     单条：只有最低 id 的启用管理员保留标记，其余清零。**仅在多标记时生效**——
//     单标记（哪怕落在非最低 id）是配置备份载荷的显式事实，归一不得迁移；
//   - 若没有任何启用管理员带标记（旧库补列、旧备份/旧快照还原、表重建，
//     或标记行被带外改写），把最低 id 的启用管理员补标为入口。
//
// 幂等：稳态（恰有一个启用管理员带标记）零写入。空库或无启用管理员时零命中
// ——「至少一个启用管理员」由调用方各自的门负责（导入校验/启停保护）。
func EnsureSetupAdminFlag(ctx context.Context, ex setupAdminExecer) error {
	if _, err := ex.ExecContext(ctx, `UPDATE users SET is_setup_admin=0 WHERE `+setupAdminStalePredicate); err != nil {
		return err
	}
	// 仅在**多标记并存**时收敛（先清非最低 id 的启用管理员标记，再交给下方补标）
	// ——单标记不迁移：配置备份载荷显式把标记落在非最低 id 的管理员上时，该标记
	// 是备份里的显式事实，清零会违背「标记随载荷落库」的语义（随后补标又落到最低
	// id，等于篡改载荷）。集群快照不走这条：其 canonical 载荷在下发前已清零标记
	// （sanitizeUsersForHash），从端恒命中下方 S3 补标。
	// 多标记形态下两条相邻语句都不命中（补标分支要求「没有任何启用管理员带标记」），
	// 才会永久滞留、被 handlers 判为不可删/禁/降级。
	// 该 SQLite 子查询自引用 users 表在 UPDATE 中合法（同库既有迁移同款形态）。
	if _, err := ex.ExecContext(ctx, `UPDATE users SET is_setup_admin=0 WHERE `+setupAdminMultiPredicate); err != nil {
		return err
	}
	if _, err := ex.ExecContext(ctx, `UPDATE users SET is_setup_admin=1 WHERE `+setupAdminBackfillPredicate); err != nil {
		return err
	}
	return nil
}

// setupAdminFlagWriteProbeSQL 判定启动期标记归一是否可能改写任何行：三条 UPDATE
// 互为前置（前一条的结果影响后一条），无法逐条穷举，故一次只读探测取三条件
// 的并集——S1 陈旧标记（带标记但非启用管理员）、S2 多标记并存、S3 无标记需
// 补标。稳态（恰有一个启用管理员带标记）恒 false，收敛库启动零写。只读查询
// 不取写锁（_txlock=immediate 下写语句才是立即写事务）。
func setupAdminFlagWriteProbeSQL() string {
	return `SELECT EXISTS(SELECT 1 FROM users WHERE ` + setupAdminStalePredicate +
		` UNION ALL SELECT 1 FROM users WHERE ` + setupAdminMultiPredicate +
		` UNION ALL SELECT 1 FROM users WHERE ` + setupAdminBackfillPredicate + `)`
}

// setupAdminPredicateParity 启动期自检：探测 SQL 必须逐字包含三条归一谓词
// （与 execMigrationWriteIfNeeded 的「探测谓词必须出现在写语句 WHERE 段」自检
// 同范式）——登记漂移时响亮失败，而不是静默跳过归一。
func setupAdminPredicateParity() error {
	probe := setupAdminFlagWriteProbeSQL()
	for _, item := range []struct{ name, predicate string }{
		{"S1 陈旧标记", setupAdminStalePredicate},
		{"S2 多标记并存", setupAdminMultiPredicate},
		{"S3 无标记补标", setupAdminBackfillPredicate},
	} {
		if !strings.Contains(probe, item.predicate) {
			return fmt.Errorf("setup admin 探测门与归一漂移：探测 SQL 缺少%s谓词", item.name)
		}
	}
	// 补列回填判据同源：users.is_setup_admin 首标（newColumns 通道）必须逐字
	// 引用 S3 谓词——判据改判时不随动即在此响亮失败，而不是两处静默分叉。
	if !strings.Contains(setupAdminColumnBackfill, setupAdminBackfillPredicate) {
		return fmt.Errorf("setup admin 探测门与归一漂移：users.is_setup_admin 补列回填未逐字引用 S3 补标谓词")
	}
	return nil
}

// ensureSetupAdminFlagAtStartup 是启动迁移对 EnsureSetupAdminFlag 的入口：
// 先只读探测，命中才在一个写事务内完成三条归一（口径纳入
// startupMigrationWriteTx，二次启动收敛库零写）。
func ensureSetupAdminFlagAtStartup() error {
	if err := setupAdminPredicateParity(); err != nil {
		return err
	}
	var needed bool
	if err := DB.QueryRow(setupAdminFlagWriteProbeSQL()).Scan(&needed); err != nil {
		return err
	}
	if !needed {
		return nil
	}
	return withWriteTx("setup admin flag normalization", func(tx *sql.Tx) error {
		return EnsureSetupAdminFlag(context.Background(), tx)
	})
}

// IsSetupAdmin 判定用户是否为受保护的 break-glass 管理入口。
// 标记缺失（任何行都未标记——旧库尚未跑迁移/直连旧测试库）时回落到
// SetupAdminFallbackUserID，保持升级窗口内的保护面不塌陷。
func IsSetupAdmin(ctx context.Context, ex setupAdminExecer, userID int) (bool, error) {
	var flagged int
	err := ex.QueryRowContext(ctx, `SELECT COALESCE(is_setup_admin,0) FROM users WHERE id=?`, userID).Scan(&flagged)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if flagged == 1 {
		return true, nil
	}
	var marked int
	if err := ex.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE COALESCE(is_setup_admin,0)=1`).Scan(&marked); err != nil {
		return false, err
	}
	if marked == 0 {
		return userID == SetupAdminFallbackUserID, nil
	}
	return false, nil
}
