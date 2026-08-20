package services

import (
	"context"
	"log"

	"lazy-balancer-v2/internal/db"
)

// legacySecurityEnumBackfills 把 R50 之前落库的枚举空串行归一到 Create 侧
// 默认值（R52 发现1）：空串行在发射端零产出规则而 UI 宣称控制已启用，且
// Update 对空串 400 拒绝导致无法手动修复，集群快照又原样镜像到从节点。
var legacySecurityEnumBackfills = []string{
	"UPDATE security_policies SET ip_acl_mode='deny' WHERE COALESCE(TRIM(ip_acl_mode),'')=''",
	"UPDATE security_policies SET mode='off' WHERE COALESCE(TRIM(mode),'')=''",
	"UPDATE security_policies SET geoip_mode='deny' WHERE COALESCE(TRIM(geoip_mode),'')=''",
}

// NormalizeLegacySecurityPolicyEnums 启动时一次性归一 security_policies 的
// 遗留枚举空串行。主节点：实际变更 >0 时在同一事务内递增集群版本，从节点随
// 下次同步收敛。从节点按 sync_security 分流（R54-N1）：
//   - sync_security=1：完全跳过（R53-A-3）——主节点快照权威下发；若主节点为
//     无归一修复的旧版本，本地归一会与旧主快照互相覆盖（归一翻转 ACL 发射
//     行为 → 首次 Pull 漂移全量重拉 → 快照恢复遗留空串行），每重启一次行为
//     翻转一次；保留遗留空串行是旧主集群下的一致状态。
//   - sync_security=0：security 段被门控、没有快照流，本地归一是遗留空串行
//     唯一修复路径（Update 400 拒修、发射端零规则），执行归一但不 bump
//     集群版本（从节点无版本权威，bump 会与主节点版本流冲突）。
func NormalizeLegacySecurityPolicyEnums(ctx context.Context) {
	var isMaster, syncSecurity bool
	if err := db.DB.QueryRowContext(ctx, "SELECT COALESCE(is_master,0), COALESCE(sync_security,1) FROM global_config WHERE id=1").Scan(&isMaster, &syncSecurity); err != nil {
		log.Printf("security enum normalize: failed to read cluster role, skipping: %v", err)
		return
	}
	if !isMaster && syncSecurity {
		return
	}
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("security enum normalize: failed to begin transaction: %v", err)
		return
	}
	defer tx.Rollback()
	var changed int64
	for _, stmt := range legacySecurityEnumBackfills {
		res, err := tx.ExecContext(ctx, stmt)
		if err != nil {
			log.Printf("security enum normalize: backfill failed: %v", err)
			return
		}
		n, err := res.RowsAffected()
		if err != nil {
			log.Printf("security enum normalize: failed to read affected rows: %v", err)
			return
		}
		changed += n
	}
	if changed == 0 {
		return
	}
	if isMaster {
		if err := BumpClusterVersion(ctx, tx); err != nil {
			log.Printf("security enum normalize: failed to bump cluster version: %v", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		log.Printf("security enum normalize: failed to commit: %v", err)
		return
	}
	if isMaster {
		log.Printf("security enum normalize: normalized %d legacy empty-enum rows, cluster version bumped", changed)
	} else {
		log.Printf("security enum normalize: normalized %d legacy empty-enum rows (slave, sync_security off, no version authority)", changed)
	}
}
