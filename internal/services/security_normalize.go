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
// 遗留枚举空串行。仅主节点执行：实际变更 >0 时在同一事务内递增集群版本，
// 从节点随下次同步收敛。从节点完全跳过（R53-A-3）——其职责是镜像主节点快照；
// 若主节点为无归一修复的旧版本，从节点本地归一会与旧主快照互相覆盖（归一
// 翻转 ACL 发射行为 → 首次 Pull 漂移全量重拉 → 快照恢复遗留空串行），每重启
// 一次行为翻转一次；保留遗留空串行是旧主集群下的一致状态。
func NormalizeLegacySecurityPolicyEnums(ctx context.Context) {
	var isMaster bool
	if err := db.DB.QueryRowContext(ctx, "SELECT COALESCE(is_master,0) FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
		log.Printf("security enum normalize: failed to read cluster role, skipping: %v", err)
		return
	}
	if !isMaster {
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
	if err := BumpClusterVersion(ctx, tx); err != nil {
		log.Printf("security enum normalize: failed to bump cluster version: %v", err)
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("security enum normalize: failed to commit: %v", err)
		return
	}
	log.Printf("security enum normalize: normalized %d legacy empty-enum rows, cluster version bumped", changed)
}
