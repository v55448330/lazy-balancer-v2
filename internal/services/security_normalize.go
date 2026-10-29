package services

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"lazy-balancer-v2/internal/db"
)

// security_policies 枚举列合法值集合（单一出处）：写侧白名单（handlers
// validateSecurityPolicyEnums，跨包 400 语义）、归一回填语句、脏行谓词、渲染
// 守卫（security.go 经 securityEnumValid）与 ValidBlockStatusCode 全部查同一
// 集合，新增枚举值只改这里。此前四处字面量并列，漏改回填会每次启动把用户新
// 启用的值静默归一关闭。一致性由 security_enum_sets_test.go 钉死。
var (
	securityModes            = []string{"off", "custom_only", "detection", "blocking"}
	securityIPACLModes       = []string{"allow", "deny", "绕过"}
	securityGeoIPModes       = []string{"off", "allow", "deny"}
	securityBlockStatusCodes = []int{0, 400, 401, db.DefaultBlockStatusCode, 404, 503}
)

// securityEnumSQLList 把字符串枚举集合渲染成 SQL IN 片段（'a','b'）。
func securityEnumSQLList(set []string) string {
	quoted := make([]string, len(set))
	for i, v := range set {
		quoted[i] = "'" + v + "'"
	}
	return strings.Join(quoted, ",")
}

// securityBlockStatusCodeSQLList 把拦截状态码集合渲染成 SQL IN 片段（0,400,…）。
func securityBlockStatusCodeSQLList() string {
	nums := make([]string, len(securityBlockStatusCodes))
	for i, v := range securityBlockStatusCodes {
		nums[i] = strconv.Itoa(v)
	}
	return strings.Join(nums, ",")
}

// securityEnumValid 报告 v 是否属于枚举集合（渲染守卫与归一消费端共用同一判定）。
func securityEnumValid(set []string, v string) bool {
	for _, allowed := range set {
		if v == allowed {
			return true
		}
	}
	return false
}

// legacySecurityEnumBackfills 把之前落库的枚举空串行归一到 Create 侧
// 默认值：空串行在发射端零产出规则而 UI 宣称控制已启用，且
// Update 对空串 400 拒绝导致无法手动修复，集群快照又原样镜像到从节点。
var legacySecurityEnumBackfills = []string{
	// 口径从「空串」扩为「枚举外全集」（对齐 block_status_code 的既有做法）：
	// 非空非法枚举（带外直写/跨版本快照，如 mode='BLOCKING'、ip_acl_mode=
	// 'DENY'）在渲染端同样零产出规则/落入错误分支而 UI 宣称启用，与空串
	// 同型；Update 400 拒修、集群快照原样镜像，启动归一是唯一自愈路径。
	// 归一目标值沿用空串先例（deny/off/deny=Create 侧默认值族）。
	// 首尾空白脏值（带外直写/旧快照）先写回 trim 值，再由下方枚举外语句
	// 处理 trim 后仍非法的值：下方谓词用 TRIM 判定白名单，命中即跳过——
	// 而渲染/事件归属按原始值精确比较，带空白值零发射且 UI 下拉无法匹配，
	// 归一口径必须自洽（否则 ' blocking ' 永不自愈）。
	"UPDATE security_policies SET ip_acl_mode=TRIM(ip_acl_mode) WHERE ip_acl_mode IS NOT NULL AND ip_acl_mode<>TRIM(ip_acl_mode)",
	"UPDATE security_policies SET mode=TRIM(mode) WHERE mode IS NOT NULL AND mode<>TRIM(mode)",
	"UPDATE security_policies SET geoip_mode=TRIM(geoip_mode) WHERE geoip_mode IS NOT NULL AND geoip_mode<>TRIM(geoip_mode)",
	fmt.Sprintf("UPDATE security_policies SET ip_acl_mode='deny' WHERE COALESCE(TRIM(ip_acl_mode),'') NOT IN (%s)", securityEnumSQLList(securityIPACLModes)),
	fmt.Sprintf("UPDATE security_policies SET mode='off' WHERE COALESCE(TRIM(mode),'') NOT IN (%s)", securityEnumSQLList(securityModes)),
	fmt.Sprintf("UPDATE security_policies SET geoip_mode='deny' WHERE COALESCE(TRIM(geoip_mode),'') NOT IN (%s)", securityEnumSQLList(securityGeoIPModes)),
	// 之前落库的 threshold=0 行——UI 显示 0、发射端 >0 判断
	// 跳过阈值 SecAction 而 CRS 回落默认 5（「UI 宣称 0、实际 5」的展示/行为
	// 漂移，与空串枚举行同型）。归一到 Create 侧 max1(x,5) 的默认值 5。
	// 库值唯一真相（批 3）：口径从 `=0` 扩为 `<=0`——写侧 max1/枚举白名单恒
	// 产生正值，负值只能是带外直写；NULL 由 COALESCE(...,0) 归并同分支。
	// 渲染侧对回填后仍无效的值 fail-visible（BuildCorazaDirectives）。
	// 字面量 5 改绑定 db.DefaultAnomalyThreshold 单源。
	fmt.Sprintf("UPDATE security_policies SET anomaly_threshold=%d WHERE COALESCE(anomaly_threshold,0)<=0", db.DefaultAnomalyThreshold),
	// 429 已剔除出拦截状态码白名单（限流专用语义，
	// overviewmetrics.go 限流卡片按 code=429 计数，WAF 拦截页 429 会混入
	// 限流指标口径）——存量 429 行归一为默认拦截状态码 403。
	// security_block_pages 无 status_code 列（建表见 db.go 的
	// security_block_pages CREATE TABLE；遗留列由 runMigrations 的
	// dropColumnIfExists 清单清除），429 仅可能存于 security_policies。
	// 库值唯一真相（批 3）：从 `=429` 扩为枚举外全集（写侧白名单 0/400/401/
	// 403/404/503，0=未设置跟随默认 403 为类型②省略型合法值）——旧备份/带外
	// 脏值（如 418）随启动归一，渲染层不再消费枚举外状态码。
	fmt.Sprintf("UPDATE security_policies SET block_status_code=%d WHERE block_status_code IS NOT NULL AND block_status_code NOT IN (%s)", db.DefaultBlockStatusCode, securityBlockStatusCodeSQLList()),
	// rate_limit_rps 历史脏行（enabled=1 &
	// rps<1，修复前 Update 缺陷可落库）绑定启用规则时整份配置生成失败
	// （渲染层 fail-visible）。启动归一关停业务开关——rps 库值保持原样
	//（不造假默认值），INFO 摘要行披露归一计数；写侧 validateRateLimitShape
	// 现行校验 rps>=1，本条仅兜历史形态。
	"UPDATE security_policies SET rate_limit_enabled=0 WHERE rate_limit_enabled=1 AND COALESCE(rate_limit_rps,0)<1",
}

// ValidBlockStatusCode 报告 v 是否为拦截状态码合法值：写侧
// validateSecurityPolicyEnums 白名单（400/401/403/404/503）+ 0=未设置跟随
// 默认 403（类型②省略型合法值，批 3 Ruling）。导入门（handlers）与集群
// apply 门共用本谓词；合法值集合单一出处=securityBlockStatusCodes。
func ValidBlockStatusCode(v int) bool {
	for _, allowed := range securityBlockStatusCodes {
		if v == allowed {
			return true
		}
	}
	return false
}

// securityEnumRow 是归一前后对比所需的枚举列快照（含策略标识）。
// rate_limit_enabled 为归一目标：rps 非法行会被关停（保护面收窄），与
// mode→off 同型，必须能逐策略留痕（只报总条数无法定位「哪条策略的限流被关」）。
// rate_limit_rps 自身不被任何回填语句改写（只作为关停判据），故不取快照列
// ——同一事务内的前后比较恒相等，属不可达比较项。
// anomaly_threshold/block_status_code 同属「归一改写了库值」的字段：旧备份/
// 带外脏值留下的 0 阈值或枚举外状态码会在启动时被改写，必须能回答「哪条策略、
// 哪个字段、从什么值改成什么值」——只报总条数无法定位。
type securityEnumRow struct {
	id                         int64
	name                       string
	ipACLMode, mode, geoIPMode string
	rateLimitEnabled           int
	anomalyThreshold           int
	blockStatusCode            int
}

// securityEnumDirtyRows 选出枚举列非法或带首尾空白的策略行——谓词与
// legacySecurityEnumBackfills 的三个枚举条目同源：枚举白名单片段直接由
// 同一集合变量生成（securityEnumSQLList/securityBlockStatusCodeSQLList），
// 不存在第二份字面量。归一本身是保护语义变更（mode 非法→off 会停发该策略全部
// 规则；ip_acl_mode 空→deny 会突然开始按名单拦截），只报总条数无法定位
// 「哪条策略、哪个字段、从什么值变成什么值」，故在变更前后各取一次快照。
func securityEnumDirtyRows(ctx context.Context, tx *sql.Tx) ([]securityEnumRow, error) {
	const dirtyPredicate = `SELECT id, COALESCE(name,''), COALESCE(ip_acl_mode,''), COALESCE(mode,''), COALESCE(geoip_mode,''),
			COALESCE(rate_limit_enabled,0), COALESCE(anomaly_threshold,0), COALESCE(block_status_code,0)
		FROM security_policies
		WHERE (ip_acl_mode IS NOT NULL AND ip_acl_mode<>TRIM(ip_acl_mode))
		   OR (mode IS NOT NULL AND mode<>TRIM(mode))
		   OR (geoip_mode IS NOT NULL AND geoip_mode<>TRIM(geoip_mode))
		   OR COALESCE(TRIM(ip_acl_mode),'') NOT IN (%s)
		   OR COALESCE(TRIM(mode),'') NOT IN (%s)
		   OR COALESCE(TRIM(geoip_mode),'') NOT IN (%s)
		   OR (COALESCE(rate_limit_enabled,0)=1 AND COALESCE(rate_limit_rps,0)<1)
		   OR COALESCE(anomaly_threshold,0)<=0
		   OR COALESCE(block_status_code,0) NOT IN (%s)`
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(dirtyPredicate,
		securityEnumSQLList(securityIPACLModes),
		securityEnumSQLList(securityModes),
		securityEnumSQLList(securityGeoIPModes),
		securityBlockStatusCodeSQLList()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []securityEnumRow
	for rows.Next() {
		var r securityEnumRow
		if err := rows.Scan(&r.id, &r.name, &r.ipACLMode, &r.mode, &r.geoIPMode, &r.rateLimitEnabled,
			&r.anomalyThreshold, &r.blockStatusCode); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// securityEnumChange 是一条枚举列归一记录（field 为列名、from/to 为原始/
// 归一后取值）。
type securityEnumChange struct {
	id                    int64
	name, field, from, to string
}

// securityEnumNormalizedChanges 用同一事务内回读的现值与归一前快照对比，
// 产出逐字段变更清单（未变化的字段不产出）。
func securityEnumNormalizedChanges(ctx context.Context, tx *sql.Tx, before []securityEnumRow) ([]securityEnumChange, error) {
	var out []securityEnumChange
	for _, b := range before {
		var ipACLMode, mode, geoIPMode string
		var rateLimitEnabled, anomalyThreshold, blockStatusCode int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(ip_acl_mode,''), COALESCE(mode,''), COALESCE(geoip_mode,''),
				COALESCE(rate_limit_enabled,0), COALESCE(anomaly_threshold,0), COALESCE(block_status_code,0)
				FROM security_policies WHERE id=?`, b.id).
			Scan(&ipACLMode, &mode, &geoIPMode, &rateLimitEnabled, &anomalyThreshold, &blockStatusCode); err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return nil, err
		}
		for _, f := range []struct {
			name, from, to string
		}{
			{"ip_acl_mode", b.ipACLMode, ipACLMode},
			{"mode", b.mode, mode},
			{"geoip_mode", b.geoIPMode, geoIPMode},
			{"rate_limit_enabled", strconv.Itoa(b.rateLimitEnabled), strconv.Itoa(rateLimitEnabled)},
			{"anomaly_threshold", strconv.Itoa(b.anomalyThreshold), strconv.Itoa(anomalyThreshold)},
			{"block_status_code", strconv.Itoa(b.blockStatusCode), strconv.Itoa(blockStatusCode)},
		} {
			if f.from == f.to {
				continue
			}
			out = append(out, securityEnumChange{id: b.id, name: b.name, field: f.name, from: f.from, to: f.to})
		}
	}
	return out, nil
}

// securityEnumReportNormalized 把逐字段变更写进日志，并对「保护语义收窄」
// 的方向额外落一条系统审计——mode 非 off → off（该策略的 CRS 与自定义规则
// 全部停止发射）与 rate_limit_enabled 1 → 0（rps 非法被关停，该策略不再
// 限流）同属保护面收窄，处置口径必须一致（此前限流关停只有 INFO 计数，
// 审计中心无法回答「哪条策略被关了」）。归一本身不改变（对齐 Create 默认值族、
// 避免整份配置生成失败）。
func securityEnumReportNormalized(changes []securityEnumChange) {
	for _, ch := range changes {
		Logf("warn", "security enum normalize: 策略 %q（#%d）%s 由 %q 归一为 %q", ch.name, ch.id, ch.field, ch.from, ch.to)
		switch {
		case ch.field == "mode" && ch.to == "off" && ch.from != "off":
			RecordAuditLog("system", "修改状态", "安全策略",
				FormatAuditDetail(fmt.Sprintf("策略 %q（#%d）mode 由 %q 归一为 off（该策略规则停止发射）", ch.name, ch.id, ch.from), AuditResultPart("success")), "")
		case ch.field == "rate_limit_enabled" && ch.from == "1" && ch.to == "0":
			RecordAuditLog("system", "修改状态", "安全策略",
				FormatAuditDetail(fmt.Sprintf("策略 %q（#%d）限流被启动归一关停（rate_limit_rps 非法 <1，该策略不再限流）", ch.name, ch.id), AuditResultPart("success")), "")
		}
	}
}

// NormalizeLegacySecurityPolicyEnums 启动时一次性归一 security_policies 的
// 遗留枚举空串行。主节点：实际变更 >0 时在同一事务内递增集群版本，从节点随
// 下次同步收敛。从节点按 sync_security 分流
//
//	sync_security=1：完全跳过——主节点快照权威下发；若主节点为
//	  无归一修复的旧版本，本地归一会与旧主快照互相覆盖（归一翻转 ACL 发射
//	  行为 → 首次 Pull 漂移全量重拉 → 快照恢复遗留空串行），每重启一次行为
//	  翻转一次；保留遗留空串行是旧主集群下的一致状态。
//	- sync_security=0：security 段被门控、没有快照流，本地归一是遗留空串行
//	  唯一修复路径（Update 400 拒修、发射端零规则），执行归一但不 bump
//	  集群版本（从节点无版本权威，bump 会与主节点版本流冲突）。
func NormalizeLegacySecurityPolicyEnums(ctx context.Context) {
	// 保留内联：复合原子读（角色 + sync_security 单查询），拆成
	// RoleOf + 第二次查询会引入两读之间的开关翻转窗口。
	var isMaster, syncSecurity bool
	if err := db.DB.QueryRowContext(ctx, "SELECT COALESCE(is_master,1), COALESCE(sync_security,1) FROM global_config WHERE id=1").Scan(&isMaster, &syncSecurity); err != nil {
		Logf("warn", "security enum normalize: failed to read cluster role, skipping: %v", err)
		return
	}
	if !isMaster && syncSecurity {
		return
	}
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		Logf("error", "security enum normalize: failed to begin transaction: %v", err)
		return
	}
	defer tx.Rollback()
	var versionBefore int64
	if isMaster {
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1").Scan(&versionBefore); err != nil {
			Logf("error", "security enum normalize: failed to read cluster version: %v", err)
			return
		}
	}
	// 归一前快照：逐策略/逐字段的 from 值（见 securityEnumDirtyRows 注释）。
	// 读失败按整体放弃处理——归一仍可在下次启动重做，宁可不动也不留
	// 「改了但说不清改了谁」的现场。
	enumBefore, enumErr := securityEnumDirtyRows(ctx, tx)
	if enumErr != nil {
		Logf("error", "security enum normalize: failed to snapshot dirty enum rows: %v", enumErr)
		return
	}
	var changed int64
	for _, stmt := range legacySecurityEnumBackfills {
		res, err := tx.ExecContext(ctx, stmt)
		if err != nil {
			Logf("error", "security enum normalize: backfill failed: %v", err)
			return
		}
		n, err := res.RowsAffected()
		if err != nil {
			Logf("error", "security enum normalize: failed to read affected rows: %v", err)
			return
		}
		changed += n
	}
	if changed == 0 {
		return
	}
	// 变更清单在同一事务内回读对比（commit 前），报告在 commit 后输出——
	// 审计/日志只描述已落库的事实。
	enumChanges, enumErr := securityEnumNormalizedChanges(ctx, tx, enumBefore)
	if enumErr != nil {
		Logf("error", "security enum normalize: failed to diff normalized enum rows: %v", enumErr)
		return
	}
	if isMaster {
		// 二次启动起行级版本触发器已持久化于库，上方每条 UPDATE 已按命中行数
		// bump 过；显式递增会叠加成多次。落「启动前值+1」的确定性
		// 值：无论触发器是否已安装/触发，一次启动归一只净增 1，测试（无触发
		// 器）与生产口径一致。版本语义只需单调递增，多次 bump 折叠为一次不
		// 影响从节点收敛。
		if _, err := tx.ExecContext(ctx, "UPDATE global_config SET cluster_version=? WHERE id=1", versionBefore+1); err != nil {
			Logf("error", "security enum normalize: failed to bump cluster version: %v", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		Logf("error", "security enum normalize: failed to commit: %v", err)
		return
	}
	if isMaster {
		Logf("info", "security enum normalize: normalized %d legacy rows (empty-enum/threshold/status-code/rate-limit dirty rows), cluster version bumped", changed)
	} else {
		Logf("info", "security enum normalize: normalized %d legacy rows (empty-enum/threshold/status-code/rate-limit dirty rows; slave, sync_security off, no version authority)", changed)
	}
	securityEnumReportNormalized(enumChanges)
}
