package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
	"lazy-balancer-v2/internal/models"
)

var restartRequiredHandler = struct {
	sync.RWMutex
	fn func()
	// installed 表示 main 已注入优雅重启信号：RequestRestart 据此区分
	// 生产环境与独立/测试环境，后者需调用方回退各自的进程退出路径。
	installed bool
}{fn: defaultRestartRequiredHandler}

func defaultRestartRequiredHandler() {
	go func() {
		time.Sleep(time.Second)
		os.Exit(0)
	}()
}

// SetRestartRequiredHandler installs the graceful restart signal used by the
// process lifecycle. Passing nil restores the standalone fallback behavior.
func SetRestartRequiredHandler(handler func()) {
	restartRequiredHandler.Lock()
	defer restartRequiredHandler.Unlock()
	if handler == nil {
		restartRequiredHandler.fn = defaultRestartRequiredHandler
		restartRequiredHandler.installed = false
		return
	}
	restartRequiredHandler.fn = handler
	restartRequiredHandler.installed = true
}

// RestartRequiredHandlerInstalled 报告 main 是否注入了优雅重启处理器：
// 未注入时 RequestRestart 返回 false，且默认实现会 os.Exit——调用方据此在
// 触发前决定「先审计再重启」还是「可见失败留痕」，不必先触发再回退。
func RestartRequiredHandlerInstalled() bool {
	restartRequiredHandler.RLock()
	defer restartRequiredHandler.RUnlock()
	return restartRequiredHandler.installed
}

// RequestRestart 是管理面板触发的统一重启入口：admin TLS 更新与用户
// 服务重启与集群同步的 Admin TLS 热切换共用同一触发器（main 注入的优雅停机
// 信号，HTTP 优雅关停后退出）。返回 false 表示未注入优雅重启处理器（独立/
// 测试环境），调用方回退自身的进程退出路径。
func RequestRestart() bool {
	restartRequiredHandler.RLock()
	handler := restartRequiredHandler.fn
	installed := restartRequiredHandler.installed
	restartRequiredHandler.RUnlock()
	if !installed {
		return false
	}
	handler()
	return true
}

// apiKeyWhitelistCachePurgeAll 由 middleware 包 init 装配（middleware→services
// 单向导入无环）：users 节（含 api_keys）整体替换提交后
// 清空 API Key 白名单 CIDR 解析缓存——缓存键形 keyID|白名单原串无法枚举存活
// Key，逐 Key 清扫不可行。默认空操作（单测直连 services 时无 middleware 装配）。
var apiKeyWhitelistCachePurgeAll = func() {}

// SetAPIKeyWhitelistCachePurgeAll 装配全量清扫钩子（middleware init 注册）。
func SetAPIKeyWhitelistCachePurgeAll(purge func()) {
	apiKeyWhitelistCachePurgeAll = purge
}

// snapshotBrandingDegradeWarned 保证「数据目录未配置」的品牌同步降级只留痕一次
// （dataDir=="" 属显式降级，不得每轮静默跳过）。
var snapshotBrandingDegradeWarned atomic.Bool

// applySnapshotBrandingChecked 调用单源 applySnapshotBranding（branding_sync.go）
// 后回读校验落盘结果，把「只记日志」的失败转换成可重试 error，供调用方写
// apply_ok_branding_failed 标记。回读路径必须与单源写入路径保持一致
// （dataDir/branding.json）。cfg 缺失或 dataDir 未配置=显式降级：留痕一次并跳过。
// 失败操作审计经 SyncService 的失败节流写入（同一错误内容不按
// 重试轮重复）——本 path 在标记驱动重试下会每轮重达，未节流即审计洪泛。
// written 报告本轮是否实际写出文件：品牌文件不在节哈希口径内（branding.json
// 是派生文件，payload 里的 branding_json 属 users 节），304 补偿重拉轮三节
// 哈希可能全一致，调用方必须用该标志把「文件收敛」并入 Caddy 重载判据——
// 否则默认站点内嵌的落地文案滞留旧值直到下一次真实节变更。
func (s *SyncService) applySnapshotBrandingChecked(cfg *config.Config, content string) (written bool, err error) {
	if cfg == nil || cfg.DataDir == "" {
		if snapshotBrandingDegradeWarned.CompareAndSwap(false, true) {
			Logf("warn", "集群品牌配置同步已降级：数据目录未配置，branding.json 不落盘（下次重启请检查品牌配置）")
			RecordAuditLog("system", "警告", "集群同步", "品牌配置同步跳过：数据目录未配置", "")
		}
		return false, nil
	}
	changed, err := applySnapshotBranding(cfg.DataDir, content)
	if err != nil {
		detail := fmt.Sprintf("品牌配置落盘失败: %v", err)
		if s.syncFailureAuditDue("同步失败", "集群同步", detail) {
			RecordAuditLog("system", "同步失败", "集群同步", detail, "")
		}
		return false, err
	}
	expected := content
	if expected == "" {
		expected = emptyBrandingTemplate
	}
	actual, err := os.ReadFile(filepath.Join(cfg.DataDir, "branding.json"))
	if err != nil {
		return false, fmt.Errorf("回读品牌配置: %w", err)
	}
	if string(actual) != expected {
		return false, errors.New("品牌配置文件内容与快照不一致")
	}
	return changed, nil
}

// rebuildCrawlerSnapshotForSync 集群 apply / 升主后的爬虫运行快照重建缝
// （测试可注入计数；生产=CrawlerUpdateManager 同一 DB→文件单源实现）。
var rebuildCrawlerSnapshotForSync = RebuildCrawlerIPListSnapshot

// syncWafFileLockHook / syncReloadLockHook 是 applySnapshot 对应临界区入口的
// 测试观察点（生产恒 nil，调用点已持锁）。锁序护栏用例在钩子内停住，用
// TryLock 断言「锁确实被持有时才进入临界区」，取代按固定时间窗猜测进度——
// 预持锁 + 时间窗的旧形态既可能在申请锁之前超时（假绿），也可能因前置阶段
// 同样争用该锁（wafFilesDrifted→BuildWafFileRef）而在错误位置阻塞，把「被
// 阻塞」误判为「已入临界区」。
var (
	syncWafFileLockHook func()
	syncReloadLockHook  func()
)

func (s *SyncService) applySnapshot(ctx context.Context, snapshot models.ClusterSnapshot) error {
	// 与 s.caddy == nil 同型的 fail-visible 守卫：NewSyncService 恒注入
	// cluster，但独立构造/未来新调用方会解引用 panic；给出「不可判定」错误
	// 而不是崩溃。
	if s.cluster == nil {
		return errors.New("集群服务未初始化")
	}
	// (2026-09-10 审计):ACME 状态校验由 Pull 侧 verifiedSnapshotIntegrity 统一
	// 执行(验签后、apply 前单点);此处重复执行已删——applySnapshot 唯一生产
	// 调用方即 Pull,两次结果必然相同。
	// 开关以主节点快照下发的 MasterSyncSwitches 为准；旧主节点快照
	// 不携带开关时回退本地默认全开，保持 schema 兼容。三分类合并后仅
	// users(恒 true)/rules/security 三开关(集群双端同版本升级)。
	switches := SyncSwitches{Users: true, Rules: true, Security: true}
	if snapshot.MasterSyncSwitches != nil {
		switches = SyncSwitches{
			// 系统数据恒同步(2026-09-11 裁定):纵使旧主节点快照嵌入 false 也强制应用。
			Users:    true,
			Rules:    snapshot.MasterSyncSwitches.Rules,
			Security: snapshot.MasterSyncSwitches.Security,
		}
	}
	// 三个后置副作用标记同住 last_sync_error 一列：单次读取后本地分类（此前
	// 三个 helper 各发一条 SELECT，一个同步周期合计 6–9 次点查同一行同一列）。
	markerMessage, markerKnown := s.readSyncMarkerMessage(ctx)
	// markerCovers 复刻各 helper 的 fail-closed 语义：读失败视同「标记存在」。
	markerCovers := func(prefix string) bool {
		return !markerKnown || strings.HasPrefix(markerMessage, prefix)
	}
	// 重载失败补偿标记必须在快照事务前捕获——事务内「记录同步状态」
	// 会清空 last_sync_error，提交后再读永远漏判；标记在=上轮 apply 后 /load
	// 失败，本轮即使渲染输入无变化也必须强制重载（304 补偿重拉通道的终点）。
	reloadCompensation := markerCovers(syncReloadFailureMarkerPrefix)
	// 品牌落盘失败标记必须与重载标记同点捕获——事务内「记录同步
	// 状态」会清空 last_sync_error，提交后再读永远漏判，品牌节又不在哈希口径内
	// （users 节未变时不会重放），没有标记就会永久停在上轮失败态。
	brandingRetry := markerCovers(syncBrandingFailureMarkerPrefix)
	// Commit 结果不确定标记同样在事务前捕获：补偿轮必须重试品牌落盘并
	// 强制重载，即使已提交形态的三节哈希与证书材料均已一致。
	commitUncertainRetry := markerCovers(syncCommitUncertainMarkerPrefix)
	// previous 只装载 apply 消费面（三节哈希/证书轴/ACME
	// ownership），不再全量构建快照（避免每次 apply 白做 CRS 树全量哈希）。
	previous, err := s.cluster.clusterSnapshotForApply(ctx)
	if err != nil {
		return fmt.Errorf("备份本地快照: %w", err)
	}
	// 本地重建哈希用于漂移检测：记录哈希与主节点一致但本地数据不符时，
	// 哈希跳过让位于强制重放，避免数据丢失被永久掩盖。
	skip := computeSectionSkips(ctx, s.db, snapshot, switches, previous.SectionHashes)
	// 规则日志清理基线：lb_rules 全量替换会删掉主节点已删除的规则，但访问
	// 日志是每节点本地文件（Caddy 按 log_enabled 在各节点独立写
	// /app/logs/rules），快照替换只动表行与证书文件——不在此清理则从节点
	// 磁盘永久残留（UI/看门狗/日志统计都按存活规则过滤，无人可见）。地址
	// 必须在事务前读（事务内 lb_rules 已被清空重写）。读失败仅 warn 跳过
	// 清理：残留是派生数据，不能因此阻断同步。
	var localRuleIDsBeforeApply []string
	if switches.Rules {
		ids, idsErr := loadLocalRuleIDs(ctx, s.db)
		if idsErr != nil {
			Logf("warn", "集群同步：读取本地规则清单失败，跳过消失规则的访问日志清理: %v", idsErr)
		} else {
			localRuleIDsBeforeApply = ids
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始快照事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// 事务内二次复核：Pull 的 admission 前复核与本事务之间角色/凭据
	// 可能被 Promote 翻转（Promote 会先排干在途拉取，本复核是纵深防御——
	// 任何未来新增的 apply 调用方也在写库前中止）。零值守卫=直接调用
	// applySnapshot 的测试路径，跳过。
	if guard := s.applyGuard; guard.MasterURL != "" || guard.Token != "" {
		var isMaster bool
		var masterURL, token string
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(is_master,1), COALESCE(master_url,''), COALESCE(cluster_token,'') FROM global_config WHERE id=1`).Scan(&isMaster, &masterURL, &token); err != nil {
			return fmt.Errorf("复核同步角色: %w", err)
		}
		if isMaster || masterURL != guard.MasterURL || token != guard.Token {
			return errSyncApplyRoleChanged
		}
	}
	// 将主节点开关镜像到本地列：从节点 UI/Status 读取本地列展示真实同步范围。
	// 移入事务内，apply 失败回滚时开关镜像一并回滚，避免半套开关落盘。
	// 触发器带 is_master=1 守卫，此写不会 bump cluster_version。
	if snapshot.MasterSyncSwitches != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE global_config SET
			sync_users=1, sync_rules=?, sync_security=?
			WHERE id=1 AND COALESCE(is_master,1)=0`,
			snapshot.MasterSyncSwitches.Rules, snapshot.MasterSyncSwitches.Security); err != nil {
			return fmt.Errorf("镜像同步开关: %w", err)
		}
	}
	// 规则轴不同步、安全节本轮重放：保留的本地绑定命中的策略对象会被主端
	// 同 id 载荷整表镜像替换（保护语义静默改变）。检查必须在事务内、删除前
	// 读本地面（见 warnPreservedBindingPolicyOverrides）。
	if !skip.skip("security") && skip.disabled["rules"] {
		s.warnPreservedBindingPolicyOverrides(ctx, tx, snapshot)
	}
	if err := replaceSnapshotTx(ctx, tx, snapshot, skip); err != nil {
		return err
	}
	// 主节点为各从节点独立配置的大屏站点坐标：只取本地 registration_id 对应的
	// 一项写入本机 global_config；不触碰其他节点，也不参与通用 global_config
	// 同步列/触发器的版本传播（node-local 字段）。
	if len(snapshot.NodeSites) > 0 {
		var registrationID int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(registration_id,0) FROM global_config WHERE id=1`).Scan(&registrationID); err != nil {
			return fmt.Errorf("读取本节点注册编号: %w", err)
		}
		if site, ok := snapshot.NodeSites[registrationID]; ok {
			if _, err := tx.ExecContext(ctx, `UPDATE global_config SET server_map_lat=?, server_map_lon=? WHERE id=1 AND COALESCE(is_master,1)=0`, site.ServerMapLat, site.ServerMapLon); err != nil {
				return fmt.Errorf("应用本节点站点坐标: %w", err)
			}
		}
	}
	// 证书文件轴（删旧+写新）与 cert_jobs 替换同门于 rules 开关——
	// 开关关闭时从节点本地 acme_dns 规则保留，其证书行/文件不得按主节点快照删改。
	// 证书轴差异（删/增/内容变更）是末段条件重载的强制信号——证书
	// 文件路径确定性意味着内容变化时渲染 JSON 字节不变，不强制则 Caddy 内存
	// 继续用旧证书。
	certsChanged := false
	if !skip.disabled["rules"] {
		certsChanged = snapshotCertsDiffer(previous.Certs, snapshot.Certs)
		if err := removeMissingSnapshotCerts(previous.Certs, snapshot.Certs); err != nil {
			return errors.Join(fmt.Errorf("删除本地旧证书: %w", err), s.restoreSnapshotArtifacts(previous, snapshot))
		}
		// 有意无条件物化（不按 certsChanged 门控）：这是「证书文件被带外删除/
		// 权限被改错」的自愈通道；写放大由 writeCertPair 自身承担——内容一致
		// 且权限正确时零写（只读比对，见 certstore.go）。DNS ownership 同理：
		// ownership.Replace 对相同字节零写。certsChanged 仍是末段条件重载的
		// 强制信号（路径确定性 ⇒ 内容变化不改变渲染字节）。
		if err := materializeSnapshotCerts(snapshot.Certs); err != nil {
			return errors.Join(fmt.Errorf("写入同步证书: %w", err), s.restoreSnapshotArtifacts(previous, snapshot))
		}
	}
	if !skip.disabled["rules"] {
		// 同证书轴：无条件物化 = ownership 文件被删/被改坏时的自愈；相同内容
		// 零写（ownership.Replace 先做 bytes.Equal）。
		if err := s.materializeSnapshotDNSOwnership(snapshot.ACME); err != nil {
			return errors.Join(fmt.Errorf("写入同步 DNS 所有权状态: %w", err), s.restoreSnapshotArtifacts(previous, snapshot))
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE global_config SET applied_version=?, cluster_version=?, sync_fingerprint=?, last_sync=datetime('now'), last_sync_error='' WHERE id=1`, snapshot.Version, snapshot.Version, snapshot.Fingerprint); err != nil {
		return errors.Join(
			fmt.Errorf("记录同步状态: %w", err),
			s.restoreSnapshotArtifacts(previous, snapshot),
		)
	}
	commitSnapshot := s.commitSnapshotTx
	if commitSnapshot == nil {
		commitSnapshot = (*sql.Tx).Commit
	}
	if err := commitSnapshot(tx); err != nil {
		// database/sql 的 Commit 错误不能证明事务未提交：实际已提交时恢复旧
		// 文件会制造 DB/磁盘分叉。释放可能仍未结束的事务，保留本轮材料并
		// 持久化补偿标记；下轮无论 304 与否都按主端快照重新收敛。
		_ = tx.Rollback()
		marker := fmt.Sprintf("%s: 提交结果不确定；证书与 DNS 文件保留本轮内容，下轮同步将全量重拉: %v", syncCommitUncertainMarkerPrefix, err)
		s.persistSyncError(ctx, marker, models.SyncErrorCodeApplyFailed)
		return fmt.Errorf("提交快照事务失败，提交结果不确定（已保留本轮证书与 DNS 文件，下轮同步将全量重拉）: %w", err)
	}
	// 规则日志清理（快照已提交）：与证书轴同层同门——rules 节应用后按
	// 「上一版有、快照没有」的差集删除本地访问日志。失败仅 warn/审计，
	// 不阻断同步（快照已提交，日志是派生数据）。
	if switches.Rules && len(localRuleIDsBeforeApply) > 0 {
		kept := make(map[string]bool, len(snapshot.Rules))
		for _, rule := range snapshot.Rules {
			kept[rule.CaddyID] = true
		}
		removedLogs, logFailures := 0, 0
		for _, id := range localRuleIDsBeforeApply {
			if kept[id] {
				continue
			}
			removedLogs++
			if err := RemoveRuleLogFiles(id); err != nil {
				logFailures++
				Logf("warn", "集群同步：删除消失规则 %s 的访问日志失败（残留仅在本地磁盘）: %v", id, err)
			}
		}
		if removedLogs > 0 {
			detail := fmt.Sprintf("清理消失规则的访问日志：%d 条", removedLogs)
			if logFailures > 0 {
				detail += fmt.Sprintf("，失败 %d 条（见应用日志）", logFailures)
			}
			RecordAuditLog("system", "清理", "规则日志", detail, "")
		}
	}
	// log_level 随快照落库后热生效——必须在事务提交后调用（ApplyLogLevel
	// 从 db.DB 读全局配置，提交前读到的仍是旧值）。三分类合并后全局配置随
	// users 节(恒同步)——users 节被哈希跳过(unchanged)时本地设置未变,
	// 不重放。失败仅记日志（ApplyLogLevel 内部已记），不中断同步。
	if !skip.skip("users") {
		ApplyLogLevel()
		// api_keys 已随 users 节整体替换并提交——清空
		// 白名单 CIDR 解析缓存（逐 Key 清扫无法枚举存活 Key；重建廉价）。
		apiKeyWhitelistCachePurgeAll()
	}
	// 品牌配置随节同步(2026-09-11):快照携带的 branding.json 落盘本地
	// 并注入 landing——必须在下方 Caddy 重载前完成,新文案随重载生效。
	// 落盘失败不得只审计——写 apply_ok_branding_failed 标记
	// （apply_ok_reload_failed 同族），304 分支据此全量重拉并在下一轮强制
	// 重试；users 节被哈希跳过时标记同样强制重试。
	// written 是本轮文件真实收敛的信号：品牌文件内容不在节哈希口径内，
	// 补偿重拉轮三节哈希可能全一致，漏并入重载判据会让默认站点落地文案
	// 滞留旧值（标记已被事务清空，无后续自愈）。
	brandingWritten := false
	if snapshot.BasicSettings.BrandingJSON != nil && (!skip.skip("users") || brandingRetry || reloadCompensation || commitUncertainRetry) {
		var brandingErr error
		brandingWritten, brandingErr = s.applySnapshotBrandingChecked(s.cfg, *snapshot.BasicSettings.BrandingJSON)
		if brandingErr != nil {
			brandingWritten = false
			Logf("error", "同步品牌配置未落盘（数据库已应用，文件未收敛，下轮重试）: %v", brandingErr)
			s.persistSyncError(ctx, syncBrandingFailureMarkerPrefix+": 品牌配置落盘失败（数据库已应用，文件未收敛，下轮同步重试）", models.SyncErrorCodeApplyFailed)
		}
	}
	logSectionSyncOutcome(skip, snapshot.Version)
	if len(skip.drifted) > 0 {
		Logf("warn", "检测到本地数据与同步记录不一致（%s），已强制重新应用", strings.Join(skip.drifted, "、"))
		RecordAuditLog("system", "同步自愈", "集群同步", FormatAuditDetail(fmt.Sprintf("本地数据与记录不一致：%s", strings.Join(skip.drifted, "、")), fmt.Sprintf("已强制重新应用版本：%d", snapshot.Version)), "")
	}
	// 漂移强制重放后本地数据已镜像主节点——drifted 节必须存本地重建口径哈希作为
	// 稳定参照，否则跨构建口径分歧时（如 COALESCE 加固前后）漂移判定永远不一致、
	// 每周期全量重拉+Caddy 重载。
	bookkeepingErr := recordAppliedSectionHashes(ctx, s.db, snapshot, skip, switches, previous.SectionHashes)
	if bookkeepingErr != nil {
		// 记账失败不回滚已提交的快照应用（本地数据已镜像主节点），但必须
		// 可见：漂移/跳过判定在下轮起失真前，节流审计暴露该故障。
		detail := fmt.Sprintf("记录已应用节哈希失败: %v", bookkeepingErr)
		if s.syncFailureAuditDue("同步失败", "集群同步", detail) {
			RecordAuditLog("system", "同步失败", "集群同步", detail, "")
		}
	}
	logSyncSwitchGuards(ctx, s.db, snapshot, skip, switches)

	// 门控常态只走 wafFilesDrifted（stat 签名缓存 + 含版本标签的记账比对），
	// 不再每次 apply 对 CRS 全树 tar.gz+xdb 做全量内容哈希；仅当本轮记账
	// 写入失败（applied_waf_ref_* 不可信）时回退 wafFilesRefDiffers 的
	// 「不依赖 DB 记账」内容哈希兜底——标签分叉（如 .version 陈旧）由
	// wafFilesDrifted 的含标签比对开路，内容哈希比较只作记账失败时的补充，
	// 不会短路标签自愈（fetch 路径内 rewriteVersionIfMissingOrStale）。
	// changed 标志在函数作用域声明，供末段条件重载判定。
	var crsChanged, xdbChanged, threatChanged bool
	if switches.Security && (s.wafFilesDrifted(ctx) || (bookkeepingErr != nil && wafFilesRefDiffers(snapshot.WafFiles))) {
		// 同步校验/应用只写应用日志与审计，不写其他任务的三库日志。
		bundle, ferr := s.fetchWafFiles(ctx, snapshot.WafFiles)
		// 调用点持 WafFileLock——与 lbbak 导入
		// （config_backup_lbbak.go caller-side 持锁）、三库更新器（内锁）与
		// BuildWafFileBundle 读相位（内锁）串行，杜绝同步落盘与导入/更新交错
		// 打出混合 rules 树/撕裂 xdb。ApplyWafFileBundle 本体不可内锁（lbbak
		// 已持锁调用，内锁=双锁死锁）。锁序：本点不持 CaddyOpLock（重载段在
		// 其后单独取），wafFileMu→CaddyOpLock 与导入锁序同向；禁止反向嵌套
		// （持 CaddyOpLock 再取 wafFileMu 即 AB-BA）。
		var aerr error
		if ferr == nil {
			// defer 释放：本函数在 gin 路由栈内（手动同步端点装了 gin.Recovery），
			// 临界区内 panic 被恢复为 500 时裸 Unlock 永不执行——包级锁永久泄漏，
			// 后续重载/导入/规则库更新/同步全部阻塞且无持有者诊断信息。
			withWafFileLock(func() {
				if syncWafFileLockHook != nil {
					syncWafFileLockHook()
				}
				crsChanged, xdbChanged, threatChanged, aerr = ApplyWafFileBundle(bundle)
				if aerr == nil {
					// 收口（SecurityEngine 域移交）：主端删除威胁源后，从端
					// 残留 threat-<source>.iplist.fast 会让 wafFilesRefDiffers /
					// wafFilesDrifted 恒判漂移——每轮全量重拉却永不删除，且
					// 全量重拉永不收敛。应用成功后按主端引用集合真实收敛本地
					// 文件集（删除失败留下警告，下轮漂移判定重试；方向安全）。
					pruned, pruneErr := pruneSyncedThreatFiles(snapshot.WafFiles)
					if pruneErr != nil {
						Logf("warn", "同步安全数据：威胁库残留文件清理失败（下轮漂移重试）: %v", pruneErr)
					}
					if len(pruned) > 0 {
						threatChanged = true
						Logf("info", "同步安全数据：清理主端已删除威胁源的本地残留文件: %s", strings.Join(pruned, "、"))
					}
				}
			})
		}
		if ferr != nil {
			Logf("error", "同步安全数据失败（数据库版本行已同步）: %v", ferr)
			// 安全数据失败按内容去重（每轮 apply 都会重试）。
			detail := fmt.Sprintf("拉取安全数据失败: %v", ferr)
			if s.syncFailureAuditDue("同步失败", "安全数据", detail) {
				RecordAuditLog("system", "同步失败", "安全数据", detail, "")
			}
		} else if aerr != nil {
			Logf("error", "落盘同步安全数据失败: %v", aerr)
			detail := fmt.Sprintf("落盘安全数据失败: %v", aerr)
			if s.syncFailureAuditDue("同步失败", "安全数据", detail) {
				RecordAuditLog("system", "同步失败", "安全数据", detail, "")
			}
		} else if crsChanged || xdbChanged || threatChanged {
			detail := wafBundleSyncDetail(bundle, crsChanged, xdbChanged)
			RecordAuditLog("system", "同步", "安全数据", detail, "")
			// 同步有变动=完整更新流程(与自动更新器同款阶段流水)
			if xdbChanged {
				if err := Reload(); err != nil {
					Logf("error", "同步后 ip2region 内存缓存热换失败(下次重启生效): %v", err)
				}
				RebuildRegionTreeCacheForSync()
			}
		}
	}
	// 安全节替换 security_ip_lists 后重建爬虫运行快照（插件只读
	// /app/data/crawler-ip-lists.json，不从 DB 派生；无此钩子时从节点/升主/
	// 导入后执行面停在旧代或缺失，爬虫豁免/伪装判定与主节点分裂）。快照写
	// 失败不回滚已提交快照——留痕后由下次更新/重启收敛。
	if switches.Security && !skip.skip("security") {
		if err := rebuildCrawlerSnapshotForSync(); err != nil {
			Logf("warn", "集群同步：爬虫运行快照重建失败（DB 已应用，插件按旧快照运行至下次收敛）: %v", err)
		}
	}
	// Caddy 重载必须在事务提交之后：buildWafHandler 等安全配置读取走 db.DB，
	// 提交前的事务内生成看不到本次写入的 security_* 表。重载失败仅记录，
	// 不回滚已提交的快照。本路径必须强制——证书文件
	// （materializeSnapshotCerts）与 WAF 数据（ApplyWafFileBundle）在生成前已
	// 落盘，生成期内容比对相等 → 快照为空 → 自动强制不触发；而「仅数据文件
	// 变化、JSON 字节相同」正是 errSameConfig 短路让从节点插件内存停留旧库的
	// 场景。applySnapshot 仅在新快照版本时运行，强制无冗余开销。
	// 渲染+强制重载入 CaddyOpLock——此前与重启
	// watcher（渲染 DB→/load，持锁）交错时，跨同步 commit 点的旧渲染可后到
	// 覆盖新配置，从节点静默回退上一版本（三通道自愈全探不到）。锁序安全：
	// 锁内仅 ApplyConfigForce 的 s.mu（叶操作），Pull 路径锁不反向嵌套。
	// 渲染数据未变跳过 /load——判定口径=节级信号
	// 三节（users/rules/security，渲染的全部 DB 输入）哈希跳过 + WAF 数据文件
	// 无变化 + 证书轴无变化（证书内容变化 JSON 字节不变，必须强制）+ 品牌文件
	// 本轮实际写出（派生文件不在节哈希口径内；补偿重拉轮三节全跳过时文件已
	// 收敛，默认站点落地文案必须随重载生效）+ 无重载
	// 失败补偿标记（标记在=上轮重载失败，本轮是 304 补偿重拉的语义终点，必须
	// 强制；标记由事务内「记录同步状态」清空，故在事务前捕获）。版本行
	// next_update/update_status 族、登录锁等纯簿记列不在节 payload 内，不触发；
	// 但 sync_interval 属 users 节 basic_settings payload（参与节哈希），其变更
	// 会翻转 users 节哈希并触发重载——注释勿再把它列入「不触发」族。
	// last_good 兼容：渲染未变则既有 last_good 仍是当前运行配置的准确
	// 快照，无需重写。
	renderInputsChanged := !(skip.skip("users") && skip.skip("rules") && skip.skip("security"))
	mustReload := renderInputsChanged || crsChanged || xdbChanged || threatChanged || certsChanged || brandingWritten || reloadCompensation || commitUncertainRetry
	var reloadErr error
	if mustReload {
		// defer 释放：panic（gin.Recovery 恢复）后包级锁不得泄漏——否则后续
		// 全部配置写窗口永久不可用。
		withCaddyOpLock(func() {
			if syncReloadLockHook != nil {
				syncReloadLockHook()
			}
			if s.caddy == nil {
				// nil CaddyService 是合法构造（测试/独立运维路径）。
				// 按「不可判定」走既有重载失败标记语义（marker→304 补偿重拉），
				// 而不是解引用 panic。
				reloadErr = errors.New("Caddy 服务未初始化")
			} else {
				// 渲染源必须是本服务句柄（快照刚提交到 s.db）：GenerateCaddyConfig()
				// 恒用包级 db.DB，多库形态（测试/嵌入式网关）会把 A 库快照提交后
				// 按 B 库内容渲染并 /load（写入 A、渲染 B，静默错配）。
				// certSource 同用 s.db（快照事务已提交，证书候选与渲染同一真相）；
				// rulesWrittenInTx=true：快照写过 lb_rules，谓词 miss 需 per-rule 补查。
				reloadErr = s.caddy.ApplyConfigForce(generateCaddyConfigWithCertSource(s.db, s.db, true))
			}
		})
	}
	if reloadErr != nil {
		err := reloadErr
		Logf("error", "集群同步后重载 Caddy 失败（快照已提交）: %v", err)
		// 登记后台重载失败面——从节点的 caddy_apply_error 从不由 handlers
		// 写路径落盘，本登记是「快照已提交但运行配置未收敛」分叉的全局
		// 横幅/状态接口信号（与证书/CRS 等后台来源同一消费面）。
		RecordBackgroundApplyFailure(BackgroundApplyClusterSync, err)
		// Caddy /load 持续故障时补偿重拉每轮都会到达此处——同内容
		// 重载失败只留一条操作审计（标记/日志仍按轮刷新）。
		detail := fmt.Sprintf("同步应用后自动重载失败: %v", err)
		if s.syncFailureAuditDue("重载失败", "Caddy服务", detail) {
			RecordAuditLog("system", "重载失败", "Caddy服务", detail, "")
		}
		// 写入标记：运行配置与数据库不一致。304 分支识别该标记并全量重拉补偿重试，
		// 避免陈旧运行配置存活到下次真实变更或重启。标记必须跨调用方 ctx 取消存活，
		// 套用 persistSyncError 的 WithoutCancel+2s 超时模式。
		marker := fmt.Sprintf(syncReloadFailureMarkerPrefix+": %v", err)
		markerCtx, markerCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer markerCancel()
		result, werr := s.db.ExecContext(markerCtx, "UPDATE global_config SET last_sync_error=? WHERE id=1 AND "+slaveRoleConditionSQL, encodeSyncError(marker, models.SyncErrorCodeApplyFailed))
		if werr != nil {
			Logf("error", "集群同步重载失败标记写入失败: %v", werr)
		} else if rows, raerr := result.RowsAffected(); raerr != nil {
			Logf("error", "集群同步重载失败标记写入异常（读取影响行数失败，错误 %v）：自愈通道可能失效，请检查数据库", raerr)
		} else if rows == 0 {
			// 从端补偿标记只在从端语境有意义：提交与重载之间完成升主的节点
			// 不得把「同步重载失败」写回主节点（Promote 已清空该列）。
			Logf("info", "集群同步重载失败标记跳过：本节点已升为主节点")
		}
	} else if mustReload {
		// 重载成功即清除本来源的失败面记录（含 304 补偿重拉成功形态——
		// 上轮失败登记的失败面随本轮成功收敛）。
		ClearBackgroundApplyFailure(BackgroundApplyClusterSync)
		RecordAuditLog("system", "重载", "Caddy服务", "同步应用后自动重载", "")
	} else {
		// 跳过重载本身留一行应用日志（不进操作审计——零真实重载不落审计，
		// 与 errSameConfig 短路同口径的审计真实性裁定）。
		Logf("info", "集群同步：渲染输入无变化，跳过 Caddy 重载")
	}
	clusterSnapshotCaches.Delete(s.db)
	// 重启判定遇读失败只跳过：把降级默认值 {selfsigned, disabled} 当真值比对，
	// 运行态为 upload 证书时一次瞬时读失败会被误判「配置变化」触发进程重启
	// （重启抖动），反向则可能漏判真实变化。读失败仅 warn 并跳过本轮判定：
	// 不重启、不改状态。
	if adminTLS, tlsErr := LoadAdminTLSConfigE(); tlsErr != nil {
		Logf("warn", "集群同步后读取 Admin TLS 配置失败，跳过重启判定（不触发重启）: %v", tlsErr)
	} else if RuntimeAdminTLSChanged(adminTLS) {
		if RestartRequiredHandlerInstalled() {
			// 先审计后触发：优雅停机信号会让进程在数秒内退出，审计行必须
			// 先落库（与 handlers.RestartService 的「审计→重启」同序）。
			RecordAuditLog("system", "重启", "系统", "同步到新的 HTTPS 访问配置，自动重启生效", "")
			Logf("info", "Admin TLS config changed via sync, restarting to apply")
			RequestRestart()
		} else {
			// 未注入优雅重启处理器（独立运维/测试构造）：默认实现是
			// os.Exit(0)，落到那里既不重启侧可见也不留痕，测试进程更会被
			// 静默截断且判通过。改为可见失败：warn + 审计 + 跳过本轮重启。
			Logf("warn", "集群同步：Admin TLS 配置已变化，但进程未安装优雅重启处理器，跳过自动重启")
			RecordAuditLog("system", "重启失败", "系统", "同步到新的 HTTPS 访问配置，但进程未安装优雅重启处理器，未自动重启", "")
		}
	}
	// 三分类合并:全局配置随 users 节恒同步,不存在「基本设置:开关关闭」
	// 形态;unchanged 侧由节级审计(哈希一致)正确区分。
	// 2026-10-03 用户裁定：汇总行反映节级实际应用面——原内容清单（规则 N
	// 条/用户 N 个/基本设置：已同步…）与同秒的「哈希一致跳过」自相矛盾，
	// 读者误以为全部节都已写入。
	appliedSecs, hashSkipped, disSkipped := sectionOutcomeNames(skip)
	summaryParts := []string{fmt.Sprintf("应用版本：%d", snapshot.Version)}
	if len(appliedSecs) > 0 {
		summaryParts = append(summaryParts, "本轮应用："+strings.Join(appliedSecs, "、"))
	}
	if len(hashSkipped) > 0 {
		summaryParts = append(summaryParts, "跳过（哈希一致）："+strings.Join(hashSkipped, "、"))
	}
	if len(disSkipped) > 0 {
		summaryParts = append(summaryParts, "跳过（开关关闭）："+strings.Join(disSkipped, "、"))
	}
	if len(appliedSecs) == 0 {
		summaryParts = append(summaryParts, "全部节无变化")
	}
	if !mustReload {
		summaryParts = append(summaryParts, "Caddy 重载：跳过（渲染输入无变化）")
	}
	// 不再输出「Caddy 全局配置：已同步」——该段恒真（v3 快照的 CaddyConfig
	// 恒非 nil）且已被节级三态覆盖：全局配置并入 users（系统数据）节，节实际
	// 应用/跳过面见上列（2026-10-03「汇总行反映节级实际应用面」裁定）。
	RecordAuditLog("system", "同步", "集群同步", FormatAuditDetail(summaryParts...), "")
	return nil
}

// wafBundleSyncDetail 按组件实际变化组合同步结果文案：更新的组件带版本号，
// 未变化的标注已是最新——操作日志读者能直接看出本次同步更新了什么。
func wafBundleSyncDetail(bundle *WafFileBundle, crsChanged, xdbChanged bool) string {
	crsPart := "CRS 规则已是最新"
	if crsChanged {
		crsPart = "CRS 规则已更新"
		if bundle.CRSVersion != "" {
			crsPart = "CRS 规则已更新至 " + bundle.CRSVersion
		}
	}
	xdbPart := "IP2Region数据库已是最新"
	if xdbChanged {
		xdbPart = "IP2Region数据库已更新"
		if bundle.IP2RegionTag != "" {
			xdbPart = "IP2Region数据库已更新至 " + bundle.IP2RegionTag
		}
	}
	// 2026-09-18 用户裁定:明确数据来源语义——从节点不自动升级,规则库变更唯
	// 一来源是主节点同步
	return "从主节点同步：" + crsPart + "；" + xdbPart
}

// pruneSyncedThreatFiles 按主端引用集合收敛本地威胁库文件（收口，
// SecurityEngine 域移交的「从端 ApplyWafFileBundle 不删多余 .fast」半项）。
// 主端删除威胁源后，从端残留 threat-<source>.iplist.fast 会让
// wafFilesRefDiffers（len 不等/逐源不符）与 wafFilesDrifted（本地 ref 含
// 残留源）恒判漂移，每轮全量重拉却永不删除——收敛必须显式删除。
//
// 删除范围=白名单源名（与 scanThreatFastFiles 同口径：白名单外文件不参与
// ref/漂移比对，同步不管辖）且不在 ref.ThreatSha256s 的 .fast 及其 .iplist
// 文本伴生文件；ref 为 nil 时不动（主端无任何 WAF 组件——裁定：nullRef
// 豁免重拉，也无从判定删除集合）。
//
// 调用方必须已持 WafFileLock（与 CRS/威胁库更新器、lbbak 导入串行）。
// 逐文件删除失败不中断（错误聚合返回，下轮漂移判定会重试）；返回至少删除
// 了一个文件的源名列表。
func pruneSyncedThreatFiles(ref *models.ClusterWafFilesRef) ([]string, error) {
	if ref == nil {
		return nil, nil
	}
	matches, err := filepath.Glob(filepath.Join(wafDir, "threat-*.iplist.fast"))
	if err != nil {
		return nil, fmt.Errorf("扫描本地威胁库文件: %w", err)
	}
	pruned := make([]string, 0)
	var errs []error
	for _, fastPath := range matches {
		source := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(fastPath), "threat-"), ".iplist.fast")
		if source == "" || !validThreatFileName(source) {
			continue
		}
		if _, kept := ref.ThreatSha256s[source]; kept {
			continue
		}
		removed := false
		for _, path := range []string{fastPath, filepath.Join(wafDir, "threat-"+source+".iplist")} {
			if err := os.Remove(path); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, fmt.Errorf("删除威胁库 %s: %w", source, err))
				}
				continue
			}
			removed = true
		}
		if removed {
			pruned = append(pruned, source)
		}
	}
	return pruned, errors.Join(errs...)
}

func (s *SyncService) restoreSnapshotArtifacts(previous, current models.ClusterSnapshot) error {
	// previous 是 apply 前的本地快照，不是主端 incoming；失败回滚恢复本地基线。
	// rules 开关禁用时主端 ownership 从未写入（初始物化已跳过），因此此处仍须
	// 恢复 previous 本地 ownership，不能与写入侧同门跳过。
	return errors.Join(restoreSnapshotCerts(previous.Certs, current.Certs), s.materializeSnapshotDNSOwnership(previous.ACME))
}

func (s *SyncService) materializeSnapshotDNSOwnership(acme *models.ClusterACMEState) error {
	if acme == nil {
		return nil
	}
	if err := validateDNSOwnership(acme.DNSOwnership); err != nil {
		return err
	}
	dataDir := ""
	if s.cfg != nil {
		dataDir = s.cfg.DataDir
	}
	if dataDir == "" {
		var err error
		// *sql.DB 满足 snapshotStore 接口，与 clusterSnapshotDataDir 合一（Phase10）。
		dataDir, err = clusterSnapshotDataDir(context.Background(), s.db)
		if err != nil {
			return err
		}
	}
	// 与 DNS-01 签发共用 ownership 包的单源原子写与 fileMu：apply 期间即使
	// 退役队列的 zombie 执行仍在 Add/Remove，也不会与整文件替换交错。锁只在
	// Replace 内覆盖文件 I/O；调用方事务/其他锁不会在 fileMu 内被反向获取。
	return ownership.Replace(dataDir, acme.DNSOwnership)
}

func restoreSnapshotCerts(previous, current []models.ClusterCertificate) error {
	return errors.Join(removeMissingSnapshotCerts(current, previous), materializeSnapshotCerts(previous))
}

// snapshotCertsDiffer 报告快照证书轴与本地存量是否存在差异（删除/新增/内容
// 变更），按 RuleID 对齐比较 PEM 对——末段条件重载的强制信号
// 证书文件路径确定性意味着内容变化时渲染 JSON 字节不变，差异存在必须强制
// 重载，否则 Caddy 内存继续服役旧证书。
func snapshotCertsDiffer(previous, current []models.ClusterCertificate) bool {
	if len(previous) != len(current) {
		return true
	}
	prevByRule := make(map[string]models.ClusterCertificate, len(previous))
	for _, cert := range previous {
		prevByRule[cert.RuleID] = cert
	}
	for _, cert := range current {
		prev, ok := prevByRule[cert.RuleID]
		if !ok || prev.CertPEM != cert.CertPEM || prev.KeyPEM != cert.KeyPEM {
			return true
		}
	}
	return false
}

// loadLocalRuleIDs 读取当前库内全部规则 id（集群 apply 的「上一版规则」基线，
// 供消失规则的访问日志清理做差集）。
func loadLocalRuleIDs(ctx context.Context, database *sql.DB) ([]string, error) {
	rows, err := database.QueryContext(ctx, `SELECT caddy_id FROM lb_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func removeMissingSnapshotCerts(previous, current []models.ClusterCertificate) error {
	currentIDs := make(map[string]bool, len(current))
	for _, cert := range current {
		currentIDs[cert.RuleID] = true
	}
	var errs []error
	for _, cert := range previous {
		if !currentIDs[cert.RuleID] {
			if err := RemoveCertFiles(cert.RuleID); err != nil {
				errs = append(errs, fmt.Errorf("删除证书 %s: %w", cert.RuleID, err))
			}
		}
	}
	return errors.Join(errs...)
}

func replaceSnapshotTx(ctx context.Context, tx *sql.Tx, snapshot models.ClusterSnapshot, skip *sectionSkips) error {
	if skip == nil || skip.disabled == nil {
		skip = &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}
	}
	if !skip.skip("rules") {
		if err := clearSyncTables(ctx, tx, "path_rules", "upstreams", "lb_rules"); err != nil {
			return err
		}
	}
	// cert_jobs 存主节点下发的证书（从节点自身不签发），与 ca_providers/certificate_configs
	// 同为全量替换，不纳入 rules 节哈希跳过：rules 节命中哈希跳过后证书 INSERT 仍会重放，
	// 残留旧行会撞 (rule_id,domain) 唯一索引，导致同步永久失败。
	// 仅哈希跳过（unchanged）保持上述全量回放；rules 开关关闭（disabled）时
	// 证书轴必须联动跳过——证书行/文件是规则轴的派生数据：开关关闭时从节点保留本地
	// 规则（含 enabled=1 的 acme_dns 规则），若仍清空 cert_jobs 并按主节点快照删本地
	// 证书文件，从节点该规则的 TLS 会静默永久丢失（渲染侧无证书即不入 TLS 连接策略，
	// Caddy 正常加载零报错，从节点不签发也无自愈路径）。注意 skip() 是
	// disabled||unchanged 的合并视图，此处须精确判 disabled。
	if !skip.disabled["rules"] {
		if err := clearSyncTables(ctx, tx, "cert_jobs"); err != nil {
			return err
		}
	}
	// login_failed_attempts/login_locked_until 是从节点登录端点写入的本地
	// 记账（不随快照同步）。users 节清表前读出，回插后回写（见
	// restoreLocalLoginLockouts），避免主节点无关的 users 变更意外解锁从节点
	// 被锁账户。
	var localLoginLockouts map[string]loginLockoutState
	var localAPIKeyLastUsed map[int]sql.NullString
	if !skip.skip("users") {
		preserved, err := readLocalLoginLockouts(ctx, tx)
		if err != nil {
			return err
		}
		localLoginLockouts = preserved
		preservedKeys, err := readLocalAPIKeyLastUsed(ctx, tx)
		if err != nil {
			return err
		}
		localAPIKeyLastUsed = preservedKeys
		if err := clearSyncTables(ctx, tx, "api_keys", "users"); err != nil {
			return err
		}
	}
	// ACME 配置/CA 提供商与 cert_jobs 同门——rules 开关关闭时从节点
	// 保留本地规则（含本地 acme_dns 规则），若 ACME 表仍按主节点快照全量替换：
	// ①本地规则的 acme_config_id 悬空；②主端同 id 配置覆盖后可能绑定到错误
	// DNS 账号（promote 后按错误账号签发/续期）。只给 cert_jobs 加了
	// 精确 disabled 门，引用目标必须同门。
	var statements []string
	if snapshot.ACME != nil && !skip.disabled["rules"] {
		statements = append(statements, "DELETE FROM certificate_configs", "DELETE FROM ca_providers")
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("清理快照数据: %w", err)
		}
	}
	if snapshot.ACME != nil && !skip.disabled["rules"] {
		for _, provider := range snapshot.ACME.CAProviders {
			// 从端全部时间列统一平面格式（nullableTimeFlat/
			// UTC 直写），消除驱动序列化 '+00:00'/RFC3339 后缀形态与主端三态并存。
			if _, err := tx.ExecContext(ctx, `INSERT INTO ca_providers (id,name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`, provider.ID, provider.Name, provider.Provider, provider.DirectoryURL, nullableString(provider.Credentials), provider.MaxConcurrent, provider.MinIntervalMS, provider.Enabled, provider.CreatedAt.UTC().Format(crsTimeLayout), provider.UpdatedAt.UTC().Format(crsTimeLayout)); err != nil {
				return fmt.Errorf("写入快照 CA 提供商 %d: %w", provider.ID, err)
			}
		}
		for _, config := range snapshot.ACME.CertificateConfigs {
			if _, err := tx.ExecContext(ctx, `INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?)`, config.ID, config.Name, config.DNSProvider, nullableString(config.DNSCredentials), config.Enabled, config.CreatedAt.UTC().Format(crsTimeLayout), nullableTimeFlat(config.UpdatedAt.NullTime)); err != nil {
				return fmt.Errorf("写入快照证书配置 %d: %w", config.ID, err)
			}
		}
	}
	if !skip.skip("rules") {
		if err := insertSnapshotRules(ctx, tx, snapshot.Rules); err != nil {
			return err
		}
	}
	if !skip.skip("users") {
		if err := insertSnapshotUsersAndKeys(ctx, tx, snapshot); err != nil {
			return err
		}
		if err := restoreLocalLoginLockouts(ctx, tx, localLoginLockouts); err != nil {
			return err
		}
		if err := restoreLocalAPIKeyLastUsed(ctx, tx, localAPIKeyLastUsed); err != nil {
			return err
		}
	}
	// 证书回插与清空同门（见上方 cert_jobs 清空处注释）。
	if !skip.disabled["rules"] {
		for _, cert := range snapshot.Certs {
			message := "从主节点同步"
			if cert.SourceStatus != "" {
				message += "，源任务状态：" + cert.SourceStatus
			}
			// 到期口径收敛：源值优先；源值缺失或**不可被消费侧解析**（旧主节点/
			// 旧备份行、带外直写异常形态）时从证书材料派生并回填 expires_at。
			// 否则本地行 expires_at 对聚合口径恒 NULL，而聚合消费面（节点健康
			// certs_expiring_30d）以 datetime(expires_at) 为门，会漏报真正临期的
			// 证书；/certificates 与 /certificates/jobs 也会对同一行给出「空/有」
			// 两种结论。仅「空值」判定留过缺口：非空坏值同样落 NULL 却不派生。
			expiresAt := cert.ExpiresAt
			if !snapshotExpiresAtUsable(expiresAt) {
				// 空串与不可解析形态都按「源值缺失」处理：不可解析串落库后
				// datetime(expires_at)=NULL，与空值在消费侧等价，但对读侧行值
				// 是垃圾——显式归 NULL，派生成功则改用材料口径。
				expiresAt = ""
				if cert.CertPEM != "" {
					if notAfter, ok := CertNotAfterFromPEM(cert.CertPEM); ok {
						expiresAt = notAfter.UTC().Format(crsTimeLayout)
					}
				}
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO cert_jobs (rule_id,domain,status,message,expires_at,cert_pem,key_pem,ca_provider_id,renewal_attempts,ca_available_after,last_error_code,created_at,updated_at) SELECT ?,COALESCE(NULLIF(?,''),domain),'issued',?,?,?,?,?,?,?,?,COALESCE(NULLIF(?,''),CURRENT_TIMESTAMP),NULLIF(?,'') FROM lb_rules WHERE caddy_id=? AND tls_source='acme_dns'`, cert.RuleID, canonicalSnapshotCertDomain(cert.Domain), message, nullableString(expiresAt), cert.CertPEM, cert.KeyPEM, cert.CAProviderID, cert.RenewalAttempts, nullableTimeFlat(cert.CAAvailableAfter.NullTime), nullableString(cert.LastErrorCode), cert.CreatedAt, cert.UpdatedAt, cert.RuleID); err != nil {
				return fmt.Errorf("写入快照证书 %s: %w", cert.RuleID, err)
			}
		}
	}
	// 三分类合并:全局配置应用(基本设置落库)从 global_config 节门改挂
	// users 节——users 恒同步,仅哈希一致(unchanged)时跳过;此时本地设置
	// 未变,但同步间隔属集群编排自身(快照侧始终下发),即使 unchanged 也
	// 必须应用,否则从节点轮询周期与 UI 显示双陈旧。
	if !skip.skip("users") {
		if err := updateSnapshotSettings(ctx, tx, snapshot); err != nil {
			return err
		}
	} else if snapshot.BasicSettings.SyncInterval != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE global_config SET sync_interval=? WHERE id=1 AND COALESCE(is_master,1)=0`, normalizeSyncInterval(*snapshot.BasicSettings.SyncInterval)); err != nil {
			return fmt.Errorf("写入同步间隔: %w", err)
		}
	}
	// CRS/IP2Region 版本行随安全防护开关(三分类合并,2026-09-11 差分门控
	// 修正的延续):不进节哈希(security payload 只带 waf ref,版本行走内容
	// 差分),按「快照行 vs 本地行」差分应用——版本行变化由
	// security_crs_version 触发器 bump 版本驱动 Pull 到达,此处差分命中即
	// 重放;开关关闭跳过(disabled 精确判,不含 unchanged)。全量替换语义:
	// 先清后插,空载荷=主节点清空。
	if !skip.disabled["security"] && snapshotSecurityVersionRowsDiffer(ctx, tx, snapshot) {
		for _, stmt := range []string{"DELETE FROM security_crs_version", "DELETE FROM security_ip2region_version"} {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("清理版本行同步表: %w", err)
			}
		}
		if err := applySecurityCRSVersion(ctx, tx, snapshot.SecurityCRSVersion); err != nil {
			return err
		}
		if err := applySecurityIP2RegionVersion(ctx, tx, snapshot.SecurityIP2RegionVersion); err != nil {
			return err
		}
	}
	if !skip.skip("security") {
		if err := applySecurityTables(ctx, tx, snapshot, !skip.disabled["rules"]); err != nil {
			return err
		}
	}
	// 修订：主节点活跃登录锁在 users 节处理（重放+本地记账回写）之后应用，
	// 且不受 users 节哈希跳过门控——锁变更不改变 users 节哈希（login_* 不在节
	// 载荷内），典型路径恰是「users 节跳过、仅 locked_users 变化」。
	if err := applyLockedUsers(ctx, tx, snapshot.LockedUsers); err != nil {
		return err
	}
	return nil
}

func clearSyncTables(ctx context.Context, tx *sql.Tx, tables ...string) error {
	for _, t := range tables {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+t); err != nil {
			return fmt.Errorf("清理同步表 %s 失败: %w", t, err)
		}
	}
	return nil
}

func insertSnapshotUsersAndKeys(ctx context.Context, tx *sql.Tx, snapshot models.ClusterSnapshot) error {
	for _, user := range snapshot.Users {
		if _, err := tx.ExecContext(ctx, `INSERT INTO users (id,username,password_hash,role,display_name,is_enabled,password_version,password_changed_at,created_at,last_login,mfa_enabled,mfa_secret,mfa_recovery_codes,mfa_last_timestep,auth_provider,oidc_subject,oidc_issuer,is_setup_admin) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			user.ID, user.Username, user.PasswordHash, user.Role, user.DisplayName, user.IsEnabled, user.PasswordVersion, user.PasswordChangedAt, user.CreatedAt.UTC().Format(crsTimeLayout), nullableTimeFlat(user.LastLogin.NullTime),
			user.MFAEnabled, user.MFASecret, user.MFARecoveryCodes, user.MFALastTimestep,
			user.AuthProvider, user.OIDCSubject, user.OIDCIssuer, user.IsSetupAdmin); err != nil {
			return fmt.Errorf("写入快照用户 %s: %w", user.Username, err)
		}
	}
	// 保护目标本地归一：canonical 载荷（v3 唯一下发形态）里的 is_setup_admin
	// 已被 sanitizeUsersForHash 清零，故本处恒命中「无标记」分支——按「最低 id 的
	// 启用管理员」在从节点重建，保证本地保护面可用。
	// 携带标记的非 canonical 载荷（旧协议/手工构造）不走该分支，归一按载荷事实
	// 处理：单条有效标记即便落在非最低 id 也保留（与配置备份同语义，迁移等于篡改
	// 载荷），陈旧标记（挂在非启用管理员行）清除，多条并存才收敛到最低 id。想要
	// 「恒按本地重建」的前提是载荷本身不带标记——这一点由 canonical 清零保证。
	if err := db.EnsureSetupAdminFlag(ctx, tx); err != nil {
		return fmt.Errorf("归一 setup 管理员标记: %w", err)
	}
	for _, key := range snapshot.APIKeys {
		// 空白名单落 ''(与主端 encodeMCPIPWhitelist
		// 同语义)——json.Marshal(nil) 产字面量 "null",中间件白名单守卫把
		// 非空串当配置(Unmarshal null 成功但 0 CIDR)→ 无白名单 Key 在
		// 从节点全来源 403。
		whitelistJSON := []byte("")
		if len(key.MCPIPWhitelist) > 0 {
			// 快照不经 REST 写侧校验：逐条规范化，无法解析的条目丢弃并留痕
			// （丢弃=收紧允许来源）。全部条目都非法时写显式 "[]" —— 中间件
			// 解析成功但 0 条网络，恒不匹配即 deny-all；绝不能落 ''（等同
			// 「无白名单」= 全来源放行，把畸形数据变成访问面放宽）。
			normalized, dropped := NormalizeMCPIPWhitelistStrings(key.MCPIPWhitelist)
			if len(dropped) > 0 {
				Logf("warn", "同步密钥 %d：MCP IP 白名单含无法解析的条目，已按 fail-closed 丢弃: %v", key.ID, dropped)
			}
			var err error
			whitelistJSON, err = json.Marshal(normalized)
			if err != nil {
				return fmt.Errorf("序列化快照密钥 %d 的 MCP IP 白名单: %w", key.ID, err)
			}
			if len(normalized) == 0 {
				Logf("warn", "同步密钥 %d：MCP IP 白名单全部条目无法解析，落显式 deny-all（该 Key 在从节点拒绝所有来源）", key.ID)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by,expires_at,is_enabled,mcp_enabled,read_only,mcp_ip_whitelist,last_used,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, key.ID, key.Name, key.KeyHash, key.KeyPrefix, key.CreatedBy, nullableString(key.ExpiresAt), key.IsEnabled, key.MCPEnabled, key.ReadOnly, string(whitelistJSON), nullableTimeFlat(key.LastUsed.NullTime), key.CreatedAt.UTC().Format(crsTimeLayout)); err != nil {
			return fmt.Errorf("写入快照密钥 %d: %w", key.ID, err)
		}
	}
	return nil
}

// loginLockoutState 是 users 表从节点本地登录记账（login_failed_attempts/
// login_locked_until）的读出快照：登录端点写入、不随集群快照同步。
type loginLockoutState struct {
	failedAttempts int
	lockedUntil    sql.NullString
	// 新1:mfa_last_timestep 本地态(TOTP 重放防护依据),重放后取 MAX 保留。
	mfaLastTimestep int64
	// last_login 是节点本地记账（登录端点写入，快照 canonical
	// 载荷将其清零），v3 信封化后从端拿到的就是清零值；users 节重放若不
	// 回写本地值，从节点用户页“最后登录”每次同步都会变成空。
	lastLogin sql.NullString
}

// readLocalLoginLockouts 在 users 节清表前读出存量 username → 登录记账。
// username 与主节点快照口径一致（UNIQUE 列），作为重放后回写的连接键。
func readLocalLoginLockouts(ctx context.Context, tx *sql.Tx) (map[string]loginLockoutState, error) {
	// 新1:同时读出 mfa_last_timestep——users 节重放若用
	// 主节点旧值覆盖,从节点已消费的 TOTP 码在 ±1 容差窗内重新可用,击穿
	// 重放防护;回写侧取 MAX 保留(见 restoreLocalLoginLockouts)。
	rows, err := tx.QueryContext(ctx, "SELECT username, COALESCE(login_failed_attempts,0), login_locked_until, COALESCE(mfa_last_timestep,0), last_login FROM users")
	if err != nil {
		return nil, fmt.Errorf("读取本地登录锁定记账: %w", err)
	}
	defer rows.Close()
	lockouts := make(map[string]loginLockoutState)
	for rows.Next() {
		var username string
		var state loginLockoutState
		if err := rows.Scan(&username, &state.failedAttempts, &state.lockedUntil, &state.mfaLastTimestep, &state.lastLogin); err != nil {
			return nil, fmt.Errorf("扫描本地登录锁定记账: %w", err)
		}
		lockouts[username] = state
	}
	return lockouts, rows.Err()
}

// readLocalAPIKeyLastUsed 在 api_keys 清表前读出存量 id → last_used（本地
// 调用记账，快照 canonical 清零）。同族：不回写会让从节点 API Key
// “最后使用”在每次 users 节重放后清空。
func readLocalAPIKeyLastUsed(ctx context.Context, tx *sql.Tx) (map[int]sql.NullString, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id, last_used FROM api_keys")
	if err != nil {
		return nil, fmt.Errorf("读取本地 API Key 使用记账: %w", err)
	}
	defer rows.Close()
	used := make(map[int]sql.NullString)
	for rows.Next() {
		var id int
		var lastUsed sql.NullString
		if err := rows.Scan(&id, &lastUsed); err != nil {
			return nil, fmt.Errorf("扫描本地 API Key 使用记账: %w", err)
		}
		used[id] = lastUsed
	}
	return used, rows.Err()
}

// restoreLocalAPIKeyLastUsed 在 api_keys 重插后按 id 回写本地 last_used：
// 取本地与快照中较晚者（快照通常为空，等价于保留本地值）；主节点已删除的
// Key UPDATE 命中 0 行，删除语义仍由快照回放保持。
func restoreLocalAPIKeyLastUsed(ctx context.Context, tx *sql.Tx, used map[int]sql.NullString) error {
	for id, lastUsed := range used {
		if _, err := tx.ExecContext(ctx, `UPDATE api_keys SET last_used=CASE
			WHEN ? IS NULL THEN last_used
			WHEN last_used IS NULL THEN ?
			WHEN last_used < ? THEN ?
			ELSE last_used END WHERE id=?`, lastUsed, lastUsed, lastUsed, lastUsed, id); err != nil {
			return fmt.Errorf("回写 API Key %d 的本地使用记账: %w", id, err)
		}
	}
	return nil
}

// restoreLocalLoginLockouts 在 users 节重插完成后按 username 回写本地登录记账。
// 主节点已删除（或改名）的用户 UPDATE 命中 0 行——删除语义由快照回放保持，
// 本地记账不复活用户。
func restoreLocalLoginLockouts(ctx context.Context, tx *sql.Tx, lockouts map[string]loginLockoutState) error {
	for username, state := range lockouts {
		// 新1:mfa_last_timestep 取 MAX(本地, 快照值)——timestep 随墙钟
		// 单调,取 max 不产生锁死(禁用/重置置 0 时旧值 < 未来码 step,安全);
		// 重放防护窗不再被主节点旧值重开。
		if _, err := tx.ExecContext(ctx, `UPDATE users SET login_failed_attempts=?, login_locked_until=?, mfa_last_timestep=MAX(COALESCE(mfa_last_timestep,0),?),
			last_login=CASE WHEN ? IS NULL THEN last_login WHEN last_login IS NULL THEN ? WHEN last_login < ? THEN ? ELSE last_login END
			WHERE username=?`, state.failedAttempts, state.lockedUntil, state.mfaLastTimestep, state.lastLogin, state.lastLogin, state.lastLogin, state.lastLogin, username); err != nil {
			return fmt.Errorf("回写用户 %s 的本地登录锁定记账: %w", username, err)
		}
	}
	return nil
}

// applyLockedUsers 把主节点活跃登录锁合并进从节点本地 users 表。
// 只延长、绝不缩短/清除、绝不动 login_failed_attempts：现有值为空或早于入参才
// 更新——固定格式 UTC 时间串的字典序即时间序（与 auth recordLoginFailure 写入、
// loginLockedNow 判定同口径），主从/本地锁取更晚者。陌生用户名（主端新锁用户
// 尚未随 users 节下发等）UPDATE 命中 0 行，安全落空；载荷 nil（旧主端）no-op，
// 绝不清除本地锁。主端解锁不传播（从端锁自然过期）——fail-closed 设计。
func applyLockedUsers(ctx context.Context, tx *sql.Tx, locked []models.ClusterLockedUser) error {
	skipped := 0
	for _, entry := range locked {
		// 载荷时间先归一为平面 UTC：上面的「只延长」判定是 SQL 字符串比较，
		// 字典序只有在两端同为 'YYYY-MM-DD HH:MM:SS' 时才等于时间序。旧主端/
		// 带外形态下发 RFC3339（'T' > 空格）会被判为「更晚」，把已过期/更早的
		// 锁写成非平面形态（后续 loginLockedNow 的比较与前端展示同时失真）；
		// 无法解析的形态完全不可信，跳过并留一条 warn——保留本地锁是
		// fail-closed 方向（不缩短）。
		lockedUntil, ok := normalizeSnapshotLockedUntil(entry.LockedUntil)
		if !ok {
			skipped++
			Logf("warn", "快照登录锁时间形态异常（用户名 %s，值 %q），已跳过该条（保留本地锁）", entry.Username, entry.LockedUntil)
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET login_locked_until=? WHERE username=? AND (login_locked_until IS NULL OR login_locked_until < ?)`,
			lockedUntil, entry.Username, lockedUntil); err != nil {
			return fmt.Errorf("同步用户 %s 的主节点登录锁: %w", entry.Username, err)
		}
	}
	return nil
}

// normalizeSnapshotLockedUntil 把快照登录锁时间归一为平面 UTC 串（写入侧唯一
// 格式），供 applyLockedUsers 的字符串比较与落库共用。接受两种来源形态
// （平面 + RFC3339，单源 parseUTCSlot）；空值/不可解析返回 false。
func normalizeSnapshotLockedUntil(value string) (string, bool) {
	parsed := parseUTCSlot(strings.TrimSpace(value))
	if parsed.IsZero() {
		return "", false
	}
	return parsed.UTC().Format(crsTimeLayout), true
}

// policyWhitelistEnabled 兼容旧快照缺列：缺省视为启用（语义=名单非空即生效）。
func policyWhitelistEnabled(p map[string]interface{}) bool {
	if v, ok := p["ip_whitelist_enabled"]; ok {
		// 快照 dump 的 INTEGER 列经 json.Unmarshal 落入 map 为 float64（0/1），
		// bool 形态仅手工构造快照出现——两种都必须接受，否则 0 被误判为启用
		//（主端关闭的信任名单在从端变更为启用，从端更宽松）。整数形态来自
		// normalizeSnapshotPolicyRow 的归一结果（幂等：归一后的行再次判定须
		// 得到同一答案）。
		switch t := v.(type) {
		case bool:
			return t
		case float64:
			return t != 0
		case int64:
			return t != 0
		case int:
			return t != 0
		}
	}
	return true
}

// snapshotTrustDetection 快照行的 trust_detection：缺列（旧主节点快照/旧备份）
// 归 0（直通语义不影响非 stage0 策略——该列仅 stage0 消费）。
func snapshotTrustDetection(p map[string]interface{}) interface{} {
	switch v := p["trust_detection"].(type) {
	case bool:
		return v
	case float64:
		return v != 0
	case int64:
		// 归一后的行（normalizeSnapshotPolicyRow 写成 SQLite INTEGER 形态）：
		// 再次判定必须得到同一布尔值，否则 apply 会把归一值写回 false。
		return v != 0
	case int:
		return v != 0
	}
	return false
}

// InferSnapshotPolicyType 快照行的策略类型：主节点显式值直接透传；”/缺失（旧主
// 节点快照、旧备份导入的缺列行）按内容推断（models.InferPolicyType 单一事实
// 源）——从节点/导入侧落库后类型不得滞留 ”（策略页分组与阶段外字段归一的
// 判定依赖）。
func InferSnapshotPolicyType(p map[string]interface{}) interface{} {
	if t, ok := p["policy_type"].(string); ok && t != "" {
		return t
	}
	asString := func(key string) string {
		s, _ := p[key].(string)
		return s
	}
	asBool := func(key string) bool {
		switch v := p[key].(type) {
		case bool:
			return v
		case float64:
			return v != 0
		}
		return false
	}
	asInt := func(key string) int {
		if v, ok := p[key].(float64); ok {
			return int(v)
		}
		return 0
	}
	return models.InferPolicyType(&models.SecurityPolicy{
		Mode:         asString("mode"),
		IPACLEnabled: asBool("ip_acl_enabled"), IPACLList: asString("ip_acl_list"), IPACLListRefs: asString("ip_acl_list_refs"),
		IPBlacklist:        json.RawMessage(asString("ip_blacklist")),
		IPWhitelistEnabled: asBool("ip_whitelist_enabled"), IPWhitelist: json.RawMessage(asString("ip_whitelist")), IPWhitelistRefs: asString("ip_whitelist_refs"),
		RateLimitEnabled: asBool("rate_limit_enabled"), RateLimitRPS: asInt("rate_limit_rps"),
		CustomRules: json.RawMessage(asString("custom_rules")),
		GeoIPMode:   asString("geoip_mode"), GeoIPCountries: json.RawMessage(asString("geoip_countries")),
	})
}

// applySecurityTables 把主节点安全表忠实复制到从节点。
//
// 已知且有意保留的覆盖边界（记入审计台账，非缺陷）：策略表的
// crs_rule_groups / crs_excluded_rules / geoip_countries 只作 JSON 文本透传，
// 本函数不做语义校验。主节点写侧（handlers 的保存/导入入口，含
// ValidateGeoIPCountries）已拦非法形状；可达的漏网面仅「带外直改主库 / 旧备份
// 绕过写侧校验」。渲染期若遇畸形 JSON：crs_rule_groups 按空集合降级=放行全量
// 规则组（安全方向），geoip_countries 按空集合降级=不渲染地域规则（deny 模式
// 会被静默削弱）——渲染侧对该形态有 60s 限流 warn。取舍是「忠实复制 + 可用性
// 优先」；如需加固，应在下发侧（validateSnapshotACMEState 家族）加只告警不阻断
// 的形状检查，而不是让从节点拒绝主机快照。
//
// syncBindings 决定是否按主节点载荷全量替换 security_policy_bindings——
// 绑定表是「规则 × 策略」的联结表，两个被引用面必须与载荷同源才可镜像。
// rules 开关关闭时从节点保留本地规则（正是该开关要保护的那批），此时清空
// 重建绑定会让本地规则静默失去全部 WAF 防护（渲染侧 policiesForRule 无命中
// = 无 WAF handler，fail-open），且从节点只读无法重建绑定；插入主端绑定则只
// 产生指向本机不存在规则的悬挂死行。故调用方传 !skip.disabled["rules"]，
// 本地绑定与本地规则同门保留（与 cert_jobs / ACME 表同一条不变量）。
// 策略/自定义规则/拦截页不引用规则 id，仍按安全节镜像。
func applySecurityTables(ctx context.Context, tx *sql.Tx, snapshot models.ClusterSnapshot, syncBindings bool) error {
	// 与规则/用户等表一致的全量替换语义：空载荷意味着主节点已清空，从节点必须
	// 同步删除，不能因载荷为空而提前返回。
	// security_crs_version/security_ip2region_version 的 DELETE 已随版本行
	// 应用挪至 waf_files 节(2026-09-11 裁定),此处不再清理。
	statements := []string{
		"DELETE FROM security_policies",
		"DELETE FROM security_custom_rules",
		"DELETE FROM security_block_pages",
		// security_ip_lists（v2.3.0）与威胁情报库源表（v2.3.x）不在此无条件
		// 删除：旧主端快照不携带该载荷时缺席=保留本地（见下方 nil 门），
		// 携带空数组 [] 才是显式清空。
	}
	if syncBindings {
		statements = append([]string{"DELETE FROM security_policy_bindings"}, statements...)
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("清理安全同步表: %w", err)
		}
	}
	// security_ip_lists 先于 security_policies 落库：策略 refs 以 JSON 引用
	// 列表 id，列表先行可保证引用目标即时存在（全量替换事务内顺序无正确性
	// 影响，固定顺序仅为确定性）。
	// 载荷缺席（旧主端 v2.3.0- 快照未携带该键）= 保留本地（不清空），与威胁
	// 源/爬虫源 nil 门同口径；携带空数组 [] = 显式清空；携带即全量替换。
	if snapshot.SecurityIPLists != nil {
		if _, err := tx.ExecContext(ctx, "DELETE FROM security_ip_lists"); err != nil {
			return fmt.Errorf("清理 security_ip_lists: %w", err)
		}
		var ipLists []map[string]interface{}
		if len(snapshot.SecurityIPLists) > 0 {
			if err := json.Unmarshal(snapshot.SecurityIPLists, &ipLists); err != nil {
				return fmt.Errorf("解析 security_ip_lists: %w", err)
			}
		}
		for _, l := range ipLists {
			entries, cerr := snapshotJSONText("security_ip_lists.entries", l["entries"])
			if cerr != nil {
				return fmt.Errorf("写入 security_ip_list（id=%v）失败: %w", l["id"], cerr)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO security_ip_lists (id,name,description,category,entries,created_by,created_at,updated_by,updated_at,system) VALUES (?,?,?,?,?,?,?,?,?,?)`,
				l["id"], l["name"], l["description"], l["category"], entries, l["created_by"], l["created_at"], l["updated_by"], l["updated_at"], l["system"]); err != nil {
				return fmt.Errorf("写入 security_ip_list: %w", err)
			}
		}
	}
	// 威胁情报库源行（v2.3.x）：载荷缺席（旧主端快照）= 保留本地（不清空），
	// 与 backup 侧「缺席表保留本地」同口径；携带即全量替换。
	if snapshot.SecurityThreatSources != nil {
		if _, err := tx.ExecContext(ctx, "DELETE FROM security_threat_sources"); err != nil {
			return fmt.Errorf("清理威胁库源表: %w", err)
		}
		var threatSources []map[string]interface{}
		if len(snapshot.SecurityThreatSources) > 0 {
			if err := json.Unmarshal(snapshot.SecurityThreatSources, &threatSources); err != nil {
				return fmt.Errorf("解析 security_threat_sources: %w", err)
			}
		}
		for _, row := range threatSources {
			normalizeSnapshotSourceRow(row)
			if _, err := tx.ExecContext(ctx, `INSERT INTO security_threat_sources (id,name,display_name,url,format,update_enabled,apply_enabled,entry_count,version,update_status,message,last_checked,next_update,trigger,started_at,finished_at,consecutive_failures,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				row["id"], row["name"], row["display_name"], row["url"], row["format"], row["update_enabled"], row["apply_enabled"], row["entry_count"], row["version"], row["update_status"], row["message"],
				snapshotNullableDatetime(row["last_checked"]), snapshotNullableDatetime(row["next_update"]), row["trigger"],
				snapshotNullableDatetime(row["started_at"]), snapshotNullableDatetime(row["finished_at"]),
				row["consecutive_failures"], row["created_at"], row["updated_at"]); err != nil {
				return fmt.Errorf("写入威胁库源行: %w", err)
			}
		}

	}
	// 爬虫地址库独立源行：载荷缺席=保留本地，携带即全量替换（与威胁源同语义）。
	if snapshot.SecurityCrawlerSources != nil {
		if _, err := tx.ExecContext(ctx, "DELETE FROM security_crawler_sources"); err != nil {
			return fmt.Errorf("清理爬虫地址库源表: %w", err)
		}
		var crawlerSources []map[string]interface{}
		if len(snapshot.SecurityCrawlerSources) > 0 {
			if err := json.Unmarshal(snapshot.SecurityCrawlerSources, &crawlerSources); err != nil {
				return fmt.Errorf("解析 security_crawler_sources: %w", err)
			}
		}
		for _, row := range crawlerSources {
			normalizeSnapshotSourceRow(row)
			if _, err := tx.ExecContext(ctx, `INSERT INTO security_crawler_sources (id,name,display_name,url,format,update_enabled,entry_count,version,update_status,message,last_checked,next_update,trigger,started_at,finished_at,consecutive_failures,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				row["id"], row["name"], row["display_name"], row["url"], row["format"], row["update_enabled"], row["entry_count"], row["version"], row["update_status"], row["message"],
				snapshotNullableDatetime(row["last_checked"]), snapshotNullableDatetime(row["next_update"]), row["trigger"],
				snapshotNullableDatetime(row["started_at"]), snapshotNullableDatetime(row["finished_at"]),
				row["consecutive_failures"], row["created_at"], row["updated_at"]); err != nil {
				return fmt.Errorf("写入爬虫地址库源行: %w", err)
			}
		}
	}
	var policies []map[string]interface{}
	if len(snapshot.SecurityPolicies) > 0 {
		if err := json.Unmarshal(snapshot.SecurityPolicies, &policies); err != nil {
			return fmt.Errorf("解析 security_policies: %w", err)
		}
	}
	for _, p := range policies {
		// (2026-09-10 审计):滚动升级窗口告警——旧主节点(v2.2.6-)快照可能
		// 携带 mode=off+启用自定义规则(旧语义仍发射),新语义 off=全关渲染,
		// 该策略的自定义拦截静默失效直至主节点升级并重发快照。一行 warn 提示
		// 运维,不改变应用行为。
		// warn 加启用判定——off+全停用规则也告警是
		// 误报(与迁移判定口径一致,只关心 enabled=1 的规则)。custom_rules
		// 两种形状(ID 数组/内嵌对象)都检查 enabled 键。
		if p["mode"] == "off" {
			var crs []interface{}
			if raw, ok := p["custom_rules"].(string); ok {
				json.Unmarshal([]byte(raw), &crs)
			} else if arr, ok := p["custom_rules"].([]interface{}); ok {
				crs = arr
			}
			hasEnabled := false
			for _, cr := range crs {
				if m, ok := cr.(map[string]interface{}); ok {
					if v, ok := m["enabled"].(bool); ok && v {
						hasEnabled = true
						break
					}
				}
			}
			// ID 数组形状(现代存储形态)元素为数字,
			// 上面 map 断言恒 false——需连 snapshot.SecurityCustomRules 查启用态
			if !hasEnabled && len(crs) > 0 {
				for _, cr := range crs {
					if id, ok := cr.(float64); ok {
						for _, scr := range snapshot.SecurityCustomRules {
							if int(scr.ID) == int(id) && scr.Enabled {
								hasEnabled = true
								break
							}
						}
						if hasEnabled {
							break
						}
					}
				}
			}
			if hasEnabled {
				Logf("warn", "快照携带 mode=off 且挂启用自定义规则的策略 %v(旧主节点语义):新版本 off=全关,该策略自定义规则暂不生效,请升级主节点后由其重发快照(或改用 custom_only)", p["name"])
			}
		}
		// 库值唯一真相（批 3）：apply 门值列归一（与 security 节哈希输入共用
		// normalizeSnapshotPolicyRow 单源——两侧各写一份会让「主端哈希 ≠ 从端
		// 落库后重建哈希」长期不等，节点列表该节永久显示滞后）。
		normalizeSnapshotPolicyRow(p)
		// JSON 文本列逐列序列化，任一失败即中止本条策略（fail-visible）：静默
		// 落 NULL 会让读路径的 COALESCE 兜底掩盖形态错误——例如
		// geoip_countries 变 NULL 时渲染按「无地域规则」降级（deny 模式静默削弱）。
		policyJSON := make(map[string]interface{}, len(snapshotPolicyJSONColumns))
		for _, column := range snapshotPolicyJSONColumns {
			text, cerr := snapshotJSONText(column, p[column])
			if cerr != nil {
				return fmt.Errorf("写入 security_policy（id=%v）失败: %w", p["id"], cerr)
			}
			policyJSON[column] = text
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_policies (id,name,description,mode,anomaly_threshold,ip_acl_mode,ip_acl_list,ip_acl_enabled,ip_whitelist,ip_whitelist_enabled,ip_blacklist,rate_limit_enabled,rate_limit_rps,rate_limit_burst,crs_rule_groups,crs_excluded_rules,custom_rules,block_page_id,block_status_code,enabled,updated_by,created_at,updated_at,geoip_countries,geoip_mode,geoip_crawler_exempt,geoip_crawler_engines,waf_check_response,log_request_body,ip_acl_list_refs,ip_whitelist_refs,policy_type,trust_detection) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			p["id"], p["name"], p["description"], p["mode"], p["anomaly_threshold"],
			p["ip_acl_mode"], policyJSON["ip_acl_list"], p["ip_acl_enabled"],
			policyJSON["ip_whitelist"], policyWhitelistEnabled(p), policyJSON["ip_blacklist"],
			p["rate_limit_enabled"], p["rate_limit_rps"], p["rate_limit_burst"],
			policyJSON["crs_rule_groups"], policyJSON["crs_excluded_rules"], policyJSON["custom_rules"],
			p["block_page_id"], p["block_status_code"], p["enabled"], p["updated_by"], p["created_at"], p["updated_at"],
			policyJSON["geoip_countries"], p["geoip_mode"], p["geoip_crawler_exempt"], policyJSON["geoip_crawler_engines"], p["waf_check_response"], p["log_request_body"],
			policyJSON["ip_acl_list_refs"], policyJSON["ip_whitelist_refs"], InferSnapshotPolicyType(p), snapshotTrustDetection(p)); err != nil {
			return fmt.Errorf("写入 security_policy: %w", err)
		}
	}
	var bindings []map[string]interface{}
	if syncBindings && len(snapshot.SecurityBindings) > 0 {
		if err := json.Unmarshal(snapshot.SecurityBindings, &bindings); err != nil {
			return fmt.Errorf("解析 security_bindings: %w", err)
		}
	}
	for _, b := range bindings {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)`, b["rule_caddy_id"], b["policy_id"]); err != nil {
			return fmt.Errorf("写入 security_policy_binding: %w", err)
		}
	}
	if !syncBindings {
		// 规则轴不同步时保留的本地绑定可能引用主节点策略集里已不存在的
		// policy_id（例如本机曾是主节点、策略编号与主端不同）——该绑定渲染时
		// 无命中即无防护。行为不变（保留数据），但把它显式记成一条 warn，
		// 避免「已保留绑定」被误读为「本地规则仍在防护中」。
		var dangling int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_policy_bindings b
			WHERE NOT EXISTS (SELECT 1 FROM security_policies p WHERE p.id=b.policy_id)`).Scan(&dangling); err != nil {
			return fmt.Errorf("检查保留的本地安全策略绑定: %w", err)
		}
		if dangling > 0 {
			Logf("warn", "规则同步已关闭：保留的本地安全策略绑定有 %d 条引用了主节点不存在的策略，这些绑定不产生防护；如需本地 WAF 请同时关闭安全防护同步", dangling)
		}
	}
	if err := applySecurityCustomRules(ctx, tx, snapshot.SecurityCustomRules); err != nil {
		return err
	}
	if err := applySecurityBlockPages(ctx, tx, snapshot.SecurityBlockPages); err != nil {
		return err
	}
	return nil
}

// warnPreservedBindingPolicyOverrides 留痕「规则轴不同步 + 安全节重放」形态下
// 保留的本地绑定所命中、且内容会被主端同 id 载荷覆盖的策略条数。
//
// 背景：绑定表与 rules 开关同门（本地绑定保留），但策略表仍按安全节镜像——
// 同 id 策略的内容随主端改变，绑定命中的保护语义（mode/geoip/自定义规则…）
// 静默换成主端形态。既有「悬挂 id」warn 只数「策略不存在」，该形态 id 仍在
// 故零信号（关闭规则同步正是为了保住本地防护，被放宽却无痕＝fail-open 且
// 不可解）。本函数在事务内、删除前读本地面，用与主端快照**同一 dump 函数与
// 同一 COALESCE 列清单**（值域可比）逐 id 比对。
//
// 失败一律不阻断 apply：这是可观测性留痕，读/解码失败按「检查已降级」自身
// 留痕（静默跳过让告警覆盖不可判定却看起来正常）。
func (s *SyncService) warnPreservedBindingPolicyOverrides(ctx context.Context, tx *sql.Tx, snapshot models.ClusterSnapshot) {
	if len(snapshot.SecurityPolicies) == 0 || s.cluster == nil {
		// 空载荷=主节点已清空策略表，保留绑定随即成为悬挂行（由 applySecurityTables
		// 的 dangling warn 覆盖），无需逐 id 内容比对。
		return
	}
	bindingPolicyIDs, err := readBindingPolicyIDs(ctx, tx)
	if err != nil {
		Logf("warn", "集群同步：读取保留的安全策略绑定失败，跳过策略覆盖检查: %v", err)
		return
	}
	if len(bindingPolicyIDs) == 0 {
		return
	}
	localPolicies, err := s.cluster.snapshotSecurityPolicies(ctx, tx)
	if err != nil {
		Logf("warn", "集群同步：读取本地安全策略失败，跳过策略覆盖检查: %v", err)
		return
	}
	overridden, err := countPreservedBindingPolicyOverrides(localPolicies, snapshot.SecurityPolicies, bindingPolicyIDs)
	if err != nil {
		Logf("warn", "集群同步：比对本地安全策略与主节点载荷失败，跳过策略覆盖检查: %v", err)
		return
	}
	if overridden == 0 {
		return
	}
	Logf("warn", "规则同步已关闭：保留的本地安全策略绑定命中的 %d 条策略内容已被本轮主端镜像覆盖（保护语义随之改变）；如需完全保留本地策略，请同时关闭安全防护同步", overridden)
}

// readBindingPolicyIDs 返回保留绑定引用的策略 id 集合（distinct）。
func readBindingPolicyIDs(ctx context.Context, store snapshotStore) (map[int64]struct{}, error) {
	rows, err := store.QueryContext(ctx, `SELECT DISTINCT policy_id FROM security_policy_bindings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := map[int64]struct{}{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			// 与行遍历错误同口径 fail-visible：部分集合会让「被覆盖」的通知
			// 静默变少（告警缺口比多报更危险）。
			return nil, err
		}
		ids[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}

// countPreservedBindingPolicyOverrides 统计「绑定引用且在两侧都存在、但内容
// 不同」的策略条数。两侧行都经 normalizeSnapshotPolicyRow 归一并按关键字序
// 序列化（与 security 节哈希同一归一单源），本地 dump 的 COALESCE 归一与主端
// 载荷同域，故「空值形态差异」不会误报。
func countPreservedBindingPolicyOverrides(localPolicies, masterPolicies json.RawMessage, bindingPolicyIDs map[int64]struct{}) (int, error) {
	localByID, err := indexSnapshotPolicyRows(localPolicies)
	if err != nil {
		return 0, fmt.Errorf("解析本地安全策略: %w", err)
	}
	var masterRows []map[string]interface{}
	if err := json.Unmarshal(masterPolicies, &masterRows); err != nil {
		return 0, fmt.Errorf("解析主节点安全策略: %w", err)
	}
	overridden := 0
	for _, row := range masterRows {
		if row == nil {
			continue
		}
		if _, hit := bindingPolicyIDs[int64(toFloat64(row["id"]))]; !hit {
			continue
		}
		localRow, exists := localByID[int64(toFloat64(row["id"]))]
		if !exists {
			// 本地无同 id 行：绑定将成为悬挂行，由 applySecurityTables 的
			// dangling warn 覆盖（本告警只讲「内容被覆盖」）。
			continue
		}
		localContent, err := canonicalSnapshotPolicyContent(localRow)
		if err != nil {
			return 0, err
		}
		masterContent, err := canonicalSnapshotPolicyContent(row)
		if err != nil {
			return 0, err
		}
		if localContent != masterContent {
			overridden++
		}
	}
	return overridden, nil
}

// indexSnapshotPolicyRows 把策略行载荷按 id 建索引（空/缺失载荷返回空 map）。
func indexSnapshotPolicyRows(raw json.RawMessage) (map[int64]map[string]interface{}, error) {
	rows := map[int64]map[string]interface{}{}
	if len(raw) == 0 {
		return rows, nil
	}
	var decoded []map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	for _, row := range decoded {
		if row == nil {
			continue
		}
		rows[int64(toFloat64(row["id"]))] = row
	}
	return rows, nil
}

// canonicalSnapshotPolicyContent 返回归一后的策略行内容指纹：normalizeSnapshotPolicyRow
// 是 apply 写侧与 security 节哈希的共用归一（单源），键序由 encoding/json 的
// map 排序保证确定。归一在副本上执行，不污染调用方的行。
func canonicalSnapshotPolicyContent(row map[string]interface{}) (string, error) {
	copied := make(map[string]interface{}, len(row)+2)
	for key, value := range row {
		copied[key] = value
	}
	normalizeSnapshotPolicyRow(copied)
	encoded, err := json.Marshal(copied)
	if err != nil {
		return "", fmt.Errorf("序列化安全策略（id=%v）: %w", row["id"], err)
	}
	return string(encoded), nil
}

// snapshotPolicyJSONColumns 是 security_policies 的 JSON 文本列（值经
// dumpTableAsJSON 已为 JSON 字符串，落库前仍需按列序列化并在失败时中止）。
var snapshotPolicyJSONColumns = []string{
	"ip_acl_list",
	"ip_whitelist",
	"ip_blacklist",
	"crs_rule_groups",
	"crs_excluded_rules",
	"custom_rules",
	"geoip_countries",
	"geoip_crawler_engines",
	"ip_acl_list_refs",
	"ip_whitelist_refs",
}

// snapshotJSONText 写入快照中的 JSON 文本列。dumpTableAsJSON 已把该列作为
// JSON 字符串携带，直接透传，避免二次编码成带引号的字面量。
// 序列化失败返回 error（fail-visible）：此前返回 nil 让该列静默落 NULL，读路径
// COALESCE 兜底会把形态错误掩盖成「空列表」——geoip_countries 变空即 deny 模式
// 静默削弱、crs_rule_groups 变空即放行全量规则组，均不可接受。
func snapshotJSONText(column string, value interface{}) (interface{}, error) {
	switch v := value.(type) {
	case nil:
		return nil, nil
	case string:
		return v, nil
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("列 %s 的值（%T）无法序列化为 JSON: %w", column, value, err)
		}
		return string(encoded), nil
	}
}

func applySecurityCustomRules(ctx context.Context, tx *sql.Tx, rules []models.SecurityCustomRule) error {
	// 只读预检：主节点下发的规则若含尾部反斜杠/空条件/非法 target 或 operator，
	// 发射侧会整条跳过它们（safe no-op），此处仅记录一条告警，不阻断忠实复制
	// （从节点与主节点保持一致）。
	invalid := false
	for _, rule := range rules {
		// 补 customRuleEmissionIssue（含名字控制字符/双引号、
		// legacy 单 target 形态）——此前只查 conditions，名字含引号的规则被
		// 忠实复制到从节点但仅在发射时跳过，复制阶段无告警（可观测性缺口）。
		if conditionsEmissionIssue(rule.Conditions) != "" || customRuleEmissionIssue(models.CustomRule{
			ID:             rule.ID,
			Name:           rule.Name,
			Enabled:        rule.Enabled,
			Conditions:     rule.Conditions,
			ConditionLogic: rule.ConditionLogic,
			Action:         rule.Action,
			Score:          rule.Score,
		}) != "" {
			invalid = true
			break
		}
	}
	if invalid {
		Logf("warn", "集群同步的自定义规则存在非法项（尾部反斜杠/空条件/非法 target/operator 或名字含控制字符），发射时将跳过 — 主节点应尽快修复")
	}
	for _, rule := range rules {
		conditions := rule.Conditions
		if conditions == nil {
			conditions = []models.CustomRuleCondition{}
		}
		conditionsJSON, err := json.Marshal(conditions)
		if err != nil {
			return fmt.Errorf("序列化快照自定义安全规则 %d 的条件: %w", rule.ID, err)
		}
		conditionLogic := rule.ConditionLogic
		if conditionLogic == "" {
			conditionLogic = "and"
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_custom_rules (id,name,description,conditions,condition_logic,action,score,enabled,updated_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			rule.ID, rule.Name, rule.Description, string(conditionsJSON), conditionLogic, rule.Action, rule.Score, rule.Enabled, rule.UpdatedBy, rule.CreatedAt, rule.UpdatedAt); err != nil {
			return fmt.Errorf("写入快照自定义安全规则 %d: %w", rule.ID, err)
		}
	}
	return nil
}

func applySecurityBlockPages(ctx context.Context, tx *sql.Tx, pages []models.SecurityBlockPage) error {
	for _, page := range pages {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_block_pages (id,name,description,content,content_type,is_default,is_builtin,created_by,created_at,updated_by,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			page.ID, page.Name, page.Description, page.Content, page.ContentType, page.IsDefault, page.IsBuiltin, page.CreatedBy, page.CreatedAt, page.UpdatedBy, page.UpdatedAt); err != nil {
			return fmt.Errorf("写入快照拦截页面 %d: %w", page.ID, err)
		}
	}
	// 快照（或经主节点扩散的快照）可能携带 ≥2 个 is_default=1
	// 的拦截页，全部落库后均不可编辑/删除且会被 branding 覆盖。从节点侧防御：
	// 降级多余默认页，仅保留 MIN(id) 一行，与主节点导入路径行为一致。
	if _, err := tx.ExecContext(ctx, `UPDATE security_block_pages SET is_default=0 WHERE is_default=1 AND id != (SELECT MIN(id) FROM security_block_pages WHERE is_default=1)`); err != nil {
		return fmt.Errorf("降级多余的默认拦截页: %w", err)
	}
	// 保留行内容可能为种子库存而用户定制内容在被降级行上。内容提升
	// 只在主节点导入路径做（config_backup.go 可渲染 branding 判定「库存」内容）；
	// 从节点无 branding 渲染可用，且须与主节点内容忠实一致，此处不做提升——
	// 主节点修复后随后续同步自愈。
	return nil
}

// clusterRuleLibVersionInsertSQL 是 CRS/IP2Region 版本行的写入单源
// 与 clusterRuleLibVersionColumns 的列集合逐列对应；
// 表名由调用方白名单传入（仅两张固定表）。
const clusterRuleLibVersionInsertSQL = `INSERT INTO %s (id,version,updated_at,auto_update,update_status,message,last_checked,next_update,trigger,started_at,finished_at,schedule_days,schedule_time) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`

// snapshotActiveUpdateStatusMessage 是快照搬运来的活动态在从端的归一文案：
// 从节点不可能执行该类任务（RunsOn=RoleMasterOnly），保留「更新中」是假
// 运行态，按 failed + 本句解释归一（与启动期「进程重启回收」同族但归属不同）。
const snapshotActiveUpdateStatusMessage = "来自主节点快照的进行中状态，本节点不执行该任务"

// snapshotActiveUpdateStatus 判定快照载荷里的状态是否属于「进行中」活动态。
// 判据单源 IsActiveUpdateStatus（覆盖 CRS/IP2Region 四活动词与源表 running），
// 快照通道与配置导入通道必须共用同一类判据（保留本薄封装：跨包测试以它钉住
// 判据口径，删除会让判据失去唯一直测入口）。
func snapshotActiveUpdateStatus(status string) bool {
	return IsActiveUpdateStatus(status)
}

// normalizeSnapshotPolicyRow 把快照策略行归一为「从端落库值」口径，单源供
// apply 写侧与 security 节哈希输入共用：
//   - anomaly_threshold<=0/nil→db.DefaultAnomalyThreshold（Create 侧默认，与
//     主节点启动回填同口径）；
//   - rate_limit_burst<0→0（省略型规范值，负值仅带外可达）；
//   - block_status_code 枚举外→db.DefaultBlockStatusCode（默认拦截状态码，与
//     启动归一/导入门同口径）。
//     rate_limit_rps 有意不归一：无默认可归，镜像语义下主从渲染同报错
//     （fail-visible，buildRateLimitHandler）；
//   - geoip_crawler_exempt/engines 缺列补 schema 默认（旧主节点/手工快照），
//     NOT NULL 新列不得把兼容载荷变成整条 apply 失败；
//   - 派生列 policy_type/trust_detection/ip_whitelist_enabled 按落库形态
//     （字符串/INTEGER 0-1）写入行——apply 在 INSERT 时计算，哈希侧必须同形，
//     否则同一行两侧字节不等。
func normalizeSnapshotPolicyRow(p map[string]interface{}) {
	if toFloat64(p["anomaly_threshold"]) <= 0 {
		p["anomaly_threshold"] = int64(db.DefaultAnomalyThreshold)
	}
	if toFloat64(p["rate_limit_burst"]) < 0 {
		p["rate_limit_burst"] = int64(0)
	}
	if !ValidBlockStatusCode(int(toFloat64(p["block_status_code"]))) {
		p["block_status_code"] = int64(db.DefaultBlockStatusCode)
	}
	if p["geoip_crawler_exempt"] == nil {
		p["geoip_crawler_exempt"] = int64(0)
	}
	if p["geoip_crawler_engines"] == nil {
		p["geoip_crawler_engines"] = "[]"
	}
	p["policy_type"] = InferSnapshotPolicyType(p)
	p["trust_detection"] = boolToSnapshotInteger(snapshotTrustDetection(p))
	if policyWhitelistEnabled(p) {
		p["ip_whitelist_enabled"] = int64(1)
	} else {
		p["ip_whitelist_enabled"] = int64(0)
	}
}

// boolToSnapshotInteger 把归一结果写成 SQLite INTEGER 列的快照字节形态
// （dump 侧 0/1 数值），避免哈希输入出现 true/false 与 1/0 两种编码。
func boolToSnapshotInteger(value interface{}) int64 {
	switch v := value.(type) {
	case bool:
		if v {
			return 1
		}
		return 0
	}
	return 0
}

// normalizeSnapshotSourceRow 归一源表行（威胁情报库/爬虫地址库）的活动态任务
// 三列，写回行 map——apply 写侧与 security 节哈希输入共用。活动态只属于执行
// 该任务的进程；从节点收到后若不归一，主端以「已是最新/失败」收尾时只写运行
// 态列、不 bump 版本，从端行会长期滞留活动态且无任何收敛通道。
func normalizeSnapshotSourceRow(row map[string]interface{}) {
	updateStatus, message, finishedAt := normalizeSnapshotTaskState(row["update_status"], row["message"], row["last_checked"], row["finished_at"])
	row["update_status"], row["message"], row["finished_at"] = updateStatus, message, finishedAt
}

// normalizeSnapshotTaskState 归一从主端快照搬运的活动态任务行：
// status→failed、message→来源说明、finished_at→主端最后检查时刻。
// 非活动态三列原样返回（保持源值，含 nil 与自定义文案）。
//
// 活动态行在主端本无结束时间；只改状态与文案会让落库行呈现「已失败但
// finished_at 为空」，任务监控的耗时统计按当前时刻计算并持续增长，升主后
// 残留的 started_at 也会串味。以主端 last_checked（该活动态最后一次被
// 观测的时刻）作为结束时间；缺失时才回退源 finished_at。
func normalizeSnapshotTaskState(status, message, lastChecked, finishedAt any) (any, any, any) {
	text, _ := status.(string)
	if !snapshotActiveUpdateStatus(text) {
		return status, message, finishedAt
	}
	if snapshotDatetimePresent(lastChecked) {
		return "failed", snapshotActiveUpdateStatusMessage, lastChecked
	}
	return "failed", snapshotActiveUpdateStatusMessage, finishedAt
}

// snapshotDatetimePresent 判定快照载荷时间列是否有值（nil/空白串=无值）。
func snapshotDatetimePresent(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	}
	return true
}

// snapshotDatetimeText 把归一结果按字符串形态交给 nullableString（版本行
// 参数为字符串列）。
func snapshotDatetimeText(value any) string {
	text, _ := value.(string)
	return text
}

// applyRuleLibVersionRows 全量替换写入一张版本表（先清后插由调用方负责）。
func applyRuleLibVersionRows(ctx context.Context, tx *sql.Tx, table string, rows []clusterRuleLibVersionRow) error {
	statement := fmt.Sprintf(clusterRuleLibVersionInsertSQL, table)
	for _, row := range rows {
		// 活动态（checking/downloading/installing/reloading）只属于执行该
		// 任务的进程；从节点不运行该任务，落到本地的活动态是主端镜像且
		// 永不收敛 → 归一（含结束时间）并解释来源。
		updateStatus, message, finishedAt := normalizeSnapshotTaskState(row.UpdateStatus, row.Message, row.LastChecked, row.FinishedAt)
		// schedule_days/schedule_time 随版本行全量替换
		// 落库（升主即生效）；空串来源=旧主端快照缺列，读取端 normalizeScheduleRow
		// 回落默认，与 NOT NULL 约束兼容。
		if _, err := tx.ExecContext(ctx, statement, row.ID, row.Version, nullableString(row.UpdatedAt), row.AutoUpdate, updateStatus, message,
			nullableString(row.LastChecked), nullableString(row.NextUpdate), nullableString(row.Trigger), nullableString(row.StartedAt), nullableString(snapshotDatetimeText(finishedAt)),
			row.ScheduleDays, row.ScheduleTime); err != nil {
			return fmt.Errorf("写入快照 %s 版本 %d: %w", table, row.ID, err)
		}
	}
	return nil
}

func applySecurityCRSVersion(ctx context.Context, tx *sql.Tx, versions []models.ClusterSecurityCRSVersion) error {
	rows := make([]clusterRuleLibVersionRow, 0, len(versions))
	for _, version := range versions {
		rows = append(rows, clusterRuleLibVersionRow(version))
	}
	return applyRuleLibVersionRows(ctx, tx, "security_crs_version", rows)
}

func applySecurityIP2RegionVersion(ctx context.Context, tx *sql.Tx, versions []models.ClusterSecurityIP2RegionVersion) error {
	rows := make([]clusterRuleLibVersionRow, 0, len(versions))
	for _, version := range versions {
		rows = append(rows, clusterRuleLibVersionRow(version))
	}
	return applyRuleLibVersionRows(ctx, tx, "security_ip2region_version", rows)
}

func validateSnapshotACMEState(snapshot models.ClusterSnapshot) error {
	if snapshot.ACME == nil {
		// 生产仅 v3 快照可达此处（verifiedSnapshotIntegrity 已按
		// SchemaVersion==CurrentSnapshotSchema 拒掉过旧/过新），旧 v2 放行
		// 分支不可达，缺 ACME 区段统一硬拒。
		return errors.New("schema v3 快照缺少必需的 ACME 区段")
	}
	if snapshot.ACME.CAProviders == nil || snapshot.ACME.CertificateConfigs == nil || len(snapshot.ACME.DNSOwnership) == 0 {
		return errors.New("快照 ACME 区段缺少 ca_providers、certificate_configs 或 dns_ownership")
	}
	if err := validateDNSOwnership(snapshot.ACME.DNSOwnership); err != nil {
		return err
	}
	providers := make(map[int]struct{}, len(snapshot.ACME.CAProviders))
	for _, provider := range snapshot.ACME.CAProviders {
		if provider.ID <= 0 || provider.Name == "" || provider.Provider == "" || provider.DirectoryURL == "" {
			// 行级坏数据（仅 v1 导入残留/直改库可达）整包拒绝会让
			// rules/users 等无关节同步一并瘫痪——与发现3/ 同型
			// 逐行 warn+continue，坏行照常镜像落库（空串不违反
			// NOT NULL），该行名下签发由主节点按单任务失败承担，修复后自愈。
			Logf("warn", "快照 CA 提供商 %d 字段不完整（单行损坏，跳过该校验，该行名下签发将按单任务失败），需人工修复", provider.ID)
			continue
		}
		providers[provider.ID] = struct{}{}
	}
	configs := make(map[int]struct{}, len(snapshot.ACME.CertificateConfigs))
	for _, config := range snapshot.ACME.CertificateConfigs {
		if config.ID <= 0 || config.Name == "" || config.DNSProvider == "" {
			Logf("warn", "快照证书配置 %d 字段不完整（单行损坏，跳过该校验，该行名下签发将按单任务失败），需人工修复", config.ID)
			continue
		}
		configs[config.ID] = struct{}{}
	}
	for _, rule := range snapshot.Rules {
		if !rule.EnableTLS || rule.TLSSource != "acme_dns" {
			continue
		}
		// 发现3：acme_config_id=0 / 悬挂配置引用在主节点是「单规则损坏」
		// 状态（issuer 按单任务失败，写入侧已被三层校验+事务内应用
		// 拦截，仅导入残留/直改库可达）。整包拒绝会让一条坏规则瘫痪全部从
		// 节点同步——对齐 verifySnapshotConsistency 的 fail-open 哲学，逐条
		// 跳过+warn，主节点修复后随后续同步自愈。
		if rule.ACMEConfigID == 0 {
			Logf("warn", "快照规则 %s 未设置证书配置（单规则损坏，跳过该校验，签发将按单任务失败），需人工修复", rule.CaddyID)
			continue
		}
		if _, exists := configs[rule.ACMEConfigID]; !exists {
			Logf("warn", "快照规则 %s 引用了不存在的证书配置 %d（单规则损坏，跳过该校验，签发将按单任务失败），需人工修复", rule.CaddyID, rule.ACMEConfigID)
			continue
		}
		if rule.CAProviderID != 0 {
			if _, exists := providers[rule.CAProviderID]; exists {
				continue
			}
			// 悬挂 CA 提供商引用与 acme_config_id 轴同型 fail-open
			// 整包拒绝会让一条坏规则瘫痪全部从节点同步；签发
			// 仅主节点，按单任务失败/回退，主节点修复后随后续同步自愈。
			Logf("warn", "快照规则 %s 引用了不存在的 CA 提供商 %d（单规则损坏，跳过该校验，签发将按单任务失败），需人工修复", rule.CaddyID, rule.CAProviderID)
			continue
		}
	}
	for _, cert := range snapshot.Certs {
		if cert.CAProviderID == 0 {
			continue
		}
		if _, exists := providers[cert.CAProviderID]; !exists {
			// 证书行的悬挂 CA 引用同样 fail-open——证书文件由
			// materializeSnapshotCerts 同步、签发仅主节点，整包拒绝会让
			// 全部从节点永久 degraded（ValidationFailed 每周期重试但永不收敛）。
			Logf("warn", "快照证书 %s 引用了不存在的 CA 提供商 %d（单证书损坏，跳过该校验），需人工修复", cert.RuleID, cert.CAProviderID)
			continue
		}
	}
	return nil
}

// canonicalSnapshotCertDomain 把快照证书行的域串归一为排序规范形；不可规范化
// （空串/历史畸形形态）时原样返回——空串的 COALESCE 语义（回退规则域）与既有
// 容错行为保持不变。落库值必须与消费面（任务 upsert 冲突键与精确回查、
// HasCertJob）的规范串口径一致，否则同规则同域集会在从端并存两行。
func canonicalSnapshotCertDomain(domain string) string {
	if canonical, err := CanonicalACMEDomains(domain); err == nil {
		return canonical
	}
	return domain
}

func insertSnapshotRules(ctx context.Context, tx *sql.Tx, rules []models.LbRule) error {
	// 生成式子路由 @id 命名空间保留（与 v2 导入同门）：主端快照若含
	// <规则ID>_path_<n>/_geoip/_redirect 形态的第二条规则，从端渲染同样会被
	// Caddy 以 duplicate ID 拒绝；在落库前点名，避免整节应用失败只留下引擎级
	// 配置路径错误。
	ruleIDs := make([]string, 0, len(rules))
	for _, rule := range rules {
		ruleIDs = append(ruleIDs, rule.CaddyID)
	}
	for _, rule := range rules {
		if conflict := RuleIDNamespaceConflict(rule.CaddyID, ruleIDs); conflict != "" {
			return fmt.Errorf("快照规则 %q 与规则 %q 的子路由 @id 命名空间冲突", rule.CaddyID, conflict)
		}
	}
	// INSERT 列清单与值投影走唯一事实源（rule_write_columns.go），
	// 全量列（含 id 与审计四列）——从端镜像必须保留主端主键与审计值。
	columns := LbRuleInsertColumns()
	statement := LbRuleInsertSQL(columns)
	for _, rule := range rules {
		// 传输归一（单一事实源，2026-10-11）：与主端 snapshotRules 导出共用
		// normalizeRuleForTransport（body 钳制[]/TCP+TLS 死形态[]/
		// TCP 七字段[]）——三面（导出/从端落库/备份导入）同构是 rules
		// 节哈希主从相等的不变量基础。历史两处平行手写块改一侧漏另一侧即
		// 本次「分区滞后」永不自愈事故的根因。
		normalizeRuleForTransport(&rule)
		if _, err := tx.ExecContext(ctx, statement, LbRuleInsertArgs(&rule, columns)...); err != nil {
			return fmt.Errorf("写入快照规则 %s: %w", rule.CaddyID, err)
		}
		for _, upstream := range rule.Upstreams {
			// 上游传输归一（单一事实源，与主端导出同函数）：落库值与导出
			// canonical 必须同形，否则 rules 节哈希主从恒不等。
			normalizeUpstreamForTransport(&upstream, rule.Protocol)
			if _, err := tx.ExecContext(ctx, `INSERT INTO upstreams (id,rule_id,host,port,weight,dynamic_dns,enabled,protocol,max_connections,origin_domain) VALUES (?,?,?,?,?,?,?,?,?,?)`, upstream.ID, rule.CaddyID, upstream.Host, upstream.Port, upstream.Weight, false /* dynamic_dns 废弃列：落库恒 0 */, upstream.Enabled, upstream.Protocol, upstream.MaxConnections, upstream.OriginDomain); err != nil {
				return fmt.Errorf("写入快照上游 %s: %w", rule.CaddyID, err)
			}
		}
		if err := insertSnapshotPathRules(ctx, tx, rule.CaddyID, rule.PathRules); err != nil {
			return err
		}
	}
	return nil
}

// 本函数与 nullableTimeFlat 的时间戳布局统一引用
// crsTimeLayout 常量（此前字面量与常量双拼法并存）。
func insertSnapshotPathRules(ctx context.Context, tx *sql.Tx, ruleID string, pathRules []models.PathRule) error {
	for _, pathRule := range pathRules {
		var upstreamsJSON any
		if pathRule.Upstreams != nil {
			encoded, err := json.Marshal(pathRule.Upstreams)
			if err != nil {
				return fmt.Errorf("序列化快照路径 %s 的上游: %w", pathRule.Path, err)
			}
			upstreamsJSON = string(encoded)
		}
		// 单条 INSERT：id<=0 时传 NULL 交由 AUTOINCREMENT（SQLite 对
		// INTEGER PRIMARY KEY 的 NULL 即自增）——此前 id 在/不在列清单的两条
		// 逐字镜像语句，改列漏同步即静默写错行。
		var idArg any
		if pathRule.ID > 0 {
			idArg = pathRule.ID
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO path_rules (id,rule_id,sort_order,match_type,path,upstream_path,upstreams_json,response_mode,response_status,response_body,response_content_type,redirect_to,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, idArg, ruleID, pathRule.SortOrder, pathRule.MatchType, pathRule.Path, pathRule.UpstreamPath, upstreamsJSON, pathRule.ResponseMode, pathRule.ResponseStatus, pathRule.ResponseBody, pathRule.ResponseContentType, pathRule.RedirectTo, pathRule.CreatedAt.UTC().Format(crsTimeLayout), nullableTimeFlat(pathRule.UpdatedAt)); err != nil {
			return fmt.Errorf("写入快照路径 %s: %w", pathRule.Path, err)
		}
	}
	return nil
}

func updateSnapshotSettings(ctx context.Context, tx *sql.Tx, snapshot models.ClusterSnapshot) error {
	settings := snapshot.BasicSettings
	if settings.JWTExpireMinutes != nil {
		normalized := normalizeJWTExpireMinutes(*settings.JWTExpireMinutes)
		settings.JWTExpireMinutes = &normalized
	}
	// 安全事件保留/采样三列与主端装载侧共用同一归一：判据与 CaddyConfig
	// 是否随包无关（旧主端可只带这三列），故在任何写入分支之前统一处理。
	normalizeSnapshotSecurityRetentionSettings(&settings)
	var baseClauses []string
	var baseArgs []any
	addBase := func(column string, value any) {
		baseClauses = append(baseClauses, column+"=?")
		baseArgs = append(baseArgs, value)
	}
	if settings.LogLevel != nil {
		addBase("log_level", *settings.LogLevel)
	}
	if settings.TaskLogSizeMB != nil {
		addBase("task_log_size_mb", *settings.TaskLogSizeMB)
	}
	if settings.AuditLogSizeMB != nil {
		addBase("audit_log_size_mb", *settings.AuditLogSizeMB)
	}
	if settings.RuntimeLogSizeMB != nil {
		addBase("runtime_log_size_mb", *settings.RuntimeLogSizeMB)
	}
	if settings.AuditRetentionMonths != nil {
		addBase("audit_retention_months", *settings.AuditRetentionMonths)
	}
	if settings.JWTExpireMinutes != nil {
		addBase("jwt_expire_minutes", *settings.JWTExpireMinutes)
	}
	if settings.Timezone != nil {
		addBase("timezone", *settings.Timezone)
	}
	if settings.ACMEEmail != nil {
		addBase("acme_email", *settings.ACMEEmail)
	}
	if settings.CertExpiryDays != nil {
		days := normalizeCertExpiryDays(*settings.CertExpiryDays)
		addBase("cert_expiry_days", days)
	}
	if settings.CertRenewalDays != nil {
		addBase("cert_renewal_days", *settings.CertRenewalDays)
	}
	if settings.CertRenewalAttempts != nil {
		addBase("cert_renewal_attempts", *settings.CertRenewalAttempts)
	}
	if settings.DefaultCAProviderID != nil {
		addBase("default_ca_provider_id", *settings.DefaultCAProviderID)
	}
	if settings.DNSProvider != nil {
		addBase("dns_provider", *settings.DNSProvider)
	}
	if settings.SyncInterval != nil {
		addBase("sync_interval", normalizeSyncInterval(*settings.SyncInterval))
	}
	if settings.AdminTLSEnabled != nil {
		addBase("admin_tls_enabled", *settings.AdminTLSEnabled)
	}
	if settings.AdminTLSMode != nil {
		addBase("admin_tls_mode", *settings.AdminTLSMode)
	}
	if settings.AdminTLSCert != nil {
		addBase("admin_tls_cert", *settings.AdminTLSCert)
	}
	if settings.AdminTLSKey != nil {
		addBase("admin_tls_key", *settings.AdminTLSKey)
	}
	if settings.MFAWriteGuard != nil {
		addBase("mfa_write_guard", *settings.MFAWriteGuard)
	}
	if settings.MFALockoutEnabled != nil {
		addBase("mfa_lockout_enabled", *settings.MFALockoutEnabled)
	}
	if settings.GitHubProxyURL != nil {
		addBase("github_proxy_url", *settings.GitHubProxyURL)
	}
	if settings.OIDCConfig != nil {
		addBase("oidc_config", *settings.OIDCConfig)
	}
	// branding_json 缺席=旧主端未携带，保留本地；非 nil 空串才是显式清空。
	if settings.BrandingJSON != nil {
		addBase("branding_json", *settings.BrandingJSON)
	}
	// 与主端装载侧共用同一归一（同族 sync_interval/jwt_expire_minutes/
	// cert_expiry_days/threat_screen_mode 的既有做法）：仅归一「在场但非法」
	// 的值；nil 是旧主端缺席，跳过而非补默认。归一无条件执行（在 CaddyConfig
	// 门之前）——装载侧也是无条件归一，apply 侧若受门控，手造/未来构造出
	// 「CaddyConfig=nil + 数值列非 nil」形态时主端按归一值算 users 节哈希、
	// 从端保留旧值 → 哈希恒不等（每轮重放+重载）。门只决定是否写入这些列。
	normalizeSnapshotCaddyNumericSettings(&settings)
	if snapshot.CaddyConfig != nil {
		addBase("caddy_config", *snapshot.CaddyConfig)
		if settings.AccessLogJSON != nil {
			addBase("access_log_json", *settings.AccessLogJSON)
		}
		if settings.AccessLogFormat != nil {
			addBase("access_log_format", *settings.AccessLogFormat)
		}
		if settings.CaddyLogLevel != nil {
			addBase("caddy_log_level", *settings.CaddyLogLevel)
		}
		if settings.CaddyLogSizeMB != nil {
			addBase("caddy_log_size_mb", *settings.CaddyLogSizeMB)
		}
		if settings.RequestBodyMaxSizeMB != nil {
			addBase("request_body_max_size_mb", *settings.RequestBodyMaxSizeMB)
		}
		if settings.HTTPReadTimeout != nil {
			addBase("http_read_timeout", *settings.HTTPReadTimeout)
		}
		if settings.HTTPWriteTimeout != nil {
			addBase("http_write_timeout", *settings.HTTPWriteTimeout)
		}
		if settings.HTTPIdleTimeout != nil {
			addBase("http_idle_timeout", *settings.HTTPIdleTimeout)
		}
		if settings.UpstreamKeepaliveTimeout != nil {
			addBase("upstream_keepalive_timeout", *settings.UpstreamKeepaliveTimeout)
		}
		if settings.ProxyDialTimeout != nil {
			addBase("proxy_dial_timeout", *settings.ProxyDialTimeout)
		}
		if settings.ProxyResponseHeaderTimeout != nil {
			addBase("proxy_response_header_timeout", *settings.ProxyResponseHeaderTimeout)
		}
		if settings.ProxyReadTimeout != nil {
			addBase("proxy_read_timeout", *settings.ProxyReadTimeout)
		}
		if settings.ProxyWriteTimeout != nil {
			addBase("proxy_write_timeout", *settings.ProxyWriteTimeout)
		}
		if settings.ProxyStreamTimeout != nil {
			addBase("proxy_stream_timeout", *settings.ProxyStreamTimeout)
		}
		if settings.ProxyFlushInterval != nil {
			addBase("proxy_flush_interval", *settings.ProxyFlushInterval)
		}
		if settings.ProxyStreamCloseDelay != nil {
			addBase("proxy_stream_close_delay", *settings.ProxyStreamCloseDelay)
		}
		if settings.ServerTokensHidden != nil {
			addBase("server_tokens_hidden", *settings.ServerTokensHidden)
		}
		if settings.TrustedProxyEnabled != nil {
			addBase("trusted_proxy_enabled", *settings.TrustedProxyEnabled)
		}
		if settings.TrustedProxyRanges != nil {
			addBase("trusted_proxy_ranges", *settings.TrustedProxyRanges)
		}
		if settings.TrustedProxyRangeRefs != nil {
			addBase("trusted_proxy_range_refs", *settings.TrustedProxyRangeRefs)
		}
		if settings.TrustedProxyHeaders != nil {
			addBase("trusted_proxy_headers", *settings.TrustedProxyHeaders)
		}
		if settings.TrustedProxyStrict != nil {
			addBase("trusted_proxy_strict", *settings.TrustedProxyStrict)
		}
	}
	if len(baseClauses) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE global_config SET `+strings.Join(baseClauses, ",")+` WHERE id=1`, baseArgs...); err != nil {
			return fmt.Errorf("写入快照基础设置: %w", err)
		}
	}
	// github_token 有意不下发：节点本地机密。
	// 自动备份设置组随 users 节落库。指针缺席=旧主端
	// 快照未携带该组——跳过写入保留从端本地值(镜像 branding_json 缺席语义,
	// 不清零);新主端恒携带全组。last_run 为节点本地运行态,永不在此写入。
	// 威胁库任务级排程三列同口径入块(升主即生效)。
	var settingClauses []string
	var settingArgs []any
	if settings.AutoBackupEnabled != nil {
		settingClauses = append(settingClauses, "auto_backup_enabled=?")
		settingArgs = append(settingArgs, *settings.AutoBackupEnabled)
	}
	if settings.AutoBackupFrequency != nil {
		settingClauses = append(settingClauses, "auto_backup_frequency=?")
		settingArgs = append(settingArgs, *settings.AutoBackupFrequency)
	}
	if settings.AutoBackupTime != nil {
		settingClauses = append(settingClauses, "auto_backup_time=?")
		settingArgs = append(settingArgs, *settings.AutoBackupTime)
	}
	if settings.AutoBackupDay != nil {
		settingClauses = append(settingClauses, "auto_backup_day=?")
		settingArgs = append(settingArgs, *settings.AutoBackupDay)
	}
	if settings.AutoBackupKeep != nil {
		settingClauses = append(settingClauses, "auto_backup_keep=?")
		settingArgs = append(settingArgs, *settings.AutoBackupKeep)
	}
	if settings.AutoBackupSections != nil {
		settingClauses = append(settingClauses, "auto_backup_sections=?")
		settingArgs = append(settingArgs, *settings.AutoBackupSections)
	}
	if settings.ThreatAutoUpdate != nil {
		settingClauses = append(settingClauses, "threat_auto_update=?")
		settingArgs = append(settingArgs, *settings.ThreatAutoUpdate)
	}
	if settings.ThreatScheduleDays != nil {
		settingClauses = append(settingClauses, "threat_schedule_days=?")
		settingArgs = append(settingArgs, *settings.ThreatScheduleDays)
	}
	if settings.ThreatScheduleTime != nil {
		settingClauses = append(settingClauses, "threat_schedule_time=?")
		settingArgs = append(settingArgs, *settings.ThreatScheduleTime)
	}
	if settings.CrawlerAutoUpdate != nil {
		settingClauses = append(settingClauses, "crawler_auto_update=?")
		settingArgs = append(settingArgs, *settings.CrawlerAutoUpdate)
	}
	if settings.CrawlerScheduleDays != nil {
		settingClauses = append(settingClauses, "crawler_schedule_days=?")
		settingArgs = append(settingArgs, *settings.CrawlerScheduleDays)
	}
	if settings.CrawlerScheduleTime != nil {
		settingClauses = append(settingClauses, "crawler_schedule_time=?")
		settingArgs = append(settingArgs, *settings.CrawlerScheduleTime)
	}
	// 自动封禁六项配置同口径入块（指针缺席=旧主端快照未
	// 携带——跳过写入保留从端本地值，不清零；新主端恒携带全组，升主即生效）。
	// 安全事件保留/采样三列已在上方经 normalizeSnapshotSecurityRetentionSettings
	// 归一（与主端装载侧同一函数），此处只负责入块。
	if settings.SecurityEventsRetentionDays != nil {
		settingClauses = append(settingClauses, "security_events_retention_days=?")
		settingArgs = append(settingArgs, *settings.SecurityEventsRetentionDays)
	}
	if settings.SecurityEventsRowCap != nil {
		settingClauses = append(settingClauses, "security_events_row_cap=?")
		settingArgs = append(settingArgs, *settings.SecurityEventsRowCap)
	}
	if settings.ThreatTrafficSampleN != nil {
		settingClauses = append(settingClauses, "threat_traffic_sample_n=?")
		settingArgs = append(settingArgs, *settings.ThreatTrafficSampleN)
	}
	// 大屏视觉模式：枚举白名单与写侧同源（models.IsValidThreatScreenMode）；
	// 非法值归默认而非落脏值——渲染/读侧直读库值，脏枚举会让大屏回退分支
	// 与配置面自相矛盾。nil=旧主端缺席，跳过写入保留从端本地值。
	if settings.ThreatScreenMode != nil {
		mode := *settings.ThreatScreenMode
		if !models.IsValidThreatScreenMode(mode) {
			mode = db.DefaultThreatScreenMode
		}
		settingClauses = append(settingClauses, "threat_screen_mode=?")
		settingArgs = append(settingArgs, mode)
	}
	if settings.AutobanEnabled != nil {
		settingClauses = append(settingClauses, "autoban_enabled=?")
		settingArgs = append(settingArgs, *settings.AutobanEnabled)
	}
	if settings.AutobanThreshold != nil {
		settingClauses = append(settingClauses, "autoban_threshold=?")
		settingArgs = append(settingArgs, *settings.AutobanThreshold)
	}
	if settings.AutobanWindowMinutes != nil {
		settingClauses = append(settingClauses, "autoban_window_minutes=?")
		settingArgs = append(settingArgs, *settings.AutobanWindowMinutes)
	}
	if settings.AutobanDuration != nil {
		settingClauses = append(settingClauses, "autoban_duration=?")
		settingArgs = append(settingArgs, *settings.AutobanDuration)
	}
	if settings.AutobanScope != nil {
		settingClauses = append(settingClauses, "autoban_scope=?")
		settingArgs = append(settingArgs, *settings.AutobanScope)
	}
	if settings.AutobanDryRun != nil {
		settingClauses = append(settingClauses, "autoban_dry_run=?")
		settingArgs = append(settingArgs, *settings.AutobanDryRun)
	}
	if len(settingClauses) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE global_config SET `+strings.Join(settingClauses, ",")+` WHERE id=1`, settingArgs...); err != nil {
			return fmt.Errorf("写入快照扩展设置: %w", err)
		}
	}
	// 同步来的 task_log_size_mb 必须立即越过 TTL 缓存生效，
	// 否则从节点最长 5 分钟仍按旧阈值轮转。幂等且无失败面。
	InvalidateTaskLogSizeCache()
	return nil
}

func materializeSnapshotCerts(certs []models.ClusterCertificate) error {
	for _, cert := range certs {
		if err := WriteCertFiles(cert.RuleID, cert.CertPEM, cert.KeyPEM); err != nil {
			return err
		}
	}
	return nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// snapshotExpiresAtUsable 判定快照到期串能否被消费侧口径解析（SQLite
// datetime() 接受的两种落库形态，与 parseUTCSlot 同源）。空串与不可解析形态
// 都视为「源值缺失」，由证书材料派生——否则该行在聚合口径下恒 NULL
// （datetime(坏值)=NULL），节点健康的临期证书统计会静默漏行。
func snapshotExpiresAtUsable(value string) bool {
	return !parseUTCSlot(value).IsZero()
}

// snapshotNullableDatetime 快照可空时间列的 any 入口（dumpTableAsJSON 行值
// 为 JSON any）：空串/nil → NULL，与版本行 nullableString 调用同口径。
// 快照时间列恒为 JSON 字符串（dumpTableAsJSON 产出口径）；非字符串形态属载荷
// 异常——按 NULL 落库并留一条 warn（不静默吞掉形态漂移）。
func snapshotNullableDatetime(value interface{}) any {
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		return nullableString(v)
	default:
		Logf("warn", "快照时间列值类型异常（%T），按 NULL 落库: %v", value, value)
		return nil
	}
}

// nullableTimeFlat（2026-10-11 时间戳格式统一；收口全部写点）
// 从端落库时间统一 SQLite 平面格式 'YYYY-MM-DD HH:MM:SS'（UTC）——此前直写
// time.Time 由驱动序列化为带时区后缀格式，与主端 datetime('now') 平面格式
// 三态并存（时间戳同构迁移的写入侧终结点）；空值路径保持 NULL 语义。
func nullableTimeFlat(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time.UTC().Format(crsTimeLayout)
}

// normalizeVersionRows 把 nil 规范化为空切片
// 手造/旧主端快照 nil 序列化为 "null"，本地空表为 "[]"，旧比较口径恒判
// 「有差异」→ 每次 apply 白做 DELETE+INSERT。生产快照恒非 nil
// （snapshotSecurity*Version 返回 make(...)），本归一让手造形态与生产一致。
func normalizeVersionRows[T any](rows []T) []T {
	if rows == nil {
		return []T{}
	}
	return rows
}

// snapshotSecurityVersionRowsDiffer 比较快照携带的 CRS/IP2Region 版本行与
// 本地行(2026-09-11:版本行差分门控——不进节哈希,以内容差分决定重放)。
// 查询失败时本地行保持空切片:快照非空即判「有差异」触发重放(向主端收敛,
// 原「按无差异处理」描述对非空快照分支不成立);序列化失败(不可
// 达,类型固定)按无差异。
// 本地读取列清单与快照 dump 共用 clusterRuleLibVersionColumns /
// scanClusterRuleLibVersionRow（的「快照列与差分行不同步」教训）。
func snapshotSecurityVersionRowsDiffer(ctx context.Context, tx *sql.Tx, snapshot models.ClusterSnapshot) bool {
	snapJSON := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
	wantCRS := snapJSON(normalizeVersionRows(snapshot.SecurityCRSVersion))
	wantIP2R := snapJSON(normalizeVersionRows(snapshot.SecurityIP2RegionVersion))

	localCRS := make([]models.ClusterSecurityCRSVersion, 0)
	rows, err := readClusterRuleLibVersionRows(ctx, tx, "security_crs_version")
	if err == nil {
		for _, row := range rows {
			localCRS = append(localCRS, row.crsVersion())
		}
	} else {
		return true
	}
	localIP2R := make([]models.ClusterSecurityIP2RegionVersion, 0)
	rows2, err2 := readClusterRuleLibVersionRows(ctx, tx, "security_ip2region_version")
	if err2 == nil {
		for _, row := range rows2 {
			localIP2R = append(localIP2R, row.ip2RegionVersion())
		}
	} else {
		return true
	}
	return snapJSON(localCRS) != wantCRS || snapJSON(localIP2R) != wantIP2R
}

// toFloat64 将 map[string]interface{} 中的数值安全转为 float64(JSON 解析
// 数字默认 float64;int 直转)。
func toFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return 0
	}
}
