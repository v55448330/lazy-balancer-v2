package services

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"lazy-balancer-v2/internal/db"
)

// CRS seed sources for an empty live rules tree.
const (
	crsSeedFromSnapshot = "snapshot"
	crsSeedFromDist     = "dist"
)

// decideCRSSeedSource picks where an empty live CRS tree is seeded from: the
// persisted snapshot wins only when it carries a version different from the
// image-bundled rules (i.e. the user installed an update at some point);
// anything else falls back to the pristine image copy.
func decideCRSSeedSource(distVersion, snapshotVersion string, snapshotExists bool) string {
	if snapshotExists && snapshotVersion != distVersion {
		return crsSeedFromSnapshot
	}
	return crsSeedFromDist
}

// SeedCRSRules populates the live CRS dir when a fresh /app/waf bind mount
// hides the image-baked rules: seed from the persisted snapshot when it
// carries user-updated rules, otherwise from the pristine waf.dist copy.
// 返回错误：播种后写入 VERSION 标记失败必须上抛（标记缺失会让下次启动对账
// 按错误版本选方向）；调用方（启动序列）可忽略返回值，但不得把「已播种」当
// 成功日志记录。
func SeedCRSRules() error {
	return seedCRSRulesFrom(crsLiveDir, crsSnapshotDir, crsDistDir)
}

func seedCRSRulesFrom(liveDir, snapshotDir, distDir string) error {
	wafFileMu.Lock()
	defer wafFileMu.Unlock()
	return seedCRSRulesFromInLock(liveDir, snapshotDir, distDir)
}

// seedCRSRulesFromInLock 的判定、辅助文件补种、树复制与快照自愈全程由调用方
// 持 wafFileMu，和运行期 CRS 树交换保持同一代际边界。
// 规则树需要在本次播种中重建（残缺树清除 / 从快照或 dist 复制）时，整段进入
// 树交换窗口——清除与替换之间 live 可能缺失或只有部分树，窗口内渲染必须失败。
// 规则树已完整（只补 setup/stock/overrides 等辅助文件）时不置窗口，避免启动
// 期无谓地拒绝并发生成。
func seedCRSRulesFromInLock(liveDir, snapshotDir, distDir string) error {
	if crsRulesTreeIntact(filepath.Join(liveDir, "rules")) {
		return seedCRSRulesFromInLockUnmarked(liveDir, snapshotDir, distDir)
	}
	var seedErr error
	_ = withTreeSwapWindow(func() error {
		seedErr = seedCRSRulesFromInLockUnmarked(liveDir, snapshotDir, distDir)
		return nil
	})
	return seedErr
}

func seedCRSRulesFromInLockUnmarked(liveDir, snapshotDir, distDir string) error {
	rulesPath := filepath.Join(liveDir, "rules")
	// rules 完整时不得直接 return——setup/stock/overrides 可能单独缺失
	// （挂载卷只读残影/部分删除），旧实现让这些文件永久缺失而渲染侧 Include
	// 恒失败。规则树完整则跳过树复制，但仍补种缺失的辅助文件（存在不覆盖）。
	rulesIntact := false
	if _, err := os.Stat(rulesPath); err == nil {
		if crsRulesTreeIntact(rulesPath) {
			rulesIntact = true
		} else {
			// 崩溃窗口（moveTree copyDir 回退直写 live 中途崩溃）留下的
			// 部分残树——目录存在但探针缺失，按缺失处理：清除后重新播种。ReconcileCRSState
			// 只按版本标记对账，发现不了这种退化。
			Logf("info", "crs seed: live rules tree %s is incomplete (missing %s), reseeding", rulesPath, crsRulesProbeFile)
			if err := os.RemoveAll(rulesPath); err != nil {
				// 契约：无法清除残缺树=未完成播种，必须上抛（与「播种后写
				// VERSION 失败」同一契约）。旧实现返回 nil，上层无法区分
				// 「已播种」与「未播种」——live 树残缺/缺失时渲染侧对各 Include
				// 走「缺失→warn+跳过」，WAF 只剩 IP 控制面，仅一条 error 日志。
				return fmt.Errorf("crs seed: 清除残缺 rules 树 %s 失败: %w", rulesPath, err)
			}
		}
	}
	// waf/custom 已移除：自定义规则存 DB、内联发射为 coraza
	// 指令，无任何文件消费方，不再重建该死目录。
	// 审计日志已迁入 /app/logs/waf-audit(2026-09-14 用户裁定:日志统一 /app/logs);
	// 旧 /app/waf/audit 仍重建(挂载隐藏骨架+历史文件留存量兼容,回滚安全)。
	if err := os.MkdirAll(filepath.Join(filepath.Dir(liveDir), "audit"), 0755); err != nil {
		Logf("error", "crs seed: failed to create legacy waf audit dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(auditLogPath), 0755); err != nil {
		Logf("error", "crs seed: failed to create %s: %v", filepath.Dir(auditLogPath), err)
	}

	snapshotVersion := ""
	if data, err := os.ReadFile(filepath.Join(snapshotDir, "VERSION")); err == nil {
		snapshotVersion = strings.TrimSpace(string(data))
	}
	snapshotDegenerate := false
	snapshotRules := filepath.Join(snapshotDir, "rules")
	if _, err := os.Stat(snapshotRules); err != nil {
		// 新-4：VERSION 标记尚在而 rules 树缺失（persistCRSSnapshotFrom 的
		// RemoveAll 之后崩溃残留）同属退化快照——置退化标记走 heal 重建，不留
		// 永不自愈的 VERSION-only 残骸。
		if snapshotVersion != "" {
			Logf("info", "crs seed: snapshot %s carries a version marker but no rules tree, treating as degenerate", snapshotDir)
			snapshotDegenerate = true
		}
		snapshotVersion = "" // a snapshot without a rules tree is unusable
	} else if !crsRulesTreeIntact(snapshotRules) {
		// persistCRSSnapshotFrom 崩溃窗口（RemoveAll 中途，VERSION 尚存 +
		// rules 部分残留）留下的退化快照不能作种——播成退化 live 后下次启动探针
		// 再清再播同源，跨重启循环。回退 dist，快照留现场供诊断。
		Logf("info", "crs seed: snapshot rules tree %s is incomplete (missing %s), falling back to dist", snapshotRules, crsRulesProbeFile)
		snapshotVersion = ""
		snapshotDegenerate = true
	}
	src := distDir
	srcVersion := CRSBundledVersion
	if decideCRSSeedSource(CRSBundledVersion, snapshotVersion, snapshotVersion != "") == crsSeedFromSnapshot {
		src = snapshotDir
		srcVersion = snapshotVersion
	}
	if !rulesIntact {
		// 播种同样走 tmp+rename 事务替换——半树 seed 会让探针门在
		// 下次启动再次清空重播，且 live 出现不完整规则树。
		if err := replaceDirFrom(filepath.Join(src, "rules"), filepath.Join(liveDir, "rules")); err != nil {
			Logf("error", "crs seed: failed to seed rules from %s: %v", src, err)
			return fmt.Errorf("crs seed: 播种规则树 %s 失败: %w", src, err)
		}
	}
	setupPath := filepath.Join(liveDir, "crs-setup.conf")
	if _, err := os.Stat(setupPath); os.IsNotExist(err) {
		if err := copyFile(filepath.Join(src, "crs-setup.conf"), setupPath); err != nil {
			Logf("error", "crs seed: failed to seed crs-setup.conf from %s: %v", src, err)
		}
	}
	for _, aux := range []string{"crs-setup.stock.conf", "zz-user-overrides.conf"} {
		// 存在即不覆盖（用户自定义 overrides/基线不得被播种回写）。
		if _, err := os.Stat(filepath.Join(liveDir, aux)); err == nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(src, aux)); err == nil {
			if err := copyFile(filepath.Join(src, aux), filepath.Join(liveDir, aux)); err != nil {
				Logf("error", "crs seed: failed to seed %s from %s: %v", aux, src, err)
			}
		}
	}
	// 播种后落版本标记：对账逻辑据此区分「磁盘实际版本」与「数据库记录版本」。
	// 写失败必须上抛且不得记「已播种」成功——标记缺失时磁盘版本不可知，下一次
	// 启动的播种/对账会按错误版本选方向（回退快照或把 DB 版本行校正到旧值）。
	if !rulesIntact {
		if err := writeCRSVersionMarker(liveDir, srcVersion); err != nil {
			Logf("error", "crs seed: 播种后写入 VERSION 标记失败（磁盘版本不可知，待下次成功更新补齐）: %v", err)
			return fmt.Errorf("播种后写入 CRS VERSION 标记: %w", err)
		}
		Logf("info", "crs seed: seeded %s from %s", liveDir, src)
	}
	// 发现2：退化快照回退播种成功后，用新播种的 live 树重建快照，让快照
	// 自愈而不是永远停留在退化状态直到下次成功更新。live 本就完整时
	// 版本取 live 自身标记，不得用 dist 版本给用户更新树错标。
	if snapshotDegenerate {
		healVersion := srcVersion
		if rulesIntact {
			// live 已完整：版本只认 live 自身标记；标记缺失/空则版本不可知，
			// 保持退化快照留现场，不得用 dist 版本冒充。
			healVersion = ""
			if raw, readErr := os.ReadFile(filepath.Join(liveDir, "VERSION")); readErr == nil {
				healVersion = strings.TrimSpace(string(raw))
			}
		}
		healCRSSnapshotFromLiveInLock(liveDir, snapshotDir, healVersion)
	}
	return nil
}

// healCRSSnapshotFromLiveInLock 用健康 live 树重建快照（退化快照与整体缺席
// 两种形态共用）：live 树自身也不健康（如 dist 源退化）或版本不可知时保留
// 留现场语义，不做回写。
func healCRSSnapshotFromLiveInLock(liveDir, snapshotDir, version string) {
	if version == "" || !crsRulesTreeIntact(filepath.Join(liveDir, "rules")) {
		Logf("info", "crs: live tree unhealthy or version unknown, leaving snapshot %s in place for diagnosis", snapshotDir)
		return
	}
	if err := persistCRSSnapshotFromInLock(liveDir, snapshotDir, version); err != nil {
		Logf("error", "crs: failed to rebuild snapshot %s from live tree: %v", snapshotDir, err)
		return
	}
	Logf("info", "crs: rebuilt snapshot %s from live tree (%s)", snapshotDir, version)
}

// writeCRSVersionMarker records the on-disk CRS version under the live dir so
// startup reconciliation can tell the disk version from the DB record.
// 与同包其它持久化同口径（tmp+fsync+rename）：该文件是 planCRSReconcile 的
// 权威输入，裸 os.WriteFile 的崩溃窗口会留下 0 字节/半截 VERSION，让下一次
// 启动的对账基于错误版本选方向（回退快照或改写 DB 版本行）。
var crsVersionMarkerWrite = writeFileAtomicSynced

func writeCRSVersionMarker(liveDir, version string) error {
	if version == "" {
		return nil
	}
	if err := crsVersionMarkerWrite(filepath.Join(liveDir, crsVersionFile), []byte(version+"\n"), 0644); err != nil {
		Logf("error", "crs seed: failed to write version marker: %v", err)
		return err
	}
	return nil
}

func readCRSVersionMarker(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, crsVersionFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// crsVersionFile marks the on-disk CRS version inside a tree root (live dir
// and snapshot dir both carry one).
const crsVersionFile = "VERSION"

// crsProbeFile is a representative rules file present in every CRS release;
// byte-comparing it between trees is a cheap content check for the bootstrap
// path where no version marker exists yet. 路径由安装契约常量派生（单源）——
// 两处各写一遍会在上游结构变更时单侧漂移。
const crsProbeFile = "rules/" + crsRulesProbeFile

func crsTreeProbeMatches(a, b string) bool {
	aData, aErr := os.ReadFile(filepath.Join(a, crsProbeFile))
	bData, bErr := os.ReadFile(filepath.Join(b, crsProbeFile))
	if aErr != nil || bErr != nil {
		return false
	}
	return bytes.Equal(aData, bData)
}

type crsReconcileAction int

const (
	crsReconcileNone crsReconcileAction = iota
	crsReconcileWriteMarker
	crsReconcileRestoreSnapshot
	crsReconcileCorrectDB
)

type crsReconcilePlan struct {
	action crsReconcileAction
	// markerVersion is the version written for WriteMarker/RestoreSnapshot.
	markerVersion string
	// dbVersion is the disk version the DB row is corrected to for CorrectDB.
	dbVersion string
	// ambiguous marks the legacy no-marker case where the disk version cannot
	// be determined; callers only log an advice line and change nothing.
	ambiguous bool
}

// planCRSReconcile decides how to realign the disk CRS tree, the data-volume
// snapshot and the DB version row at startup. Cases covered:
//   - marker == DB            → nothing to do (steady state)
//   - DB == snapshot ≠ disk   → disk reverted (unmounted /app/waf rebuilt
//     from the image) → restore the user-updated tree from the snapshot
//   - disk ≠ DB, no snapshot  → disk is the truth (image-bundled rules
//     changed by an upgrade, or user update lost with no snapshot) →
//     correct the DB row to the disk version
//   - no marker (legacy disk) → bootstrap the marker from the snapshot/DB
//     when they agree and a content probe confirms, otherwise fall back to
//     the bundled version — or stay hands-off when the disk version is
//     genuinely unknowable.
func planCRSReconcile(liveV, snapV, dbV, bundledV string, snapshotRulesExist, probeMatches bool) crsReconcilePlan {
	if liveV == "" {
		if snapshotRulesExist && snapV != "" && snapV == dbV {
			if probeMatches {
				return crsReconcilePlan{action: crsReconcileWriteMarker, markerVersion: dbV}
			}
			return crsReconcilePlan{action: crsReconcileRestoreSnapshot, markerVersion: snapV}
		}
		if dbV == bundledV {
			return crsReconcilePlan{action: crsReconcileWriteMarker, markerVersion: bundledV}
		}
		// 旧部署磁盘既无标记、快照也对不上：无法确认磁盘版本，保持现状
		// 并提示手动更新一次（更新会补齐标记与快照，之后完全自洽）。
		return crsReconcilePlan{action: crsReconcileNone, ambiguous: true}
	}
	if liveV == dbV {
		return crsReconcilePlan{action: crsReconcileNone}
	}
	if snapshotRulesExist && snapV != "" && snapV == dbV {
		return crsReconcilePlan{action: crsReconcileRestoreSnapshot, markerVersion: snapV}
	}
	return crsReconcilePlan{action: crsReconcileCorrectDB, dbVersion: liveV}
}

// restoreCRSFromSnapshotInLock 是调用方已持 wafFileMu 的快照恢复实现（唯一
// 生产入口是 ReconcileCRSState 的锁内路径；自加锁包装已移除——它会让读者
// 误以为存在可与锁内路径并行的第二套恢复语义）。
// 装入前先对快照执行与 seed/备份恢复同一棵探针门——退化快照（部分
// rules + 完整 VERSION）拒绝恢复，调用方记录错误并保留 live 现场。
func restoreCRSFromSnapshotInLock(liveDir, snapshotDir, version string) error {
	if !crsRulesTreeIntact(filepath.Join(snapshotDir, "rules")) {
		return fmt.Errorf("快照 rules 树不完整（缺失 %s），拒绝恢复", crsRulesProbeFile)
	}
	// 事务替换——先完整拷贝到 rules.tmp，成功后才删旧树并 rename；
	// 拷贝中断时 live 保持上一代完整树（旧实现先删后拷，失败即丢树）。
	if err := replaceDirFrom(filepath.Join(snapshotDir, "rules"), filepath.Join(liveDir, "rules")); err != nil {
		return err
	}
	for _, name := range []string{"crs-setup.conf", "crs-setup.stock.conf", "zz-user-overrides.conf"} {
		if _, err := os.Stat(filepath.Join(snapshotDir, name)); err == nil {
			if err := copyFile(filepath.Join(snapshotDir, name), filepath.Join(liveDir, name)); err != nil {
				return err
			}
		}
	}
	// VERSION 写失败必须上抛：调用方据此跳过 BumpClusterVersion 与「恢复成功」
	// 审计——否则 live 标记缺失/停留旧值，而规则树与版本记录已是恢复后的版本，
	// 下一次启动会重复恢复或按旧标记把 DB 版本行校正回旧值。
	if err := writeCRSVersionMarker(liveDir, version); err != nil {
		return fmt.Errorf("写入 CRS VERSION 标记: %w", err)
	}
	return nil
}

// ReconcileCRSState realigns the CRS disk tree, data-volume snapshot and DB
// version row. a slave's CRS files and version row are both
// governed by cluster sync, local reconciliation would fight it.
//
// 原注释「仅在启动时调用」的前提已失效——runConfigLoad
// （cmd/server/main.go）同时经 SetConfigLoadRerun 暴露给 startup:config-load
// 的 manual/caddy-restart 触发。因此任何真正改变磁盘规则文件的成功路径
// （restore/correct）都必须显式 BumpClusterVersion，否则从节点在下一次无关
// 版本 bump 前仍持旧规则引用。
func ReconcileCRSState() {
	if isMaster, err := RoleOf(context.Background(), db.DB); err != nil {
		// 角色读取失败≠从节点——留痕后跳过本轮对账（静默跳过会掩盖 DB 异常）。
		Logf("warn", "CRS 状态对账: 角色读取失败，本轮跳过: %v", err)
		return
	} else if !isMaster {
		return
	}
	// 版本读取必须取「错误可见」口径：本路径会写 VERSION 标记/恢复快照并
	// 「校正」DB 版本行 + bump 集群版本——用展示容错值（读失败回落 bundled）
	// 会在 DB 瞬断时把 bundled 当权威写坏标记/版本行。读失败按同函数内
	// 「角色读取失败即跳过」的既有口径处理。
	dbV, err := readCurrentCRSVersion()
	if err != nil {
		Logf("warn", "CRS 状态对账: 版本记录读取失败，本轮跳过（不写标记/不改版本行）: %v", err)
		return
	}
	reconcileCRSStateFrom(crsLiveDir, crsSnapshotDir, dbV)
}

func reconcileCRSStateFrom(liveDir, snapshotDir, dbV string) {
	wafFileMu.Lock()
	defer wafFileMu.Unlock()
	reconcileCRSStateFromInLock(liveDir, snapshotDir, dbV)
}

// reconcileCRSStateFromInLock 的版本判定、快照自愈、标记写入、树恢复和 DB
// 校正均在同一个 wafFileMu 临界区内完成。
func reconcileCRSStateFromInLock(liveDir, snapshotDir, dbV string) {
	snapV := readCRSVersionMarker(snapshotDir)
	snapshotRulesExist := false
	snapshotDegenerate := false
	snapshotRules := filepath.Join(snapshotDir, "rules")
	if _, err := os.Stat(snapshotRules); err == nil {
		if crsRulesTreeIntact(snapshotRules) {
			snapshotRulesExist = true
		} else {
			// 退化快照不作权威源——probe 不匹配分支会拿快照覆盖 live，
			// 退化快照会把 live 换成弱化树。按无快照处理并记录，快照留现场。
			Logf("info", "crs reconcile: snapshot rules tree %s is incomplete (missing %s), not treating it as authoritative", snapshotRules, crsRulesProbeFile)
			snapV = ""
			snapshotDegenerate = true
		}
	} else {
		// 新-4：VERSION 标记尚在而 rules 树缺失同属退化快照，live 健康时
		// 走 heal 重建（与 seed 侧同一判定口径）。
		if snapV != "" {
			Logf("info", "crs reconcile: snapshot %s carries a version marker but no rules tree, treating as degenerate", snapshotDir)
			snapshotDegenerate = true
		}
		snapV = ""
	}
	liveV := readCRSVersionMarker(liveDir)
	// 发现2：live 树完好且版本标记可确定时，用 live 树重建退化快照——
	// 用户更新版本在容器重建前即被保留，不必等下次成功更新才自愈。
	if snapshotDegenerate {
		healCRSSnapshotFromLiveInLock(liveDir, snapshotDir, liveV)
	} else if snapV == "" && liveV != "" && liveV != CRSBundledVersion {
		// 快照整体缺席（目录被删/数据卷换新/首次更新时快照写入失败）不进上面
		// 的退化判定：对账在 liveV==dbV 时判 none 且再无任何写快照的入口，
		// 非卷挂载 /app/waf 的部署容器重建即回退镜像捆绑版本、用户更新成果
		// 丢失。live 树完好且版本可确定（且非 bundled——那本可就由 dist 重播）
		// 时按 live 重建快照；helper 自带 live 树完整性门，失败只留日志。
		healCRSSnapshotFromLiveInLock(liveDir, snapshotDir, liveV)
	} else if liveV != "" && liveV == dbV && snapV != "" && snapV != liveV {
		// 快照完整但落后（更新时持久化失败或历史残留）：无论 live 是否
		// bundled，只要健康 live/DB 同代且已有快照，就必须刷新快照，避免卷
		// 重建后 seed 选中旧版本。liveV==dbV 保证合法恢复源分支不被重写；
		// 快照整体缺席时 bundled 仍由上一分支刻意跳过（dist 可直接重播）。
		healCRSSnapshotFromLiveInLock(liveDir, snapshotDir, liveV)
		snapV = liveV
	}
	plan := planCRSReconcile(liveV, snapV, dbV, CRSBundledVersion, snapshotRulesExist, crsTreeProbeMatches(liveDir, snapshotDir))
	switch plan.action {
	case crsReconcileNone:
		if plan.ambiguous {
			Logf("info", "crs reconcile: 磁盘 CRS 无版本标记且与快照不一致（记录版本 %s），建议手动更新一次以补齐版本追踪", dbV)
		}
	case crsReconcileWriteMarker:
		writeCRSVersionMarker(liveDir, plan.markerVersion)
	case crsReconcileRestoreSnapshot:
		if err := restoreCRSFromSnapshotInLock(liveDir, snapshotDir, plan.markerVersion); err != nil {
			Logf("error", "crs reconcile: 从快照恢复 CRS %s 失败: %v", plan.markerVersion, err)
			return
		}
		// 文件态变更不写 security_crs_version 行——必须显式 bump，否则
		// 从节点与按需 bundle 引用在下次无关版本变更前仍指旧规则。
		if err := BumpClusterVersion(context.Background(), db.DB); err != nil {
			Logf("error", "crs reconcile: 恢复后递增集群版本失败: %v", err)
		}
		if m := GetCRSUpdateManager(); m != nil {
			m.rescanRuleCount()
		}
		Logf("info", "crs reconcile: 磁盘 CRS 已回退（容器重建），从数据卷快照恢复为 %s", plan.markerVersion)
		RecordAuditLog("system", "恢复", "CRS规则库", FormatAuditDetail("容器重建后从持久快照恢复 "+plan.markerVersion, AuditResultPart("success")), "")
	case crsReconcileCorrectDB:
		if _, err := db.DB.Exec("UPDATE security_crs_version SET version=?, updated_at=datetime('now') WHERE id=1", plan.dbVersion); err != nil {
			Logf("error", "crs reconcile: 校正版本记录为磁盘实际版本 %s 失败: %v", plan.dbVersion, err)
			return
		}
		// CorrectDB 同样改变主节点发布事实；必须主动 bump，已对齐的从节点
		// 才不会因 304 继续持有校正前的版本标识。
		if err := BumpClusterVersion(context.Background(), db.DB); err != nil {
			Logf("error", "crs reconcile: 校正版本记录后递增集群版本失败: %v", err)
		}
		Logf("info", "crs reconcile: 版本记录已校正为磁盘实际版本 %s（原记录 %s）", plan.dbVersion, dbV)
		// 发现2：原记录对应的更新成果随规则树丢失被静默废弃，必须留审计痕迹。
		RecordAuditLog("system", "恢复", "CRS规则库", FormatAuditDetail(fmt.Sprintf("磁盘规则树与版本记录不一致，版本记录已从 %s 校正为磁盘实际版本 %s（原记录对应的更新成果已废弃）", dbV, plan.dbVersion), AuditResultPart("success")), "")
	}
}
