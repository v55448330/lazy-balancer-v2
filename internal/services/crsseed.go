package services

import (
	"bytes"
	"fmt"
	"log"
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
func SeedCRSRules() {
	seedCRSRulesFrom(crsLiveDir, crsSnapshotDir, crsDistDir)
}

func seedCRSRulesFrom(liveDir, snapshotDir, distDir string) {
	rulesPath := filepath.Join(liveDir, "rules")
	if _, err := os.Stat(rulesPath); err == nil {
		if crsRulesTreeIntact(rulesPath) {
			return
		}
		// R50 B-#5：崩溃窗口（moveTree copyDir 回退直写 live 中途崩溃）留下的
		// 部分残树——目录存在但探针缺失，按缺失处理：清除后重新播种。ReconcileCRSState
		// 只按版本标记对账，发现不了这种退化。
		log.Printf("crs seed: live rules tree %s is incomplete (missing %s), reseeding", rulesPath, crsRulesProbeFile)
		if err := os.RemoveAll(rulesPath); err != nil {
			log.Printf("crs seed: failed to clear incomplete rules tree %s: %v", rulesPath, err)
			return
		}
	}
	// The bind mount also hides the aux dir referenced by the generated WAF
	// config (SecAuditLog lives under waf/audit), so recreate the skeleton.
	// waf/custom 已移除（审计 W4 裁定）：自定义规则存 DB、内联发射为 coraza
	// 指令，无任何文件消费方，不再重建该死目录。
	wafDir := filepath.Dir(liveDir)
	if err := os.MkdirAll(filepath.Join(wafDir, "audit"), 0755); err != nil {
		log.Printf("crs seed: failed to create %s: %v", filepath.Join(wafDir, "audit"), err)
	}

	snapshotVersion := ""
	if data, err := os.ReadFile(filepath.Join(snapshotDir, "VERSION")); err == nil {
		snapshotVersion = strings.TrimSpace(string(data))
	}
	snapshotDegenerate := false
	snapshotRules := filepath.Join(snapshotDir, "rules")
	if _, err := os.Stat(snapshotRules); err != nil {
		// R53 新-4：VERSION 标记尚在而 rules 树缺失（persistCRSSnapshotFrom 的
		// RemoveAll 之后崩溃残留）同属退化快照——置退化标记走 heal 重建，不留
		// 永不自愈的 VERSION-only 残骸。
		if snapshotVersion != "" {
			log.Printf("crs seed: snapshot %s carries a version marker but no rules tree, treating as degenerate", snapshotDir)
			snapshotDegenerate = true
		}
		snapshotVersion = "" // a snapshot without a rules tree is unusable
	} else if !crsRulesTreeIntact(snapshotRules) {
		// R51 F2：persistCRSSnapshotFrom 崩溃窗口（RemoveAll 中途，VERSION 尚存 +
		// rules 部分残留）留下的退化快照不能作种——播成退化 live 后下次启动探针
		// 再清再播同源，跨重启循环。回退 dist，快照留现场供诊断。
		log.Printf("crs seed: snapshot rules tree %s is incomplete (missing %s), falling back to dist", snapshotRules, crsRulesProbeFile)
		snapshotVersion = ""
		snapshotDegenerate = true
	}
	src := distDir
	srcVersion := CRSBundledVersion
	if decideCRSSeedSource(CRSBundledVersion, snapshotVersion, snapshotVersion != "") == crsSeedFromSnapshot {
		src = snapshotDir
		srcVersion = snapshotVersion
	}
	if err := copyDir(filepath.Join(src, "rules"), filepath.Join(liveDir, "rules")); err != nil {
		log.Printf("crs seed: failed to seed rules from %s: %v", src, err)
		return
	}
	setupPath := filepath.Join(liveDir, "crs-setup.conf")
	if _, err := os.Stat(setupPath); os.IsNotExist(err) {
		if err := copyFile(filepath.Join(src, "crs-setup.conf"), setupPath); err != nil {
			log.Printf("crs seed: failed to seed crs-setup.conf from %s: %v", src, err)
		}
	}
	for _, aux := range []string{"crs-setup.stock.conf", "zz-user-overrides.conf"} {
		if _, err := os.Stat(filepath.Join(src, aux)); err == nil {
			_ = copyFile(filepath.Join(src, aux), filepath.Join(liveDir, aux))
		}
	}
	// 播种后落版本标记：对账逻辑据此区分「磁盘实际版本」与「数据库记录版本」。
	writeCRSVersionMarker(liveDir, srcVersion)
	log.Printf("crs seed: seeded %s from %s", liveDir, src)
	// R52 发现2：退化快照回退播种成功后，用新播种的 live 树重建快照，让快照
	// 自愈而不是永远停留在退化状态直到下次成功更新。
	if snapshotDegenerate {
		healDegenerateCRSSnapshot(liveDir, snapshotDir, srcVersion)
	}
}

// healDegenerateCRSSnapshot 用健康 live 树重建退化快照（R52 发现2）。live 树
// 自身也不健康（如 dist 源退化）或版本不可知时保留留现场语义，不做回写。
func healDegenerateCRSSnapshot(liveDir, snapshotDir, version string) {
	if version == "" || !crsRulesTreeIntact(filepath.Join(liveDir, "rules")) {
		log.Printf("crs: live tree unhealthy or version unknown, leaving degenerate snapshot %s in place for diagnosis", snapshotDir)
		return
	}
	if err := persistCRSSnapshotFrom(liveDir, snapshotDir, version); err != nil {
		log.Printf("crs: failed to rebuild snapshot %s from live tree: %v", snapshotDir, err)
		return
	}
	log.Printf("crs: rebuilt degenerate snapshot %s from live tree (%s)", snapshotDir, version)
}

// writeCRSVersionMarker records the on-disk CRS version under the live dir so
// startup reconciliation can tell the disk version from the DB record.
func writeCRSVersionMarker(liveDir, version string) {
	if version == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(liveDir, crsVersionFile), []byte(version+"\n"), 0644); err != nil {
		log.Printf("crs seed: failed to write version marker: %v", err)
	}
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
// path where no version marker exists yet.
const crsProbeFile = "rules/REQUEST-901-INITIALIZATION.conf"

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

// restoreCRSFromSnapshot copies the persisted snapshot tree back over the
// live dir (rules + setup + user override files) and refreshes the marker.
// R51 F2：装入前先对快照执行与 seed/备份恢复同一棵探针门——退化快照（部分
// rules + 完整 VERSION）拒绝恢复，调用方记录错误并保留 live 现场。
func restoreCRSFromSnapshot(liveDir, snapshotDir, version string) error {
	if !crsRulesTreeIntact(filepath.Join(snapshotDir, "rules")) {
		return fmt.Errorf("快照 rules 树不完整（缺失 %s），拒绝恢复", crsRulesProbeFile)
	}
	if err := os.RemoveAll(filepath.Join(liveDir, "rules")); err != nil {
		return err
	}
	if err := copyDir(filepath.Join(snapshotDir, "rules"), filepath.Join(liveDir, "rules")); err != nil {
		return err
	}
	for _, name := range []string{"crs-setup.conf", "crs-setup.stock.conf", "zz-user-overrides.conf"} {
		if _, err := os.Stat(filepath.Join(snapshotDir, name)); err == nil {
			if err := copyFile(filepath.Join(snapshotDir, name), filepath.Join(liveDir, name)); err != nil {
				return err
			}
		}
	}
	writeCRSVersionMarker(liveDir, version)
	return nil
}

// ReconcileCRSState realigns the CRS disk tree, data-volume snapshot and DB
// version row at startup. Master-only: a slave's CRS files and version row
// are both governed by cluster sync, local reconciliation would fight it.
//
// 前提：本函数仅在启动时调用（main.go 仅一处调用点）；运行期调用将持旧
// WafFiles 引用直到下次版本 bump。若未来新增运行期调用点，restore 成功后
// 须 BumpClusterVersion。
func ReconcileCRSState() {
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,0) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		return
	}
	reconcileCRSStateFrom(crsLiveDir, crsSnapshotDir, currentCRSVersion())
}

func reconcileCRSStateFrom(liveDir, snapshotDir, dbV string) {
	snapV := readCRSVersionMarker(snapshotDir)
	snapshotRulesExist := false
	snapshotDegenerate := false
	snapshotRules := filepath.Join(snapshotDir, "rules")
	if _, err := os.Stat(snapshotRules); err == nil {
		if crsRulesTreeIntact(snapshotRules) {
			snapshotRulesExist = true
		} else {
			// R51 F2：退化快照不作权威源——probe 不匹配分支会拿快照覆盖 live，
			// 退化快照会把 live 换成弱化树。按无快照处理并记录，快照留现场。
			log.Printf("crs reconcile: snapshot rules tree %s is incomplete (missing %s), not treating it as authoritative", snapshotRules, crsRulesProbeFile)
			snapV = ""
			snapshotDegenerate = true
		}
	} else {
		// R53 新-4：VERSION 标记尚在而 rules 树缺失同属退化快照，live 健康时
		// 走 heal 重建（与 seed 侧同一判定口径）。
		if snapV != "" {
			log.Printf("crs reconcile: snapshot %s carries a version marker but no rules tree, treating as degenerate", snapshotDir)
			snapshotDegenerate = true
		}
		snapV = ""
	}
	liveV := readCRSVersionMarker(liveDir)
	// R52 发现2：live 树完好且版本标记可确定时，用 live 树重建退化快照——
	// 用户更新版本在容器重建前即被保留，不必等下次成功更新才自愈。
	if snapshotDegenerate {
		healDegenerateCRSSnapshot(liveDir, snapshotDir, liveV)
	}
	plan := planCRSReconcile(liveV, snapV, dbV, CRSBundledVersion, snapshotRulesExist, crsTreeProbeMatches(liveDir, snapshotDir))
	switch plan.action {
	case crsReconcileNone:
		if plan.ambiguous {
			log.Printf("crs reconcile: 磁盘 CRS 无版本标记且与快照不一致（记录版本 %s），建议手动更新一次以补齐版本追踪", dbV)
		}
	case crsReconcileWriteMarker:
		writeCRSVersionMarker(liveDir, plan.markerVersion)
	case crsReconcileRestoreSnapshot:
		if err := restoreCRSFromSnapshot(liveDir, snapshotDir, plan.markerVersion); err != nil {
			log.Printf("crs reconcile: 从快照恢复 CRS %s 失败: %v", plan.markerVersion, err)
			return
		}
		if m := GetCRSUpdateManager(); m != nil {
			m.rescanRuleCount()
		}
		log.Printf("crs reconcile: 磁盘 CRS 已回退（容器重建），从数据卷快照恢复为 %s", plan.markerVersion)
		RecordAuditLog("system", "恢复", "CRS规则库", FormatAuditDetail("容器重建后从持久快照恢复 "+plan.markerVersion, AuditResultPart("success")), "")
	case crsReconcileCorrectDB:
		if _, err := db.DB.Exec("UPDATE security_crs_version SET version=?, updated_at=datetime('now') WHERE id=1", plan.dbVersion); err != nil {
			log.Printf("crs reconcile: 校正版本记录为磁盘实际版本 %s 失败: %v", plan.dbVersion, err)
			return
		}
		log.Printf("crs reconcile: 版本记录已校正为磁盘实际版本 %s（原记录 %s）", plan.dbVersion, dbV)
		// R52 发现2：原记录对应的更新成果随规则树丢失被静默废弃，必须留审计痕迹。
		RecordAuditLog("system", "恢复", "CRS规则库", FormatAuditDetail(fmt.Sprintf("磁盘规则树与版本记录不一致，版本记录已从 %s 校正为磁盘实际版本 %s（原记录对应的更新成果已废弃）", dbV, plan.dbVersion), AuditResultPart("success")), "")
	}
}
