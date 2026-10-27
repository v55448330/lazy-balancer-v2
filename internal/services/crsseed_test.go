package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestDecideCRSSeedSource(t *testing.T) {
	cases := []struct {
		name            string
		distVersion     string
		snapshotVersion string
		snapshotExists  bool
		want            string
	}{
		{"snapshot carrying a newer version wins", "v4.14.0", "v4.15.0", true, crsSeedFromSnapshot},
		{"snapshot carrying any different version wins", "v4.14.0", "v4.13.0", true, crsSeedFromSnapshot},
		{"missing snapshot falls back to dist", "v4.14.0", "", false, crsSeedFromDist},
		{"snapshot equal to bundled falls back to dist", "v4.14.0", "v4.14.0", true, crsSeedFromDist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideCRSSeedSource(tc.distVersion, tc.snapshotVersion, tc.snapshotExists)
			if got != tc.want {
				t.Fatalf("decideCRSSeedSource(%q, %q, %v)=%q, want %q",
					tc.distVersion, tc.snapshotVersion, tc.snapshotExists, got, tc.want)
			}
		})
	}
}

func TestSeedCRSRules_liveRulesPresentIsNoOp(t *testing.T) {
	// Given a live CRS dir that already has a complete rules tree, plus a dist
	// with a distinguishable tree and auxiliary files.
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", "REQUEST-900.conf"), "SecRule live")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(distDir, "rules", "REQUEST-900.conf"), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "rules", "REQUEST-950.conf"), "SecRule dist-only")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When seeding
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then the live rules tree is untouched（不得用 dist 树替换），且 dist
	// 独有的规则文件不得出现——旧断言未声明 dist fixture，copyFile 因源缺失
	// 静默失败，无法区分「正确跳过树复制」与「写失败」。
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", "REQUEST-900.conf"))
	if err != nil || string(data) != "SecRule live" {
		t.Fatalf("live rules=%q,%v, want untouched", data, err)
	}
	if _, err := os.Stat(filepath.Join(liveDir, "rules", "REQUEST-950.conf")); !os.IsNotExist(err) {
		t.Fatal("完整 rules 树不得被 dist 树覆盖（dist-only 规则出现在 live）")
	}
	// 辅助文件仍按「缺失才补种」语义补种（存在不覆盖）。
	if setup, err := os.ReadFile(filepath.Join(liveDir, "crs-setup.conf")); err != nil || string(setup) != "# dist setup" {
		t.Fatalf("缺失的 crs-setup.conf 应从 dist 补种: %q, %v", setup, err)
	}
	// 树完整时不写 VERSION 标记（仅播种路径写）。
	if _, err := os.Stat(filepath.Join(liveDir, crsVersionFile)); !os.IsNotExist(err) {
		t.Fatal("完整 rules 树路径不得写版本标记（版本只由播种/更新落盘）")
	}
}

func TestSeedCRSRules_seedsFromSnapshotWhenVersionDiffers(t *testing.T) {
	// Given an empty live dir, a snapshot with a user-updated version, and a dist copy
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(snapshotDir, "rules", "REQUEST-901.conf"), "SecRule snapshot")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", crsRulesProbeFile), "SecRule snapshot init")
	writeTestFile(t, filepath.Join(snapshotDir, "crs-setup.conf"), "# snapshot setup")
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), "v4.15.0\n")
	writeTestFile(t, filepath.Join(distDir, "rules", "REQUEST-900.conf"), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When seeding
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then rules and setup come from the snapshot, and the waf skeleton exists
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", "REQUEST-901.conf"))
	if err != nil || string(data) != "SecRule snapshot" {
		t.Fatalf("seeded rules=%q,%v, want snapshot content", data, err)
	}
	setup, _ := os.ReadFile(filepath.Join(liveDir, "crs-setup.conf"))
	if string(setup) != "# snapshot setup" {
		t.Fatalf("crs-setup.conf=%q, want snapshot setup", setup)
	}
	// 裁定后骨架仅重建 audit；custom 死目录不再创建（防回归）。
	if info, err := os.Stat(filepath.Join(root, "waf", "audit")); err != nil || !info.IsDir() {
		t.Fatalf("waf/audit missing after seed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "waf", "custom")); !os.IsNotExist(err) {
		t.Fatalf("waf/custom must not be recreated after seed, stat err=%v", err)
	}
}

func TestSeedCRSRules_seedsFromDistWhenSnapshotMissing(t *testing.T) {
	// Given an empty live dir and a dist copy, but no snapshot at all
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(distDir, "rules", "REQUEST-900.conf"), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When seeding
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then the live tree comes from the dist copy
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", "REQUEST-900.conf"))
	if err != nil || string(data) != "SecRule dist" {
		t.Fatalf("seeded rules=%q,%v, want dist content", data, err)
	}
	setup, _ := os.ReadFile(filepath.Join(liveDir, "crs-setup.conf"))
	if string(setup) != "# dist setup" {
		t.Fatalf("crs-setup.conf=%q, want dist setup", setup)
	}
}

func TestSeedCRSRules_seedsFromDistWhenSnapshotMatchesBundled(t *testing.T) {
	// Given a snapshot whose VERSION equals the bundled version (no user update)
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(snapshotDir, "rules", "REQUEST-900.conf"), "SecRule snapshot")
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), CRSBundledVersion+"\n")
	writeTestFile(t, filepath.Join(distDir, "rules", "REQUEST-900.conf"), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When seeding
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then the pristine dist copy wins over the identical snapshot
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", "REQUEST-900.conf"))
	if err != nil || string(data) != "SecRule dist" {
		t.Fatalf("seeded rules=%q,%v, want dist content", data, err)
	}
}

func TestSeedCRSRules_fallsBackToDistWhenSnapshotHasNoRules(t *testing.T) {
	// Given a snapshot with a differing VERSION but no rules tree (unusable)
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), "v4.15.0\n")
	writeTestFile(t, filepath.Join(distDir, "rules", "REQUEST-900.conf"), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When seeding
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then the dist copy is used instead of the broken snapshot
	data, err := os.ReadFile(filepath.Join(liveDir, "rules", "REQUEST-900.conf"))
	if err != nil || string(data) != "SecRule dist" {
		t.Fatalf("seeded rules=%q,%v, want dist content", data, err)
	}
}

func TestSeedCRSRules_writesVersionMarker(t *testing.T) {
	// Given an empty live dir and a snapshot carrying a user-updated version
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	if err := os.MkdirAll(liveDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(snapshotDir, "rules", "REQUEST-901.conf"), "SecRule snapshot")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", crsRulesProbeFile), "SecRule snapshot init")
	writeTestFile(t, filepath.Join(snapshotDir, "crs-setup.conf"), "# snapshot setup")
	writeTestFile(t, filepath.Join(snapshotDir, "VERSION"), "v4.15.0\n")
	writeTestFile(t, filepath.Join(distDir, "rules", "REQUEST-900.conf"), "SecRule dist")
	writeTestFile(t, filepath.Join(distDir, "crs-setup.conf"), "# dist setup")

	// When seeding from the snapshot
	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	// Then the live dir carries the snapshot version marker
	if got := readCRSVersionMarker(liveDir); got != "v4.15.0" {
		t.Fatalf("live marker=%q, want v4.15.0", got)
	}
}

func TestPlanCRSReconcile_matrix(t *testing.T) {
	cases := []struct {
		name                             string
		liveV, snapV, dbV, bundledV      string
		snapshotRulesExist, probeMatches bool
		want                             crsReconcileAction
		wantAmbiguous                    bool
	}{
		{"steady state: marker equals DB", "v4.15.0", "v4.15.0", "v4.15.0", "v4.14.0", true, true, crsReconcileNone, false},
		{"disk reverted: DB matches snapshot", "v4.14.0", "v4.15.0", "v4.15.0", "v4.14.0", true, false, crsReconcileRestoreSnapshot, false},
		{"no snapshot: disk is truth", "v4.28.0", "", "v4.14.0", "v4.28.0", false, false, crsReconcileCorrectDB, false},
		{"legacy marker-less disk matches snapshot content", "", "v4.15.0", "v4.15.0", "v4.14.0", true, true, crsReconcileWriteMarker, false},
		{"legacy marker-less disk differs from snapshot", "", "v4.15.0", "v4.15.0", "v4.14.0", true, false, crsReconcileRestoreSnapshot, false},
		{"legacy marker-less pristine disk", "", "", "v4.14.0", "v4.14.0", false, false, crsReconcileWriteMarker, false},
		{"legacy marker-less unknown version stays hands-off", "", "", "v4.15.0", "v4.14.0", false, false, crsReconcileNone, true},
		{"snapshot disagrees with DB: disk is truth", "v4.14.0", "v4.13.0", "v4.15.0", "v4.14.0", true, false, crsReconcileCorrectDB, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := planCRSReconcile(tc.liveV, tc.snapV, tc.dbV, tc.bundledV, tc.snapshotRulesExist, tc.probeMatches)
			if plan.action != tc.want || plan.ambiguous != tc.wantAmbiguous {
				t.Fatalf("planCRSReconcile(%q,%q,%q,%q,%v,%v)=%+v, want action=%v ambiguous=%v",
					tc.liveV, tc.snapV, tc.dbV, tc.bundledV, tc.snapshotRulesExist, tc.probeMatches, plan, tc.want, tc.wantAmbiguous)
			}
		})
	}
}

func TestRestoreCRSFromSnapshot_recoversUserUpdatedTree(t *testing.T) {
	// Given a reverted live tree (image-bundled rules) and a persisted snapshot
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsProbeFile), "SecRule bundled")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", crsProbeFile), "SecRule updated")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", crsRulesProbeFile), "SecRule updated init")
	writeTestFile(t, filepath.Join(snapshotDir, "crs-setup.conf"), "# updated setup")
	writeTestFile(t, filepath.Join(snapshotDir, "zz-user-overrides.conf"), "# user lines")
	writeTestFile(t, filepath.Join(snapshotDir, crsVersionFile), "v4.15.0\n")

	// When restoring
	if err := restoreCRSFromSnapshot(liveDir, snapshotDir, "v4.15.0"); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Then rules, setup and overrides come from the snapshot and the marker is refreshed
	rule, _ := os.ReadFile(filepath.Join(liveDir, "rules", crsProbeFile))
	if string(rule) != "SecRule updated" {
		t.Fatalf("restored rules=%q, want snapshot content", rule)
	}
	setup, _ := os.ReadFile(filepath.Join(liveDir, "crs-setup.conf"))
	if string(setup) != "# updated setup" {
		t.Fatalf("restored setup=%q, want snapshot setup", setup)
	}
	overrides, err := os.ReadFile(filepath.Join(liveDir, "zz-user-overrides.conf"))
	if err != nil || string(overrides) != "# user lines" {
		t.Fatalf("restored overrides=%q,%v, want snapshot copy", overrides, err)
	}
	if got := readCRSVersionMarker(liveDir); got != "v4.15.0" {
		t.Fatalf("live marker=%q, want v4.15.0", got)
	}
}

func TestPersistCRSSnapshotFrom_roundTrip(t *testing.T) {
	// Given an installed live tree with user overrides
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsProbeFile), "SecRule installed")
	writeTestFile(t, filepath.Join(liveDir, "crs-setup.conf"), "# installed setup")
	writeTestFile(t, filepath.Join(liveDir, "zz-user-overrides.conf"), "# user lines")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), "v4.15.0\n")

	// When persisting the snapshot
	if err := persistCRSSnapshotFrom(liveDir, snapshotDir, "v4.15.0"); err != nil {
		t.Fatalf("persist: %v", err)
	}

	// Then the snapshot carries rules, setup, overrides and the version marker
	for _, rel := range []string{
		filepath.Join("rules", crsProbeFile),
		"crs-setup.conf",
		"zz-user-overrides.conf",
		crsVersionFile,
	} {
		if _, err := os.Stat(filepath.Join(snapshotDir, rel)); err != nil {
			t.Fatalf("snapshot missing %s: %v", rel, err)
		}
	}
	if got := readCRSVersionMarker(snapshotDir); got != "v4.15.0" {
		t.Fatalf("snapshot marker=%q, want v4.15.0", got)
	}
}

func TestPersistCRSSnapshotFrom_blocksWhileWafFileLockHeld(t *testing.T) {
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsProbeFile), "SecRule installed")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), "v4.15.0")

	probeBlocksUnderWafFileLock(t, "CRS 快照持久化", func() error {
		return persistCRSSnapshotFrom(liveDir, snapshotDir, "v4.15.0")
	})
}

func TestSeedCRSRules_healsDegenerateSnapshotWithLiveVersion(t *testing.T) {
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", "REQUEST-900.conf"), "SecRule live")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(liveDir, "VERSION"), "v4.15.0\n")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", "REQUEST-900.conf"), "SecRule snapshot-partial")

	seedCRSRulesFrom(liveDir, snapshotDir, distDir)

	raw, err := os.ReadFile(filepath.Join(snapshotDir, "VERSION"))
	if err != nil {
		t.Fatalf("read healed snapshot VERSION: %v", err)
	}
	if strings.TrimSpace(string(raw)) != "v4.15.0" {
		t.Fatalf("snapshot VERSION=%q, want live v4.15.0 (not bundled)", strings.TrimSpace(string(raw)))
	}
}

func TestSeedCRSRules_blocksWhileWafFileLockHeld(t *testing.T) {
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule live")

	probeBlocksUnderWafFileLock(t, "CRS 播种判定与写相位", func() error {
		seedCRSRulesFrom(liveDir, snapshotDir, distDir)
		return nil
	})
}

func TestReconcileCRSState_nilDatabaseIsNoOp(t *testing.T) {
	// Given a direct call before database initialization (a supported test and
	// startup-defensive shape); there is no role to reconcile or files to touch.
	oldDB := db.DB
	db.DB = nil
	t.Cleanup(func() { db.DB = oldDB })
	root := t.TempDir()
	oldLive, oldSnapshot := crsLiveDir, crsSnapshotDir
	crsLiveDir = filepath.Join(root, "waf", "crs")
	crsSnapshotDir = filepath.Join(root, "data", "crs")
	t.Cleanup(func() { crsLiveDir, crsSnapshotDir = oldLive, oldSnapshot })
	// 健康 live 树 + 缺失快照是「自愈会创建快照」的可观察形态：角色读取失败
	// 后若仍继续对账，快照目录会被建出来。
	writeTestFile(t, filepath.Join(crsLiveDir, "rules", crsRulesProbeFile), "SecRule live")
	writeTestFile(t, filepath.Join(crsLiveDir, crsVersionFile), "v4.15.0\n")

	// When
	ReconcileCRSState()

	// Then: reconciliation returns without dereferencing a nil *sql.DB and
	// leaves the filesystem untouched.
	if _, err := os.Stat(crsSnapshotDir); !os.IsNotExist(err) {
		t.Fatalf("nil DB 对账不得触碰文件系统（快照目录被创建/已存在: err=%v）", err)
	}
	got, err := os.ReadFile(filepath.Join(crsLiveDir, crsVersionFile))
	if err != nil || string(got) != "v4.15.0\n" {
		t.Fatalf("live 版本标记被改写: %q err=%v", got, err)
	}
}

func TestReconcileCRSState_blocksWhileWafFileLockHeld(t *testing.T) {
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule live")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), "v4.15.0\n")

	probeBlocksUnderWafFileLock(t, "CRS 对账判定与写相位", func() error {
		reconcileCRSStateFrom(liveDir, snapshotDir, "v4.15.0")
		return nil
	})
}

// 快照整体缺席（目录被删/数据卷换新/更新时快照写入失败）不进退化判定：
// live 树健康且版本可确定时必须按 live 重建，否则 liveV==dbV 判 none 后再无
// 任何写快照的入口，容器重建即回退镜像捆绑版本（用户更新成果丢失）。
func TestReconcileCRSState_rebuildsMissingSnapshotFromLive(t *testing.T) {
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule user-updated")
	writeTestFile(t, filepath.Join(liveDir, "crs-setup.conf"), "# user setup")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), "v4.15.0\n")

	reconcileCRSStateFrom(liveDir, snapshotDir, "v4.15.0")

	if got := readCRSVersionMarker(snapshotDir); got != "v4.15.0" {
		t.Fatalf("快照 VERSION=%q, want v4.15.0（缺席快照必须按 live 重建）", got)
	}
	if data, err := os.ReadFile(filepath.Join(snapshotDir, "rules", crsRulesProbeFile)); err != nil || string(data) != "SecRule user-updated" {
		t.Fatalf("重建快照 rules=%q,err=%v, want live 内容", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(snapshotDir, "crs-setup.conf")); err != nil || string(data) != "# user setup" {
		t.Fatalf("重建快照 setup=%q,err=%v, want live 内容", data, err)
	}
}

// 镜像捆绑版本（live 无用户更新）不重建缺席快照：dist 本就可重播，凭空写
// 快照只会让快照与捆绑版本等值（decideCRSSeedSource 仍回退 dist）。
func TestReconcileCRSState_skipsSnapshotRebuildForBundledLive(t *testing.T) {
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule bundled")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), CRSBundledVersion+"\n")

	reconcileCRSStateFrom(liveDir, snapshotDir, CRSBundledVersion)

	if _, err := os.Stat(snapshotDir); !os.IsNotExist(err) {
		t.Fatalf("bundled live 不应重建快照: stat err=%v", err)
	}
}

// restoreCRSFromSnapshot 仅供测试的加锁包装：生产路径统一走
// ReconcileCRSState 持 wafFileMu 后调用 restoreCRSFromSnapshotInLock，
// 生产代码不得再导出「自加锁」的第二套恢复入口。
func restoreCRSFromSnapshot(liveDir, snapshotDir, version string) error {
	wafFileMu.Lock()
	defer wafFileMu.Unlock()
	return restoreCRSFromSnapshotInLock(liveDir, snapshotDir, version)
}

// 无法清除残缺 rules 树时必须上抛：上层要能区分「已播种」与「未播种」。旧实现
// 只打一条 error 日志后 return nil，live 树残缺时渲染侧对每个 Include 走
// 「缺失→warn+跳过」，WAF 被静默降级为只剩 IP 控制面。
func TestSeedCRSRules_residualTreeClearFailureIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 忽略目录权限位，无法构造 RemoveAll 失败")
	}
	root := t.TempDir()
	liveDir := filepath.Join(root, "waf", "crs")
	snapshotDir := filepath.Join(root, "data", "crs")
	distDir := filepath.Join(root, "waf.dist", "crs")
	// 残缺树：rules 目录存在但探针文件缺失（崩溃窗口形态）
	writeTestFile(t, filepath.Join(liveDir, "rules", "REQUEST-900.conf"), "SecRule partial")
	writeTestFile(t, filepath.Join(distDir, "rules", crsRulesProbeFile), "SecRule init")
	// 去掉 live 父目录写权限 → RemoveAll(rules) 无法 unlink 目录项
	if err := os.Chmod(liveDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(liveDir, 0o755) })

	err := seedCRSRulesFrom(liveDir, snapshotDir, distDir)
	if err == nil {
		t.Fatal("清除残缺 rules 树失败时播种必须返回 error（不得当成功静默）")
	}
	if !strings.Contains(err.Error(), "清除残缺 rules 树") {
		t.Fatalf("error=%v, want 点名清除残缺树失败", err)
	}
}
